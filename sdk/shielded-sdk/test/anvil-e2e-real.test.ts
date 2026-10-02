/**
 * Full Lifecycle Anvil E2E — REAL VAnchor with REAL Groth16 proofs on-chain
 *
 * Unlike anvil-e2e.test.ts (which uses MockVAnchor and skips ZK verification
 * on-chain), this test deploys the production stack:
 *
 *   Poseidon libs → PoseidonHasher → Verifier2_2/2_16/8_2/8_16 (from the
 *   trusted-setup ceremony output) → VAnchorVerifier → TokenWrapperHandler →
 *   FungibleTokenWrapper → AnchorHandler → VAnchorTree → ShieldedCredits →
 *   ShieldedGateway
 *
 * and proves the complete loop with real proofs verified ON-CHAIN:
 *
 *   1. wrap USDC → tsUSD in the FungibleTokenWrapper
 *   2. deposit tsUSD into VAnchorTree (real Groth16 proof, verified on-chain)
 *   3. anonymized withdrawal through ShieldedGateway.shieldedFundCredits
 *      (real join-split proof spending the deposit UTXO, verified on-chain)
 *   4. EIP-712 SpendAuth → operator claimPayment
 *   5. expiry reclaim of an unconsumed authorization
 *   6. withdrawCredits of the remaining balance
 *   7. direct VAnchor withdrawal of the change UTXO (second real proof)
 *
 * Prerequisites:
 *   - Circuit artifacts staged at build/circuits/vanchor_2_8/
 *     (run scripts/trusted-setup/ceremony.sh then scripts/stage-circuit-artifacts.sh)
 *   - forge build completed (out/ artifacts)
 *
 * Run:
 *   npx vitest run test/anvil-e2e-real.test.ts --timeout 600000
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { execSync, spawn, type ChildProcess } from "child_process";
import { ethers } from "ethers";
import {
  Keypair,
  Utxo,
  MerkleTree,
  ChainType,
  typedChainId,
  FIELD_SIZE,
} from "../src/protocol/index.js";
import {
  buildWitnessInputs,
  computeExtDataHash,
  computePublicAmount,
} from "../src/proof/witness.js";
import { encodeSolidityProof } from "../src/proof/prover.js";
import {
  ShieldedCreditsClient,
  generateCreditKeys,
} from "../src/contract/credits-client.js";

const ROOT_DIR = join(import.meta.dirname, "../../../");
const CIRCUIT_DIR = join(ROOT_DIR, "build/circuits/vanchor_2_8");
const WASM_PATH = join(CIRCUIT_DIR, "poseidon_vanchor_2_8_js/poseidon_vanchor_2_8.wasm");
const ZKEY_PATH = join(CIRCUIT_DIR, "circuit_final.zkey");
const VERIFIERS_SOL_DIR = join(ROOT_DIR, "build/trusted-setup/verifiers");

const ANVIL_PORT = Number(process.env.ANVIL_PORT ?? 8556);
const RPC_URL = `http://127.0.0.1:${ANVIL_PORT}`;
const DEPLOYER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // anvil account 0
const OPERATOR_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // anvil account 1

const MAX_EDGES = 7;
const TREE_LEVELS = 30;

const SKIP =
  process.env.SKIP_ANVIL_E2E === "1" ||
  !existsSync(WASM_PATH) ||
  !existsSync(ZKEY_PATH);

const ERC20_ABI = [
  "function mint(address to, uint256 amount) external",
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address account) external view returns (uint256)",
];

const WRAPPER_ABI = [
  "function initialize(uint16,address,address,uint256,bool,address) external",
  "function wrap(address tokenAddress, uint256 amount) external payable",
  "function approve(address, uint256) external returns (bool)",
  "function balanceOf(address) external view returns (uint256)",
  "function valid(address) external view returns (bool)",
];

const VANCHOR_ABI = [
  "function transact(bytes, bytes, tuple(address,int256,address,uint256,uint256,address), tuple(bytes,bytes,uint256[],uint256[2],uint256,uint256), tuple(bytes,bytes)) external payable",
  "function initialize(uint256, uint256) external",
  "function getLastRoot() external view returns (uint256)",
  "function getZeroHash(uint32) external view returns (uint256)",
  "function getNextIndex() external view returns (uint32)",
  "function isSpent(uint256) external view returns (bool)",
  "event NewCommitment(uint256 commitment, uint256 subTreeIndex, uint256 leafIndex, bytes encryptedOutput)",
  "event NewNullifier(uint256 nullifier)",
];

const GATEWAY_ABI = [
  "function shieldedFundCredits(tuple(bytes proof, bytes auxPublicInputs, bytes externalData, bytes publicInputs, bytes encryptions), bytes32 commitment, address spendingKey) external payable",
  "function registerPool(address wrappedToken, address pool) external",
];

function loadArtifact(name: string): { abi: unknown; bytecode: string } {
  const artifact = JSON.parse(
    readFileSync(join(ROOT_DIR, `out/${name}.sol/${name}.json`), "utf-8")
  );
  return { abi: artifact.abi, bytecode: artifact.bytecode.object };
}

async function deployFromOut(
  name: string,
  deployer: ethers.Wallet,
  ...args: unknown[]
): Promise<ethers.Contract> {
  const { abi, bytecode } = loadArtifact(name);
  const factory = new ethers.ContractFactory(abi as ethers.InterfaceAbi, bytecode, deployer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

/** Extract deployedTo from `forge create --json` stdout (pretty-printed). */
function parseForgeCreateOutput(out: Buffer): string {
  const text = out.toString();
  const match = text.match(/"deployedTo"\s*:\s*"(0x[0-9a-fA-F]{40})"/);
  if (!match) {
    throw new Error(`forge create did not return deployedTo:\n${text}`);
  }
  return match[1];
}

/** Deploy a ceremony-generated Groth16 verifier via forge create. */
function forgeCreateVerifier(
  circuitName: string,
  contractName: string
): string {
  const out = execSync(
    `FOUNDRY_VIA_IR=false forge create --broadcast --json --rpc-url ${RPC_URL} --private-key ${DEPLOYER_KEY} ` +
      `build/trusted-setup/verifiers/${circuitName}_verifier.sol:${contractName}`,
    { cwd: ROOT_DIR, maxBuffer: 64 * 1024 * 1024 }
  );
  return parseForgeCreateOutput(out);
}

/** Deploy PoseidonHasher linked against pre-deployed Poseidon libraries. */
function forgeCreatePoseidonHasher(libs: Record<string, string>): string {
  const libFlags = [2, 3, 4, 5, 6]
    .map(
      (t) =>
        `--libraries protocol-solidity/hashers/Poseidon.sol:PoseidonT${t}:${libs[`T${t}`]}`
    )
    .join(" ");
  const out = execSync(
    `FOUNDRY_VIA_IR=false forge create --broadcast --json --rpc-url ${RPC_URL} --private-key ${DEPLOYER_KEY} ` +
      `${libFlags} dependencies/protocol-solidity/packages/contracts/contracts/hashers/PoseidonHasher.sol:PoseidonHasher`,
    { cwd: ROOT_DIR, maxBuffer: 64 * 1024 * 1024 }
  );
  return parseForgeCreateOutput(out);
}

/** Deploy VAnchorTree linked against VAnchorEncodeInputs. */
function forgeCreateVAnchorTree(args: {
  verifier: string;
  levels: number;
  hasher: string;
  handler: string;
  token: string;
  maxEdges: number;
}): string {
  const encodeInputsLib = parseForgeCreateOutput(
    execSync(
      `FOUNDRY_VIA_IR=false forge create --broadcast --json --rpc-url ${RPC_URL} --private-key ${DEPLOYER_KEY} ` +
        `dependencies/protocol-solidity/packages/contracts/contracts/libs/VAnchorEncodeInputs.sol:VAnchorEncodeInputs`,
      { cwd: ROOT_DIR, maxBuffer: 64 * 1024 * 1024 }
    )
  );
  const out = execSync(
    `FOUNDRY_VIA_IR=false forge create --broadcast --json --rpc-url ${RPC_URL} --private-key ${DEPLOYER_KEY} ` +
      `--libraries dependencies/protocol-solidity/packages/contracts/contracts/libs/VAnchorEncodeInputs.sol:VAnchorEncodeInputs:${encodeInputsLib} ` +
      `dependencies/protocol-solidity/packages/contracts/contracts/vanchors/instances/VAnchorTree.sol:VAnchorTree ` +
      `--constructor-args ${args.verifier} ${args.levels} ${args.hasher} ${args.handler} ${args.token} ${args.maxEdges}`,
    { cwd: ROOT_DIR, maxBuffer: 64 * 1024 * 1024 }
  );
  return parseForgeCreateOutput(out);
}

function computeResourceId(contractAddr: string, chainId: bigint): string {
  return ethers.toBeHex((chainId << 160n) | BigInt(contractAddr), 32);
}

describe.skipIf(SKIP)("Anvil E2E (REAL VAnchor + REAL on-chain proofs)", () => {
  let anvil: ChildProcess | undefined;
  let provider: ethers.JsonRpcProvider;
  let deployer: ethers.Wallet;
  let deployerAddress: string;
  let operator: ethers.Wallet;

  let usdc: ethers.Contract;
  let wrapper: ethers.Contract;
  let pool: ethers.Contract; // VAnchorTree
  let credits: ShieldedCreditsClient;
  let creditsAddr: string;
  let gateway: ethers.Contract;
  let gatewayAddr: string;
  let wrapperAddr: string;
  let poolAddr: string;

  let tree: MerkleTree;
  let chainId: bigint; // typed chain id
  let rawChainId: bigint;
  let edgeZero: bigint; // getZeroHash(outerLevels - 1) for disabled edges

  // UTXO state carried across the lifecycle
  const keypair = new Keypair();
  let depositUtxo: Utxo;
  let changeUtxo: Utxo;

  beforeAll(async () => {
    provider = new ethers.JsonRpcProvider(RPC_URL);
    try {
      await provider.getNetwork();
    } catch {
      anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {
        stdio: "ignore",
      });
      await new Promise((r) => setTimeout(r, 2000));
      provider = new ethers.JsonRpcProvider(RPC_URL);
    }

    // NonceManager avoids stale cached nonces across rapid sequential deploys
    deployer = new ethers.NonceManager(
      new ethers.Wallet(DEPLOYER_KEY, provider)
    ) as unknown as ethers.Wallet;
    operator = new ethers.Wallet(OPERATOR_KEY, provider);
    deployerAddress = await deployer.getAddress();

    const network = await provider.getNetwork();
    rawChainId = network.chainId;
    chainId = typedChainId(ChainType.EVM, Number(rawChainId));
    tree = await MerkleTree.create(TREE_LEVELS);

    console.log("Deploying REAL shielded stack on Anvil...");

    // 1. Mock stablecoin
    usdc = await deployFromOut("MockERC20", deployer);
    const usdcAddr = await usdc.getAddress();
    console.log("  MockERC20:", usdcAddr);

    // 2. Poseidon libraries (circomlibjs bytecode)
    const circomlibjs = await import("circomlibjs");
    const genContract =
      circomlibjs.poseidon_gencontract ?? circomlibjs.default?.poseidon_gencontract;
    const poseidonLibs: Record<string, string> = {};
    for (let t = 1; t <= 5; t++) {
      const abi = genContract.generateABI(t);
      const bytecode = genContract.createCode(t);
      const factory = new ethers.ContractFactory(abi, bytecode, deployer);
      const c = await factory.deploy();
      await c.waitForDeployment();
      poseidonLibs[`T${t + 1}`] = await c.getAddress();
    }
    console.log("  Poseidon T2-T6 deployed");

    // 3. PoseidonHasher (library-linked via forge)
    const hasherAddr = forgeCreatePoseidonHasher(poseidonLibs);
    console.log("  PoseidonHasher:", hasherAddr);

    // 4. Ceremony verifiers
    const v2_2 = forgeCreateVerifier("poseidon_vanchor_2_2", "Verifier2_2");
    const v2_16 = forgeCreateVerifier("poseidon_vanchor_16_2", "Verifier2_16");
    const v8_2 = forgeCreateVerifier("poseidon_vanchor_2_8", "Verifier8_2");
    const v8_16 = forgeCreateVerifier("poseidon_vanchor_16_8", "Verifier8_16");
    console.log("  Verifiers deployed");
    nmSkip(5); // PoseidonHasher + 4 verifiers deployed via forge

    // 5. VAnchorVerifier router
    const vanchorVerifier = await deployFromOut(
      "VAnchorVerifier",
      deployer,
      v2_2,
      v2_16,
      v8_2,
      v8_16
    );
    console.log("  VAnchorVerifier:", await vanchorVerifier.getAddress());

    // 6. TokenWrapperHandler (deployer = bridge during setup)
    const twHandler = await deployFromOut(
      "TokenWrapperHandler",
      deployer,
      deployerAddress,
      [],
      []
    );

    // 7. FungibleTokenWrapper
    wrapper = await deployFromOut(
      "FungibleTokenWrapper",
      deployer,
      "Tangle Shielded USD",
      "tsUSD"
    );
    await (
      await wrapper.initialize(
        0, // feePercentage
        deployerAddress, // feeRecipient
        await twHandler.getAddress(),
        ethers.MaxUint256, // wrappingLimit (test amounts are 18-decimal)
        false, // isNativeAllowed
        deployerAddress // admin
      )
    ).wait();
    wrapperAddr = await wrapper.getAddress();
    console.log("  FungibleTokenWrapper:", wrapperAddr);

    // 8. Register wrapper resource + USDC as wrappable (mirrors DeployShieldedPool)
    const wrapperResourceId = computeResourceId(wrapperAddr, rawChainId);
    await (
      await twHandler.setResource(wrapperResourceId, wrapperAddr)
    ).wait();
    const addSig = ethers.keccak256(ethers.toUtf8Bytes("add(address,uint32)")).slice(0, 10);
    const proposalData = ethers.solidityPacked(
      ["bytes32", "bytes4", "bytes4", "bytes20"],
      [wrapperResourceId, addSig, ethers.toBeHex(1, 4), usdcAddr]
    );
    await (
      await twHandler.executeProposal(wrapperResourceId, proposalData)
    ).wait();
    expect(await wrapper.valid(usdcAddr)).toBe(true);

    // 9. AnchorHandler + VAnchorTree (the real pool; links VAnchorEncodeInputs)
    const anchorHandler = await deployFromOut(
      "AnchorHandler",
      deployer,
      deployerAddress,
      [],
      []
    );
    poolAddr = forgeCreateVAnchorTree({
      verifier: await vanchorVerifier.getAddress(),
      levels: TREE_LEVELS,
      hasher: hasherAddr,
      handler: await anchorHandler.getAddress(),
      token: wrapperAddr,
      maxEdges: MAX_EDGES,
    });
    pool = new ethers.Contract(poolAddr, VANCHOR_ABI, deployer);
    console.log("  VAnchorTree:", poolAddr);
    nmSkip(2); // VAnchorEncodeInputs lib + VAnchorTree deployed via forge

    // Deposit/withdrawal limits (the step DeployShieldedPool previously missed)
    await (await pool.initialize(0n, ethers.MaxUint256)).wait();

    const anchorResourceId = computeResourceId(poolAddr, rawChainId);
    await (
      await anchorHandler.setResource(anchorResourceId, poolAddr)
    ).wait();

    // 10. ShieldedCredits + ShieldedGateway
    const creditsContract = await deployFromOut("ShieldedCredits", deployer);
    creditsAddr = await creditsContract.getAddress();
    credits = new ShieldedCreditsClient(creditsAddr, deployer);

    gateway = await deployFromOut(
      "ShieldedGateway",
      deployer,
      deployerAddress, // TANGLE placeholder (unused in credits flow)
      creditsAddr,
      deployerAddress // owner
    );
    gatewayAddr = await gateway.getAddress();
    await (await gateway.registerPool(wrapperAddr, poolAddr)).wait();
    console.log("  ShieldedCredits:", creditsAddr);
    console.log("  ShieldedGateway:", gatewayAddr);

    // Sanity: SDK off-chain zero values must match the on-chain hasher table
    edgeZero = await pool.getZeroHash(TREE_LEVELS - 1);
    const onchainRoot = await pool.getLastRoot();
    console.log("  Empty-tree root (on-chain):", onchainRoot.toString());
    console.log("  Edge zero (zeros[29]):     ", edgeZero.toString());
    // The on-chain empty-tree root convention is zeros(levels-1); the SDK's
    // empty-tree root is zeros(levels). Both are valid starting roots for
    // proofs whose inputs are all zero-amount (membership check disabled).
    console.log("  SDK empty-tree root:       ", tree.root.toString());
  }, 300_000);

  afterAll(() => {
    if (anvil?.pid) {
      try {
        process.kill(anvil.pid);
      } catch {
        /* already dead */
      }
      try {
        process.kill(-anvil.pid);
      } catch {
        /* already dead */
      }
    }
  });

  /**
   * Fast-forward the NonceManager after `forge create` deployed contracts
   * with the same key outside ethers. We know the exact number of forge txs,
   * so increment deterministically — querying the node here is racy because
   * anvil's "pending" tag can lag or catch up mid-flight, and a too-high
   * nonce gets queued (never mined) instead of rejected.
   */
  function nmSkip(count: number): void {
    const nm = deployer as unknown as ethers.NonceManager;
    for (let i = 0; i < count; i++) nm.increment();
  }

  /** Build roots array for the 8-edge circuit: [localRoot, edgeZero x7]. */
  function buildRoots(localRoot: bigint): bigint[] {
    return [localRoot, ...Array(MAX_EDGES).fill(edgeZero) as bigint[]];
  }

  /** Generate a real Groth16 proof and pack it for VAnchor.transact. */
  async function proveTransact(params: {
    inputs: Utxo[];
    outputs: [Utxo, Utxo];
    extAmount: bigint;
    recipient: string;
    fee?: bigint;
    /// Override roots[0] (e.g. for the first deposit, where the on-chain
    /// empty-tree root convention is zeros(levels-1), not zeros(levels))
    localRoot?: bigint;
  }): Promise<{
    proofBytes: Uint8Array;
    publicInputs: {
      roots: string;
      extensionRoots: string;
      inputNullifiers: bigint[];
      outputCommitments: [bigint, bigint];
      publicAmount: bigint;
      extDataHash: bigint;
    };
  }> {
    const fee = params.fee ?? 0n;
    const extDataHash = computeExtDataHash({
      recipient: params.recipient,
      extAmount: params.extAmount,
      relayer: ethers.ZeroAddress,
      fee,
      refund: 0n,
      token: wrapperAddr,
      encryptedOutput1: new Uint8Array(0),
      encryptedOutput2: new Uint8Array(0),
    });

    const localRoot = params.localRoot ?? tree.root;
    const witnessInput = await buildWitnessInputs({
      inputs: params.inputs,
      outputs: params.outputs,
      tree,
      extDataHash,
      extAmount: params.extAmount,
      fee,
      chainId,
      roots: buildRoots(localRoot),
    });

    const snarkjs = await import("snarkjs");
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      witnessInput as unknown as Record<string, unknown>,
      WASM_PATH,
      ZKEY_PATH
    );

    const { proofBytes } = await encodeSolidityProof({ proof, publicSignals });

    const nullifiers = await Promise.all(
      params.inputs.map((u) => u.getNullifier())
    );
    const commitments = (await Promise.all(
      params.outputs.map((u) => u.getCommitment())
    )) as [bigint, bigint];

    const rootsArr = buildRoots(localRoot);
    return {
      proofBytes,
      publicInputs: {
        roots: ethers.AbiCoder.defaultAbiCoder().encode(
          [`uint256[${MAX_EDGES + 1}]`],
          [rootsArr]
        ),
        extensionRoots: "0x",
        inputNullifiers: nullifiers,
        outputCommitments: commitments,
        publicAmount: computePublicAmount(params.extAmount, fee),
        extDataHash,
      },
    };
  }

  it("deposit: wrap USDC and deposit tsUSD with a real on-chain-verified proof", async () => {
    const depositAmount = 100n * 10n ** 18n;

    // Mint USDC and wrap into tsUSD (the pool token)
    await (await usdc.mint(deployerAddress, depositAmount)).wait();
    await (await usdc.approve(wrapperAddr, depositAmount)).wait();
    await (await wrapper.wrap(await usdc.getAddress(), depositAmount)).wait();
    expect(await wrapper.balanceOf(deployerAddress)).toBe(depositAmount);
    console.log("  Wrapped 100 USDC -> tsUSD ✓");

    // Deposit: 2 zero inputs, outputs = [100 UTXO, 0 change]
    depositUtxo = Utxo.create({ chainId, amount: depositAmount, keypair });
    const zeroChange = await Utxo.zero(chainId, keypair);
    const zeroIn1 = await Utxo.zero(chainId, keypair);
    const zeroIn2 = await Utxo.zero(chainId, keypair);
    zeroIn1.index = 0;
    zeroIn2.index = 0;

    console.time("  deposit proof");
    const { proofBytes, publicInputs } = await proveTransact({
      inputs: [zeroIn1, zeroIn2],
      outputs: [depositUtxo, zeroChange],
      extAmount: depositAmount,
      recipient: ethers.ZeroAddress,
      // All inputs are zero-amount so membership checks are disabled; use the
      // on-chain current root (zeros(levels-1) for the empty tree) which is
      // the only root isKnownRoot() accepts at this point.
      localRoot: await pool.getLastRoot(),
    });
    console.timeEnd("  deposit proof");

    await (await wrapper.approve(poolAddr, depositAmount)).wait();

    const tx = await pool.transact(
      proofBytes,
      "0x",
      [
        ethers.ZeroAddress, // recipient
        depositAmount, // extAmount (deposit)
        ethers.ZeroAddress, // relayer
        0n, // fee
        0n, // refund
        wrapperAddr, // token == wrapped token: direct tsUSD transfer
      ],
      [
        publicInputs.roots,
        publicInputs.extensionRoots,
        publicInputs.inputNullifiers,
        publicInputs.outputCommitments,
        publicInputs.publicAmount,
        publicInputs.extDataHash,
      ],
      ["0x", "0x"]
    );
    const receipt = await tx.wait();
    console.log("  deposit tx gas:", receipt!.gasUsed.toString());

    // Sync local tree with the inserted commitments
    const nextIdx = await pool.getNextIndex();
    expect(nextIdx).toBe(2n);
    depositUtxo.index = 0;
    await tree.insert(await depositUtxo.getCommitment());
    await tree.insert(await zeroChange.getCommitment());

    // The local tree root must match the on-chain root exactly
    const onchainRoot = await pool.getLastRoot();
    expect(tree.root).toBe(onchainRoot);
    console.log("  deposit verified on-chain; roots match ✓");

    // Pool now holds the tsUSD
    expect(await wrapper.balanceOf(poolAddr)).toBe(depositAmount);
  }, 120_000);

  it("withdraw via gateway: real join-split proof funds ShieldedCredits", async () => {
    const creditKeys = generateCreditKeys();
    const fundAmount = 50n * 10n ** 18n;

    // Inputs: the deposit UTXO (index 0) + a zero input
    const zeroIn = await Utxo.zero(chainId, keypair);
    zeroIn.index = 0;

    // Outputs: change UTXO (50) + zero
    changeUtxo = Utxo.create({ chainId, amount: fundAmount, keypair });
    const zeroOut = await Utxo.zero(chainId, keypair);

    console.time("  withdrawal proof");
    const { proofBytes, publicInputs } = await proveTransact({
      inputs: [depositUtxo, zeroIn],
      outputs: [changeUtxo, zeroOut],
      extAmount: -fundAmount,
      recipient: gatewayAddr, // gateway enforces recipient == itself
    });
    console.timeEnd("  withdrawal proof");

    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const anchorProof = {
      proof: proofBytes,
      auxPublicInputs: "0x",
      externalData: abiCoder.encode(
        ["tuple(address,int256,address,uint256,uint256,address)"],
        [[gatewayAddr, -fundAmount, ethers.ZeroAddress, 0n, 0n, wrapperAddr]]
      ),
      publicInputs: abiCoder.encode(
        ["tuple(bytes,bytes,uint256[],uint256[2],uint256,uint256)"],
        [[
          publicInputs.roots,
          publicInputs.extensionRoots,
          publicInputs.inputNullifiers,
          publicInputs.outputCommitments,
          publicInputs.publicAmount,
          publicInputs.extDataHash,
        ]]
      ),
      encryptions: abiCoder.encode(
        ["tuple(bytes,bytes)"],
        [["0x", "0x"]]
      ),
    };

    const tx = await gateway.shieldedFundCredits(
      anchorProof,
      creditKeys.commitment,
      creditKeys.spendingPublicKey
    );
    const receipt = await tx.wait();
    console.log("  shieldedFundCredits gas:", receipt!.gasUsed.toString());

    // Credits funded with exactly the withdrawn amount
    const acct = await credits.getAccount(creditKeys.commitment);
    expect(acct.balance).toBe(fundAmount);
    expect(acct.spendingKey).toBe(creditKeys.spendingPublicKey);
    expect(acct.token).toBe(ethers.getAddress(wrapperAddr));
    console.log("  credits funded anonymously via REAL proof ✓");

    // Atomic flow: gateway holds nothing after the tx
    expect(await wrapper.balanceOf(gatewayAddr)).toBe(0n);

    // Nullifier of the deposit UTXO is spent on-chain
    expect(await pool.isSpent(await depositUtxo.getNullifier())).toBe(true);

    // Sync tree: change + zero commitments inserted
    changeUtxo.index = 2;
    await tree.insert(await changeUtxo.getCommitment());
    await tree.insert(await zeroOut.getCommitment());
    expect(tree.root).toBe(await pool.getLastRoot());
    console.log("  change UTXO committed; roots match ✓");

    // Stash keys for the spend tests
    this_creditKeys = creditKeys;
  }, 120_000);

  let this_creditKeys: ReturnType<typeof generateCreditKeys>;

  it("spend: EIP-712 SpendAuth → operator claimPayment", async () => {
    const spendAmount = 10n * 10n ** 18n;

    const { authHash } = await credits.authorizeSpend({
      spendingPrivateKey: this_creditKeys.spendingPrivateKey,
      commitment: this_creditKeys.commitment,
      serviceId: 0n,
      jobIndex: 0,
      amount: spendAmount,
      operator: operator.address,
    });
    console.log("  spend authorized ✓");

    const operatorCredits = new ShieldedCreditsClient(creditsAddr, operator);
    const opBalBefore = await wrapper.balanceOf(operator.address);
    await operatorCredits.claimPayment(authHash, operator.address);
    const opBalAfter = await wrapper.balanceOf(operator.address);
    expect(opBalAfter - opBalBefore).toBe(spendAmount);

    const acct = await credits.getAccount(this_creditKeys.commitment);
    expect(acct.balance).toBe(40n * 10n ** 18n);
    console.log("  operator claimed 10 tsUSD ✓");
  }, 60_000);

  it("reclaim: unconsumed expired authorization returns funds", async () => {
    const spendAmount = 5n * 10n ** 18n;

    // Authorize with a 60-second expiry, then let it lapse
    const { authHash } = await credits.authorizeSpend({
      spendingPrivateKey: this_creditKeys.spendingPrivateKey,
      commitment: this_creditKeys.commitment,
      serviceId: 0n,
      jobIndex: 1,
      amount: spendAmount,
      operator: operator.address,
      expirySeconds: 60,
    });

    let acct = await credits.getAccount(this_creditKeys.commitment);
    expect(acct.balance).toBe(35n * 10n ** 18n);

    await provider.send("evm_increaseTime", [120]);
    await provider.send("evm_mine", []);

    await credits.reclaimExpiredAuth(authHash, this_creditKeys.commitment);

    acct = await credits.getAccount(this_creditKeys.commitment);
    expect(acct.balance).toBe(40n * 10n ** 18n);
    console.log("  expired auth reclaimed ✓");
  }, 60_000);

  it("withdraw: user exits remaining credits to a fresh address", async () => {
    const recipient = ethers.Wallet.createRandom().address;
    const amount = 40n * 10n ** 18n;

    await credits.withdraw({
      spendingPrivateKey: this_creditKeys.spendingPrivateKey,
      commitment: this_creditKeys.commitment,
      recipient,
      amount,
    });

    expect(await wrapper.balanceOf(recipient)).toBe(amount);
    const acct = await credits.getAccount(this_creditKeys.commitment);
    expect(acct.balance).toBe(0n);
    console.log("  remaining 40 tsUSD withdrawn ✓");
  }, 60_000);

  it("change UTXO: direct shielded withdrawal with a second real proof", async () => {
    const withdrawAmount = 25n * 10n ** 18n;
    const recipient = ethers.Wallet.createRandom().address;

    const zeroIn = await Utxo.zero(chainId, keypair);
    zeroIn.index = 0;
    const change2 = Utxo.create({
      chainId,
      amount: 50n * 10n ** 18n - withdrawAmount,
      keypair,
    });
    const zeroOut = await Utxo.zero(chainId, keypair);

    console.time("  change-withdrawal proof");
    const { proofBytes, publicInputs } = await proveTransact({
      inputs: [changeUtxo, zeroIn],
      outputs: [change2, zeroOut],
      extAmount: -withdrawAmount,
      recipient,
    });
    console.timeEnd("  change-withdrawal proof");

    const tx = await pool.transact(
      proofBytes,
      "0x",
      [recipient, -withdrawAmount, ethers.ZeroAddress, 0n, 0n, wrapperAddr],
      [
        publicInputs.roots,
        publicInputs.extensionRoots,
        publicInputs.inputNullifiers,
        publicInputs.outputCommitments,
        publicInputs.publicAmount,
        publicInputs.extDataHash,
      ],
      ["0x", "0x"]
    );
    const receipt = await tx.wait();
    console.log("  change withdrawal gas:", receipt!.gasUsed.toString());

    expect(await wrapper.balanceOf(recipient)).toBe(withdrawAmount);
    expect(await pool.isSpent(await changeUtxo.getNullifier())).toBe(true);

    change2.index = 4;
    await tree.insert(await change2.getCommitment());
    await tree.insert(await zeroOut.getCommitment());
    expect(tree.root).toBe(await pool.getLastRoot());
    console.log("  change UTXO spent; 25 tsUSD remains shielded ✓");
  }, 120_000);

  it("double-spend: replaying a spent nullifier reverts", async () => {
    const zeroIn = await Utxo.zero(chainId, keypair);
    zeroIn.index = 0;
    // Pure transfer: outputs must sum to the spent input (amount invariant)
    const out1 = Utxo.create({ chainId, amount: 50n * 10n ** 18n, keypair });
    const out2 = await Utxo.zero(chainId, keypair);

    // Rebuild a proof spending the ALREADY SPENT change UTXO.
    // The proof itself is valid; the on-chain nullifier check must reject it.
    const { proofBytes, publicInputs } = await proveTransact({
      inputs: [changeUtxo, zeroIn],
      outputs: [out1, out2],
      extAmount: 0n,
      recipient: ethers.ZeroAddress,
    });

    await expect(
      pool.transact(
        proofBytes,
        "0x",
        [ethers.ZeroAddress, 0n, ethers.ZeroAddress, 0n, 0n, wrapperAddr],
        [
          publicInputs.roots,
          publicInputs.extensionRoots,
          publicInputs.inputNullifiers,
          publicInputs.outputCommitments,
          publicInputs.publicAmount,
          publicInputs.extDataHash,
        ],
        ["0x", "0x"]
      )
    ).rejects.toThrow();
    console.log("  spent nullifier rejected ✓");
  }, 120_000);
});
