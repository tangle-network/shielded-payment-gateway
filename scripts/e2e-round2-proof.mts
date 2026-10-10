/**
 * Phase 1.3 — First REAL round-2 proof on-chain (Tempo testnet).
 *
 * Mirrors sdk/shielded-sdk/test/anvil-e2e-real.test.ts, but pointed at the
 * round-2 rehearsal stack (deployments-round2/tempo.json) with pathUSD as the
 * underlying stablecoin (6 decimals):
 *
 *   wrap pathUSD → tsUSD → deposit (real Groth16 proof, round-2 zkey) →
 *   withdrawal (real join-split proof) → verifier sanity (invalid proof
 *   reverts) → double-spend sanity (spent nullifier reverts)
 *
 * Usage:
 *   PRIVATE_KEY=0x... npx tsx scripts/e2e-round2-proof.mts
 *
 * Writes deployments-round2/e2e-proof-round2.json with all tx hashes.
 */
import { ethers } from "ethers";
import { writeFileSync } from "fs";
import { join } from "path";
import {
  ROOT_DIR,
  getProvider,
  loadDeployments,
  proveTransact,
  transactArgs,
  syncTree,
  withRetry,
  Keypair,
  Utxo,
  MerkleTree,
  ChainType,
  typedChainId,
  ERC20_ABI,
  WRAPPER_ABI,
  VANCHOR_ABI,
  TREE_LEVELS,
  type ProverContext,
} from "./round2-lib.mjs";

const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY");

const WRAP_AMOUNT = 10_000_000n; // 10 pathUSD (6dp)
const DEPOSIT_AMOUNT = 5_000_000n; // 5
const WITHDRAW_AMOUNT = 2_000_000n; // 2

async function main() {
  const d = loadDeployments();
  const provider = getProvider();
  const deployer = new ethers.NonceManager(
    new ethers.Wallet(PRIVATE_KEY!, provider)
  ) as unknown as ethers.Wallet;
  const deployerAddr = await deployer.getAddress();
  console.log(`Deployer: ${deployerAddr}`);
  console.log(`Pool:     ${d.vanchorTree}`);
  console.log(`Wrapper:  ${d.fungibleTokenWrapper}`);

  const typed = typedChainId(ChainType.EVM, d.chainId);
  const pathusd = new ethers.Contract(d.stablecoin, ERC20_ABI, deployer);
  const wrapper = new ethers.Contract(
    d.fungibleTokenWrapper,
    WRAPPER_ABI,
    deployer
  );
  const pool = new ethers.Contract(d.vanchorTree, VANCHOR_ABI, deployer);

  const edgeZero: bigint = await withRetry(() =>
    pool.getZeroHash(TREE_LEVELS - 1)
  );
  // Sync any existing leaves (the pool is shared across reruns of this script).
  const synced = await syncTree(provider, d.vanchorTree);
  const tree = synced.tree;
  console.log(`synced ${synced.leaves.length} existing leaves`);
  const ctx: ProverContext = {
    tree,
    chainId: typed,
    wrapperAddr: d.fungibleTokenWrapper,
    edgeZero,
  };
  const keypair = new Keypair();

  const result: Record<string, unknown> = {
    chainId: d.chainId,
    deployer: deployerAddr,
    pool: d.vanchorTree,
    wrapper: d.fungibleTokenWrapper,
    amounts: {
      wrap: WRAP_AMOUNT.toString(),
      deposit: DEPOSIT_AMOUNT.toString(),
      withdraw: WITHDRAW_AMOUNT.toString(),
    },
  };

  // ── Sanity 0: code present at all recorded addresses ──────────────────
  for (const [name, addr] of Object.entries({
    poseidonHasher: d.poseidonHasher,
    vanchorVerifier: d.vanchorVerifier,
    tokenWrapperHandler: d.tokenWrapperHandler,
    fungibleTokenWrapper: d.fungibleTokenWrapper,
    anchorHandler: d.anchorHandler,
    vanchorTree: d.vanchorTree,
    shieldedCredits: d.shieldedCredits,
    shieldedGateway: d.shieldedGateway,
    ...d.verifiers,
    ...d.poseidon,
    vanchorEncodeInputs: d.vanchorEncodeInputs,
  })) {
    const code = await withRetry(() => provider.getCode(addr), {
      label: `getCode ${name}`,
    });
    if (code === "0x") throw new Error(`No code at ${name} (${addr})`);
  }
  console.log("code present at all deployed addresses ✓");

  // ── Sanity 1: known-invalid proof reverts in the verifier path ────────
  {
    const bogus = new Uint8Array(256); // all-zero proof points
    bogus[31] = 1; // non-zero but invalid curve point encoding
    const call = transactArgs(
      {
        proofBytes: bogus,
        proofMs: 0,
        publicInputs: {
          roots: ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint256[8]"],
            [[...(Array(8).fill(0n) as bigint[])]]
          ),
          extensionRoots: "0x",
          inputNullifiers: [1n, 2n],
          outputCommitments: [3n, 4n],
          publicAmount: 0n,
          extDataHash: 5n,
        },
      },
      {
        recipient: ethers.ZeroAddress,
        extAmount: 0n,
        relayer: ethers.ZeroAddress,
        fee: 0n,
        refund: 0n,
        token: d.fungibleTokenWrapper,
      }
    );
    let reverted = false;
    try {
      await withRetry(
        () =>
          provider.call({
            to: d.vanchorTree,
            data: pool.interface.encodeFunctionData(
              "transact",
              call as never[]
            ),
            from: deployerAddr,
          }),
        { label: "invalid-proof eth_call", tries: 2 }
      );
    } catch {
      reverted = true;
    }
    if (!reverted)
      throw new Error("sanity failure: invalid proof did NOT revert");
    console.log("sanity: known-invalid proof reverts on-chain ✓");
    result.invalidProofReverts = true;
  }

  // ── Step 1: wrap pathUSD → tsUSD ──────────────────────────────────────
  await withRetry(async () =>
    (await pathusd.approve(d.fungibleTokenWrapper, WRAP_AMOUNT)).wait()
  );
  const wrapTx = await withRetry(async () =>
    (await wrapper.wrap(d.stablecoin, WRAP_AMOUNT)).wait()
  );
  console.log(`wrap tx: ${wrapTx!.hash} (gas ${wrapTx!.gasUsed})`);
  result.wrapTx = wrapTx!.hash;

  // ── Step 2: deposit with REAL round-2 Groth16 proof ───────────────────
  const depositUtxo = Utxo.create({
    chainId: typed,
    amount: DEPOSIT_AMOUNT,
    keypair,
  });
  const zeroChange = await Utxo.zero(typed, keypair);
  const zeroIn1 = await Utxo.zero(typed, keypair);
  const zeroIn2 = await Utxo.zero(typed, keypair);
  zeroIn1.index = 0;
  zeroIn2.index = 0;

  const lastRoot: bigint = await withRetry(() => pool.getLastRoot());
  const t0 = performance.now();
  const depProof = await proveTransact(ctx, {
    inputs: [zeroIn1, zeroIn2],
    outputs: [depositUtxo, zeroChange],
    extAmount: DEPOSIT_AMOUNT,
    recipient: ethers.ZeroAddress,
    localRoot: lastRoot,
  });
  console.log(`deposit proof generated in ${depProof.proofMs.toFixed(0)}ms`);

  await withRetry(async () =>
    (await wrapper.approve(d.vanchorTree, DEPOSIT_AMOUNT)).wait()
  );

  const depReceipt = await withRetry(async () =>
    (
      await pool.transact(
        ...(transactArgs(depProof, {
          recipient: ethers.ZeroAddress,
          extAmount: DEPOSIT_AMOUNT,
          relayer: ethers.ZeroAddress,
          fee: 0n,
          refund: 0n,
          token: d.fungibleTokenWrapper,
        }) as never[])
      )
    ).wait()
  );
  console.log(
    `deposit tx: ${depReceipt!.hash} (gas ${depReceipt!.gasUsed})`
  );
  result.depositTx = depReceipt!.hash;
  result.depositGas = depReceipt!.gasUsed.toString();
  result.depositProofMs = depProof.proofMs;

  // Sync local tree with the two inserted leaves
  depositUtxo.index = Number(await withRetry(() => pool.getNextIndex())) - 2;
  await tree.insert(await depositUtxo.getCommitment());
  await tree.insert(await zeroChange.getCommitment());
  const onchainRoot: bigint = await withRetry(() => pool.getLastRoot());
  if (tree.root !== onchainRoot)
    throw new Error("root mismatch after deposit");
  console.log("deposit verified on-chain; roots match ✓");

  // ── Step 3: withdrawal with REAL join-split proof ─────────────────────
  const recipient = ethers.Wallet.createRandom().address;
  const change = Utxo.create({
    chainId: typed,
    amount: DEPOSIT_AMOUNT - WITHDRAW_AMOUNT,
    keypair,
  });
  const zeroOut = await Utxo.zero(typed, keypair);
  const zeroIn = await Utxo.zero(typed, keypair);
  zeroIn.index = 0;

  const wdProof = await proveTransact(ctx, {
    inputs: [depositUtxo, zeroIn],
    outputs: [change, zeroOut],
    extAmount: -WITHDRAW_AMOUNT,
    recipient,
  });
  console.log(
    `withdrawal proof generated in ${wdProof.proofMs.toFixed(0)}ms`
  );

  const wdReceipt = await withRetry(async () =>
    (
      await pool.transact(
        ...(transactArgs(wdProof, {
          recipient,
          extAmount: -WITHDRAW_AMOUNT,
          relayer: ethers.ZeroAddress,
          fee: 0n,
          refund: 0n,
          token: d.fungibleTokenWrapper,
        }) as never[])
      )
    ).wait()
  );
  console.log(
    `withdrawal tx: ${wdReceipt!.hash} (gas ${wdReceipt!.gasUsed})`
  );
  result.withdrawTx = wdReceipt!.hash;
  result.withdrawGas = wdReceipt!.gasUsed.toString();
  result.withdrawProofMs = wdProof.proofMs;
  result.withdrawRecipient = recipient;

  const recipBal: bigint = await withRetry(() =>
    wrapper.balanceOf(recipient)
  );
  if (recipBal !== WITHDRAW_AMOUNT)
    throw new Error(`recipient balance ${recipBal} != ${WITHDRAW_AMOUNT}`);
  const spent = await withRetry(() =>
    pool.isSpent(wdProof.publicInputs.inputNullifiers[0])
  );
  if (!spent) throw new Error("deposit nullifier not marked spent");
  console.log("withdrawal landed; nullifier spent ✓");

  // ── Sanity 2: double-spend of the deposit UTXO reverts ────────────────
  {
    const out1 = Utxo.create({
      chainId: typed,
      amount: DEPOSIT_AMOUNT, // inputs sum = depositUtxo (5e6); outputs must match
      keypair,
    });
    const out2 = await Utxo.zero(typed, keypair);
    const zi = await Utxo.zero(typed, keypair);
    zi.index = 0;
    const dsProof = await proveTransact(ctx, {
      inputs: [depositUtxo, zi], // depositUtxo is already spent
      outputs: [out1, out2],
      extAmount: 0n,
      recipient: ethers.ZeroAddress,
    });
    let reverted = false;
    try {
      await withRetry(
        async () =>
          (
            await pool.transact(
              ...(transactArgs(dsProof, {
                recipient: ethers.ZeroAddress,
                extAmount: 0n,
                relayer: ethers.ZeroAddress,
                fee: 0n,
                refund: 0n,
                token: d.fungibleTokenWrapper,
              }) as never[])
            )
          ).wait(),
        { label: "double-spend", tries: 1 }
      );
    } catch {
      reverted = true;
    }
    if (!reverted)
      throw new Error("sanity failure: double-spend did NOT revert");
    console.log("sanity: double-spend (spent nullifier) reverts ✓");
    result.doubleSpendReverts = true;
  }

  result.ok = true;
  const outPath = join(
    ROOT_DIR,
    "deployments-round2/e2e-proof-round2.json"
  );
  writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.log(`\nE2E COMPLETE — wrote ${outPath}`);
  console.log(JSON.stringify(result, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
