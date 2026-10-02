/**
 * ZK Benchmark: proof generation time, proof size, local verification time,
 * and on-chain Groth16 verification gas.
 *
 * Prerequisites:
 *   - Circuit artifacts: ./scripts/trusted-setup/ceremony.sh (repo root)
 *     produces build/circuits/<layout>/ with wasm + circuit_final.zkey +
 *     verification_key.json + Verifier<edges>_<inputs>.sol
 *   - anvil + forge on PATH (only for the on-chain gas measurement)
 *
 * Usage (from sdk/shielded-sdk):
 *   npx tsx benchmark/zk-bench.ts                # 2-input circuits (2_2, 2_8)
 *   npx tsx benchmark/zk-bench.ts --16           # include 16-input circuits
 *   npx tsx benchmark/zk-bench.ts --runs 5       # proving runs per circuit
 *   npx tsx benchmark/zk-bench.ts --no-onchain   # skip anvil gas measurement
 *
 * Prints a Markdown table and writes build/zk-benchmarks.json at the repo root.
 */

import { existsSync, writeFileSync, mkdirSync, copyFileSync, rmSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { spawn, execFileSync, type ChildProcess } from "child_process";
import * as snarkjs from "snarkjs";
import { ethers } from "ethers";
import {
  Keypair,
  Utxo,
  MerkleTree,
  ChainType,
  typedChainId,
} from "../src/protocol/index.js";
import {
  buildWitnessInputs,
  computeExtDataHash,
} from "../src/proof/witness.js";

const ROOT_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../");
const BUILD_CIRCUITS = join(ROOT_DIR, "build/circuits");

const ARGS = process.argv.slice(2);
const WITH_16 = ARGS.includes("--16");
const ONCHAIN = !ARGS.includes("--no-onchain");
const RUNS = (() => {
  const i = ARGS.indexOf("--runs");
  return i >= 0 ? parseInt(ARGS[i + 1], 10) : 3;
})();

const ANVIL_PORT = 8599;
const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;
// Anvil default account 0 (well-known dev key, local only)
const ANVIL_PK =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

interface CircuitSpec {
  name: string;
  inputs: 2 | 16;
  edges: 2 | 8;
  verifierContract: string;
}

const CIRCUITS: CircuitSpec[] = [
  { name: "poseidon_vanchor_2_2", inputs: 2, edges: 2, verifierContract: "Verifier2_2" },
  { name: "poseidon_vanchor_2_8", inputs: 2, edges: 8, verifierContract: "Verifier8_2" },
  ...(WITH_16
    ? [
        { name: "poseidon_vanchor_16_2", inputs: 16, edges: 2, verifierContract: "Verifier2_16" },
        { name: "poseidon_vanchor_16_8", inputs: 16, edges: 8, verifierContract: "Verifier8_16" },
      ]
    : []),
] as CircuitSpec[];

interface BenchResult {
  circuit: string;
  constraints: number | null;
  publicInputs: number;
  runs: number;
  proveMsMin: number;
  proveMsMedian: number;
  verifyMs: number;
  proofJsonBytes: number;
  calldataBytes: number;
  zkeyBytes: number | null;
  wasmBytes: number | null;
  onchainVerifyGas: number | null;
}

function circuitDir(spec: CircuitSpec) {
  return join(BUILD_CIRCUITS, `vanchor_${spec.inputs}_${spec.edges}`);
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

async function buildDepositWitness(spec: CircuitSpec) {
  const keypair = new Keypair();
  const tree = await MerkleTree.create(30);
  const chainId = typedChainId(ChainType.EVM, 84532);
  const depositAmount = 10n * 10n ** 18n;

  const output = Utxo.create({ chainId, amount: depositAmount, keypair });
  const changeOutput = await Utxo.zero(chainId, keypair);
  const inputs = await Promise.all(
    Array.from({ length: spec.inputs }, async () => {
      const u = await Utxo.zero(chainId, keypair);
      u.index = 0;
      return u;
    })
  );

  const extDataHash = computeExtDataHash({
    recipient: ethers.ZeroAddress,
    extAmount: depositAmount,
    relayer: ethers.ZeroAddress,
    fee: 0n,
    refund: 0n,
    token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    encryptedOutput1: new Uint8Array(0),
    encryptedOutput2: new Uint8Array(0),
  });

  const roots = [tree.root, ...Array<bigint>(spec.edges - 1).fill(0n)];

  return buildWitnessInputs({
    inputs,
    outputs: [output, changeOutput],
    tree,
    extDataHash,
    extAmount: depositAmount,
    fee: 0n,
    chainId,
    roots,
  });
}

function constraintCount(spec: CircuitSpec): number | null {
  const r1cs = join(
    ROOT_DIR,
    "build/trusted-setup/circuits",
    spec.name,
    `${spec.name}.r1cs`
  );
  if (!existsSync(r1cs)) return null;
  try {
    const out = execFileSync("snarkjs", ["r1cs", "info", r1cs], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const m = out.match(/# of Constraints:\s*(\d+)/);
    return m ? parseInt(m[1], 10) : null;
  } catch {
    return null;
  }
}

// ─── On-chain verification gas ───────────────────────────────────────────────

let anvil: ChildProcess | null = null;
const GENERATED_DIR = join(ROOT_DIR, "src/generated");

/// Stage the snarkjs-exported verifiers into a forge source path and build.
/// `forge create <path>:<Contract>` silently skips compiling files outside
/// src/test/script when the cache is warm, so we copy them into
/// src/generated/ (gitignored) and use the normal build pipeline.
function stageVerifiers(): void {
  mkdirSync(GENERATED_DIR, { recursive: true });
  for (const spec of CIRCUITS) {
    const src = join(circuitDir(spec), `${spec.verifierContract}.sol`);
    if (existsSync(src)) {
      copyFileSync(src, join(GENERATED_DIR, `${spec.verifierContract}.sol`));
    }
  }
  execFileSync("forge", ["build"], { cwd: ROOT_DIR, stdio: "ignore" });
}

function unstageVerifiers(): void {
  rmSync(GENERATED_DIR, { recursive: true, force: true });
}

async function startAnvil(): Promise<void> {
  anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {
    stdio: "ignore",
  });
  const provider = new ethers.JsonRpcProvider(ANVIL_RPC);
  for (let i = 0; i < 50; i++) {
    try {
      await provider.getBlockNumber();
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error("anvil did not start");
}

function stopAnvil() {
  if (anvil?.pid) {
    try {
      process.kill(anvil.pid);
    } catch {
      /* already dead */
    }
  }
}

async function measureOnchainVerifyGas(
  spec: CircuitSpec,
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
): Promise<number | null> {
  // Forge artifact from the staged build: out/<File>.sol/<Contract>.json
  const artifactPath = join(
    ROOT_DIR,
    "out",
    `${spec.verifierContract}.sol`,
    `${spec.verifierContract}.json`
  );
  if (!existsSync(artifactPath)) return null;

  const { readFileSync } = await import("fs");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf-8"));
  const provider = new ethers.JsonRpcProvider(ANVIL_RPC);
  const wallet = new ethers.Wallet(ANVIL_PK, provider);
  const factory = new ethers.ContractFactory(
    artifact.abi,
    artifact.bytecode.object,
    wallet
  );
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();

  const iface = new ethers.Interface([
    `function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[${publicSignals.length}] calldata input) external view returns (bool)`,
  ]);
  // NOTE: the Solidity verifier expects the G2 point (pi_b) with Fq2
  // components swapped relative to snarkjs proof.json — same convention as
  // `snarkjs groth16 exportSolidityCallData`.
  const data = iface.encodeFunctionData("verifyProof", [
    [proof.pi_a[0], proof.pi_a[1]],
    [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    [proof.pi_c[0], proof.pi_c[1]],
    publicSignals,
  ]);

  // Sanity: with ample gas the proof must verify, otherwise the pairing is
  // failing and any gas number would be meaningless.
  const ok = await provider.call({ to: await verifier.getAddress(), data });
  if (BigInt(ok) !== 1n) {
    throw new Error(`${spec.name}: on-chain verification returned false`);
  }

  // Measure actual gas used via debug_traceCall. NOTE: anvil's estimateGas
  // under-reports badly on the snarkjs assembly verifier (the contract
  // forwards sub(gas(), 2000) to precompiles and returns false instead of
  // reverting when starved, which confuses the estimator's binary search).
  try {
    const trace = await provider.send("debug_traceCall", [
      { to: await verifier.getAddress(), data, gas: "0x1c9c380" },
      "latest",
      {},
    ]);
    return Number(BigInt(trace.gas));
  } catch {
    const gas = await provider.estimateGas({
      to: await verifier.getAddress(),
      data,
    });
    return Number(gas);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function benchCircuit(spec: CircuitSpec): Promise<BenchResult | null> {
  const dir = circuitDir(spec);
  const wasmPath = join(dir, `${spec.name}_js`, `${spec.name}.wasm`);
  const zkeyPath = join(dir, "circuit_final.zkey");
  const vkeyPath = join(dir, "verification_key.json");

  if (!existsSync(wasmPath) || !existsSync(zkeyPath) || !existsSync(vkeyPath)) {
    console.log(`SKIP ${spec.name}: artifacts missing in ${dir}`);
    console.log(`     run ./scripts/trusted-setup/ceremony.sh first`);
    return null;
  }

  console.log(`\n=== ${spec.name} ===`);
  const witnessInput = await buildDepositWitness(spec);

  const times: number[] = [];
  let proof: snarkjs.Groth16Proof | null = null;
  let publicSignals: snarkjs.PublicSignals = [];
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    const r = await snarkjs.groth16.fullProve(
      witnessInput as unknown as snarkjs.CircuitSignals,
      wasmPath,
      zkeyPath
    );
    const dt = performance.now() - t0;
    times.push(dt);
    proof = r.proof;
    publicSignals = r.publicSignals;
    console.log(`  prove run ${i + 1}/${RUNS}: ${(dt / 1000).toFixed(2)}s`);
  }
  if (!proof) return null;

  // Local verification time
  const { readFileSync } = await import("fs");
  const vKey = JSON.parse(readFileSync(vkeyPath, "utf-8"));
  const vt0 = performance.now();
  const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  const verifyMs = performance.now() - vt0;
  if (!valid) throw new Error(`${spec.name}: proof failed local verification!`);

  // Sizes
  const proofJsonBytes = JSON.stringify(proof).length;
  const calldataBytes = 256 + 32 * publicSignals.length; // 8 field elems + public inputs
  const { statSync } = await import("fs");
  const zkeyBytes = statSync(zkeyPath).size;
  const wasmBytes = statSync(wasmPath).size;

  // On-chain verification gas
  let onchainVerifyGas: number | null = null;
  if (ONCHAIN) {
    try {
      onchainVerifyGas = await measureOnchainVerifyGas(spec, proof, publicSignals);
      console.log(`  on-chain verify gas: ${onchainVerifyGas ?? "n/a"}`);
    } catch (e) {
      console.log(`  on-chain gas measurement failed: ${(e as Error).message}`);
    }
  }

  console.log(
    `  median prove: ${(median(times) / 1000).toFixed(2)}s | verify: ${verifyMs.toFixed(0)}ms | proof: ${proofJsonBytes}B json / ${calldataBytes}B calldata`
  );

  return {
    circuit: spec.name,
    constraints: constraintCount(spec),
    publicInputs: publicSignals.length,
    runs: RUNS,
    proveMsMin: Math.round(Math.min(...times)),
    proveMsMedian: Math.round(median(times)),
    verifyMs: Math.round(verifyMs),
    proofJsonBytes,
    calldataBytes,
    zkeyBytes,
    wasmBytes,
    onchainVerifyGas,
  };
}

async function main() {
  const results: BenchResult[] = [];

  if (ONCHAIN) {
    stageVerifiers();
    await startAnvil();
  }
  try {
    for (const spec of CIRCUITS) {
      const r = await benchCircuit(spec);
      if (r) results.push(r);
    }
  } finally {
    stopAnvil();
    if (ONCHAIN) unstageVerifiers();
  }

  if (results.length === 0) {
    console.log("\nNo circuits benchmarked.");
    return;
  }

  console.log("\n| Circuit | Constraints | Prove median | Verify (local) | Proof (calldata) | On-chain verify gas |");
  console.log("|---|---|---|---|---|---|");
  for (const r of results) {
    console.log(
      `| ${r.circuit} | ${r.constraints ?? "?"} | ${(r.proveMsMedian / 1000).toFixed(2)}s | ${r.verifyMs}ms | ${r.calldataBytes}B | ${r.onchainVerifyGas?.toLocaleString() ?? "n/a"} |`
    );
  }

  const outPath = join(ROOT_DIR, "build/zk-benchmarks.json");
  writeFileSync(outPath, JSON.stringify({ timestamp: new Date().toISOString(), runs: RUNS, results }, null, 2));
  console.log(`\nWrote ${outPath}`);
  // ethers providers/anvil children can keep the event loop alive
  process.exit(0);
}

main().catch((e) => {
  stopAnvil();
  if (ONCHAIN) unstageVerifiers();
  console.error(e);
  process.exit(1);
});
