/**
 * Generate witness input JSON + .wtns files for the proof-scaling benchmark.
 *
 * Usage (from sdk/shielded-sdk):
 *   npx tsx benchmark/gen-witness.ts
 *
 * Writes, per circuit, to <repo>/build/bench/<name>/:
 *   input.json     — circuit input (deposit witness)
 *   witness.wtns   — calculated witness (via snarkjs wtns calculate)
 */
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
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
const SDK_DIR = join(ROOT_DIR, "sdk/shielded-sdk");
const SNARKJS = join(SDK_DIR, "node_modules/.bin/snarkjs");
const BENCH_DIR = join(ROOT_DIR, "build/bench");

async function buildDepositWitness(inputs: number, edges: number) {
  const keypair = new Keypair();
  const tree = await MerkleTree.create(30);
  const chainId = typedChainId(ChainType.EVM, 84532);
  const depositAmount = 10n * 10n ** 18n;

  const output = Utxo.create({ chainId, amount: depositAmount, keypair });
  const changeOutput = await Utxo.zero(chainId, keypair);
  const utxoInputs = await Promise.all(
    Array.from({ length: inputs }, async () => {
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

  const roots = [tree.root, ...Array<bigint>(edges - 1).fill(0n)];

  return buildWitnessInputs({
    inputs: utxoInputs,
    outputs: [output, changeOutput],
    tree,
    extDataHash,
    extAmount: depositAmount,
    fee: 0n,
    chainId,
    roots,
  });
}

async function main() {
  for (const [inputs, edges] of [
    [2, 2],
    [16, 2],
  ] as const) {
    const name = `poseidon_vanchor_${inputs}_${edges}`;
    const dir = join(BENCH_DIR, name);
    mkdirSync(dir, { recursive: true });
    const inputPath = join(dir, "input.json");
    const wtnsPath = join(dir, "witness.wtns");
    if (existsSync(wtnsPath)) {
      console.log(`SKIP ${name}: witness.wtns exists`);
      continue;
    }
    console.log(`building witness input for ${name}...`);
    const witnessInput = await buildDepositWitness(inputs, edges);
    writeFileSync(inputPath, JSON.stringify(witnessInput));
    const wasmPath = join(
      ROOT_DIR,
      `build/circuits/vanchor_${inputs}_${edges}/${name}_js/${name}.wasm`
    );
    console.log(`calculating witness (snarkjs wtns calculate)...`);
    execFileSync(SNARKJS, ["wtns", "calculate", wasmPath, inputPath, wtnsPath], {
      stdio: "inherit",
    });
    console.log(`wrote ${wtnsPath}`);
  }
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
