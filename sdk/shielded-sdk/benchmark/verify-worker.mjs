/**
 * Worker: tight-loop Groth16 verification. Loads the verification key and a
 * pre-generated proof once, then calls snarkjs.groth16.verify repeatedly.
 *
 * Usage: node benchmark/verify-worker.mjs <vkey> <proof> <public> <count>
 * Prints JSON: { verified, failed, wallMs, perSec }
 */
import { readFileSync } from "fs";
import * as snarkjs from "snarkjs";

const [vkeyPath, proofPath, publicPath, countStr] = process.argv.slice(2);
const count = parseInt(countStr, 10);

const vKey = JSON.parse(readFileSync(vkeyPath, "utf8"));
const proof = JSON.parse(readFileSync(proofPath, "utf8"));
const publicSignals = JSON.parse(readFileSync(publicPath, "utf8"));

// sanity
if (!(await snarkjs.groth16.verify(vKey, publicSignals, proof))) {
  console.error("proof does not verify; aborting");
  process.exit(1);
}

let verified = 0;
let failed = 0;
const t0 = performance.now();
for (let i = 0; i < count; i++) {
  if (await snarkjs.groth16.verify(vKey, publicSignals, proof)) verified++;
  else failed++;
}
const wallMs = performance.now() - t0;
console.log(
  JSON.stringify({
    verified,
    failed,
    wallMs: Number(wallMs.toFixed(1)),
    perSec: Number(((verified / wallMs) * 1000).toFixed(1)),
  })
);
process.exit(0);
