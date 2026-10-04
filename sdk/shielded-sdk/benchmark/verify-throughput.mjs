/**
 * Off-chain Groth16 verification throughput benchmark (RLN-mode operator cost).
 *
 * Single process: 1000 sequential snarkjs.groth16.verify calls.
 * Concurrency C in {4, 8}: C parallel node worker processes, 1000 verifies
 * each, aggregate throughput = total verifies / wall time of the batch.
 * Each level runs strictly sequentially; machine state recorded before each.
 *
 * Usage (from sdk/shielded-sdk):
 *   node benchmark/verify-throughput.mjs [--per-worker 1000]
 *
 * Writes <repo>/build/bench/verify-throughput-<timestamp>.json
 */
import { spawn } from "child_process";
import { writeFileSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import os from "os";

const ROOT_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../");
const SDK_DIR = join(ROOT_DIR, "sdk/shielded-sdk");
const BENCH_DIR = join(ROOT_DIR, "build/bench");
const WORKER = join(SDK_DIR, "benchmark/verify-worker.mjs");

const ARGS = process.argv.slice(2);
const argVal = (flag, dflt) => {
  const i = ARGS.indexOf(flag);
  return i >= 0 ? parseInt(ARGS[i + 1], 10) : dflt;
};
const PER_WORKER = argVal("--per-worker", 1000);

// Use the 2_2 circuit artifacts + a real proof from the scaling run (fall back
// to any concurrency directory that has proof_0.json).
const circuitDir = join(ROOT_DIR, "build/circuits/vanchor_2_2");
const vkeyPath = join(circuitDir, "verification_key.json");
let proofPath = null;
let publicPath = null;
for (const c of [1, 2, 4, 8]) {
  const p = join(BENCH_DIR, "poseidon_vanchor_2_2", `c${c}`, "proof_0.json");
  const q = join(BENCH_DIR, "poseidon_vanchor_2_2", `c${c}`, "public_0.json");
  try {
    readFileSync(p);
    readFileSync(q);
    proofPath = p;
    publicPath = q;
    break;
  } catch {}
}
if (!proofPath) {
  console.error(
    "no proof found; run benchmark/prove-scaling.mjs --circuit 2_2 first"
  );
  process.exit(1);
}

function machineState() {
  return {
    loadavg: os.loadavg().map((x) => Number(x.toFixed(2))),
    freeMemBytes: os.freemem(),
  };
}

function runWorker(count) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const proc = spawn(
      process.execPath,
      [WORKER, vkeyPath, proofPath, publicPath, String(count)],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    let out = "";
    let err = "";
    proc.stdout.on("data", (d) => (out += d));
    proc.stderr.on("data", (d) => (err += d));
    proc.on("close", (code) => {
      const wallMs = performance.now() - t0;
      let parsed = null;
      try {
        parsed = JSON.parse(out.trim().split("\n").pop());
      } catch {}
      resolve({ ok: code === 0 && parsed, wallMs, parsed, stderr: err.slice(-400) });
    });
  });
}

async function runLevel(concurrency, perWorker) {
  const stateBefore = machineState();
  console.log(
    `\n=== verify throughput @ concurrency ${concurrency} (${perWorker} verifies/worker) ===`
  );
  console.log(
    `    loadavg ${stateBefore.loadavg.join("/")} freeMem ${(stateBefore.freeMemBytes / 2 ** 30).toFixed(1)}GiB`
  );
  const t0 = performance.now();
  const workers = await Promise.all(
    Array.from({ length: concurrency }, () => runWorker(perWorker))
  );
  const batchWallMs = performance.now() - t0;
  const totalVerified = workers.reduce((s, w) => s + (w.parsed?.verified ?? 0), 0);
  const totalFailed = workers.reduce((s, w) => s + (w.parsed?.failed ?? 0), 0);
  const workersOk = workers.filter((w) => w.ok).length;
  const summary = {
    concurrency,
    perWorker,
    workersOk,
    totalVerified,
    totalFailed,
    batchWallMs: Number(batchWallMs.toFixed(1)),
    aggregateVerifiesPerSec: Number(((totalVerified / batchWallMs) * 1000).toFixed(1)),
    perWorkerVerifiesPerSec: workers.map((w) => w.parsed?.perSec ?? null),
    machineStateBefore: stateBefore,
  };
  console.log(
    `  -> ${totalVerified} verified, ${totalFailed} failed | ${summary.aggregateVerifiesPerSec} verifies/s aggregate (${summary.perWorkerVerifiesPerSec.join(", ")}/worker)`
  );
  if (workersOk < concurrency)
    console.log(
      `  WARNING: only ${workersOk}/${concurrency} workers ok:`,
      workers.filter((w) => !w.ok).map((w) => w.stderr)
    );
  return summary;
}

async function main() {
  const run = {
    startedAt: new Date().toISOString(),
    host: os.hostname(),
    cpu: os.cpus()[0]?.model,
    cores: os.cpus().length,
    node: process.version,
    snarkjs: JSON.parse(
      readFileSync(join(SDK_DIR, "node_modules/snarkjs/package.json"), "utf8")
    ).version,
    circuit: "poseidon_vanchor_2_2",
    levels: [],
  };
  run.levels.push(await runLevel(1, PER_WORKER));
  run.levels.push(await runLevel(4, PER_WORKER));
  run.levels.push(await runLevel(8, PER_WORKER));
  run.finishedAt = new Date().toISOString();
  const outPath = join(
    BENCH_DIR,
    `verify-throughput-${run.startedAt.replace(/[:.]/g, "-")}.json`
  );
  writeFileSync(outPath, JSON.stringify(run, null, 2));
  console.log(`\nWrote ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
