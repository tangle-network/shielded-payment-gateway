/**
 * Proof-generation scaling benchmark.
 *
 * For each circuit (poseidon_vanchor_2_2, poseidon_vanchor_16_2), runs
 * `snarkjs groth16 prove` as C parallel OS processes (C = 1, 2, 4, 8) and
 * measures per-proof wall latency (process spawn -> exit, i.e. including
 * Node startup + zkey load), throughput in proofs/sec over the whole batch,
 * and peak RSS per proving process (via /usr/bin/time -l).
 *
 * Machine state (loadavg, free memory) is recorded before every level.
 * Benchmarks at different concurrency levels run strictly SEQUENTIALLY.
 *
 * Usage (from sdk/shielded-sdk):
 *   node benchmark/prove-scaling.mjs [--circuit 2_2|16_2] [--proofs N]
 *
 * Writes <repo>/build/bench/prove-scaling-<timestamp>.json
 */
import { spawn, execFileSync } from "child_process";
import { mkdirSync, writeFileSync, readFileSync, rmSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import os from "os";

const ROOT_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../");
const SDK_DIR = join(ROOT_DIR, "sdk/shielded-sdk");
const SNARKJS = join(SDK_DIR, "node_modules/.bin/snarkjs");
const BENCH_DIR = join(ROOT_DIR, "build/bench");

const ARGS = process.argv.slice(2);
const argVal = (flag, dflt) => {
  const i = ARGS.indexOf(flag);
  return i >= 0 ? ARGS[i + 1] : dflt;
};
const ONLY_CIRCUIT = argVal("--circuit", null);

const CIRCUITS = [
  { name: "poseidon_vanchor_2_2", dir: "vanchor_2_2", proofsPerLevel: 12 },
  { name: "poseidon_vanchor_16_2", dir: "vanchor_16_2", proofsPerLevel: 8 },
].filter((c) => !ONLY_CIRCUIT || c.name.endsWith(ONLY_CIRCUIT));

const CONCURRENCY = [1, 2, 4, 8];

function machineState() {
  return {
    loadavg: os.loadavg().map((x) => Number(x.toFixed(2))),
    totalMemBytes: os.totalmem(),
    freeMemBytes: os.freemem(),
  };
}

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(
    sorted.length - 1,
    Math.ceil((p / 100) * sorted.length) - 1
  );
  return sorted[idx];
}

function runOne(zkeyPath, wtnsPath, proofPath, publicPath, timeLogPath) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const proc = spawn(
      "/usr/bin/time",
      [
        "-l",
        SNARKJS,
        "groth16",
        "prove",
        zkeyPath,
        wtnsPath,
        proofPath,
        publicPath,
      ],
      { stdio: ["ignore", "ignore", "pipe"] }
    );
    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d));
    proc.on("error", (err) =>
      resolve({ ok: false, error: String(err), ms: performance.now() - t0 })
    );
    proc.on("close", (code) => {
      const ms = performance.now() - t0;
      let maxRssBytes = null;
      const m = stderr.match(/(\d+)\s+maximum resident set size/);
      if (m) maxRssBytes = parseInt(m[1], 10);
      try {
        writeFileSync(timeLogPath, stderr);
      } catch {}
      resolve({ ok: code === 0, ms, maxRssBytes, exitCode: code });
    });
  });
}

async function runLevel(circuit, concurrency, proofs) {
  const zkeyPath = join(ROOT_DIR, "build/circuits", circuit.dir, "circuit_final.zkey");
  const wtnsPath = join(BENCH_DIR, circuit.name, "witness.wtns");
  const outDir = join(BENCH_DIR, circuit.name, `c${concurrency}`);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const stateBefore = machineState();
  console.log(
    `\n=== ${circuit.name} @ concurrency ${concurrency} (${proofs} proofs) ===`
  );
  console.log(
    `    loadavg ${stateBefore.loadavg.join("/")} freeMem ${(stateBefore.freeMemBytes / 2 ** 30).toFixed(1)}GiB`
  );

  const results = [];
  let next = 0;
  const t0 = performance.now();

  async function worker() {
    while (next < proofs) {
      const i = next++;
      const r = await runOne(
        zkeyPath,
        wtnsPath,
        join(outDir, `proof_${i}.json`),
        join(outDir, `public_${i}.json`),
        join(outDir, `time_${i}.log`)
      );
      results.push({ index: i, ...r });
      process.stdout.write(
        `    proof ${i} ${r.ok ? "ok" : "FAILED"} ${(r.ms / 1000).toFixed(2)}s rss=${r.maxRssBytes ? (r.maxRssBytes / 2 ** 20).toFixed(0) + "MiB" : "?"}\n`
      );
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  const wallSec = (performance.now() - t0) / 1000;
  const stateAfter = machineState();

  const okResults = results.filter((r) => r.ok);
  const latSorted = okResults.map((r) => r.ms).sort((a, b) => a - b);
  const rssValues = okResults
    .map((r) => r.maxRssBytes)
    .filter((x) => x != null)
    .sort((a, b) => a - b);

  const summary = {
    circuit: circuit.name,
    concurrency,
    proofsRequested: proofs,
    proofsOk: okResults.length,
    proofsFailed: results.length - okResults.length,
    wallSec: Number(wallSec.toFixed(2)),
    throughputProofsPerSec: Number((okResults.length / wallSec).toFixed(4)),
    latencyMsP50: percentile(latSorted, 50)?.toFixed(0) ?? null,
    latencyMsP95: percentile(latSorted, 95)?.toFixed(0) ?? null,
    latencyMsMin: latSorted[0]?.toFixed(0) ?? null,
    latencyMsMax: latSorted[latSorted.length - 1]?.toFixed(0) ?? null,
    peakRssBytesPerProcess: rssValues[rssValues.length - 1] ?? null,
    medianRssBytesPerProcess: percentile(rssValues, 50) ?? null,
    machineStateBefore: stateBefore,
    machineStateAfter: stateAfter,
  };
  console.log(
    `  -> ${summary.proofsOk}/${proofs} ok | ${summary.throughputProofsPerSec} proofs/s | p50=${summary.latencyMsP50}ms p95=${summary.latencyMsP95}ms | peakRSS=${summary.peakRssBytesPerProcess ? (summary.peakRssBytesPerProcess / 2 ** 30).toFixed(2) + "GiB" : "?"}/proc`
  );
  return summary;
}

async function main() {
  const run = {
    startedAt: new Date().toISOString(),
    host: os.hostname(),
    platform: `${os.type()} ${os.release()} ${os.arch()}`,
    cpu: os.cpus()[0]?.model,
    cores: os.cpus().length,
    node: process.version,
    snarkjs: JSON.parse(
      readFileSync(join(SDK_DIR, "node_modules/snarkjs/package.json"), "utf8")
    ).version,
    levels: [],
  };
  for (const circuit of CIRCUITS) {
    for (const c of CONCURRENCY) {
      run.levels.push(await runLevel(circuit, c, circuit.proofsPerLevel));
    }
  }
  run.finishedAt = new Date().toISOString();
  const outPath = join(
    BENCH_DIR,
    `prove-scaling-${run.startedAt.replace(/[:.]/g, "-")}.json`
  );
  writeFileSync(outPath, JSON.stringify(run, null, 2));
  console.log(`\nWrote ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
