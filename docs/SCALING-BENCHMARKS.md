# Scaling Benchmarks — Shielded Payments Stack

Measured on a developer MacBook (full specs below) on **2026-10-03** against the
`circuits-v1.0.0-phase2` production ceremony artifacts (sha256-verified, 25/25
files) and a local Anvil + Ollama + Postgres stack. Every number below comes
from a recorded run; machine state (load average, free memory) was captured
before every measurement level and is included. **No numbers were re-run
selectively or interpolated — degraded and failed runs are reported alongside
the good ones.**

> **Read this first — ambient machine state.** The benchmarking machine was
> NOT idle: it ran the owner's desktop session (Warp terminal ~45% CPU,
> Chrome, WindowServer, Spotlight indexing) for the whole session. macOS
> 1-minute load averages ranged from ~10 (quietest) to ~226 (peak, during the
> 8-way 16_2 proving run, mostly self-inflicted). All runs were executed
> strictly sequentially; no two benchmarks overlapped. Treat every number as a
> **lower bound on a quiet machine**, not a best-case figure.

## Machine

| Item | Value |
|---|---|
| Model | MacBook Pro, Apple M1 Max (10 cores: 8 performance + 2 efficiency) |
| RAM | 32 GiB |
| OS | macOS 26.1 (Darwin 25.1.0, arm64, T6000) |
| Node | v26.8.1 |
| snarkjs | 0.7.6 (repo-local `node_modules`; the machine-global snarkjs is 0.5.0 and was NOT used) |
| Chain | Anvil (instant-mine, auto-mining mode), chain id 31337, port 8699 |
| LLM backend | Ollama 0.33.3, `qwen2:0.5b` chat + `mxbai-embed-large` |

Circuit artifacts: GitHub release `circuits-v1.0.0-phase2`
(tangle-network/shielded-payment-gateway), downloaded with
`gh release download`, every file verified against `SHA256SUMS.txt`
(25/25 OK) and staged into `build/circuits/` following the layout produced by
`scripts/stage-circuit-artifacts.sh`.

Constraint counts (from the ceremony's `CEREMONY.md`):
`poseidon_vanchor_2_2` = **17,682**, `poseidon_vanchor_16_2` = **133,931**.

---

## 1. Proof generation scaling (`snarkjs groth16 prove`)

Each data point is a batch of N independent OS processes running
`snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json`
(via `/usr/bin/time -l` for per-process peak RSS). Per-proof latency is the
full process wall time (Node startup + zkey load + prove), i.e. the cost an
operator pays per CLI invocation. Witnesses were pre-calculated once
(`benchmark/gen-witness.ts`) so witness generation is NOT in these numbers.

Script: `sdk/shielded-sdk/benchmark/prove-scaling.mjs`
Raw data: `sdk/shielded-sdk/benchmark/results/prove-scaling-2026-10-03T23-05-36-863Z.json` (committed)

### poseidon_vanchor_2_2 (17,682 constraints), 12 proofs per level

| Concurrency | Throughput | Latency p50 | Latency p95 | min–max | Peak RSS/proc | Load avg before |
|---|---|---|---|---|---|---|
| 1 | **0.456 proofs/s** | 2.18 s | 2.49 s | 2.00–2.49 s | 0.91 GiB | 50.8 |
| 2 | 0.494 proofs/s | 3.80 s | 5.29 s | 3.47–5.29 s | 0.94 GiB | 55.1 |
| 4 | 0.519 proofs/s | 7.59 s | 8.37 s | 6.98–8.37 s | 0.93 GiB | 75.9 |
| 8 | 0.462 proofs/s | 16.26 s | 16.97 s | 9.57–16.97 s | 0.91 GiB | 105.1 |

### poseidon_vanchor_16_2 (133,931 constraints), 8 proofs per level

| Concurrency | Throughput | Latency p50 | Latency p95 | min–max | Peak RSS/proc | Load avg before |
|---|---|---|---|---|---|---|
| 1 | **0.095 proofs/s** | 10.08 s | 12.45 s | 8.89–12.45 s | 2.52 GiB | 140.8 |
| 2 | 0.069 proofs/s | 26.29 s | 37.03 s | 20.72–37.03 s | 2.54 GiB | 110.0 |
| 4 | 0.086 proofs/s | 36.68 s | 56.61 s | 36.34–56.61 s | 2.21 GiB | 170.9 |
| 8 | 0.105 proofs/s | 76.09 s | 76.57 s | 73.94–76.57 s | 1.60 GiB | 226.4 |

**Findings.**

- **The saturation point of this machine is ONE proving process.** snarkjs
  parallelizes a single Groth16 prove across cores internally; starting a
  second process does not add throughput (2_2: 0.456 → 0.519 proofs/s from 1→4
  processes, within noise), it only divides CPU and inflates per-proof latency
  roughly linearly (2.2 s → 16.3 s at 8-way).
- Throughput ceiling: **~0.5 proofs/s for 2_2, ~0.1 proofs/s for 16_2** on
  this machine — i.e. one 2_2 proof every ~2 s, one 16_2 proof every ~10 s,
  no matter how many processes you start.
- Memory: ~0.9 GiB RSS per 2_2 prover, ~2.5 GiB per 16_2 prover (single-process
  levels). 8 concurrent 16_2 provers would need ~20 GiB at their c=1 RSS; at
  c=8 observed per-process RSS was lower (1.6 GiB) because slow paging/thrashing
  spread allocations over time.
- The 16_2 c=8 level ran under load average 226 (8 provers × internal thread
  pools + ambient); it still completed 8/8 proofs with zero failures — slow
  but correct.
- Caveat on sample sizes: 12 proofs/level for 2_2, 8 for 16_2. p95 with 8
  samples is the 8th value — coarse, reported as measured.

Reproduce:

```bash
./scripts/stage-circuit-artifacts.sh            # or stage release artifacts (see header)
cd sdk/shielded-sdk && npm install
npx tsx benchmark/gen-witness.ts                # build witnesses once
node benchmark/prove-scaling.mjs                # both circuits, all levels
node benchmark/prove-scaling.mjs --circuit 2_2  # single circuit
```

---

## 2. Off-chain verification throughput (`snarkjs groth16 verify`)

This is the RLN-mode operator-side cost: verifying incoming proofs before
accepting work. A tight in-process loop calls `snarkjs.groth16.verify` on a
real 2_2 proof (verification key + proof loaded once per worker). Concurrency
levels run separate worker processes.

Scripts: `sdk/shielded-sdk/benchmark/verify-throughput.mjs` (driver) +
`benchmark/verify-worker.mjs`. Raw data:
`sdk/shielded-sdk/benchmark/results/verify-throughput-2026-10-03T23-16-30-068Z.json` (committed)
(13,000 verifies total, 0 failures, all proofs valid).

| Concurrency | Verifies | Aggregate throughput | Per-worker | Load avg before |
|---|---|---|---|---|
| 1 | 1,000 | **87.7 verifies/s** | 89.9/s (11.1 ms per verify) | 97.5 |
| 4 | 4,000 | **153.9 verifies/s** | ~39.5/s each | 88.8 |
| 8 | 8,000 | **177.6 verifies/s** | ~22.8/s each | 84.0 |

**Findings.**

- Single-core verify cost: **~11 ms per proof** (2_2-size, 17 public signals).
- Verification scales sub-linearly with processes (1.75× at 4 workers, 2.0× at
  8) because the ambient desktop load plus 8 workers oversubscribe the 8
  performance cores; on a quiet machine expect closer to linear up to the
  performance-core count.
- Practical operator budget: even at the measured 87 verifies/s single-process
  floor, verification is ~2,400× cheaper than proving the same circuit
  (0.456 proofs/s) — off-chain verification is not the bottleneck for RLN
  mode; proof generation and on-chain settlement are.

Reproduce:

```bash
cd sdk/shielded-sdk
node benchmark/prove-scaling.mjs --circuit 2_2   # produces a proof to verify
node benchmark/verify-throughput.mjs --per-worker 1000
```

---

## 3. Router paid-request load test (SpendAuth → inference → settle)

Stack under test: the real `/api/chat` route handler from `tangle-router`
(commit `85a7a40f`, main @ 2026-10-03) served over HTTP, wired to:
Anvil (instant-mine, port 8699) with deployed `MockToken` + `ShieldedCredits`
+ `InferenceBSM`, 3 Ollama-backed operators (`qwen2:0.5b`), and a throwaway
local Postgres (`prisma db push`, per repo convention for disposable DBs).
Load scripts live in the tangle-router repo, branch `bench/load`,
under `tests/load/shielded/` (`setup.ts`, `server.ts`, `drive.ts`), pushed as branch [`bench/load`](https://github.com/tangle-network/tangle-router/tree/bench/load) (commit `d50f02b4`); they reuse
the #597 e2e harness (`tests/e2e/harness/`) with the anvil port overridden via
`TANGLE_E2E_ANVIL_PORT=8699`.

Method: ramp of 1 / 5 / 10 / 25 / 50 concurrent closed-loop clients, 60 s per
level, one funded shielded wallet per client. Each request: read the wallet's
on-chain account nonce (ShieldedCredits requires strict sequential nonces),
sign a SpendAuth (EIP-712), POST `/api/chat` with `X-Payment-Signature` and a
pinned operator (`X-Tangle-Operator`, exactly as the #597 e2e suite does —
local anvil operators are suspended by chain-sync's health-probe gate, which
rejects loopback URLs even under the local SSRF hatch). Clients pace at the
router's per-commitment rate limit (120 req/min) with 1 s backoff on 429.
Latency percentiles are over successful (HTTP 200) requests only. Chain tx
rate = operator-EOA transaction count delta (authorizeSpend + claimPayment)
per second. Machine state recorded before each level.

Official run: `tests/load/shielded/results-2026-10-03T23-52-23-825Z.json` (committed on tangle-router `bench/load`, commit `d50f02b4`) (levels run back-to-back,
strictly sequentially; 1-min load average 9.7–11.8 during the run).

| Clients | Requests | OK | Success | Attempted rps | OK latency p50 | p95 | p99 | Chain tx/s | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 16 | 16 | **100%** | 0.27 | 4,092 ms | 6,090 ms | 6,090 ms | 0.46 | clean level |
| 5 | 447 | 31 | **6.9%** | 7.4 | 3,620 ms | 4,286 ms | 4,295 ms | 0.88 | first EOA race 11 s in; 19 wallets wedged, spares exhausted, then 401 flood |
| 10 | 1,107 | 14 | 1.3% | 18.4 | 4,091 ms | 4,139 ms | 4,139 ms | 0.40 | 401 cascade |
| 25 | 2,979 | 4 | 0.13% | 49.3 | 3,819 ms | 4,350 ms | 4,350 ms | 0.11 | 401 cascade |
| 50 | 5,906 | 17 | 0.29% | 97.7 | 4,121 ms | 4,204 ms | 4,204 ms | 0.48 | 401 cascade |

Supplementary run (fresh server, `tests/load/shielded/results-2026-10-04T00-00-58-334Z.json` (same branch)):
**c=2, 30 s: 26 requests, 20 OK (77%), 3 wallets wedged** — the failure mode
already engages at 2 clients.

Error taxonomy: 401 = `authentication_error` "Nonce already used" (wedged
commitment, see ladder); 503 = `server_error` (operator selection freshness
during cascades). 502 `on_chain_error` responses (the failed authorizeSpend
itself) are so rare they barely register — each one converts into a
long-lived 401 cascade instead.

Latency decomposition of the ~4.1 s happy-path RTT (measured separately,
same machine state): Ollama `qwen2:0.5b` inference **0.02–0.05 s**; anvil
transaction round trip ~0.3–0.5 s; the remaining **~3.5–4 s is the router
synchronously awaiting the authorizeSpend receipt** — `lib/shielded/on-chain.ts`
creates its viem clients without a `pollingInterval`, so
`waitForTransactionReceipt` resolves on viem's default ~4 s HTTP poll even
though anvil mined the tx instantly. Settles/claims are fire-and-forget and
do not add to user latency.

**Settle/claim rate:** the router sustained at most **~0.9 chain tx/s**
(authorizeSpend + claimPayment combined, operator-EOA nonce delta) before the
failure mode below collapsed it; at steady c=1 it drove 0.46 tx/s (≈0.23
settles/s). The ceiling here is the router's synchronous-authorize design and
single operator EOA, not anvil (instant-mine absorbed everything offered).

### What breaks first (load ladder)

1. **Operator-EOA transaction nonce race (breaks at 2 concurrent clients,
   sometimes at 1).** `claimPayment` is fire-and-forget while the next
   request's `authorizeSpend` (or concurrent authorizes) pulls the same
   account nonce from the node; one of them dies with *"Nonce provided for
   the transaction is lower than the current nonce of the account."* First
   observed 11 s into the c=5 level (4 simultaneous failures in one second);
   3 wallets wedged in 30 s at c=2; one occurrence at c=1 in an earlier run.
   This is the same race the #597 harness works around by serializing ALL
   requests through a lock in `tests/e2e/harness/shielded-proxy.ts`.
2. **Replay-store poisoning cascade (immediate follow-on).** The route's
   nonce replay store (`checkAndInsert`) consumes the SpendAuth nonce BEFORE
   `authorizeSpend` is submitted. When the authorize tx fails (rung 1), that
   commitment is wedged for the in-memory store's 10-minute TTL: every
   subsequent request — correctly signed with the true on-chain nonce, which
   was never spent — gets 401 "Nonce already used". One tx race thus converts
   into ~10 minutes of total denial for that commitment. At c=5 all 5 active
   wallets plus all 14 spares were wedged within the 60 s level.
3. **Nothing else broke.** Ollama answered in 20–50 ms throughout (never
   saturated), Postgres pool stats showed `waitingCount: 0` (pool size 25),
   anvil mined everything instantly, and the 120 req/min per-commitment rate
   limiter correctly absorbed the 401 retry floods (429s appeared in early
   unpaced smoke runs). Memory stayed under 1 GiB for the server process.

Launch-relevant follow-ups implied by the ladder (not measured here):
serialize operator-EOA transactions behind a nonce manager/queue; evict or
defer the replay-store entry when authorizeSpend fails on-chain; set viem
`pollingInterval` on the shielded RPC transport (~4 s of every RTT today is
poll wait on instant-mine).

### Local-harness caveats (test environment, not stack behavior)

- Chain-sync's health probe is gated by `isAllowedExternalUrl`, which rejects
  loopback endpoints even when `TANGLE_ALLOW_INSECURE_OPERATOR_ENDPOINTS=1` is
  set — so locally-registered operators are always synced as `suspended` with
  `unavailable` health rows. The load server runs a 30 s loop that performs
  REAL `/health` probes against the operators and persists the results (this
  mirrors what chain-sync would write if the probe gate passed). The #597 e2e
  suite sidesteps the same issue by pinning `X-Tangle-Operator`.
- Ollama was expected to be running but was not; it was started manually
  (`ollama serve`, models already pulled: qwen2:0.5b, mxbai-embed-large).
- Anvil is instant-mine: per-request settle latency here excludes real block
  time. Chain-ceiling analysis (Base Sepolia, 2 s blocks, public-RPC
  staleness) is covered by the sibling trace agent — do not extrapolate these
  RPS numbers to a public chain.

---

## 4. Operator-lite (llm-inference-blueprint) settle path

Skipped — timeboxed to keep items 1–3 fully measured and verified.

---

## Reproduction index

| Measurement | Script | Raw output |
|---|---|---|
| Witness generation | `sdk/shielded-sdk/benchmark/gen-witness.ts` | `build/bench/*/witness.wtns` |
| Proof-gen scaling | `sdk/shielded-sdk/benchmark/prove-scaling.mjs` | `sdk/shielded-sdk/benchmark/results/prove-scaling-*.json` |
| Verify throughput | `sdk/shielded-sdk/benchmark/verify-throughput.mjs` + `verify-worker.mjs` | `sdk/shielded-sdk/benchmark/results/verify-throughput-*.json` |
| Router load ramp | tangle-router `bench/load`: `tests/load/shielded/{setup,server,drive}.ts` | `tests/load/shielded/results-*.json` |
