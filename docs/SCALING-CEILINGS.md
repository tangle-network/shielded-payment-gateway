# Chain-level ceilings

Theoretical throughput ceilings of the shielded payments system, computed from
**measured gas costs** (this repo's `docs/ZKP-BENCHMARKS.md` and the Base
Sepolia trace in `docs/DEPLOYMENTS.md`, several rows re-verified against the
live chain) and **live Base chain parameters** fetched over public RPC.

This document is pure arithmetic on measured inputs — no benchmarks were run
for it. Companion to `docs/SCALING-BENCHMARKS.md` (empirical load-test
numbers).

## 1. Inputs

### 1.1 Live chain parameters (fetched 2026-10-03 ~22:58–23:05 UTC)

Method: `eth_getBlockByNumber("latest")` + two parents on the public RPCs
(`https://mainnet.base.org`, `https://sepolia.base.org`). Block time is the
observed timestamp delta across 3 consecutive blocks.

| Parameter | Base mainnet (chain 8453) | Base Sepolia (chain 84532) |
|---|---|---|
| Sample blocks | 52,139,485 – 52,139,487 | 47,650,014 – 47,650,016 |
| Block gasLimit | **400,000,000** | **1,200,000,000** |
| Block gasUsed (3 samples) | 36.5M / 22.8M / 20.0M | 11.1M / 2.9M / 2.5M |
| Utilization vs limit | **~5–9%** | ~0.2–0.9% |
| baseFeePerGas | 0.005 gwei (all samples) | 0.005 gwei (all samples) |
| Block time | **2 s** (ts 1791068317→8319→8321) | **2 s** (ts 1791068316→8318→8320) |

Derived capacities used below:

| Tier | gas/block | gas/s | gas/day | Meaning |
|---|---|---|---|---|
| Whole chain @ limit | 400M | 200M | 17.28 T | hard ceiling, not sustainable at flat baseFee |
| Whole chain @ EIP-1559 target | 200M | 100M | 8.64 T | limit/2 — the level baseFee pressure keeps long-run usage at; exactly ½ of every "whole chain" number below |
| 5% share of limit | 20M | 10M | 864 B | ~doubles Base's current total load — "realistic heavy tenant" |
| 1% share of limit | 4M | 2M | 172.8 B | "unremarkable tenant" |

**Base Sepolia caveat:** its 1.2B gas/block limit is 3× mainnet's and
utilization is ~1%, so testnet tells us nothing about mainnet congestion or
fee behavior. All ceilings below are mainnet-parameterized.

### 1.2 Measured gas per operation

Sources: `docs/ZKP-BENCHMARKS.md` (Anvil `forge` gas reports, M1 Max) and the
Base Sepolia trace (`docs/DEPLOYMENTS.md`), the latter re-fetched for this
document via `eth_getTransactionReceipt` on `https://sepolia.base.org`
(2026-10-03 ~23:00 UTC, all `status=0x1`):

| Operation | Gas used | Source |
|---|---|---|
| `authorizeSpend` (repeat) | ~30,000 | forge gas report |
| `authorizeSpend` (first per account) | 177,836 | trace tx `0x14a2…d0f4` (forge said ~173k — measured on-chain slightly higher) |
| `claimPayment` | 73,702 | trace tx `0x4441…ba37` (forge said ~71k) |
| `settlePayment` (metered + refund) | 69,415 | trace tx `0xaa4f…c39c`, block 47,618,123 |
| `withdrawCredits` | 55,748 | trace tx `0xe75b…4e5c` |
| `deposit` (VAnchor, real 2_8 Groth16 proof) | 1,747,440 | trace tx `0x241b…a607` |
| `shieldedFundCredits` (join-split proof) | 1,878,531 | trace tx `0x2738…2a35` |
| `RLNSettlement.deposit` | ~128,000 | forge median (no ZK proof — ERC20 transfer + record) |
| RLN `batchClaim`, per claim @ batch 50 | 26,967 | forge (`test/RLNSettlementGas.t.sol`; marginal ≈24k, fixed ≈73k) |
| SP1 batch, per tx @ batch 50 | 108,546 | forge + ~270k wrapper verify amortized (`sp1-batch`; state processing only, pool Merkle updates excluded) |

## 2. Per-operation ceilings

ops/s = (tier gas/s) ÷ gas-per-op; ops/day = ops/s × 86,400. "Whole chain" =
Base doing nothing else — an upper bound, not a plan. Halve it for the
sustainable EIP-1559-target tier.

| Operation | Whole chain | 5% share | 1% share |
|---|---|---|---|
| `authorizeSpend` repeat (30k) | 6,667/s · 576M/day | 333/s · 28.8M/day | 66.7/s · 5.76M/day |
| `authorizeSpend` first (178k) | 1,124/s · 97.1M/day | 56.2/s · 4.86M/day | 11.2/s · 971k/day |
| `claimPayment` (73.7k) | 2,714/s · 234M/day | 136/s · 11.7M/day | 27.1/s · 2.34M/day |
| `settlePayment` (69.4k) | 2,881/s · 249M/day | 144/s · 12.4M/day | 28.8/s · 2.49M/day |
| `deposit` (1.747M) | 114.5/s · 9.89M/day | 5.72/s · 494k/day | 1.14/s · 98.9k/day |
| `shieldedFundCredits` (1.879M) | 106.5/s · 9.20M/day | 5.32/s · 460k/day | 1.06/s · 92.0k/day |
| RLN `batchClaim` @50 (27k) | 7,417/s · 641M/day | 371/s · 32.0M/day | 74.2/s · 6.41M/day |
| SP1-batched tx @50 (108.5k) | 1,842/s · 159M/day | 92.1/s · 7.96M/day | 18.4/s · 1.59M/day |

Reference at today's baseFee (0.005 gwei): one credit-mode request
(99,415 gas) costs ~5.0×10⁻⁷ ETH of L2 execution gas; one onboarding session
(3.63M gas) ~1.8×10⁻⁵ ETH. L1 data-posting fees are separate and not modeled
here (calldata per op is small; proofs are ≤1.2 kB).

## 3. Product-unit ceilings

### 3.1 Paid inference requests/sec — credit mode

Per request: 1 `authorizeSpend` (30k repeat) + 1 `settlePayment` (69,415) =
**99,415 gas/request** (both txs sent by the operator; the user's per-request
action is an off-chain EIP-712 signature). First-spend auths (177,836) raise
it to 247,251 gas for the first request of a fresh credit account.

| Path | gas/request | Whole chain | 5% share | 1% share |
|---|---|---|---|---|
| repeat auth + settle | 99,415 | **2,012 req/s** · 174M/day | **100.6 req/s** · 8.69M/day | **20.1 req/s** · 1.74M/day |
| first auth + settle | 247,251 | 809 req/s | 40.4 req/s | 8.1 req/s |
| repeat auth + claim (73.7k, operator-lite's current path) | 103,702 | 1,928 req/s | 96.4 req/s | 19.3 req/s |

### 3.2 Onboarding capacity (deposit + fundCredits per user session)

1 `deposit` (1,747,440) + 1 `shieldedFundCredits` (1,878,531) =
**3,625,971 gas per funded session**.

| Tier | Sessions/s | Sessions/day |
|---|---|---|
| Whole chain | 55.2 | 4.77M |
| 5% share | 2.76 | 238k |
| 1% share | 0.55 | **47.7k** |

Onboarding is ~36× more expensive per user than a request is per request —
at any serious request rate, deposit gas dominates total system gas unless
sessions are long-lived (many requests per funded session). Sustained
requests/s ≈ 36.6 × (sessions/s) at equal gas.

### 3.3 RLN mode: off-chain requests vs on-chain settlement ceiling

In RLN mode the per-request action is fully off-chain (an RLN proof signal);
the chain only sees (a) cheap stake deposits (~128k, no ZK proof → whole-chain
1,562 deposits/s, 1% share 15.6/s ≈ 1.35M/day) and (b) batched claims at
**26,967 gas/claim** (batch 50; marginal ≈24k as batch → ∞):

| Tier | Claims/s | Claims/day |
|---|---|---|
| Whole chain | 7,417 | 641M |
| 5% share | 371 | 32.0M |
| 1% share | 74.2 | 6.41M |

If one claim nets one request, 371 req/s at a 5% share is the on-chain
ceiling; the off-chain request rate itself is bounded only by operator
inference capacity and the RLN per-epoch rate limit, not by the chain. The
ratio (requests per claim) is the key design lever — currently 1:1 per
nullifier.

Privacy note: RLN deposits are a stake, not pool notes — RLN-mode privacy
comes from the nullifier/epoch scheme, and only VAnchor deposits grow the
pool anonymity set.

### 3.4 Anonymity-set growth (VAnchor deposits/day)

The pool is variable-amount, so a withdrawal hides among **all unspent
notes** — the anonymity set grows by one per `deposit`:

| Deposit rate | Source | Anonymity-set growth |
|---|---|---|
| 9.89M/day | whole-chain ceiling | fills any practical set instantly |
| 494k/day | 5% share ceiling | ~99k notes per 5 h |
| 98.9k/day | 1% share ceiling | ~99k notes/day |
| realistic early launch (100–10k/day) | — | withdrawal after 24 h mixes with only that many notes; amount- and timing-correlation matter at this scale |

This is the quantitative basis for the `feeBps = 0` launch decision
(`docs/DEPLOYMENTS.md`, protocol decisions 2026-10-03): at realistic early
volumes the anonymity set — not gas — is the scarce resource, and every fee
discourages the deposits that create it.

## 4. Structural limits

### 4.1 Merkle tree capacity (30 levels)

2³⁰ = **1,073,741,824 leaves**. Time to fill at ceiling deposit rates:

| Deposit rate | Time to fill tree |
|---|---|
| 9.89M/day (whole chain) | **108.6 days (~0.3 yr)** |
| 494k/day (5% share) | 5.95 yr |
| 98.9k/day (1% share) | 29.7 yr |
| 10k/day (healthy realistic) | ~294 yr |

Non-issue at any plausible share; only the absurd whole-chain ceiling fills
it inside a quarter. (A full tree requires deploying a new pool + root
bridging; no in-repo rotation mechanism — irrelevant before ~2030 at 1%
share.)

### 4.2 Client-side tree sync per new deposit batch

Each deposit appends one 32-byte commitment (event/calldata). A syncing
client pays, per leaf: **32 B bandwidth + ~1–2 Poseidon hashes** (incremental
tree append; sub-millisecond in WASM) to keep the frontier current, and
~1 Poseidon per watched note to keep its Merkle path valid.

| Deposit rate | Client bandwidth | Client compute |
|---|---|---|
| 5.72/s (5% ceiling) | ~183 B/s | ~6–12 Poseidon/s — trivial on any device |
| 114.5/s (whole chain) | ~3.7 kB/s (~317 MB/day) | ~120–230 Poseidon/s — fine on desktop, noticeable on mobile |
| realistic 10k/day | ~0.1/s bursts | negligible |

Bandwidth is never the bottleneck at realistic shares; the practical
constraints are `eth_getLogs` range limits on public RPCs (use an indexer)
and initial-sync catch-up time after long offline periods.

### 4.3 Nonce/auth store growth

Each SpendAuth persists one on-chain record keyed by authHash (~2–3 fresh
storage slots ≈ 64–96 B of chain state) plus an off-chain row
(~150 B indexed) on the operator/gateway side.

| Auths/day | On-chain state/yr | Off-chain DB/yr |
|---|---|---|
| 1k | ~35 MB | ~55 MB |
| 10k | ~350 MB | ~550 MB |
| 100k | ~3.5 GB | ~5.5 GB |

Bounded in practice by auth expiry: live-set size ≈ auths/day × TTL days,
and expired/settled auths are garbage-collectable off-chain (on-chain slots
are forever, but 3.5 GB/yr at 100k/day is ordinary chain-state growth).

### 4.4 Proving capacity

Client-side (measured on M1 Max, `docs/ZKP-BENCHMARKS.md`): 2-input proofs
~1.4 s → **~0.7 proofs/s single-device**; 16-input ~8.3 s → ~0.12/s.

- **Credit mode:** proofs are needed only for `deposit`/`fundCredits`
  (once per session) — per-request spends are EIP-712 signatures
  (microseconds). Client proving is never the per-request bottleneck.
- **RLN mode:** one RLN proof (~23.5k constraints, ≈1.4 s class) **per
  signal**, binding epoch+message so pre-computation is limited → per-user
  request ceiling ≈ 0.7 req/s unless the wallet proves on multiple cores.
  This is a *per-user* UX limit, not a system limit.
- **SP1 batch path:** the sequencer produces one SP1 proof per batch (50 txs
  ≈ 900k constraints of proof-verification work). Options: dedicated
  GPU/prover hardware, or the **Succinct prover network** (the repo's
  `sp1-batch/` is built on SP1, so this is a config change, not new code) —
  latency moves to minutes-scale but proving parallelizes across batches.
  At 5%-share ceiling (~92 batched txs/s ≈ 1.8 batches/s of 50) the
  sequencer needs ~2 SP1 proofs/s of aggregate capacity — a real but
  rentable amount of compute; proving cost, not chain gas, becomes the
  operating expense at that tier.

## 5. Bottleneck ranking by request rate

Credit-mode baseline: 99.4k gas/request on-chain. Absolute floor for *any*
design that touches chain state per request: one fresh SSTORE ≈ 20k gas →
even with the whole chain, Base cannot exceed ~10k state-changing
requests/s.

### 10 req/s (~1.0M gas/s, 0.5% of block)
- **Chain:** comfortable inside a 1% share. Nothing saturates.
- **Saturates first:** operational, not gas — public-RPC staleness and the
  router's ~3.5 s claim retry window (observed `AuthNotFound` races in the
  Base Sepolia trace, `docs/DEPLOYMENTS.md` known gaps).
- **Fix:** dedicated RPC + longer retry horizon. No contract change needed.

### 100 req/s (~9.9M gas/s, 2.5% of block)
- **Chain:** fits in a 5% share, but combined with onboarding (1 session/s
  at 100 req/session adds 3.6M gas/s ≈ 1.8%) total ≈ 4.3% of block — visible
  tenant; baseFee exposure begins.
- **Saturates first:** per-request settlement cost (operator gas spend
  ~5×10⁻⁷ ETH/request at 0.005 gwei — fine while baseFee stays floored,
  painful if usage pushes past target) and operator-key tx management.
- **Fixes in-repo:** `RLNSettlement.batchClaim` (27k/claim, ~3.8× vs
  individual), operator scale-out (multiple operator keys/blueprint
  operators — standard tnt-core operation).

### 1,000 req/s
- **Naive credit mode:** 99.4M gas/s ≈ 25% of block — not viable. RLN-batched
  path: 27M gas/s ≈ 6.8% of block — above a polite share but below the
  5%-of-target… still heavy; needs larger batches (marginal → 24k) or
  multi-request netting per claim.
- **Saturates first:** **onboarding gas.** At 100 requests/session, 1k req/s
  needs 10 sessions/s = 36M gas/s (18% of block) — more than the requests
  themselves. The 1.75M/1.88M deposit+fund costs are dominated by pool
  state writes and token transfers, *not* proof verification, so SP1
  batching only shaves the ~310k verify portion (→ ~1.44M/deposit batched).
- **Fixes in-repo:** RLN batching (exists), SP1 `BatchVerifier` (exists;
  modest effect on deposits, large on verify-heavy flows), operator
  scale-out (exists), longer-lived sessions / larger auths (config). Real
  fix needed beyond repo: cheaper state representation for batched inserts
  (flagged as future work in `docs/ZKP-BENCHMARKS.md`) and claim netting.

### 10,000 req/s
- **Impossible on Base L2 blockspace alone.** RLN claims at the 24k marginal
  floor = 240M gas/s > the entire 200M gas/s chain limit; onboarding at 100
  sessions/s = 363M gas/s is worse. Even a hypothetical 1-SSTORE-per-request
  design (20k) barely fits with the whole chain doing nothing else.
- **Saturates first:** everything; binding constraint is the fresh-storage
  SSTORE floor — no batching trick reduces *state changes* per request.
- **Required (not in repo):** claim aggregation (one on-chain claim per
  operator per epoch covering many nullifiers via a Merkle root — today it's
  1:1), session netting so one settle covers many requests, and ultimately a
  validium/app-rollup or recursive settlement layer. In-repo pieces (RLN
  batching, SP1 batching, operator scale-out) realistically carry the system
  to the low thousands of req/s at a ≤5% share; 10k req/s is new protocol
  work.

**Summary of what saturates first, in order as load grows:**
1. RPC reliability / retry tuning (10 req/s) — ops fix.
2. Per-request settlement gas cost + operator key management (100 req/s) —
   in-repo: RLN batching, operator scale-out.
3. Onboarding (deposit+fundCredits) gas (1k req/s) — partially in-repo
   (SP1 batching); needs cheaper batched state inserts.
4. The SSTORE floor / Base blockspace itself (10k req/s) — needs claim
   aggregation + netting or an L3; not in repo.

## 6. Caveats

- **Arithmetic, not measurement.** Ceilings assume perfect block packing and
  ignore baseFee escalation: sustained use above the 200M gas/block EIP-1559
  target raises baseFee ~12.5%/block, so "whole chain @ limit" tiers are
  theoretical maxima, and even the 5% tier would roughly double Base's
  current load (measured ~5–9% utilization at fetch time).
- Gas inputs are single-shot measurements (forge medians on Anvil; one
  on-chain sample each for the trace rows). Storage-warm vs cold variation
  (e.g. repeat vs first `authorizeSpend`: 30k vs 178k) swings ceilings ~6×.
- SP1 batch numbers exclude the pool's Merkle state updates
  (`docs/ZKP-BENCHMARKS.md` is explicit about this), so batched *deposit*
  savings are smaller than the table's per-tx row implies.
- RLN `batchClaim` per-claim gas was measured post-H-1 (per-deposit solvency
  accounting); batch-50 numbers are real forge measurements, the 24k
  marginal is a fit, not a measurement at batch >50.
- Chain parameters are a 3-block sample at one moment (2026-10-03 ~23:00
  UTC); Base has raised its gas limit over time and may again — re-fetch
  before quoting externally.
- No local benchmarks were run for this document (a sibling load test was
  running on this machine; load average 54–71 during authoring). All inputs
  are repo-measured numbers and public-RPC reads, exactly as cited.
