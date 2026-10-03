# ZKP Benchmarks & Trusted Setup

Measured numbers for the shielded payment gateway's zero-knowledge stack, how to
reproduce them, how proving keys are generated **without running our own
multi-party ceremony**, and a written recommendation on the proof system going
forward.

Measured on: Apple M1 Max (arm64, 32 GB), Node v26.8.1, snarkjs 0.7.6,
circom 2.x, Foundry 1.8.1 (solc 0.8.26, `via_ir`, 200 optimizer runs).
Gas numbers are execution gas on local Anvil; add ~21k intrinsic + calldata
for transaction totals. Re-run the scripts below for your own hardware.

## TL;DR

- VAnchor 2-input circuits are small (~17.7k constraints): proofs in **~1.4s**,
  256-byte proofs, **~270k gas** to verify on-chain (measured end-to-end on
  Anvil with real proofs; ~310k for the 15-public-input 8-edge circuit).
- The "ceremony blocker" is dead: proving keys are generated from the **public
  Perpetual Powers of Tau (ppot_0080, the PSE/Semaphore community ceremony)**
  plus a local phase-2 contribution, in minutes on a laptop. No phase-1
  ceremony of our own, ever. See [Trusted setup](#trusted-setup--public-ceremony-parameters).
- Batched settlement amortizes well: RLN `batchClaim` costs ~27k gas/claim at
  batch size 50 vs ~107k for a single claim (~4.0x, measured post-H-1 solvency
  accounting). The SP1 `BatchVerifier`
  replaces N on-chain Groth16 verifications with one SP1 wrapper proof
  plus ~101k gas/tx of state processing (measured).
- Recommendation: **stay on Groth16/BN254 for the on-chain circuits** (cheapest
  on-chain verification, exact parity with EF's zkAPI stack), and use
  **SP1 recursion/batching** — already in this repo — for scale. Do not
  rewrite circuits to PLONK/Halo2. See [Recommendation](#recommendation-groth16-vs-universaltransparent-setups).

## Circuit sizes

From `snarkjs r1cs info` on the compiled circuits
(`build/trusted-setup/circuits/`):

| Circuit | Constraints | Public inputs | ptau power |
|---|---|---|---|
| `poseidon_vanchor_2_2` | 17,680 | 9 | 2^15 |
| `poseidon_vanchor_2_8` | 17,692 | 15 | 2^15 |
| `poseidon_vanchor_16_2` | 133,931 | 21 | 2^18 |
| `poseidon_vanchor_16_8` | 134,027 | 29 | 2^18 |
| `rln_payment_2_8` (VAnchor + RLN glue) | 23,546 | — | 2^15 |

All VAnchor circuits use Poseidon over BN254 with Merkle depth 30 (vs zkAPI's
depth-32 tree — depth has no effect on verification cost, only on proving time).

## Proof generation & verification

Measured by `sdk/shielded-sdk/benchmark/zk-bench.ts` (median of 3 runs,
deposit witness, `snarkjs.groth16.fullProve`). On-chain gas measured by
deploying the snarkjs-exported Solidity verifier to Anvil and tracing a real
`verifyProof` call (`debug_traceCall`; see note below — `eth_estimateGas`
under-reports ~7x on this contract).

| Circuit | Constraints | Public inputs | Prove (median) | Verify (local) | Proof calldata | On-chain verify gas |
|---|---|---|---|---|---|---|
| `poseidon_vanchor_2_2` | 17,680 | 9 | 1.39s | 11ms | 544 B | **269,914** |
| `poseidon_vanchor_2_8` | 17,692 | 15 | 1.36s | 14ms | 736 B | **310,414** |
| `poseidon_vanchor_16_2` | 133,931 | 21 | 8.40s | 12ms | 992 B | **369,674** |
| `poseidon_vanchor_16_8` | 134,027 | 29 | 8.24s | 13ms | 1,184 B | **410,066** |

Notes:

- On-chain gas is the full call cost (21k intrinsic + calldata + execution).
  Execution-only for `verifyProof` is roughly 30k lower. Marginal cost per
  public input is ~5k gas (one `ecmul`+`ecadd` on the IC terms).
- Proof size is constant for Groth16: 8 field elements = **256 bytes**,
  plus 32 bytes per public input.
- `eth_estimateGas` on Anvil returns ~40k for this verifier — wrong by ~7x.
  The snarkjs assembly verifier forwards `sub(gas(), 2000)` to the precompiles
  and *returns false* instead of reverting when a precompile is starved, so
  the estimator's binary search converges on the gas-starved (early-return)
  path. The bench asserts the proof actually verifies, then measures real gas
  used via `debug_traceCall`.
- Proving-key (zkey) and WASM sizes are reported by the bench script in
  `build/zk-benchmarks.json`.

## On-chain gas per operation

From `forge test --gas-report` (this repo) and the bench script:

| Operation | Gas (measured) | Notes |
|---|---|---|
| Groth16 verify, 2_8 circuit (on-chain) | **310,414** | snarkjs verifier, real proof, Anvil trace (incl. intrinsic+calldata) |
| Groth16 verify, 2_2 circuit (on-chain) | **269,914** | same method |
| RLNSettlement `deposit` | ~128k | median; ERC20 transfer + deposit record |
| RLNSettlement `withdraw` | ~43k | median |
| ShieldedCredits `authorizeSpend` | ~30k repeat / ~173k first | first spend initializes storage slots |
| ShieldedCredits `claimPayment` | ~71k | operator claims against an auth |
| ShieldedCredits `withdrawCredits` | ~70k | |
| RLNSettlement `slash` | ~32k–119k | depends on storage state |

## Batched vs unbatched

### RLN settlement batching (`RLNSettlement.batchClaim`)

From `forge test --match-contract RLNSettlementGas -vv`
(`test/RLNSettlementGas.t.sol`), measured after the H-1 solvency accounting
(per-claim deposit debit + token check):

| Batch size | Total gas | Per-claim gas |
|---|---|---|
| 1 | 107,376 | 107,376 |
| 10 | 335,417 | 33,542 |
| 50 | 1,348,370 | 26,967 |

Marginal cost ≈ 24k/claim (fresh nullifier SSTORE + transfer bookkeeping);
fixed overhead ≈ 73k. At batch 50 this is a **~3.8x saving** vs claiming
individually.

### SP1 batch verification (`sp1-batch/`)

State-processing cost measured with a mock SP1 verifier
(`forge test --match-test test_gas -vv` in `sp1-batch/contracts/`,
2 nullifiers + 2 commitments per tx). The unbatched baseline is the measured
on-chain Groth16 verify for the 2_8 circuit (310k gas); the SP1 wrapper-proof
verification cost (~270k fixed per batch, per `sp1-batch/README.md`, not
re-measured here) is added on top of the state cost.

| Batch size (txs) | State-processing gas | + SP1 wrapper verify (~270k) | Per-tx total | vs unbatched verify (310k/tx) |
|---|---|---|---|---|
| 1 | 188,476 | ~458k | ~458k | 1.5x worse |
| 10 | 1,100,874 | ~1.37M | ~137k | 2.3x better |
| 50 | 5,157,309 | ~5.43M | ~109k | 2.9x better |

Honest takeaways:

- The win from SP1 batching is real but **not** the "~99%" in the SP1 README —
  that figure ignores state processing (each tx still writes 2 nullifiers +
  2 commitments, ~101k/tx measured, dominated by fresh-storage SSTOREs).
  Break-even on gas alone is batch size ~2; at 50 it's ~2.9x.
- The bigger lever for the batch path is **cheaper state representation**
  (inserting commitments into an incremental Merkle tree instead of one
  mapping slot per commitment), which the current simplified `BatchVerifier`
  does not do. That is future work, not done here.
- Proving cost moves off-chain to the sequencer: one SP1 proof covers the
  whole batch; users keep generating the same circom Groth16 proofs.
- Both the unbatched and batched paths additionally pay the pool's Merkle
  state updates, which are out of scope for this measurement.

## Trusted setup — public ceremony parameters

### What changed

`scripts/trusted-setup/ceremony.sh` now:

1. Compiles the four VAnchor circuits (+ `rln_payment_2_8` with `--with-rln`),
   bootstrapping `circomlib` into the protocol-solidity submodule if missing.
2. Downloads the **smallest sufficient** public Powers of Tau file per circuit
   from the **Perpetual Powers of Tau (ppot_0080)** mirror
   (`https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/`),
   33–200 MB instead of the old fixed 2^22 download (~1.2 GB). The old Hermez
   zkevm GCS mirror (`storage.googleapis.com/zkevm/ptau`) returns 403 — dead.
   Downloads are validated (ptau magic bytes) before use.
3. Runs a **single local phase-2 contribution** per circuit with real entropy
   (`CEREMONY_ENTROPY`, default 32 bytes from `/dev/urandom` — previously the
   script used the hardcoded string `"tangle-shielded-setup"`), then a public
   beacon, verifies the final zkey against the R1CS + ptau, and exports
   verification keys + Solidity verifiers.
4. Copies artifacts into `build/circuits/<layout>/`, the layout the SDK and
   e2e tests expect. `getCircuitArtifacts()` in the SDK now prefers these
   local keys (`TANGLE_CIRCUIT_DIR` to override) and only then falls back to
   HTTP download — the historical Webb fixture bucket
   (`protocol-solidity-fixtures.s3.amazonaws.com`) **no longer exists**
   (NoSuchBucket), so the previous default was a guaranteed failure.

Total wall time on an M1 Max for all 5 circuits: **~50 minutes**, dominated by
the two 134k-constraint circuits (~20 min each across setup, contribute,
verify); the 2-input circuits finish in ~2–3 minutes each. No coordination,
no waiting on other participants.

### Trust implications (read before mainnet)

- **Phase 1 (powers of tau): 1-of-N honest assumption over a large public
  ceremony.** ppot_0080 is the perpetual powers-of-tau run started from the
  Hermez/polygon-hermez ceremony output and extended by dozens of independent
  contributors (the same parameters the Semaphore community uses — see
  `semaphore-anchor` in this org for the in-repo precedent of reusing these).
  We verify the downloaded file is well-formed; its contributor history is
  publicly auditable. If *all* historical contributors colluded, they could
  forge proofs — the standard accepted assumption for Groth16 production
  systems (Tornado Cash, Semaphore, zkAPI all rely on exactly this).
- **Phase 2 (circuit-specific): currently 1-of-1.** Groth16 needs a
  circuit-specific phase 2, and there are **no reusable completed phase-2
  contributions for the VAnchor circuits**: protocol-solidity ships only
  R1CS/WASM artifacts; its proving keys lived in a DVC-tracked S3 bucket that
  is gone. (It *does* commit the exported Solidity verifiers under
  `packages/contracts/contracts/verifiers/` — but a verifier contract is only
  useful with its matching proving key, which is lost, so deployment must use
  the verifiers exported from *our* zkeys. Never mix Webb's old verifier
  contracts with newly generated proving keys: the vkeys differ and every
  proof would fail.) So the keys produced here trust whoever ran this script
  (you).
  - Fine for: testnets, development, the e2e proof suite.
  - **Not fine for mainnet value.** Before deploying these verifiers with
    real funds, run a proper multi-party phase 2: `snarkjs zkey contribute`
    from several independent parties (or a p0tion ceremony), ending with a
    public random beacon. The script's structure supports this — hand the
    intermediate zkey between contributors instead of piping straight to
    beacon. 1-of-N with even one honest contributor is secure.
- EF's zkAPI made the identical choice (Groth16/BN254/Poseidon, Hermez-family
  public params), so this puts us at **setup-parity**, not a disadvantage.

## Recommendation: Groth16 vs universal/transparent setups

Question: should we move the circuits to PLONK (universal setup), Halo2
(transparent), or add proof recursion? Recommendation: **no circuit rewrite;
keep Groth16 on-chain, scale with the existing SP1 batching.**

Circuit-size context: our largest circuit is 134k constraints — small by
modern standards, and these circuits change essentially never (they mirror
audited protocol-solidity circuits).

| Option | On-chain verify gas (BN254, EVM) | Setup | Fit for us |
|---|---|---|---|
| **Groth16** (status quo) | **~270k measured** (2_2; 310k for 2_8) | per-circuit phase 2 (1-of-1 now, MPC before mainnet) | Cheapest on-chain verification that exists; 256-byte proofs; exact zkAPI parity |
| PLONK (snarkjs/aztec-style) | ~280k–600k (more pairings + polynomial evaluations; larger proofs ~600 B–1 KB) | universal KZG — but the KZG SRS still needs a trusted ceremony (e.g. Ethereum's perpetual powers-of-tau / EIP-4844 ceremony) | Solves "per-circuit phase 2" but costs ~1.5–3x verification gas forever, to fix a one-time ceremony we only need to run once |
| Halo2 (KZG or IPA) | No cheap native verifier path on EVM today; practical deployments verify via aggregation/wrapping (i.e. ends up as Groth16/PLONK on-chain anyway) | transparent (IPA) or universal (KZG) | Great for proving-large-computation-then-recurse (what SP1 already does); wrong tool for a 17k-constraint fixed circuit |
| Recursion (SP1, already in repo) | ~270k fixed for any batch | none new | Already implemented in `sp1-batch/`; this is the right scaling axis |

- **zkAPI parity**: EF's launch uses the identical on-chain stack
  (Groth16/BN254/Poseidon/Merkle tree, server-side spend-proof verification,
  vault verifies at deposit/close/escape). Matching them means tooling,
  auditors, and verifiers are interchangeable; switching to PLONK/Halo2 would
  make us *more* expensive than the baseline we compete with, not less.
- Where universal/transparent setups genuinely win for us is **inside the
  zkVM** (SP1 = STARK recursion with a Groth16 wrapper), which we already
  have. If we ever outgrow it, the next step is a larger deployment of the
  same pattern (recursive aggregation of VAnchor proofs), not a circuit
  rewrite.

## Reproducing these numbers

```bash
# 1. Generate proving keys from public ppot_0080 (no ceremony coordination)
./scripts/trusted-setup/ceremony.sh --with-rln

# 2. Contract gas report (deposit/withdraw/spend)
forge test --gas-report

# 3. RLN batch scaling
forge test --match-contract RLNSettlementGas -vv

# 4. SP1 batch state-processing scaling
cd sp1-batch/contracts && forge test --match-test test_gas -vv && cd ../..

# 5. Proof time/size + on-chain Groth16 verify gas (needs anvil + forge)
cd sdk/shielded-sdk && npm install
npx tsx benchmark/zk-bench.ts          # 2-input circuits
npx tsx benchmark/zk-bench.ts --16     # include 16-input circuits
```
