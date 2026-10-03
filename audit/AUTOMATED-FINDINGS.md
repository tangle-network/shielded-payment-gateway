# Automated Security Pass — shielded-payment-gateway

**Branch:** `audit/automated-pass` (base: `origin/main` @ `c63ebf6`)
**Date:** 2026-10-02
**Scope:** `src/shielded/ShieldedCredits.sol`, `src/shielded/ShieldedGateway.sol`,
`src/shielded/RLNSettlement.sol`, `src/shielded/BatchTransactor.sol`,
`sp1-batch/contracts/src/BatchVerifier.sol` (+ interfaces for those contracts).
**Out of scope:** inherited protocol-solidity VAnchor contracts (Veridise-audited
lineage per ROADMAP.md), `src/beacon/**`, `src/shielded/LayerZeroAnchorBridge.sol`
(findings there are listed as out-of-scope and deferred to the manual review track).

## Tooling

| Tool | Version | Command | Result |
|---|---|---|---|
| Slither | 0.11.3 | `slither . --foundry-out-directory out` | 74 results across 35 contracts (pre-fix); 69 post-fix |
| Aderyn | 0.5.11 | `aderyn .` | 2 High / 13 Low categories (pre-fix) |
| Slither (BatchVerifier) | 0.11.3 | `slither src/BatchVerifier.sol --filter-paths "lib/"` (in `sp1-batch/contracts`) | 0 findings |
| Foundry | forge 1.8.1, solc 0.8.26, via_ir | `forge build --sizes` | all contracts far below 24KB limit |
| Coverage | forge 1.8.1 | `forge coverage --ir-minimum --report summary` | see below |

Note: plain `forge coverage` fails on `script/DeployShieldedPool.s.sol` ("stack too deep"
without the optimizer); `--ir-minimum` is the documented workaround.

## Fixes applied on this branch

### F-1 — CRITICAL (fixed): unauthenticated slashing drains any funded RLN deposit

`RLNSettlement.slash()` recovered a Shamir "secret" from the two supplied shares but
**never verified it against the slashed identity commitment** (the recovered `secret`
was an unused variable — also flagged as a solc warning). The only gates were
`x1 != x2` and `deposits[identityCommitment].balance > 0`. Any pair of shares with
`x1 != x2` interpolates to *some* secret, so anyone could slash **any** funded deposit
and claim the full balance after `SLASH_DELAY` (1 day).

- Evidence: `src/shielded/RLNSettlement.sol:214-263` (pre-fix); unused `secret` at old line 234.
- The interface already specified the intended check — `IRLNSettlement.slash`:
  *"verifies keccak256(secret) == commitment"*, and `identityCommitment` is documented
  as `keccak256(identitySecret)` (the Foundry tests already use that convention).
- Fix (`src/shielded/RLNSettlement.sol:227-246`): after recovering the secret,
  `if (keccak256(abi.encodePacked(secret)) != identityCommitment) revert InvalidSlash();`
  before any balance mutation. The double-signaled `nullifier` (previously an unused
  parameter) is now also marked in `usedNullifiers` so the operator cannot batch-claim
  payment for the fraudulent signals.
- Tests: `test_slash_fabricatedShares_cannotDrainDeposit`,
  `test_slash_wrongCommitment_reverts` (updated expectation),
  `test_slash_noDeposit_reverts`, `test_slash_blocksDoubleSignaledNullifier`,
  `test_finalizeSlash_emitsEvent` in `test/RLNSettlement.t.sol`.

### F-2 — Medium (fixed): ETH locked in BatchTransactor

`executeBatch` / `executeBatchDirect` are `payable` but never forward `msg.value`
(batch txs carry no per-tx value), and the contract had no withdraw function
(Slither `locked-ether`, Aderyn H-2 pre-fix). Any ETH sent was locked forever.

- Fix (`src/shielded/BatchTransactor.sol:122-127`): refund `msg.value` to `msg.sender`
  at the end of `_executeTxs`. `receive()` is retained so VAnchor native refunds
  cannot revert a batch; plain unsolicited transfers can still strand ETH (accepted,
  see D-5).
- Test: `test_executeBatchDirect_refundsMsgValue` in `test/shielded/BatchTransactor.t.sol`.

### F-3 — Low (fixed): `shieldedFundRLN` accepts an EOA settlement address

`ShieldedGateway.shieldedFundRLN` issued a low-level `call` to the user-supplied
`rlnSettlement`. A call to an address with no code returns `success == true`, so the
deposit would silently no-op **after** the VAnchor withdrawal, stranding the user's
tokens in the gateway with an outstanding approval (Slither `low-level-calls` /
`missing-zero-check`, `src/shielded/ShieldedGateway.sol:123-144` pre-fix).

- Fix: `if (rlnSettlement.code.length == 0) revert InvalidSettlementAddress(rlnSettlement);`
  (new error in `IShieldedGateway.sol`).
- Test: `test_shieldedFundRLN_eoaSettlement_reverts` in `test/shielded/ShieldedGateway.t.sol`.

### F-4 — Low (fixed): `rescueETH` hardening

Missing zero-address check on `recipient` (Slither `missing-zero-check`) and empty
`require(success)` (Aderyn L-4). Now reverts `InvalidRecipient()` on `address(0)` and
`require(success, "ETH transfer failed")` (`src/shielded/ShieldedGateway.sol:212-217`).
Tests: `test_rescueETH*` in `test/shielded/ShieldedGateway.t.sol`.

### F-5 — Hygiene (fixed): dead code / immutability / shadowing / missing events

- Removed unused `ShamirShare` struct and `_shares` mapping (Slither `unused-state`,
  Aderyn L-8) — dead code from an earlier design.
- `RLNSettlement.owner` → `immutable` (Slither `immutable-states`, Aderyn L-13).
- `ShieldedGateway` constructor param `_owner` → `_admin` (shadowed OZ `Ownable._owner`;
  Slither `shadowing-local`, Aderyn L-9). Positional deploy scripts unaffected.
- Added `OperatorRegistered` / `OperatorRemoved` / `SlashFinalized` events
  (Aderyn L-12) to `IRLNSettlement.sol` and their emit sites.
  Test: `test_registerRemoveOperator_emitEvents`.

## Triage of remaining tool findings (not fixed)

| # | Tool / detector | Location | Disposition |
|---|---|---|---|
| T-1 | Slither `uninitialized-local`, Aderyn L-10 | `RLNSettlement.sol:182` `totalAmount`; loop var `i` | **False positive** — Solidity zero-initializes; variables are only read after accumulation. |
| T-2 | Aderyn H-2 (post-fix run): "ETH transferred without address checks" | `BatchTransactor.sol:76,90` | **False positive** — the transfer is the F-2 refund to `msg.sender` (the caller's own ETH). |
| T-3 | Slither `calls-loop` / `reentrancy-benign`, Aderyn L-7 | `BatchTransactor._executeTxs` | **By design** — the batch is intentionally atomic; any failing tx reverts the whole batch (documented in the contract header). `nonReentrant` is present and the VAnchor is the sole state owner. |
| T-4 | Aderyn L-7, L-11 | `RLNSettlement.batchClaim` loop | **By design** — each nullifier must be marked spent (SSTORE per item is inherent); operator batches are size-bounded by gas. |
| T-5 | Slither `timestamp` ×7 | `ShieldedCredits` expiry checks, `RLNSettlement` slash timelock | **False positive** — `block.timestamp` is the intended expiry/timelock primitive; 1-day granularity makes miner manipulation irrelevant. |
| T-6 | Slither `assembly` | `RLNSettlement._modExp` | **Reviewed, correct** — standard modexp precompile (0x05) call for Fermat-inversion; memory layout verified. |
| T-7 | Slither `pragma`, Aderyn L-2 | all scoped files (`^0.8.26`) | **Informational** — `foundry.toml` pins `solc = "0.8.26"`; interfaces keep the caret per repo convention. |
| T-8 | Aderyn L-5 (PUSH0) | all scoped files | **Informational** — `evm_version = "cancun"`; deployment targets (Base) support PUSH0. |
| T-9 | Slither `naming-convention` | `DOMAIN_SEPARATOR`, `_`-prefixed params | **Informational/style** — repo convention; `DOMAIN_SEPARATOR` is `immutable`, not a compile-time constant. |
| T-10 | Aderyn L-1 (centralization) | owner-only fns in `ShieldedGateway`, `RLNSettlement` | **Documented risk** — owner registers pools/operators but cannot touch user funds (see contract threat-model headers). See D-2 for the operator trust assumption. |
| T-11 | Aderyn L-12 (residual) | `RLNSettlement.batchClaim` | **False positive** — `BatchClaimed` is emitted; detector misses events after loops. |
| T-12 | Slither `reentrancy-events` ×4, `events-maths`; Aderyn L-3, L-6, L-12 | `src/shielded/LayerZeroAnchorBridge.sol` | **Out of scope** (bridge contract is in the manual-review sibling's lane); no state-at-risk patterns observed on read-through. |
| T-13 | Aderyn H-1 (unsafe casting), H-3 residual | `src/beacon/bridges/LayerZeroCrossChainMessenger.sol` | **Out of scope** (`src/beacon/**`). Flagged for the manual review: `uint128(effectiveGasLimit)` downcast at line 162/199. |
| T-14 | Slither `unused` locals (solc warning) | `BatchVerifier.sol:82-83` (`publicAmountsHash`, `extDataHash` decoded, never used) | **Informational** — see D-6. |

## Documented findings (judgment calls — not fixed on this branch)

### D-1 — HIGH: `RLSettlement.batchClaim` has no solvency accounting

An authorized operator supplies `(nullifiers, amounts)` and receives `sum(amounts)`
with no check against actual deposits. A compromised or malicious operator can drain
the contract's entire token balance with fresh random nullifiers
(`src/shielded/RLNSettlement.sol:173-203`). The contract header documents the trust
model ("operators verify ZK proofs off-chain, backed by tnt-core staking/slashing"),
so this is an accepted launch risk, but it should be mitigated with a per-token
invariant (`claimedTotal[token] + amount <= depositedTotal[token] - withdrawnTotal[token]`)
and/or operator bonding. **Left to the manual review / protocol decision.**

### D-2 — HIGH: anonymous (gateway-funded) RLN deposits can never be withdrawn

`RLSettlement.withdraw` ignores its `proof` parameter and requires
`msg.sender == deposits[ic].depositor`. For deposits made via
`ShieldedGateway.shieldedFundRLN`, `depositor` is the gateway contract, which has no
withdraw function — the refund path is broken for the anonymous flow
(`src/shielded/RLNSettlement.sol:285-313`). Relatedly, operator claims do not
decrement per-identity deposit balances, so a user can pay via RLN and then withdraw
the same funds (double-spend) — only off-chain Shamir slashing deters this. Fixing
properly requires the ZK withdraw proof planned in ROADMAP Phase 4. **Documented for
launch gating; do not ship RLN deposits via the gateway without an answer here.**

### D-3 — MEDIUM: SDK/on-chain identity-commitment hash mismatch

The SDK derives `identityCommitment = Poseidon(identitySecret)`
(`sdk/shielded-sdk/test/rln-e2e.test.ts:200` etc.), while the on-chain slash
verification (F-1, matching `IRLNSettlement` docs and Foundry tests) binds
`keccak256(identitySecret)`. Slashing a Poseidon-committed identity will revert
on-chain. Either switch the SDK to keccak commitments or link a PoseidonT2 library
into `RLNSettlement` (requires `--libraries` deploy-flow changes, see
`scripts/deploy-full-stack.sh:181-185`). **Needs cross-component decision.**

### D-4 — LOW: `BatchTransactor` cannot execute native-token batches

No per-tx value exists in `BatchTx`, and `msg.value` is refunded (F-2). If native
VAnchor pools must be batched, add a `value` field to `BatchTx` and forward it.
Until then native batches are unsupported rather than broken.

### D-5 — LOW: residual ETH lock via plain transfers to `BatchTransactor`

`receive()` remains payable so VAnchor native refunds cannot revert a batch; ETH
sent by plain transfer (not via `executeBatch*`) has no refund path. Accepted;
callers are programmatic.

### D-6 — LOW: `BatchVerifier` (sp1-batch) is prototype-grade

Slither reports 0 findings, but by inspection: `publicAmountsHash`/`extDataHash` are
decoded and never validated, `commitments` is a flat set (not a Merkle tree, noted
"simplified" in the header), and there is no token accounting. Its own 9 tests pass
(`forge test` in `sp1-batch/contracts`). **Recommend excluding from the launch
surface or tracking hardening separately; `BatchTransactor` is the production path.**

### D-7 — LOW: `shieldedFundRLN` settlement address is user-supplied

Post-F-3 the EOA footgun is closed; a caller can still pass a malicious *contract*
as `rlnSettlement`, which can steal that caller's own withdrawal. Self-inflicted
only (atomic, caller-signed params). Consider an owner-registered settlement
allowlist if this becomes operator-driven.

## Test & coverage baseline

**`forge test`: 114 passed, 0 failed** (103 pre-existing + 11 added). All suites:

| Suite | Tests |
|---|---|
| RLNSettlement | 22 |
| ShieldedCredits | 32 |
| LayerZeroAnchorBridge (root + shielded) | 54 |
| ShieldedGateway (new) | 4 |
| BatchTransactor (new) | 2 |
| BatchVerifier (`sp1-batch/contracts`) | 9 |

**Contract sizes** (`forge build --sizes`, post-fix): BatchTransactor 2,140 B,
RLNSettlement 4,768 B, ShieldedCredits 4,926 B, ShieldedGateway 5,056 B — all far
under the 24,576 B limit.

**Coverage** (`forge coverage --ir-minimum`, post-fix, line / branch / function):

| Contract | Lines | Branches | Functions |
|---|---|---|---|
| RLNSettlement.sol | 89.9% (98/109) | 85.0% (102/120) | 100% (14/14) |
| ShieldedCredits.sol | 98.2% (109/111) | 85.5% (118/138) | 100% (12/12) |
| BatchTransactor.sol | 70.8% (17/24) | 72.0% (18/25) | 60% (3/5) |
| ShieldedGateway.sol | 18.5% (10/54) | 16.1% (10/62) | 27.3% (3/11) |
| LayerZeroAnchorBridge.sol (out of scope) | 100% (75/75) | 100% (79/79) | 100% (15/15) |

ShieldedGateway coverage was 0% before this branch (no test file existed); the new
suite covers admin paths. The shielded-spend paths need a MockVAnchor-driven harness
— recommended as follow-up for the manual-review track.

## Reproduction

```bash
forge soldeer update && ./scripts/setup-shielded-deps.sh
forge build --sizes
forge test                                    # 114 passed, 0 failed
forge coverage --ir-minimum --report summary
slither . --foundry-out-directory out
aderyn .
cd sp1-batch/contracts && forge test          # 9 passed (BatchVerifier)
```
