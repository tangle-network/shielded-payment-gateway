# Manual Adversarial Review — Shielded Payments Stack

- **Date:** 2026-10-02
- **Branch:** `audit/manual-review` (worktree `spg-audit-manual`, base `origin/main` @ c63ebf6)
- **Scope:** `ShieldedCredits.sol`, `ShieldedGateway.sol`, `RLNSettlement.sol`, `BatchTransactor.sol`
- **Method:** manual logic review (no tool-output duplication — slither/aderyn covered by a sibling pass), against `README.md`, `ROADMAP.md`, the in-repo circuits, and the 2026-05-15 audit signal notes.
- **Test state:** `forge test` — **114 passed / 0 failed** (baseline on branch point was 103; +11 from this audit's new tests). SDK `vitest run --exclude 'test/proof*.test.ts'` — **44 passed / 25 skipped** (anvil e2e suites self-skip without ceremony artifacts, same as CI).

Severity legend: **Critical** = direct loss of user funds, permissionless. **High** = loss of funds under a privileged-key compromise or broken core invariant. **Medium** = loss/DoS requiring specific conditions or a trusted-party failure mode. **Low** = limited-impact correctness/robustness. **Info** = notes, verified-non-issues.

---

## CRITICAL

### C-1. RLNSettlement.slash — missing secret↔commitment binding: permissionless theft of any RLN deposit — **FIXED**

`src/shielded/RLNSettlement.sol:214` (`slash`), pre-fix lines 236–246.

The Shamir interpolation recovered an `identitySecret` from the two shares, but the contract **never verified the recovered secret against the target `identityCommitment`**. The code comment even documented the omission ("we can't compute Poseidon on-chain cheaply… For now: the caller provides both the shares AND the identityCommitment"). The only guard was that the commitment had a nonzero balance. The interface spec (`IRLNSettlement.sol:57`) states slash "verifies keccak256(secret) == commitment" — the implementation simply didn't.

**Exploit sketch (pre-fix):**
1. Victim deposits 1000 USDC under `identityCommitment` (any value).
2. Attacker calls `slash(_, x1=1, y1=<random>, x2=2, y2=<random>, victimCommitment)`. `x1 != x2` passes; interpolation succeeds on any input; balance is locked into a `PendingSlash` with `slasher = attacker`.
3. After `SLASH_DELAY` (1 day), attacker calls `finalizeSlash` and receives the full deposit. No shares, no proof, no RLN involvement needed. Every funded deposit in the contract was stealable by anyone.

**Fix (this branch):** `RLNSettlement.sol:244` now enforces `keccak256(abi.encodePacked(secret)) == identityCommitment`, reverting `InvalidSlash` otherwise — matching the interface spec and the existing test-suite commitment scheme. With the binding, slashing requires knowledge of the secret, which per RLN is only revealed by a double-signal. Regression tests added: `test_slash_fabricatedShares_reverts`, `test_slash_otherIdentitySecret_reverts` in `test/RLNSettlement.t.sol`; all pre-existing slash tests still pass.

**Residual:** see M-2 — the on-chain scheme (keccak) and the circuit scheme (Poseidon) must be unified.

---

### C-2. ShieldedGateway — ZK proof does not bind destination params: mempool front-running steals the withdrawal — **FIXED**

`src/shielded/ShieldedGateway.sol:154` (`shieldedFundCredits`), also `:91`, `:119`, `:130`; `_executeShieldedWithdrawal` at `:181`.

The VAnchor proof binds only `extData` (via `extDataHash`): `recipient`, `extAmount`, `relayer`, `fee`, `refund`, `token` (`dependencies/protocol-solidity/.../structs/PublicInputs.sol`). The gateway enforced `recipient == address(this)`, but the **destination of the forwarded funds** — `commitment`/`spendingKey` (fundCredits), `serviceId` (fundService), the full `ServiceRequestParams` (requestService), `identityCommitment` (fundRLN) — is plain calldata, unbound by the proof.

**Exploit sketch (pre-fix):**
1. Victim broadcasts `shieldedFundCredits(proof, victimCommitment, victimSpendingKey)` with a valid proof over extData `(recipient=gateway, extAmount=-1000 USDC, relayer=0, …)`.
2. Attacker copies the calldata verbatim, swaps only `commitment`/`spendingKey` for their own, and front-runs. The proof still verifies (nothing in it references the credits account). VAnchor marks the victim's nullifiers spent and pays the gateway; the gateway funds the **attacker's** credit account.
3. Victim's transaction reverts (nullifier already spent). Funds are gone and the victim's UTXO is burned — theft plus griefing in one tx. Same shape for `shieldedFundService` (attacker substitutes their own `serviceId`), `shieldedRequestService` (attacker's operators/blueprint), and `shieldedFundRLN` (attacker's identity).

**Fix (this branch):** `ShieldedGateway.sol:206` enforces `extData.relayer == msg.sender` (`InvalidRelayer`). `relayer` is the only proof-bound submitter identity, so a front-runner cannot reuse the proof — changing relayer invalidates `extDataHash`, and keeping it fails the check. Consequences, documented in the contract threat-model header:
- Self-submission from an ephemeral key (already the recommended pattern) is now fully front-run-safe.
- A user who names a third-party relayer delegates submission to it; that relayer can still redirect destination params — standard Webb relayer trust, now explicit.
- `relayer = address(0)` proofs can no longer transit the gateway (breaking change for existing integrations; SDK updated accordingly).

Files updated for the breaking change: `sdk/shielded-sdk/src/contract/gateway-client.ts` (`buildShieldedWithdrawal` takes `relayer`, `fundCredits` passes the signer address), `sdk/shielded-sdk/test/anvil-e2e.test.ts`, `sdk/shielded-sdk/test/anvil-e2e-real.test.ts` (both name the submitting signer as relayer). SDK type-check (`tsc --noEmit`) and the non-proof vitest suite pass.

Tests added (`test/shielded/ShieldedGateway.t.sol` — the gateway previously had **zero** forge coverage): happy path, relayer-mismatch revert, full front-run scenario (attacker's redirected tx reverts and does **not** burn the victim's nullifiers; victim's tx then succeeds), zero-relayer revert, plus regression tests for recipient/extAmount/pool checks.

**Long-term recommendation (not implemented):** bind a destination digest (e.g. `keccak256(commitment, spendingKey, target, calldataHash)`) into the circuit public inputs / extData so destination selection is proof-enforced rather than relayer-trusted. Requires a circuit change; out of scope for a launch-gates branch.

---

## HIGH

### H-1. RLNSettlement.batchClaim — unbounded amounts, arbitrary payout address, no deposit accounting — **documented, not fixed**

`src/shielded/RLNSettlement.sol:173-203`.

Three compounding issues:
1. `amounts[]` are caller-supplied and capped by nothing — the nullifier set only enforces *uniqueness*, never *value*. The contract transfers `sum(amounts)` of the token from its own balance.
2. The payout goes to the `operator` **parameter**, an arbitrary address chosen by the caller, not to `msg.sender`.
3. Claims never debit `deposits[identityCommitment]`. The docstring claims the contract enforces "deposit accounting per identity commitment" — it does not. Even with perfectly honest operators, users can `withdraw` their full deposit *after* the operator has claimed the corresponding payments, driving the contract insolvent.

**Exploit sketch:** any one authorized-operator key (compromised, or a malicious operator the owner registered — note `registerOperator` is a single `owner` EOA with no timelock) calls `batchClaim(token, [freshRandomNullifier], [contractBalance], attacker)` once and drains the entire token balance of the contract. No proof, no per-nullifier value check.

The trust model comment ("operators verify ZK proofs off-chain, backed by tnt-core staking") means operator trust is *intended* — but the contract as written gives a single operator key unlimited, one-transaction drainage with no on-chain accounting trail, and the claimed "deposit accounting" enforcement is absent.

**Recommendation (needs a protocol decision, hence documented):**
- Track `totalDeposited[token]` / `totalClaimed[token]` and enforce `totalClaimed + batchTotal ≤ totalDeposited − totalWithdrawn` (solvency floor), or fully debit per-commitment balances if nullifier→commitment linkage is ever provided.
- Pay `msg.sender`, not an arbitrary `operator` parameter.
- Put `registerOperator`/`removeOperator` behind a timelock or multisig before mainnet.
Until then, RLN mode should be treated as an honest-operator custodial ledger and that must be loud in docs/UX.

---

## MEDIUM

### M-1. claimPayment does not verify job completion (known hole) — exploitability assessment + recommendation

`src/shielded/ShieldedCredits.sol:186-208`, rationale at `:194-205`.

**Assessment.** The hole is real but bounded:
- The SpendAuth binds `operator`, `amount`, `serviceId`, `jobIndex`, `nonce`, `expiry` under the user's EIP-712 signature. Only the named operator can claim, only up to the authorized amount, only before expiry.
- A malicious (or lazy) operator can claim 100% of an authorization while delivering nothing. The user's funds are locked from `authorizeSpend` until `expiry`; **the user has no on-chain recourse or dispute path**, and anonymity means there is no on-chain identity to slash — recourse is purely off-chain (tnt-core operator stake/reputation, if the operator is a tnt-core operator at all).
- Blast radius per incident = one authorization amount. A user who signs large, long-lived auths for an untrusted operator is fully exposed. A user who signs small per-request auths with short expiries (which the protocol already supports) caps exposure at one request's payment.

So: not a protocol-draining bug, but a deliberate trust delegation that currently fails *silently* for users. **Medium.**

**Precise recommendation:**
1. *Immediate (docs/UX, no code):* surface loudly that signing a SpendAuth prepays the named operator with no completion guarantee; default clients to per-request amounts and short expiries (minutes, not days).
2. *Near-term (small, well-defined contract addition):* add a spendingKey-signed `revokeSpendAuth(authHash, signature)` that, before claim and before expiry, marks the spend claimed and refunds the account (reusing `_refundPending`). This restores user recourse for non-delivery without any tnt-core coupling — the same key that authorized can revoke. Note the trade-off to spec first: a revoking user can also claw back *after* being served if the operator delays claiming, so operators must claim promptly (they already should).
3. *Mid-term (optional enforcement):* an opt-in per-service completion hook (e.g. operator presents a tnt-core job-completion attestation, or a user-signed receipt `JobReceipt(commitment, authHash)`) so services that want on-chain enforcement can require it, without breaking the composability the code comment defends.

### M-2. RLN identity-commitment scheme mismatch: circuit (Poseidon) vs settlement (keccak)

`circuits/rln-payment/rln_payment.circom:20` pins `identityCommitment = Poseidon(identitySecret)`; `IRLNSettlement.sol:40,57,84`, the tests, and now the C-1 fix use `keccak256(identitySecret)`.

Consequence: deposits made under circuit-derived (Poseidon) commitments can never be slashed under the keccak binding — not even legitimately after a real double-signal — because the recovered secret will never keccak-match a Poseidon commitment. Slashing is enforceable only for keccak-scheme depositors. The deposit mapping is scheme-agnostic, so both populations can coexist silently.

**Recommendation:** pick one scheme. Cheapest sound path: verify with the on-chain PoseidonT2 library already deployed for VAnchor (`dependencies/protocol-solidity/.../hashers/Poseidon.sol`) so settlement matches the circuit; or explicitly spec the settlement layer as keccak-based and change the circuit glue comment/operator tooling to match. Until unified, RLN slashing must be considered non-functional for circuit-native identities.

### M-3. fundCredits first-funder binding: commitment DoS via front-run

`src/shielded/ShieldedCredits.sol:96-131`. The first funder of a fresh commitment permanently binds `token` and `spendingKey`. Anyone can call `fundCredits` directly (by design, "direct funder"), so an observer can front-run a victim's funding with 1 wei of an arbitrary token — or with the *attacker's* spendingKey — permanently squatting the commitment. The victim's gateway transaction reverts atomically (VAnchor nullifiers are *not* burned, no funds lost), but the commitment is unusable and the victim must rotate. Costless to attempt, annoying at scale.

**Recommendation:** document and accept for launch (recovery = new commitment, no fund loss). If direct funding is not a launch feature, gate `fundCredits` to the gateway or require the first funding to include a spendingKey signature over `(commitment, token)`.

---

## LOW

### L-1. BatchTransactor.executeBatch — SP1 public values not bound to the batch
`src/shielded/BatchTransactor.sol:75-86`. `sp1Public` is caller-supplied and never checked against `txs`, so the SP1 pre-validation attests to *some* batch, not *this* one. No funds at risk (VAnchor re-verifies every Groth16 proof and owns all state), but the gas-saving invariant is illusory, and `executeBatchDirect` (`:89`) makes the SP1 step optional anyway. **Fix:** require `sp1Public` to commit to `keccak256(abi.encode(txs))` (and chain id) and enforce it on-chain.

### L-2. BatchTransactor — ETH sent with a batch is locked
`src/shielded/BatchTransactor.sol:75-91,122`. Both entry points are `payable`, but `_executeTxs` calls `IVAnchor.transact` without `value`, and there is no sweep function — any ETH sent is locked forever; native-asset pools are unusable through the batcher. **Fix:** forward per-tx value or add an owner sweep / refund-excess.

### L-3. ShieldedCredits — fee-on-transfer tokens over-credited accounts — **FIXED**
`src/shielded/ShieldedCredits.sol:96`. Pre-fix, `acct.balance += amount` credited the nominal amount even when an FoT token delivered less, overstating accounts and leaving the contract insolvent for the last withdrawers. Fixed with balance-delta accounting (`:122-131`); test `test_fundCredits_feeOnTransfer_creditsReceivedAmount` (`test/MockFeeOnTransferToken.sol`) asserts accounting == token balance. Note: rebasing tokens remain unsupported — worth one line in docs.

### L-4. RLN slash does not consume the nullifier / operator can still claim a slashed payment
`src/shielded/RLNSettlement.sol:214`. The `nullifier` parameter is ignored (underscore-named). After a deposit is slashed, the operator can still `batchClaim` the double-signaled nullifiers — arguably fine (service was rendered), but then the double-signaler pays *twice* (deposit slashed + claim honored) with the extra value coming from other depositors (see H-1). At minimum, record the slashed nullifier in `usedNullifiers` and document the intended semantics.

### L-5. RLN policy stake is withdrawable on demand — burn is front-runnable
`src/shielded/RLNSettlement.sol:283-313`. `withdraw` drains `policyStake` first, with no timelock, so a spammer can withdraw their policy stake the moment an operator calls `burnPolicyStake` (or just before), making the "burnable stake" deterrent mostly illusory. **Fix:** timelock policy-stake withdrawals or give operator burns priority via a pending-withdrawal queue.

---

## INFO

### I-1. EIP-712 SpendAuth review — verified sound (a)
`SPEND_TYPEHASH` covers commitment, serviceId, jobIndex, amount, operator, nonce, expiry; the domain separator binds name/version/chainId/verifyingContract (`ShieldedCredits.sol:79-89`). Strict nonce ordering (`:139,162`) prevents replay; expiry enforced at authorize and claim; OpenZeppelin `ECDSA.recover` rejects high-s malleable signatures, and `authHash` excludes the signature so malleability is irrelevant regardless. The shared nonce sequence between `authorizeSpend` and `withdrawCredits` prevents cross-path replay. One standard note: the domain separator is frozen in the constructor, so a chain hardfork that changes `chainId` would allow cross-fork replay of live signatures — accepted industry-wide, noted for completeness.

### I-2. reclaimExpiredAuth commitment binding (recent fix) — verified complete
`_pendingCommitments` is written at `authorizeSpend` (`:176`) and read on every refund path (`releasePayment:231`, `_settlePayment:324`, `reclaimExpiredAuth:283`); all paths fail closed (`CommitmentNotBound`) for legacy unbound rows rather than letting the caller pick the refund account. The caller-supplied `commitment` in `reclaimExpiredAuth` is checked against the stored binding (`:287`). No gaps found.

### I-3. settle/release/claim accounting — verified correct (b)
Partial-settle arithmetic: `_settlePayment` caps `amount ≤ spend.amount`, refunds the difference to the bound commitment, and nets `totalSpent` correctly (`:318-333`). The `claimed` flag makes all four settlement paths (`claimPayment`, `settlePayment`, `releasePayment`, `reclaimExpiredAuth`) mutually exclusive — double-claim reverts rather than double-pays. Expiry boundary is consistent: operator can claim at `t == expiry` (`>` check), user can reclaim only at `t > expiry` (`<=` check) — no window where both succeed. Rounding: no division anywhere in ShieldedCredits; no fee math; amounts pass through in token-native decimals (no decimals assumptions). `totalSpent` decrements on refunds make it a *net* lifetime-spend counter (cosmetic note from the May signal stands).

### I-4. Reentrancy / CEI — verified
All external-facing mutators are `nonReentrant`; state is updated before token transfers (`withdrawCredits`, `_settlePayment`); the gateway's post-transact balance check tolerates over-delivery but not under-delivery. ERC20 wrapper callbacks cannot re-enter meaningfully. `SafeERC20.forceApprove` usage is correct per-call.

### I-5. Gateway ETH handling
ETH sent alongside ERC20-pool withdrawals (or VAnchor native refunds) sits in the gateway until `rescueETH` (owner-only). Acceptable; ensure ops knows refunds land there.

### I-6. Test-coverage note
Pre-branch, `ShieldedGateway` had no forge coverage at all (SDK anvil tests only, and those self-skip without ceremony artifacts). This branch adds `test/shielded/ShieldedGateway.t.sol` (8 tests). The May signal's "close the gateway integration-test gap" action item remains open for the real-proof path — the e2e-real suite needs ceremony artifacts in CI.

---

## Fix summary (this branch)

| Finding | Fix | Tests |
|---|---|---|
| C-1 slash binding | `RLNSettlement.sol:244` keccak256(secret) == commitment | +2 revert tests, existing slash tests green |
| C-2 gateway front-run | `ShieldedGateway.sol:206` relayer == msg.sender; `IShieldedGateway.InvalidRelayer`; SDK client + anvil tests updated | +8 new gateway forge tests incl. front-run scenario |
| L-3 FoT accounting | `ShieldedCredits.sol:122-131` balance-delta crediting | +1 FoT test with new mock |
| H-1, M-1–M-3, L-1, L-2, L-4, L-5 | documented above (need protocol/design decisions) | — |

`forge test`: **114 passed, 0 failed**. SDK `tsc --noEmit` clean; `vitest run --exclude 'test/proof*.test.ts'`: 44 passed, 25 skipped (artifact-gated suites skip as in CI).
