# Roadmap: Per-Request Unlinkability via RLN

## Current State (v1 — Shipped)

**Privacy model:** Pseudonymous within a credit session, unlinkable across sessions.

Each shielded withdrawal creates a new credit account with a fresh ephemeral key.
Within a session, multiple spend authorizations share the same commitment (linkable).
Across sessions, different commitments are cryptographically unlinkable.

**Cost:** One ZK proof per session (~640ms), one ECDSA signature per request (~50k gas on-chain).

## Target State (v2 — RLN-Based)

**Privacy model:** Full per-request unlinkability. Each API call is cryptographically
unlinked from every other call, even from the same user in the same session.

**Cost:** One ZK proof per request (~640ms client-side, ~5ms off-chain verification by operator). Zero on-chain transactions per request — settlement in batches.

## Why RLN?

[Rate-Limiting Nullifiers](https://rate-limiting-nullifier.github.io/rln-docs/) (PSE/Ethereum Foundation)
use Shamir's Secret Sharing to enforce rate limits without identity:

- Each request produces a unique nullifier: `H(secretKey, epoch)`
- Each request reveals one Shamir share of the secret key
- If a user exceeds the rate limit (reuses an epoch), enough shares are revealed
  to reconstruct the secret key → deposit slashed
- Single use within an epoch = perfect unlinkability

## Circuit Composition Strategy

### Audit Surface Analysis

| Circuit | Audit Status | Constraints |
|---------|-------------|-------------|
| VAnchor (commitment, nullifier, Merkle proof) | Veridise audit ✓ | ~38k |
| RLN (Shamir share, rate-limit nullifier) | yAcademy audit ✓ | ~5k |
| **Composition glue** | **Needs audit** | **~100 est.** |

The VAnchor and RLN circuits are both Groth16 over BN254 using Poseidon.
Composing them creates a new circuit that includes both as sub-circuits.
The sub-circuit constraints are **unchanged** — existing audit findings apply.

The new audit surface is only the glue:
1. Connect VAnchor's `commitment` output to RLN's identity input
2. Add solvency check: `(ticketIndex + 1) × maxCost ≤ deposit + refunds`
3. Bind the RLN epoch to a time window

Estimated new constraints: ~50-100. This is a **composition audit**, not a full re-audit.

### Composed Circuit

```
┌─────────────────────────────────────────────────────┐
│  VAnchor sub-circuit (audited)                      │
│  ● commitment = H(chainId, amount, pubKey, blinding)│
│  ● nullifier = H(commitment, path, signature)       │
│  ● Merkle membership proof                          │
│  ● Amount conservation                              │
└──────────────────────┬──────────────────────────────┘
                       │ commitment, amount
┌──────────────────────▼──────────────────────────────┐
│  Glue logic (NEW — needs audit)                     │
│  ● identityCommitment = H(commitment)               │
│  ● solvency: (epoch + 1) × maxCost ≤ amount + R    │
│  ● epoch binding to block range                     │
└──────────────────────┬──────────────────────────────┘
                       │ identityCommitment
┌──────────────────────▼──────────────────────────────┐
│  RLN sub-circuit (audited)                          │
│  ● rlnNullifier = H(identitySecret, epoch)          │
│  ● share = identitySecret + a × messageHash         │
│  ● Shamir share for double-spend detection          │
└─────────────────────────────────────────────────────┘
```

## Implementation Phases

### Phase 1: Research & Circuit Design (2 weeks)
- [ ] Fork PSE's [rln-circuits](https://github.com/Rate-Limiting-Nullifier/rln-circuits)
- [ ] Design the composed circuit (VAnchor + glue + RLN)
- [ ] Define epoch semantics (block range? time window? per-operator?)
- [ ] Prototype in circom, verify constraint count fits in existing ptau

### Phase 2: Off-Chain Verifier (2 weeks)
- [ ] Build operator-side proof verifier (snarkjs or native)
- [ ] Nullifier database (in-memory + persistent)
- [ ] Shamir share accumulator for double-spend detection
- [ ] Secret key recovery + slash transaction builder

### Phase 3: Refund Tickets (1 week)
- [ ] Server-signed refund tickets: `r = {value, signature}`
  - `value = maxCost - actualCost` (unused capacity)
- [ ] Client-side refund accumulation
- [ ] In-circuit verification of refund ticket signatures
- [ ] Solvency proof: `deposit + totalRefunds ≥ (nextEpoch + 1) × maxCost`

### Phase 4: Contract Updates (1 week)
- [ ] Replace ShieldedCredits with RLN-based verifier
- [ ] Add slashing: anyone can submit two shares from same epoch to recover key
- [ ] Add deposit/withdrawal with RLN identity commitment
- [ ] Batch settlement: operator periodically claims accumulated payments

### Phase 5: SDK & Integration (1 week)
- [ ] Client-side proof generation for RLN
- [ ] Refund ticket management
- [ ] Epoch tracking
- [ ] Update CLI and gateway client

### Phase 6: Composition Audit (external)
- [ ] Audit the ~100 lines of glue constraints
- [ ] Verify sub-circuit boundaries are correctly preserved
- [ ] Verify Shamir share recovery math
- [ ] Verify solvency check edge cases

## Backwards Compatibility

The v1 ShieldedCredits system continues to work alongside RLN.
Operators can support both:
- EIP-712 SpendAuth (v1, cheap, pseudonymous)
- RLN proof (v2, per-request unlinkability)

Users choose their privacy level per request.

## References

- [ZK API Usage Credits](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104) — Crapis & Buterin
- [RLN Circuits](https://github.com/Rate-Limiting-Nullifier/rln-circuits) — PSE
- [RLN Docs](https://rate-limiting-nullifier.github.io/rln-docs/) — Protocol spec
- [yAcademy RLN Audit](https://hackmd.io/q4MSuFhyQjetnJFoEy8tqw)
- [Webb Protocol](https://eprint.iacr.org/2023/260) — VAnchor construction
- [Veridise VAnchor Audit](https://github.com/tangle-network/protocol-solidity)
