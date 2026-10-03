# Security Policy

## Reporting a Vulnerability

Report vulnerabilities privately to the maintainers at
[drew@tangle.tools](mailto:drew@tangle.tools), or via a GitHub Security
Advisory on this repository. Do not open public issues for unpatched
vulnerabilities.

## Launch Scope

The mainnet launch surface is the **Groth16/BN254 core loop**:

- `VAnchor` shielded pool (deposit / withdraw)
- `ShieldedGateway` (withdrawal → Tangle service lifecycle)
- `ShieldedCredits` (prepaid accounts, EIP-712 spend authorizations, claims, expiry refunds)

The **SP1 batch lane (`sp1-batch/`) is not in launch scope.** It is gated on
the upstream Plonky3 advisory
[GHSA-vj64-rjf3-w3v7](https://github.com/advisories/GHSA-vj64-rjf3-w3v7)
(`MultiField32Challenger` transcript malleability / challenge entropy loss).
This repo depends on `p3-challenger` only transitively through the SP1 SDK's
forked Plonky3 lineage (`p3-challenger 0.4.3-succinct` in
`sp1-batch/Cargo.lock`), so it cannot be fixed in-repo until SP1 upstream
releases a patched SDK. The batch lane ships only after that alert closes.

## Trusted Setup Status

Groth16 over BN254 requires a trusted setup
(`scripts/trusted-setup/ceremony.sh`):

- **Phase 1 (powers of tau):** the public Hermez `powersOfTau28_hez_final`
  ceremony (ppot_0080 lineage) — 1-of-N trust; safe if any one participant
  was honest.
- **Phase 2 (per-circuit):** currently a **1-of-1 developer contribution** —
  a single deterministic contribution plus a fixed beacon. This is a
  development setup only. **A multi-party computation (MPC) phase-2 ceremony
  with independent contributors is required before mainnet.** If the sole
  phase-2 contributor retains their toxic waste, they can forge proofs
  (e.g. withdraw from the shielded pool without a valid deposit).

## Audit Status

- VAnchor circuits: previously audited (see [`ROADMAP.md`](ROADMAP.md) for
  audit references).
- **An external audit of `ShieldedCredits` and `ShieldedGateway` is a
  pre-mainnet gate.** Do not deploy to mainnet before it completes.

Proving-key, benchmark, and circuit-size details are tracked in
[`docs/ZKP-BENCHMARKS.md`](docs/ZKP-BENCHMARKS.md).

## Known Trust-Model Limitation: Unverified Job Completion

`ShieldedCredits.claimPayment` does **not** verify job completion against
tnt-core's job lifecycle. An operator can claim payment for a spend
authorization without having fulfilled the corresponding work. This is an
intentional design decision (see the comment at
`src/shielded/ShieldedCredits.sol:179`): anonymous credits are primarily used
for off-chain services that never submit results on-chain, and the user's
EIP-712 signature over a named operator is the trust attestation.

Mitigations available to users:

- Payments not claimed before `expiry` are refundable to the user.
- `settlePayment` / `releasePayment` allow partial settlement and refund of
  unclaimed amounts.

**Integrators must surface this in their UX**: users authorizing a spend are
trusting the named operator to deliver, and the UI should make operator
identity and reputation legible before a signature is requested.
