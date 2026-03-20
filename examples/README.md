# Examples

## Payment Modes

### Credit Mode (Prepaid Credits) -- `credit-mode.ts`

One ZK proof funds a pseudonymous credit account. Subsequent requests are authorized with cheap EIP-712 ECDSA signatures (~50k gas each). Requests within a session share a pseudonym; different sessions are cryptographically unlinkable.

**Best for:** Low-latency use cases where pseudonymous (rather than fully unlinkable) privacy is acceptable. Ideal for high-frequency inference where sub-100ms per-request latency matters.

- Per-request latency: <100ms (ECDSA signature only)
- Privacy: pseudonymous within session, unlinkable across sessions
- On-chain cost: ~50k gas per request

### RLN Mode (Per-Request Proofs) -- `rln-mode.ts`

Each request carries its own ZK proof, verified off-chain by the operator (~5ms). No two requests can be linked to each other or to the depositor. Settlement happens in batches with zero per-request on-chain transactions.

**Best for:** Sensitive workloads requiring full unlinkability (medical queries, legal analysis, investigative journalism). The 640ms proof generation is CPU-bound and parallelizable -- the SDK maintains a pre-generated proof pool so the user never blocks.

- Per-request latency: ~640ms (parallelizable to near-zero with proof pool)
- Privacy: full per-request unlinkability
- On-chain cost: 0 per request (batched settlement)

## Running

```bash
export RPC_URL=http://localhost:8545
export PRIVATE_KEY=0x...
export GATEWAY=0x...  POOL=0x...  CREDITS=0x...
export WRAPPED_TOKEN=0x...  OPERATOR=0x...  SETTLEMENT=0x...

npx tsx examples/credit-mode.ts
npx tsx examples/rln-mode.ts
```
