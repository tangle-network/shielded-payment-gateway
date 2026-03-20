# RLN Payment Circuits

Composed circom 2.0 circuit that pairs Webb's VAnchor (shielded UTXO transfers) with Rate-Limiting Nullifiers (RLN) to enable per-request unlinkable payments with built-in rate limiting.

## Architecture

```
rln_payment_2_8.circom          (main instantiation)
  |
  +-- rln_payment.circom        (composition template)
        |
        +-- transaction.circom  (VAnchor: UTXO spend/create, merkle proofs, nullifiers)
        |
        +-- rln.circom          (RLN: epoch nullifier + Shamir share)
```

### VAnchor (existing, unmodified)

Handles shielded value transfer via JoinSplit:
- Verifies input UTXO ownership (private key + merkle proof against bridged roots)
- Creates output commitments (new UTXOs)
- Enforces amount invariant: `sumInputs + publicAmount == sumOutputs`

### RLN (new)

Produces per-epoch rate-limiting artifacts:
- `nullifier = Poseidon(identitySecret, externalNullifier)` -- linkable within an epoch, unlinkable across epochs
- `share_y = identitySecret + Poseidon(identitySecret, externalNullifier) * messageHash` -- degree-1 Shamir evaluation

Two shares from the same epoch (same `externalNullifier`, different `messageHash`) allow recovery of `identitySecret` via interpolation. This is the slashing condition: the on-chain verifier can slash the user's stake if two valid proofs with the same `rlnNullifier` but different shares appear.

### Glue logic (~50 constraints)

Three binding constraints connect VAnchor and RLN:

1. **Identity commitment**: `identityCommitment = Poseidon(identitySecret)` -- proves knowledge of the RLN identity preimage without revealing it. The commitment is registered on-chain during user signup.

2. **Solvency**: `(epochIndex + 1) * maxCost <= deposit + totalRefunds` -- proves the user's shielded balance can cover worst-case spend through the current epoch. Range checks on `maxCost` (128-bit), `totalRefunds` (128-bit), and `epochIndex` (64-bit) prevent underflow/overflow.

3. **RLN wiring**: `identitySecret` feeds into the RLN sub-circuit; `externalNullifier = Poseidon(epoch, chainID)` scopes rate limits per chain; `messageHash = extDataHash` binds the Shamir share to the specific transaction.

## Public inputs

| Signal | Source |
|---|---|
| `publicAmount` | VAnchor -- external deposit/withdrawal amount |
| `extDataHash` | VAnchor -- hash of external data (recipient, relayer, fee) |
| `inputNullifier[nIns]` | VAnchor -- spent UTXO nullifiers |
| `outputCommitment[nOuts]` | VAnchor -- new UTXO commitments |
| `chainID` | VAnchor -- destination chain |
| `roots[length]` | VAnchor -- bridged merkle roots |
| `rlnNullifier` | RLN -- per-epoch nullifier |
| `share_x` | RLN -- Shamir evaluation point |
| `share_y` | RLN -- Shamir evaluation result |
| `epoch` | RLN -- epoch identifier |

## Instantiation

`main/rln_payment_2_8.circom` instantiates with:
- 2 inputs, 2 outputs (standard JoinSplit)
- 8 edges (bridge roots from up to 8 chains)
- Merkle depth 30
- Standard VAnchor zero leaf

## Slashing flow

1. User submits proof with `(rlnNullifier, share_x_1, share_y_1)` for request 1.
2. User submits proof with `(rlnNullifier, share_x_2, share_y_2)` for request 2 (same epoch).
3. Anyone computes: `identitySecret = (share_y_2 - share_y_1) / (share_x_2 - share_x_1)` (in the field).
4. Contract verifies `Poseidon(identitySecret) == registeredCommitment`, slashes stake.

## Build

```bash
# Requires circom 2.x and circomlib in node_modules
circom main/rln_payment_2_8.circom --r1cs --wasm --sym -o build/
```
