# SP1 Batch Verifier

Batch verification for shielded pool transactions. One SP1 proof covers N transactions — ~270k gas total instead of N × 270k.

## How It Works

```
User 1: circom Groth16 proof (existing VAnchor circuit)
User 2: circom Groth16 proof (existing)
...
User N: circom Groth16 proof (existing)
         ↓
Sequencer: SP1 program verifies all N proofs
         ↓
One Groth16 wrapper proof (~270k gas)
         ↓
BatchVerifier.sol: processes all nullifiers + commitments
```

The existing circom circuits are untouched. Users generate proofs exactly as before. The SP1 program sits between users and the chain, batching their proofs into a single verification.

## Gas Savings

| Batch Size | Current Cost | Batched Cost | Per-User Cost | Savings |
|------------|-------------|-------------|---------------|---------|
| 1 | 270k | 270k | 270k | 0% |
| 10 | 2.7M | 270k | 27k | 90% |
| 50 | 13.5M | 270k | 5.4k | 98% |
| 100 | 27M | 270k | 2.7k | 99% |

## Structure

```
sp1-batch/
  program/          SP1 zkVM program (verifies N Groth16 proofs)
  contracts/        BatchVerifier.sol (on-chain, verifies one SP1 proof)
  script/           Batch sequencer (collects proofs, generates SP1 proof)
```

## Build

```bash
# Install SP1
curl -L https://sp1.succinct.xyz | bash
sp1up

# Build the SP1 program
cd program
cargo prove build

# Build the contract
cd ../contracts
forge build
```

## Usage

```bash
# Collect N user proofs into a batch
# Generate SP1 proof (local or via prover network)
cd script
PROVER_NETWORK_RPC=... cargo run -- --batch-dir /path/to/proofs

# Submit on-chain
cast send $BATCH_VERIFIER "processBatch(bytes,bytes)" $PROOF $PUBLIC_VALUES
```

## What Changes for Users

Nothing. Users generate the same circom Groth16 proofs as before. They submit proofs to a sequencer instead of directly to the chain. The sequencer batches them and submits one proof.

## What Changes for Operators

Operators can run the sequencer to batch user transactions. This reduces gas costs for their users and earns the operator a small fee per batched transaction.
