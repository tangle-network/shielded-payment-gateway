import * as snarkjs from 'snarkjs'
import type { CircuitArtifacts, Groth16Proof } from './prover.js'

/// UTXO representing the user's deposited balance in the Merkle tree
export interface RLNUTXO {
  identitySecret: bigint
  /// Leaf index in the identity commitment Merkle tree
  leafIndex: number
}

/// Merkle proof for inclusion in the identity tree
export interface MerkleProof {
  root: bigint
  pathElements: bigint[]
  pathIndices: number[]
}

/// RLN circuit witness inputs
export interface RLNWitnessInput {
  identitySecret: string
  pathElements: string[]
  identityPathIndex: number[]
  x: string // epoch (external nullifier)
  epoch: string
  rlnIdentifier: string
}

/// Generated RLN payment proof with public signals
export interface RLNPaymentProof {
  proof: snarkjs.Groth16Proof
  publicSignals: string[]
  nullifier: bigint
  epoch: bigint
}

/// BN254 scalar field order
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/// Generate an RLN payment proof for a single epoch.
///
/// The proof attests that:
///   1. The user knows identitySecret such that Hash(identitySecret) is in the tree
///   2. The nullifier is deterministically derived from (identitySecret, epoch)
///   3. The Shamir share (x, y) is correctly computed: y = identitySecret + hash(message) * x
///
/// @param utxo        The user's identity UTXO
/// @param tree        Merkle proof of inclusion
/// @param epoch       Current epoch identifier (e.g., block number or timestamp bucket)
/// @param rlnIdentifier  Application-specific identifier (prevents cross-app replay)
/// @param message     The message being rate-limited (e.g., hash of payment request)
/// @param artifacts   Circuit WASM and zkey paths
export async function generatePaymentProof(
  utxo: RLNUTXO,
  tree: MerkleProof,
  epoch: bigint,
  rlnIdentifier: bigint,
  message: bigint,
  artifacts: CircuitArtifacts,
): Promise<RLNPaymentProof> {
  // x-coordinate for Shamir share: hash of (epoch, rlnIdentifier, message)
  const x = poseidonHash([epoch, rlnIdentifier, message])

  // Compute nullifier: hash(identitySecret, epoch, rlnIdentifier)
  const nullifier = poseidonHash([utxo.identitySecret, epoch, rlnIdentifier])

  const witnessInput: RLNWitnessInput = {
    identitySecret: utxo.identitySecret.toString(),
    pathElements: tree.pathElements.map(String),
    identityPathIndex: tree.pathIndices,
    x: x.toString(),
    epoch: epoch.toString(),
    rlnIdentifier: rlnIdentifier.toString(),
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witnessInput as unknown as snarkjs.CircuitSignals,
    artifacts.wasmPath,
    artifacts.zkeyPath,
  )

  return {
    proof,
    publicSignals,
    nullifier,
    epoch,
  }
}

/// Placeholder Poseidon hash — in production, use circomlibjs poseidon.
/// This computes keccak256 mod FIELD_PRIME as a stand-in.
function poseidonHash(inputs: bigint[]): bigint {
  // In production, replace with circomlibjs.poseidon(inputs)
  // Using keccak256 as a deterministic placeholder
  const { keccak256, AbiCoder } = require('ethers') as typeof import('ethers')
  const encoded = AbiCoder.defaultAbiCoder().encode(
    inputs.map(() => 'uint256'),
    inputs,
  )
  const hash = BigInt(keccak256(encoded))
  return hash % FIELD_PRIME
}
