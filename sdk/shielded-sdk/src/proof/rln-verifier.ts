import * as snarkjs from 'snarkjs'
import { ethers } from 'ethers'

/// BN254 scalar field order
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/// Stored Shamir share for a nullifier
interface ShamirShare {
  x: bigint
  y: bigint
}

/// A verified payment pending on-chain settlement
interface PendingClaim {
  nullifier: bigint
  amount: bigint
}

/// Result of recording a Shamir share
export interface ShareResult {
  slashable: boolean
  identitySecret?: bigint
  x1?: bigint
  y1?: bigint
  x2?: bigint
  y2?: bigint
}

const RLN_SETTLEMENT_ABI = [
  'function batchClaim(address token, bytes32[] nullifiers, uint256[] amounts, address operator)',
  'function slash(bytes32 nullifier, uint256 x1, uint256 y1, uint256 x2, uint256 y2, bytes32 identityCommitment)',
  'function usedNullifiers(bytes32) view returns (bool)',
]

/// Off-chain RLN proof verifier for operators.
///
/// Operators run this to verify payment proofs before serving requests,
/// accumulate claims, and settle in batches on-chain.
export class RLNVerifier {
  private shares = new Map<string, ShamirShare>()
  private pendingClaims: PendingClaim[] = []
  private settlement: ethers.Contract

  constructor(
    private vkeyPath: string,
    settlementAddress: string,
    provider: ethers.Provider,
  ) {
    this.settlement = new ethers.Contract(
      settlementAddress,
      RLN_SETTLEMENT_ABI,
      provider,
    )
  }

  /// Verify an RLN payment proof against the verification key and on-chain Merkle root.
  async verifyPaymentProof(
    proof: snarkjs.Groth16Proof,
    publicSignals: string[],
    onChainRoot: bigint,
  ): Promise<boolean> {
    // publicSignals layout (RLN circuit):
    // [0] = y (share output)
    // [1] = merkleRoot
    // [2] = nullifierHash
    // [3] = x (share input / epoch)
    const merkleRoot = BigInt(publicSignals[1])
    if (merkleRoot !== onChainRoot) return false

    const { readFileSync } = await import('fs')
    const vKey = JSON.parse(readFileSync(this.vkeyPath, 'utf-8'))
    return snarkjs.groth16.verify(vKey, publicSignals, proof)
  }

  /// Check if a nullifier has already been used on-chain.
  async isNullifierFresh(nullifier: bigint): Promise<boolean> {
    const nullifierBytes = ethers.zeroPadValue(
      ethers.toBeHex(nullifier),
      32,
    )
    const used: boolean = await this.settlement.usedNullifiers(nullifierBytes)
    return !used
  }

  /// Record a Shamir share for a nullifier. If two shares exist for the same
  /// nullifier, the user double-signaled and can be slashed.
  recordShare(
    nullifier: bigint,
    x: bigint,
    y: bigint,
  ): ShareResult {
    const key = nullifier.toString()
    const existing = this.shares.get(key)

    if (!existing) {
      this.shares.set(key, { x, y })
      return { slashable: false }
    }

    // Same share — not a double-signal
    if (existing.x === x && existing.y === y) {
      return { slashable: false }
    }

    // Two distinct shares — recover identity secret
    const dx = ((x - existing.x) % FIELD_PRIME + FIELD_PRIME) % FIELD_PRIME
    const dy = ((y - existing.y) % FIELD_PRIME + FIELD_PRIME) % FIELD_PRIME
    const dxInv = modInverse(dx, FIELD_PRIME)
    const slope = (dy * dxInv) % FIELD_PRIME
    const secret =
      ((existing.y - existing.x * slope) % FIELD_PRIME + FIELD_PRIME) %
      FIELD_PRIME

    return {
      slashable: true,
      identitySecret: secret,
      x1: existing.x,
      y1: existing.y,
      x2: x,
      y2: y,
    }
  }

  /// Add a verified payment to the pending claims queue.
  addClaim(nullifier: bigint, amount: bigint): void {
    this.pendingClaims.push({ nullifier, amount })
  }

  /// Get all pending claims ready for on-chain settlement.
  getPendingClaims(): { nullifiers: bigint[]; amounts: bigint[] } {
    return {
      nullifiers: this.pendingClaims.map((c) => c.nullifier),
      amounts: this.pendingClaims.map((c) => c.amount),
    }
  }

  /// Settle all pending claims in a single on-chain batch transaction.
  async settleBatch(
    signer: ethers.Signer,
    token: string,
  ): Promise<ethers.TransactionReceipt | null> {
    if (this.pendingClaims.length === 0) return null

    const { nullifiers, amounts } = this.getPendingClaims()
    const operatorAddress = await signer.getAddress()

    const contract = this.settlement.connect(signer) as ethers.Contract
    const tx = await contract.batchClaim(
      token,
      nullifiers.map((n) => ethers.zeroPadValue(ethers.toBeHex(n), 32)),
      amounts,
      operatorAddress,
    )
    const receipt = await tx.wait()

    // Clear settled claims
    this.pendingClaims = []
    return receipt
  }
}

/// Modular multiplicative inverse using extended Euclidean algorithm
function modInverse(a: bigint, p: bigint): bigint {
  let [old_r, r] = [a % p, p]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }
  return ((old_s % p) + p) % p
}
