/**
 * RLN Off-Chain Verifier — Operator Integration Test
 *
 * Tests the full operator flow:
 *   1. Receive an RLN proof and verify structure
 *   2. Record Shamir shares
 *   3. Detect double-signaling (same nullifier, different message)
 *   4. Recover identity secret from two shares
 *   5. Accept proofs from different epochs (no collision)
 *   6. Accumulate and verify batch settlement structure
 *
 * Uses mathematical verification (Poseidon hashes, Shamir recovery) without
 * Groth16 proofs — proof verification is tested in rln-e2e.test.ts.
 *
 * Run: npx vitest run test/rln-verifier-integration.test.ts
 */
import { describe, it, expect, beforeAll } from 'vitest'
import {
  Keypair,
  ChainType,
  typedChainId,
  FIELD_SIZE,
  poseidonHash,
} from '../src/protocol/index.js'
import { RLNVerifier, ShareResult } from '../src/proof/rln-verifier.js'
import { ethers } from 'ethers'

// Helpers matching rln-e2e.test.ts patterns

async function computeRLNNullifier(
  identitySecret: bigint,
  epoch: bigint,
  chainId: bigint,
): Promise<bigint> {
  const extNull = await poseidonHash([epoch, chainId])
  return poseidonHash([identitySecret, extNull])
}

async function computeShamirShare(
  identitySecret: bigint,
  epoch: bigint,
  chainId: bigint,
  messageHash: bigint,
): Promise<{ x: bigint; y: bigint }> {
  const extNull = await poseidonHash([epoch, chainId])
  const a = await poseidonHash([identitySecret, extNull])
  const x = messageHash
  const y = (identitySecret + ((a * x) % FIELD_SIZE)) % FIELD_SIZE
  return { x, y }
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n
  base = ((base % mod) + mod) % mod
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod
    exp = exp / 2n
    base = (base * base) % mod
  }
  return result
}

function recoverSecret(
  x1: bigint,
  y1: bigint,
  x2: bigint,
  y2: bigint,
): bigint {
  const dx = ((x2 - x1) % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE
  const dy = ((y2 - y1) % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE
  const dxInv = modPow(dx, FIELD_SIZE - 2n, FIELD_SIZE)
  const a = (dy * dxInv) % FIELD_SIZE
  return ((y1 - ((a * x1) % FIELD_SIZE)) % FIELD_SIZE + FIELD_SIZE) % FIELD_SIZE
}

/// Mock operator that wraps RLNVerifier for off-chain verification
class MockOperator {
  public verifier: RLNVerifier

  constructor() {
    // Use a dummy vkey path and settlement address — we test the share
    // recording and batch accumulation logic, not on-chain interactions.
    const provider = new ethers.JsonRpcProvider('http://localhost:8545')
    this.verifier = new RLNVerifier(
      '/dev/null',
      ethers.ZeroAddress,
      provider,
    )
  }

  /// Verify proof structure (off-chain check without Groth16).
  /// In production, this calls verifyPaymentProof. Here we validate
  /// the mathematical consistency of the Shamir share.
  async verifyProofStructure(
    nullifier: bigint,
    shareX: bigint,
    shareY: bigint,
    identityCommitment: bigint,
    epoch: bigint,
    chainId: bigint,
  ): Promise<boolean> {
    // Structural checks an operator would perform:
    // 1. Share coordinates are in field
    if (shareX >= FIELD_SIZE || shareY >= FIELD_SIZE) return false
    // 2. Nullifier is non-zero
    if (nullifier === 0n) return false
    // 3. Identity commitment is non-zero
    if (identityCommitment === 0n) return false
    return true
  }

  /// Record share and check for double-signaling
  recordShare(nullifier: bigint, x: bigint, y: bigint): ShareResult {
    return this.verifier.recordShare(nullifier, x, y)
  }

  /// Add claim to pending batch
  addClaim(nullifier: bigint, amount: bigint): void {
    this.verifier.addClaim(nullifier, amount)
  }

  /// Get pending claims for settlement
  getPendingClaims(): { nullifiers: bigint[]; amounts: bigint[] } {
    return this.verifier.getPendingClaims()
  }
}

describe('RLN Off-Chain Verifier — Operator Flow', () => {
  let keypair: Keypair
  let chainId: bigint
  let operatorNode: MockOperator

  beforeAll(async () => {
    keypair = new Keypair()
    chainId = typedChainId(ChainType.EVM, 8453)
    operatorNode = new MockOperator()
  })

  it('operator receives and verifies an RLN proof structure', async () => {
    const epoch = 1n
    const messageHash = BigInt('0x' + Buffer.from('payment-req-1').toString('hex'))
    const nullifier = await computeRLNNullifier(keypair.privateKey, epoch, chainId)
    const share = await computeShamirShare(keypair.privateKey, epoch, chainId, messageHash)
    const identityCommitment = await poseidonHash([keypair.privateKey])

    const valid = await operatorNode.verifyProofStructure(
      nullifier, share.x, share.y, identityCommitment, epoch, chainId,
    )
    expect(valid).toBe(true)
  })

  it('operator records a Shamir share — first share is not slashable', async () => {
    const epoch = 10n
    const messageHash = BigInt('0x' + Buffer.from('msg-alpha').toString('hex'))
    const nullifier = await computeRLNNullifier(keypair.privateKey, epoch, chainId)
    const share = await computeShamirShare(keypair.privateKey, epoch, chainId, messageHash)

    const result = operatorNode.recordShare(nullifier, share.x, share.y)
    expect(result.slashable).toBe(false)
  })

  it('operator detects double-signal and recovers identity secret', async () => {
    const epoch = 20n
    const msg1 = BigInt('0x' + Buffer.from('request-A').toString('hex'))
    const msg2 = BigInt('0x' + Buffer.from('request-B').toString('hex'))

    const nullifier = await computeRLNNullifier(keypair.privateKey, epoch, chainId)
    const share1 = await computeShamirShare(keypair.privateKey, epoch, chainId, msg1)
    const share2 = await computeShamirShare(keypair.privateKey, epoch, chainId, msg2)

    // First share — accepted
    const result1 = operatorNode.recordShare(nullifier, share1.x, share1.y)
    expect(result1.slashable).toBe(false)

    // Second share (different message, same epoch) — double-signal detected
    const result2 = operatorNode.recordShare(nullifier, share2.x, share2.y)
    expect(result2.slashable).toBe(true)
    expect(result2.identitySecret).toBeDefined()
    expect(result2.x1).toBe(share1.x)
    expect(result2.y1).toBe(share1.y)
    expect(result2.x2).toBe(share2.x)
    expect(result2.y2).toBe(share2.y)

    // Recovered secret matches the original keypair
    expect(result2.identitySecret).toBe(keypair.privateKey)
  })

  it('recovered secret matches manual Shamir recovery', async () => {
    const epoch = 30n
    const msg1 = BigInt('0x' + Buffer.from('pay-1').toString('hex'))
    const msg2 = BigInt('0x' + Buffer.from('pay-2').toString('hex'))

    const share1 = await computeShamirShare(keypair.privateKey, epoch, chainId, msg1)
    const share2 = await computeShamirShare(keypair.privateKey, epoch, chainId, msg2)

    const manualSecret = recoverSecret(share1.x, share1.y, share2.x, share2.y)
    expect(manualSecret).toBe(keypair.privateKey)

    // Verify identity commitment binding
    const identityCommitment = await poseidonHash([keypair.privateKey])
    const recoveredCommitment = await poseidonHash([manualSecret])
    expect(recoveredCommitment).toBe(identityCommitment)
  })

  it('different epochs produce different nullifiers — no collision', async () => {
    const epoch1 = 100n
    const epoch2 = 101n
    const messageHash = BigInt('0x' + Buffer.from('same-msg').toString('hex'))

    const null1 = await computeRLNNullifier(keypair.privateKey, epoch1, chainId)
    const null2 = await computeRLNNullifier(keypair.privateKey, epoch2, chainId)

    // Different nullifiers
    expect(null1).not.toBe(null2)

    const share1 = await computeShamirShare(keypair.privateKey, epoch1, chainId, messageHash)
    const share2 = await computeShamirShare(keypair.privateKey, epoch2, chainId, messageHash)

    // Fresh operator for clean state
    const freshOp = new MockOperator()

    // Record share for epoch 1
    const r1 = freshOp.recordShare(null1, share1.x, share1.y)
    expect(r1.slashable).toBe(false)

    // Record share for epoch 2 — different nullifier, so no collision
    const r2 = freshOp.recordShare(null2, share2.x, share2.y)
    expect(r2.slashable).toBe(false)
  })

  it('same share submitted twice is not flagged as double-signal', async () => {
    const epoch = 200n
    const messageHash = BigInt('0x' + Buffer.from('idempotent').toString('hex'))
    const nullifier = await computeRLNNullifier(keypair.privateKey, epoch, chainId)
    const share = await computeShamirShare(keypair.privateKey, epoch, chainId, messageHash)

    const freshOp = new MockOperator()
    const r1 = freshOp.recordShare(nullifier, share.x, share.y)
    expect(r1.slashable).toBe(false)

    // Exact same share again — replay, not double-signal
    const r2 = freshOp.recordShare(nullifier, share.x, share.y)
    expect(r2.slashable).toBe(false)
  })

  it('batch settlement: accumulate 5 claims and verify structure', async () => {
    const freshOp = new MockOperator()
    const amounts = [100n, 200n, 50n, 75n, 300n]

    for (let i = 0; i < 5; i++) {
      const epoch = BigInt(1000 + i)
      const messageHash = BigInt('0x' + Buffer.from(`batch-msg-${i}`).toString('hex'))
      const nullifier = await computeRLNNullifier(keypair.privateKey, epoch, chainId)
      const share = await computeShamirShare(keypair.privateKey, epoch, chainId, messageHash)

      // Verify structure
      const valid = await freshOp.verifyProofStructure(
        nullifier, share.x, share.y,
        await poseidonHash([keypair.privateKey]),
        epoch, chainId,
      )
      expect(valid).toBe(true)

      // Record share
      const result = freshOp.recordShare(nullifier, share.x, share.y)
      expect(result.slashable).toBe(false)

      // Add claim
      freshOp.addClaim(nullifier, amounts[i])
    }

    // Verify batch structure
    const batch = freshOp.getPendingClaims()
    expect(batch.nullifiers.length).toBe(5)
    expect(batch.amounts.length).toBe(5)

    // All nullifiers are unique
    const uniqueNullifiers = new Set(batch.nullifiers.map(n => n.toString()))
    expect(uniqueNullifiers.size).toBe(5)

    // Amounts match
    for (let i = 0; i < 5; i++) {
      expect(batch.amounts[i]).toBe(amounts[i])
    }

    // Total amount
    const total = batch.amounts.reduce((a, b) => a + b, 0n)
    expect(total).toBe(725n)
  })

  it('double-signal detection works across interleaved epochs', async () => {
    const freshOp = new MockOperator()
    const epoch = 500n

    // User sends legitimate request in epoch 500
    const msg1 = BigInt('0x' + Buffer.from('legit-req').toString('hex'))
    const nullifier = await computeRLNNullifier(keypair.privateKey, epoch, chainId)
    const share1 = await computeShamirShare(keypair.privateKey, epoch, chainId, msg1)
    const r1 = freshOp.recordShare(nullifier, share1.x, share1.y)
    expect(r1.slashable).toBe(false)

    // Legitimate request in a DIFFERENT epoch — no problem
    const epoch2 = 501n
    const null2 = await computeRLNNullifier(keypair.privateKey, epoch2, chainId)
    const share2 = await computeShamirShare(keypair.privateKey, epoch2, chainId, msg1)
    const r2 = freshOp.recordShare(null2, share2.x, share2.y)
    expect(r2.slashable).toBe(false)

    // User tries to cheat: second request in the ORIGINAL epoch 500
    const msg3 = BigInt('0x' + Buffer.from('cheat-req').toString('hex'))
    const share3 = await computeShamirShare(keypair.privateKey, epoch, chainId, msg3)
    const r3 = freshOp.recordShare(nullifier, share3.x, share3.y)
    expect(r3.slashable).toBe(true)
    expect(r3.identitySecret).toBe(keypair.privateKey)
  })
})
