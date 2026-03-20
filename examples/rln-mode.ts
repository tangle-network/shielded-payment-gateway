#!/usr/bin/env npx tsx
/**
 * RLN Mode (Per-Request Proofs) — Full Flow
 *
 * Each request carries its own ZK proof. The operator verifies off-chain
 * (~5ms) and settles in batches. Full per-request unlinkability: no two
 * requests can be linked to each other or to the depositor.
 *
 * Latency: ~640ms per proof (CPU-bound, parallelizable via proof pool).
 * Privacy: full unlinkability across all requests.
 */

import { ethers } from 'ethers'
import * as snarkjs from 'snarkjs'
import {
  Keypair,
  ShieldedGatewayClient,
  NoteManager,
  MemoryNoteStorage,
  getCircuitArtifacts,
  poseidonHash2,
} from '@tangle-network/shielded-sdk'
import {
  generatePaymentProof,
  type RLNUTXO,
  type MerkleProof,
} from '@tangle-network/shielded-sdk/proof/rln-client'
import { RLNVerifier } from '@tangle-network/shielded-sdk/proof/rln-verifier'

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8545'
const PRIVATE_KEY = process.env.PRIVATE_KEY!
const SETTLEMENT_ADDRESS = process.env.SETTLEMENT!
const POOL_ADDRESS = process.env.POOL!
const WRAPPED_TOKEN = process.env.WRAPPED_TOKEN!
const RLN_IDENTIFIER = 1n // Application-specific identifier

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL)
  const signer = new ethers.Wallet(PRIVATE_KEY, provider)

  // --- Step 1: Deposit into shielded pool ---
  // The deposit establishes the user's identity secret in the Merkle tree.
  // This is the only on-chain action that links to the user's wallet.
  const identitySecret = BigInt(ethers.hexlify(ethers.randomBytes(31)))
  const identityCommitment = poseidonHash2(identitySecret, 0n)
  console.log('Identity commitment:', identityCommitment.toString(16))

  // In production: call RLNSettlement.deposit(token, amount, identityCommitment)
  // and register the commitment in the on-chain Merkle tree.

  // --- Step 2: Generate RLN payment proof for a request ---
  // Each proof is unlinkable. The nullifier is derived from (secret, epoch).
  const rlnArtifacts = await getCircuitArtifacts('rln_payment_2_8')
  const utxo: RLNUTXO = { identitySecret, leafIndex: 0 }

  // Simulated Merkle proof (in production, built from on-chain tree state)
  const merkleProof: MerkleProof = {
    root: identityCommitment, // Simplified for demo
    pathElements: new Array(20).fill(0n),
    pathIndices: new Array(20).fill(0),
  }

  const epoch = BigInt(Math.floor(Date.now() / 10_000)) // 10-second epochs
  const requestPayload = ethers.keccak256(ethers.toUtf8Bytes('What is the meaning of life?'))
  const messageHash = BigInt(requestPayload) % (2n ** 253n)

  const paymentProof = await generatePaymentProof(
    utxo,
    merkleProof,
    epoch,
    RLN_IDENTIFIER,
    messageHash,
    rlnArtifacts,
  )
  console.log('Generated RLN proof for epoch', epoch.toString())

  // --- Step 3: Send proof to operator ---
  // The operator receives: (proof, publicSignals, request)
  // No on-chain transaction. The proof IS the payment authorization.
  const request = {
    proof: paymentProof.proof,
    publicSignals: paymentProof.publicSignals,
    nullifier: paymentProof.nullifier,
    epoch,
    payload: 'What is the meaning of life?',
  }

  // --- Step 4: Operator verifies off-chain (~5ms) ---
  const verifier = new RLNVerifier(
    'circuits/rln-payment/verification_key.json',
    SETTLEMENT_ADDRESS,
    provider,
  )

  const onChainRoot = merkleProof.root // In production: fetch from contract
  const valid = await verifier.verifyPaymentProof(
    request.proof,
    request.publicSignals,
    onChainRoot,
  )
  console.log('Proof valid:', valid)

  // Record Shamir share for double-spend detection
  const shareX = BigInt(request.publicSignals[3])
  const shareY = BigInt(request.publicSignals[0])
  const shareResult = verifier.recordShare(request.nullifier, shareX, shareY)
  if (shareResult.slashable) {
    console.log('SLASHABLE: user double-signaled in same epoch')
  }

  // --- Step 5: Operator serves and issues refund receipt ---
  const maxCost = ethers.parseUnits('0.50', 6) // Max $0.50/request
  const actualCost = ethers.parseUnits('0.12', 6) // Actual: $0.12
  const refundValue = maxCost - actualCost
  console.log(`Served request. Refund: ${ethers.formatUnits(refundValue, 6)} USDC`)

  // Operator signs refund ticket (user accumulates these privately)
  // In production: operator signs (refundValue, nullifier) with ECDSA

  // --- Step 6: Next request uses updated refund balance ---
  // The user's solvency constraint accounts for accumulated refunds:
  //   (epochIndex + 1) * maxCost <= deposit + totalRefunds
  // Refunds extend the user's request budget beyond their initial deposit.
  const nextEpoch = epoch + 1n
  console.log('Next request will use epoch', nextEpoch.toString())

  // --- Step 7: Batch settlement ---
  // Operator accumulates claims and settles periodically on-chain.
  verifier.addClaim(request.nullifier, maxCost)
  const pending = verifier.getPendingClaims()
  console.log(`Pending claims: ${pending.nullifiers.length}`)

  // In production: operator calls verifier.settleBatch(signer, tokenAddress)
  // This submits all accumulated nullifiers + amounts in one transaction.
}

main().catch(console.error)
