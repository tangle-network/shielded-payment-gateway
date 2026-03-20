/**
 * E2E Batch Verifier Test
 *
 * Generates 5 real circom Groth16 deposit proofs (one per user),
 * packs them into a BatchInput matching the SP1 program format,
 * verifies each individually, checks batch invariants, and writes
 * batch.json to /tmp for the SP1 prover to consume.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import {
  Keypair,
  Utxo,
  MerkleTree,
  ChainType,
  typedChainId,
} from '../src/protocol/index.js'
import {
  buildWitnessInputs,
  computeExtDataHash,
} from '../src/proof/witness.js'

const CIRCUIT_DIR = '/home/drew/code/tnt-core/build/circuits/vanchor_2_8'
const WASM_PATH = join(
  CIRCUIT_DIR,
  'poseidon_vanchor_2_8_js/poseidon_vanchor_2_8.wasm'
)
const ZKEY_PATH = join(CIRCUIT_DIR, 'circuit_final.zkey')
const VKEY_PATH = join(CIRCUIT_DIR, 'verification_key.json')

const SKIP =
  process.env.SKIP_PROOF_E2E === '1' ||
  !existsSync(WASM_PATH) ||
  !existsSync(ZKEY_PATH) ||
  !existsSync(VKEY_PATH)

const NUM_USERS = 5
const EMPTY_ROOT = 0n

interface ProofResult {
  proof: Record<string, unknown>
  publicSignals: string[]
  nullifiers: bigint[]
  commitments: bigint[]
  publicAmount: bigint
  extDataHash: bigint
  chainId: bigint
  roots: bigint[]
  proofBytes: string
  userIndex: number
}

/**
 * Generate a single deposit proof for a user.
 */
async function generateDepositProof(
  snarkjs: typeof import('snarkjs'),
  userIndex: number,
  tree: MerkleTree,
  chainId: bigint
): Promise<ProofResult> {
  const keypair = new Keypair()
  const depositAmount = BigInt((userIndex + 1) * 5) * 10n ** 18n

  const output = Utxo.create({ chainId, amount: depositAmount, keypair })
  const changeOutput = await Utxo.zero(chainId, keypair)

  const zeroInput1 = await Utxo.zero(chainId, keypair)
  const zeroInput2 = await Utxo.zero(chainId, keypair)
  zeroInput1.index = 0
  zeroInput2.index = 0

  const extDataHash = computeExtDataHash({
    recipient: '0x0000000000000000000000000000000000000000',
    extAmount: depositAmount,
    relayer: '0x0000000000000000000000000000000000000000',
    fee: 0n,
    refund: 0n,
    token: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    encryptedOutput1: new Uint8Array(0),
    encryptedOutput2: new Uint8Array(0),
  })

  const roots = [
    tree.root,
    EMPTY_ROOT, EMPTY_ROOT, EMPTY_ROOT, EMPTY_ROOT,
    EMPTY_ROOT, EMPTY_ROOT, EMPTY_ROOT,
  ]

  const witnessInput = await buildWitnessInputs({
    inputs: [zeroInput1, zeroInput2],
    outputs: [output, changeOutput],
    tree,
    extDataHash,
    extAmount: depositAmount,
    fee: 0n,
    chainId,
    roots,
  })

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witnessInput as unknown as Record<string, unknown>,
    WASM_PATH,
    ZKEY_PATH
  )

  // Extract nullifiers from public signals (indices 0 and 1 for 2-input circuit)
  const nullifiers = [
    BigInt(publicSignals[0]),
    BigInt(publicSignals[1]),
  ]

  // Extract output commitments (indices after nullifiers)
  const outputCommitment = await output.getCommitment()
  const changeCommitment = await changeOutput.getCommitment()
  const commitments = [outputCommitment, changeCommitment]

  return {
    proof,
    publicSignals,
    nullifiers,
    commitments,
    publicAmount: depositAmount,
    extDataHash,
    chainId,
    roots,
    proofBytes: JSON.stringify(proof),
    userIndex,
  }
}

/**
 * Convert a bigint to a 32-byte hex string (no 0x prefix, BE).
 */
function bigintToBytes32Hex(val: bigint): string {
  const hex = val.toString(16).padStart(64, '0')
  return hex.slice(0, 64)
}

/**
 * Convert a bigint to a [u8; 32] array (big-endian) for SP1 BatchInput.
 */
function bigintToBytes32(val: bigint): number[] {
  const bytes: number[] = []
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return bytes
}

describe.skipIf(SKIP)('SP1 Batch Verifier E2E', () => {
  let tree: MerkleTree
  let chainId: bigint
  let proofs: ProofResult[]
  let vKey: Record<string, unknown>

  beforeAll(async () => {
    tree = await MerkleTree.create(30)
    chainId = typedChainId(ChainType.EVM, 8453)
    vKey = JSON.parse(readFileSync(VKEY_PATH, 'utf-8'))
    proofs = []
  })

  it(`should generate ${NUM_USERS} deposit proofs from different users`, async () => {
    const snarkjs = await import('snarkjs')

    const genStart = performance.now()

    // Generate all proofs sequentially (each needs snarkjs WASM)
    for (let i = 0; i < NUM_USERS; i++) {
      const p = await generateDepositProof(snarkjs, i, tree, chainId)
      proofs.push(p)
      console.log(`  User ${i}: proof generated (deposit=${(BigInt((i + 1) * 5))} TNT)`)
    }

    const genMs = performance.now() - genStart
    console.log(`\n  Total generation: ${(genMs / 1000).toFixed(2)}s for ${NUM_USERS} proofs (${(genMs / NUM_USERS / 1000).toFixed(2)}s avg)`)

    expect(proofs).toHaveLength(NUM_USERS)
  }, 600_000)

  it('should verify each proof individually via snarkjs', async () => {
    const snarkjs = await import('snarkjs')

    const verifyStart = performance.now()

    for (let i = 0; i < proofs.length; i++) {
      const { proof, publicSignals } = proofs[i]
      const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof)
      expect(valid, `proof ${i} failed verification`).toBe(true)
    }

    const verifyMs = performance.now() - verifyStart
    console.log(`  Verification: ${(verifyMs / 1000).toFixed(2)}s for ${proofs.length} proofs (${(verifyMs / proofs.length / 1000).toFixed(2)}s avg)`)
  }, 120_000)

  it('should have no duplicate nullifiers across the batch', () => {
    const allNullifiers = proofs.flatMap((p) => p.nullifiers)
    const nullifierSet = new Set(allNullifiers.map((n) => n.toString()))

    console.log(`  Total nullifiers: ${allNullifiers.length}`)
    console.log(`  Unique nullifiers: ${nullifierSet.size}`)

    // Each proof has 2 nullifiers, but zero-amount inputs share the same
    // nullifier derivation (keypair + index=0 + zero amount). Different
    // keypairs produce different nullifiers, so 5 users = 10 nullifiers,
    // but zero-input nullifiers may collide across users if blinding is the same.
    // With random keypairs, all should be unique.
    //
    // The critical invariant: no nullifier appears more than once.
    // If duplicates exist, the SP1 program would reject the batch.
    expect(nullifierSet.size).toBe(allNullifiers.length)
  })

  it('should have valid commitments for all outputs', () => {
    const allCommitments = proofs.flatMap((p) => p.commitments)

    for (const cm of allCommitments) {
      // Commitment must be non-zero and within the field
      expect(cm).toBeGreaterThan(0n)
    }

    console.log(`  Total commitments: ${allCommitments.length} (${proofs.length} deposits x 2 outputs)`)
  })

  it('should conserve amounts (deposits only, no withdrawals)', () => {
    let totalDeposited = 0n
    for (let i = 0; i < proofs.length; i++) {
      totalDeposited += proofs[i].publicAmount
    }

    // 5 + 10 + 15 + 20 + 25 = 75 TNT
    const expectedTotal = 75n * 10n ** 18n
    expect(totalDeposited).toBe(expectedTotal)
    console.log(`  Total deposited: ${totalDeposited / 10n ** 18n} TNT`)
  })

  it('should simulate BatchVerifier contract logic', () => {
    // Simulate on-chain state
    const nullifierSet = new Set<string>()
    const commitmentSet = new Set<string>()

    for (const p of proofs) {
      for (const nf of p.nullifiers) {
        const key = nf.toString()
        // Contract would revert on duplicate
        expect(nullifierSet.has(key), `duplicate nullifier: ${key}`).toBe(false)
        nullifierSet.add(key)
      }
      for (const cm of p.commitments) {
        commitmentSet.add(cm.toString())
      }
    }

    console.log(`  Simulated on-chain state:`)
    console.log(`    Nullifiers marked: ${nullifierSet.size}`)
    console.log(`    Commitments inserted: ${commitmentSet.size}`)
    console.log(`    Batch count: 1`)
    console.log(`    Total processed: ${proofs.length}`)
  })

  it('should pack and write batch.json for SP1 prover', () => {
    // Build the BatchInput structure matching the SP1 program's serde format
    const batchInput = {
      vkey: Array.from(readFileSync(VKEY_PATH)),
      proofs: proofs.map((p) => ({
        proof_bytes: Array.from(new TextEncoder().encode(p.proofBytes)),
        public_signals: p.publicSignals.map((s) => bigintToBytes32(BigInt(s))),
        tx_data: {
          nullifiers: p.nullifiers.map((n) => bigintToBytes32(n)),
          output_commitments: p.commitments.map((c) => bigintToBytes32(c)),
          public_amount: bigintToBytes32(p.publicAmount),
          ext_data_hash: bigintToBytes32(p.extDataHash),
          chain_id: bigintToBytes32(p.chainId),
          roots: p.roots.map((r) => bigintToBytes32(r)),
        },
      })),
    }

    const outPath = '/tmp/shielded-batch-input.json'
    writeFileSync(outPath, JSON.stringify(batchInput, null, 2))

    // Also write a human-readable summary
    const summary = {
      tx_count: proofs.length,
      total_nullifiers: proofs.reduce((n, p) => n + p.nullifiers.length, 0),
      total_commitments: proofs.reduce((n, p) => n + p.commitments.length, 0),
      total_deposited_wei: proofs.reduce((a, p) => a + p.publicAmount, 0n).toString(),
      nullifier_hashes: proofs.flatMap((p) =>
        p.nullifiers.map((n) => '0x' + bigintToBytes32Hex(n))
      ),
      commitment_hashes: proofs.flatMap((p) =>
        p.commitments.map((c) => '0x' + bigintToBytes32Hex(c))
      ),
    }
    writeFileSync('/tmp/shielded-batch-summary.json', JSON.stringify(summary, null, 2))

    console.log(`  Batch JSON written to: ${outPath}`)
    console.log(`  Summary written to: /tmp/shielded-batch-summary.json`)
    console.log(`  Batch size: ${(JSON.stringify(batchInput).length / 1024).toFixed(1)} KB`)

    // Verify the file was written and is valid JSON
    const reread = JSON.parse(readFileSync(outPath, 'utf-8'))
    expect(reread.proofs).toHaveLength(NUM_USERS)
    expect(reread.vkey.length).toBeGreaterThan(0)
  })
})
