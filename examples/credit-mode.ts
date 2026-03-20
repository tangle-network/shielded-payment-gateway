#!/usr/bin/env npx tsx
/**
 * Credit Mode (Prepaid Credits) — Full Flow
 *
 * One ZK proof funds a pseudonymous credit account.
 * Many ECDSA signatures authorize individual job payments (~50k gas each).
 * Requests within a session share a pseudonym; sessions are unlinkable.
 *
 * Latency: <100ms per request (ECDSA signature only, no ZK proof).
 * Privacy: pseudonymous within session, unlinkable across sessions.
 */

import { ethers } from 'ethers'
import {
  Keypair,
  ShieldedGatewayClient,
  ShieldedCreditsClient,
  generateCreditKeys,
  signSpendAuthorization,
  signWithdrawal,
  NoteManager,
  MemoryNoteStorage,
  getCircuitArtifacts,
} from '@tangle-network/shielded-sdk'

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8545'
const PRIVATE_KEY = process.env.PRIVATE_KEY!
const GATEWAY_ADDRESS = process.env.GATEWAY!
const POOL_ADDRESS = process.env.POOL!
const CREDITS_ADDRESS = process.env.CREDITS!
const WRAPPED_TOKEN = process.env.WRAPPED_TOKEN!
const OPERATOR_ADDRESS = process.env.OPERATOR!
const SERVICE_ID = BigInt(process.env.SERVICE_ID ?? '1')

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL)
  const signer = new ethers.Wallet(PRIVATE_KEY, provider)
  const noteManager = new NoteManager(new MemoryNoteStorage())

  // --- Step 1: Generate ephemeral credit keys ---
  // These keys are session-scoped. A new session = new keys = unlinkable.
  const creditKeys = generateCreditKeys()
  console.log('Credit commitment:', creditKeys.commitment)

  // --- Step 2: Deposit into the VAnchor shielded pool ---
  // This is the only step where the user's wallet is visible on-chain.
  const keypair = Keypair.generate()
  const artifacts = await getCircuitArtifacts('vanchor_2_8')
  const gateway = new ShieldedGatewayClient({
    provider,
    gatewayAddress: GATEWAY_ADDRESS,
    poolAddress: POOL_ADDRESS,
    wrappedTokenAddress: WRAPPED_TOKEN,
    chainId: Number((await provider.getNetwork()).chainId),
    treeLevels: 30,
    smallCircuit: artifacts,
  })

  const depositNote = await gateway.deposit({
    signer,
    keypair,
    amount: ethers.parseUnits('50', 6), // 50 USDC
    noteManager,
  })
  console.log('Deposited into shielded pool')

  // --- Step 3: Withdraw through gateway to fund credits ---
  // ZK proof proves deposit ownership without revealing the depositor.
  const fundTx = await gateway.fundCredits({
    signer,
    keypair,
    amount: ethers.parseUnits('10', 6), // Withdraw 10 USDC for credits
    commitment: creditKeys.commitment,
    spendingKey: creditKeys.spendingPublicKey,
    noteManager,
  })
  console.log('Funded credit account via shielded withdrawal')

  // --- Step 4: Sign spend authorizations for inference requests ---
  // Each signature is ~50k gas. No ZK proof needed per request.
  const credits = new ShieldedCreditsClient(CREDITS_ADDRESS, signer)
  const domainSeparator = await credits.getDomainSeparator()

  for (let i = 0; i < 5; i++) {
    const nonce = (await credits.getAccount(creditKeys.commitment)).nonce
    const auth = await signSpendAuthorization({
      spendingPrivateKey: creditKeys.spendingPrivateKey,
      commitment: creditKeys.commitment,
      serviceId: SERVICE_ID,
      jobIndex: i,
      amount: ethers.parseUnits('0.10', 6), // $0.10 per inference
      operator: OPERATOR_ADDRESS,
      nonce,
      expiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
      domainSeparator,
    })
    console.log(`Request ${i + 1}: signed spend auth (nonce=${nonce})`)
  }

  // --- Step 5: Operator claims payment ---
  // In production, the operator submits the auth on-chain and claims.
  // Omitted here — requires operator's signer.

  // --- Step 6: Withdraw remaining credits ---
  const account = await credits.getAccount(creditKeys.commitment)
  if (account.balance > 0n) {
    await credits.withdraw({
      spendingPrivateKey: creditKeys.spendingPrivateKey,
      commitment: creditKeys.commitment,
      recipient: await signer.getAddress(),
      amount: account.balance,
    })
    console.log(`Withdrew remaining ${ethers.formatUnits(account.balance, 6)} USDC`)
  }
}

main().catch(console.error)
