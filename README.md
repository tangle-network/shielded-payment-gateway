![Tangle Network Banner](https://raw.githubusercontent.com/tangle-network/tangle/refs/heads/main/assets/Tangle%20%20Banner.png)

<h1 align="center">Shielded Payment Gateway</h1>

<p align="center"><em>Anonymous pay-per-use payments for <a href="https://tangle.tools">Tangle</a> Blueprints via cross-chain shielded pools and prepaid credits.</em></p>

<p align="center">
  <a href="https://github.com/tangle-network/shielded-payment-gateway/actions"><img src="https://img.shields.io/github/actions/workflow/status/tangle-network/shielded-payment-gateway/ci.yml?branch=main&logo=github" alt="Build Status"></a>
  <a href="https://github.com/tangle-network/shielded-payment-gateway/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <a href="https://discord.com/invite/cv8EfJu3Tn"><img src="https://img.shields.io/discord/833784453251596298?label=Discord" alt="Discord"></a>
  <a href="https://t.me/tanglenet"><img src="https://img.shields.io/endpoint?color=neon&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2Ftanglenet" alt="Telegram"></a>
</p>

## Overview

Privacy-preserving payment system that enables users to pay for cloud services — LLM inference, compute, storage — without revealing their identity to the operator or on-chain observers.

**How it works:**
1. Deposit stablecoins into a shielded pool (USDC, USDT, DAI → single anonymity set)
2. Withdraw partially via a ZK proof to fund a pseudonymous credit account
3. Authorize many job payments with cheap EIP-712 signatures (~50k gas each)
4. Unspent funds stay shielded as change UTXOs, each withdrawal unlinkable to the last

The operator serves requests and claims payment, but never learns the user's wallet address, deposit history, or total balance.

## Architecture

```
User deposits (any chain) → VAnchor shielded pool
                                    ↓ ZK proof (one-time)
                            ShieldedGateway
                                    ↓ fund
                            ShieldedCredits
                                    ↓ EIP-712 sig (per job)
                            Operator serves + claims
```

### Contracts

| Contract | Purpose |
|----------|---------|
| `ShieldedGateway` | Bridges VAnchor withdrawals to Tangle service lifecycle |
| `ShieldedCredits` | Prepaid accounts with EIP-712 spend authorizations, expiry refunds |
| `LayerZeroAnchorBridge` | Cross-chain Merkle root relay via LayerZero V2 |

### Key Properties

- **Zero modifications** to Tangle's audited core contracts
- **Variable-amount** UTXO model (not fixed denominations) with JoinSplit transactions
- **Cross-chain** deposits via 8-chain bridge (Ethereum, Arbitrum, Base, Optimism, Polygon, BSC, Avalanche, Hyperliquid)
- **Expiry-based refunds** — if operator doesn't claim before deadline, user reclaims funds
- **Multi-stablecoin wrapping** — USDC + USDT + DAI → single pool token, maximizing anonymity set

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Node.js 18+
- [circom](https://github.com/iden3/circom) (for trusted setup)

### Setup

```bash
# Clone with submodules
git clone --recursive https://github.com/tangle-network/shielded-payment-gateway.git
cd shielded-payment-gateway

# Install dependencies
forge soldeer update
./scripts/setup-shielded-deps.sh

# Build
forge build

# Test (104 tests)
forge test
```

### SDK

```bash
cd sdk/shielded-sdk
npm install
npx vitest run  # 40 tests including real ZK proof generation
```

### CLI

```bash
npx tsx sdk/shielded-sdk/src/cli.ts keygen           # Generate credit account keys
npx tsx sdk/shielded-sdk/src/cli.ts balance --credits 0x... --commitment 0x...
npx tsx sdk/shielded-sdk/src/cli.ts authorize-spend --credits 0x... --amount 1 ...
```

## Deployment

```bash
# 1. Run trusted setup ceremony
./scripts/trusted-setup/ceremony.sh

# 2. Deploy everything to a chain
export RPC_URL=https://sepolia.base.org PRIVATE_KEY=0x... TANGLE=0x...
./scripts/deploy-full-stack.sh

# 3. Verify deployment
GATEWAY=0x... CREDITS=0x... POOL=0x... WRAPPER=0x... ./scripts/verify-deployment.sh
```

See [`deploy/config/`](deploy/config/) for Base Sepolia and Base Mainnet configurations.

## Research Spec

An 8-page technical paper is included: [`shielded-payments.pdf`](shielded-payments.pdf)

Covers: UTXO change mechanics, operator knowledge boundaries, privacy analysis, AI use cases (inference, image generation, agent execution, fine-tuning), cross-chain architecture, and cost comparison.

## License

MIT
