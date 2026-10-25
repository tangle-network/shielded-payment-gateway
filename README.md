![Tangle Network Banner](https://raw.githubusercontent.com/tangle-network/tangle/refs/heads/main/assets/Tangle%20%20Banner.png)

<h1 align="center">Shielded Payment Gateway</h1>

<p align="center"><em>Anonymous pay-per-use payments for <a href="https://tangle.tools">Tangle</a> Blueprints via cross-chain shielded pools and prepaid credits.</em></p>

<p align="center">
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

## Payment Modes

The system supports two payment modes. Users choose per request based on their privacy requirements.

| | **Credit Mode** (Prepaid Credits) | **RLN Mode** (Per-Request Proofs) |
|---|---|---|
| **Privacy** | Pseudonymous within session, unlinkable across sessions | Full per-request unlinkability |
| **Per-request latency** | <100ms (ECDSA signature) | ~640ms (ZK proof, parallelizable to near-zero) |
| **Per-request gas** | ~50k (on-chain) | 0 (batched settlement) |
| **ZK proofs** | 1 per session | 1 per request (off-chain verified) |
| **Abuse protection** | Nonce ordering | Shamir secret sharing (cryptoeconomic slashing) |
| **Best for** | High-frequency, low-latency inference | Sensitive workloads (medical, legal, journalism) |

Both modes coexist on the same operator. See [`examples/`](examples/) for runnable TypeScript code demonstrating each flow.

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

### Local qualification

Generic PR and push CI is retired. Run useful contract and SDK checks on an admitted Beelink at the exact pushed revision; keep real deployment and payment-flow proof separate.

```bash
beelink-gate --no-install auto https://github.com/tangle-network/shielded-payment-gateway.git <full-sha> -- \
  bash -euc './scripts/setup-shielded-deps.sh && forge build && forge test'

beelink-gate --no-install auto https://github.com/tangle-network/shielded-payment-gateway.git <full-sha> -- \
  bash -euc 'cd sdk/shielded-sdk && npm install && npx vitest run --exclude "test/proof*.test.ts"'

beelink-gate --no-install auto https://github.com/tangle-network/shielded-payment-gateway.git <full-sha> -- \
  bash -euc '
cd sp1-batch/contracts
python3 - <<"PYTHON"
import json, pathlib, subprocess
urls = {"lib/forge-std": "https://github.com/foundry-rs/forge-std.git",
        "lib/openzeppelin-contracts": "https://github.com/OpenZeppelin/openzeppelin-contracts.git"}
for path, url in urls.items():
    pin = json.loads(pathlib.Path("foundry.lock").read_text())[path]["tag"]
    dest = pathlib.Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        subprocess.run(["git", "clone", "--depth", "1", "--branch", pin["name"], "--single-branch", url, path], check=True)
    actual = subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()
    if actual != pin["rev"]:
        raise SystemExit(f"{path}: expected locked revision, found {actual}")
PYTHON
forge build
forge test'
```

Foundry must already be available on the admitted host. The setup script owns root Solidity dependencies, and `sp1-batch/contracts/foundry.lock` owns the SP1 dependency revisions; the commands refuse a pre-existing SP1 checkout at another revision. The SDK has no committed dependency lockfile, so its existing `npm install` is not frozen proof. The SDK command retains the retired workflow exclusion for proof-artifact cases; it does not prove trusted setup, an actual zero-knowledge payment, or a deployed contract. The real local and deployment procedures below remain separate qualifications.

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

# Test
forge test
```

All Solidity dependencies are soldeer-managed; nothing is written into the
`dependencies/` packages by hand, so `forge soldeer install`/`update` can be
re-run at any time. Two OpenZeppelin majors coexist:

- Gateway contracts and tests (`src/`, `test/`, `script/`) compile against **OZ 5.1.0**.
- The vendored `protocol-solidity` submodule (audited against OZ 4.x) compiles against
  **OZ 4.9.6** via a context remapping in `remappings.txt`
  (`dependencies/protocol-solidity/:@openzeppelin/contracts/=...`). Its imports of paths
  that OZ 5.x moved or removed (`security/ReentrancyGuard.sol`,
  `token/ERC20/presets/ERC20PresetMinterPauser.sol`, `security/Pausable.sol`) resolve
  unmodified.

### Local end-to-end (real ZK proofs on Anvil)

One command reproduces the full loop — trusted setup, artifact staging,
contract build, and the complete payment lifecycle with real Groth16 proofs
verified on-chain (deposit → anonymized credit funding → EIP-712 spend →
operator claim → expiry reclaim → withdrawal):

```bash
./scripts/e2e-local.sh
```

The ceremony step is skipped automatically once `build/trusted-setup/` exists.
See the script header for what a CI job needs (artifact caching).

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

## Scaling & multi-asset future

Per-transaction Groth16 proofs (BN254, Poseidon) are the launch stack — cheapest EVM verification and parity with comparable systems. Scaling beyond that is incremental, not a rewrite:

- **Batched settlement** — the `sp1-batch/` SP1 `BatchVerifier` + `BatchTransactor` prove N transactions in one proof (~101k gas/tx at batch 50, measured; see `docs/ZKP-BENCHMARKS.md`). Extending the SP1 program to prove batches of VAnchor transacts is the scaling path.
- **Multi-asset pools** — the archived [masp-protocol](https://github.com/tangle-network/masp-protocol) repo (dormant since 2024, reference-only) explored multi-asset shielded pools in circom. That direction is superseded: if multi-asset support is ever needed, it lands as a module in the SP1 program above — per masp-protocol's own `ARCHITECTURE.md` — not by reviving the circom MASP. Do not start new work in masp-protocol.

## Research Spec

Technical spec: [`shielded-payments.pdf`](shielded-payments.pdf)

Covers: UTXO change mechanics, operator knowledge boundaries, privacy analysis, AI use cases (inference, image generation, agent execution, fine-tuning), cross-chain architecture, and cost comparison.

## License

MIT
