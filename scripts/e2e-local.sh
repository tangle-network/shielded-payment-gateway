#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# Local end-to-end proof run for the shielded payment gateway.
#
# One command reproduces the whole loop on a local Anvil chain:
#
#   ./scripts/e2e-local.sh
#
# Steps:
#   1. Ensure protocol-solidity submodule + circomlib are present
#   2. Run the Groth16 trusted setup (skipped if zkeys already exist)
#      - compiles the 4 VAnchor circuits from protocol-solidity
#      - downloads the public Hermez powers-of-tau (circom.info mirror)
#      - phase-2 contribute + beacon (DETERMINISTIC, dev-only entropy)
#   3. Stage artifacts into build/circuits/ (layout the SDK tests expect)
#   4. forge build + forge test
#   5. SDK vitest suite, including REAL proof generation and the REAL
#      on-chain lifecycle test (test/anvil-e2e-real.test.ts):
#      wrap → deposit (proof) → gateway fundCredits (proof) →
#      EIP-712 spend → operator claim → expiry reclaim → withdraw →
#      change-UTXO withdrawal (proof) → double-spend rejection
#
# ─── What CI would need ───────────────────────────────────────────────────
#   - Cache `build/trusted-setup/` and `build/circuits/` keyed by:
#     hash(dependencies/protocol-solidity/circuits/**) + hash(scripts/trusted-setup/ceremony.sh)
#     + ptau size. The ceremony is the only slow step (~30-60 min cold,
#     dominated by the two 16-input circuits; ~10 min for the two 2-input ones).
#   - Cache `out/` (forge) and `sdk/shielded-sdk/node_modules/`.
#   - Tools: foundry (forge/anvil), node >= 18, circom >= 2.1.
#   - The SDK proof tests self-skip when artifacts are absent, so a CI job
#     WITHOUT the artifact cache still passes — it just doesn't prove the
#     ZK path. Gate mainnet-readiness on the artifact-cached job.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PTAU_SIZE="${PTAU_SIZE:-18}"
SNARKJS_CACHE="$ROOT_DIR/.e2e-cache/snarkjs"

echo "═══════════════════════════════════════════════════════════════"
echo "  Shielded Payment Gateway — local E2E"
echo "═══════════════════════════════════════════════════════════════"

# ─── 0. snarkjs (needs 0.7+; some systems ship an ancient global one) ─────
snarkjs_version_text() { npx snarkjs --version 2>&1 || true; }
if ! snarkjs_version_text | grep -q "snarkjs@0\.[7-9]"; then
    echo "Using local snarkjs 0.7.x from $SNARKJS_CACHE"
    if [ ! -x "$SNARKJS_CACHE/node_modules/.bin/snarkjs" ]; then
        mkdir -p "$SNARKJS_CACHE"
        (cd "$SNARKJS_CACHE" && npm init -y >/dev/null 2>&1 && npm install snarkjs@0.7.5 --no-audit --no-fund)
    fi
    export PATH="$SNARKJS_CACHE/node_modules/.bin:$PATH"
    # npx resolves from cwd first — run ceremony from the cache dir
fi

# ─── 1. Submodule circuits + circomlib ────────────────────────────────────
if [ ! -f dependencies/protocol-solidity/circuits/main/poseidon_vanchor_2_8.circom ]; then
    echo "Initializing protocol-solidity submodule..."
    git submodule update --init --recursive
fi

if [ ! -d dependencies/protocol-solidity/node_modules/circomlib ]; then
    echo "Installing circomlib for circuit compilation..."
    mkdir -p dependencies/protocol-solidity/node_modules
    tarball=$(npm view circomlib@2.0.5 dist.tarball)
    curl -sL "$tarball" | tar xz -C dependencies/protocol-solidity/node_modules
    mv dependencies/protocol-solidity/node_modules/package \
       dependencies/protocol-solidity/node_modules/circomlib
fi

# ─── 2. Trusted setup (idempotent; skips finished circuits) ───────────────
if [ ! -f build/trusted-setup/zkeys/poseidon_vanchor_16_8/circuit_final.zkey ]; then
    echo "Running trusted setup ceremony (PTAU_SIZE=$PTAU_SIZE)..."
    # Run from the snarkjs cache dir if we had to install locally so that
    # npx resolves the local 0.7.x binary.
    if [ -d "$SNARKJS_CACHE/node_modules" ]; then
        (cd "$SNARKJS_CACHE" && PTAU_SIZE="$PTAU_SIZE" "$ROOT_DIR/scripts/trusted-setup/ceremony.sh")
    else
        PTAU_SIZE="$PTAU_SIZE" ./scripts/trusted-setup/ceremony.sh
    fi
else
    echo "Trusted setup artifacts already present — skipping ceremony."
fi

# ─── 3. Stage artifacts for the SDK tests ─────────────────────────────────
./scripts/stage-circuit-artifacts.sh
./scripts/setup-rln-circuit.sh

# ─── 4. Contracts ─────────────────────────────────────────────────────────
echo "Building contracts..."
forge build

echo "Running forge test suite..."
forge test

# ─── 5. SDK: real proofs + real on-chain lifecycle ────────────────────────
echo "Running SDK tests (including REAL Groth16 proofs on Anvil)..."
cd sdk/shielded-sdk
if [ ! -d node_modules ]; then
    npm install --no-audit --no-fund
fi
npx vitest run

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  E2E COMPLETE"
echo "═══════════════════════════════════════════════════════════════"
