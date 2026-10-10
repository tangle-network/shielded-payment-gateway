#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Round-2 ceremony deployment rehearsal — Tempo testnet (chainId 42431)
#
# Copy of scripts/deploy-full-stack.sh with isolation overrides so the LIVE
# round-1 rehearsal stack records (deploy/output/*.json) are never read or
# overwritten:
#   - All state files land in deploy/output-round2/
#   - CEREMONY_DIR defaults to deploy/ceremony-round2 (sha256-pinned round-2
#     verifiers from the circuits-v2.0.0-phase2 release)
#   - Pool params passed via env vars (the deploy/config/*.json launch schema
#     is NOT passed as SHIELDED_CONFIG — it uses the rich schema, and the flat
#     script/deploy-config/tempo-testnet-shielded.json pins the LIVE round-1
#     poseidon/verifier addresses)
#   - --gas-estimate-multiplier 100 on all forge commands (Tempo quirk)
#
# Usage:
#   export RPC_URL=https://rpc.moderato.tempo.xyz
#   export PRIVATE_KEY=0x...
#   export TANGLE=0xff137b9c879c47c28ce389e84501925438ab4cda
#   ./scripts/deploy-round2-tempo.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

: "${RPC_URL:?Set RPC_URL}"
: "${PRIVATE_KEY:?Set PRIVATE_KEY}"
: "${TANGLE:?Set TANGLE (Tangle proxy address)}"
CEREMONY_DIR="${CEREMONY_DIR:-$ROOT_DIR/deploy/ceremony-round2}"
OUT_DIR="$ROOT_DIR/deploy/output-round2"
mkdir -p "$OUT_DIR"

# Pool parameters (mirrors deploy/config/tempo-testnet-shielded.json, feeBps 0)
export MERKLE_TREE_LEVELS=30
export MAX_EDGES=7
export WRAPPING_LIMIT="115792089237316195423570985008687907853269984665640564039457584007913129639935"
export FEE_PERCENTAGE=0
export IS_NATIVE_ALLOWED=false
export MIN_WITHDRAWAL_AMOUNT=0
export MAX_DEPOSIT_AMOUNT="115792089237316195423570985008687907853269984665640564039457584007913129639935"
export STABLECOINS="0x20C0000000000000000000000000000000000000"  # pathUSD
export TANGLE
unset SHIELDED_CONFIG || true

echo "═══════════════════════════════════════════════════════════════"
echo "  Round-2 Shielded Pool Deployment (isolated output dir)"
echo "═══════════════════════════════════════════════════════════════"
echo "  RPC:      $RPC_URL"
echo "  Tangle:   $TANGLE"
echo "  Out dir:  $OUT_DIR"
echo ""

# ─── Step 1: Deploy Poseidon libraries ─────────────────────────────────────
echo "Step 1: Deploying Poseidon libraries..."
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
POSEIDON_FILE="$OUT_DIR/poseidon-${CHAIN_ID}.json"

if [ -f "$POSEIDON_FILE" ] && [ "$(jq -r '.PoseidonT6 // empty' "$POSEIDON_FILE")" != "" ]; then
    echo "  Poseidon already deployed (found $POSEIDON_FILE)"
else
    # Partial files are fine — deploy-poseidon-round2.mjs resumes per-library.
    RPC_URL="$RPC_URL" PRIVATE_KEY="$PRIVATE_KEY" OUTPUT_DIR="$OUT_DIR" \
        node "$SCRIPT_DIR/deploy-poseidon-round2.mjs"
fi

POSEIDON_T2=$(jq -r '.PoseidonT2' "$POSEIDON_FILE")
POSEIDON_T3=$(jq -r '.PoseidonT3' "$POSEIDON_FILE")
POSEIDON_T4=$(jq -r '.PoseidonT4' "$POSEIDON_FILE")
POSEIDON_T5=$(jq -r '.PoseidonT5' "$POSEIDON_FILE")
POSEIDON_T6=$(jq -r '.PoseidonT6' "$POSEIDON_FILE")
export POSEIDON_T2 POSEIDON_T3 POSEIDON_T4 POSEIDON_T5 POSEIDON_T6
echo "  PoseidonT2: $POSEIDON_T2"
echo "  PoseidonT3: $POSEIDON_T3"
echo "  PoseidonT4: $POSEIDON_T4"
echo "  PoseidonT5: $POSEIDON_T5"
echo "  PoseidonT6: $POSEIDON_T6"

# ─── Step 1b: Deploy VAnchorEncodeInputs library ───────────────────────────
echo ""
echo "Step 1b: Deploying VAnchorEncodeInputs library..."
ENCODE_INPUTS_FILE="$OUT_DIR/vanchor-encode-inputs-${CHAIN_ID}.json"

if [ -f "$ENCODE_INPUTS_FILE" ]; then
    VANCHOR_ENCODE_INPUTS=$(jq -r '.address' "$ENCODE_INPUTS_FILE")
    echo "  VAnchorEncodeInputs already deployed: $VANCHOR_ENCODE_INPUTS"
else
    VANCHOR_ENCODE_INPUTS=$(FOUNDRY_VIA_IR=false forge create --broadcast --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json \
        --gas-estimate-multiplier 100 \
        "dependencies/protocol-solidity/packages/contracts/contracts/libs/VAnchorEncodeInputs.sol:VAnchorEncodeInputs" \
        | jq -r '.deployedTo')
    echo "{\"address\": \"$VANCHOR_ENCODE_INPUTS\"}" > "$ENCODE_INPUTS_FILE"
    echo "  VAnchorEncodeInputs: $VANCHOR_ENCODE_INPUTS"
fi

# ─── Step 2: Deploy Verifiers ──────────────────────────────────────────────
echo ""
echo "Step 2: Deploying Verifier contracts (round-2 ceremony artifacts)..."
VERIFIER_FILE="$OUT_DIR/verifiers-${CHAIN_ID}.json"

if [ -f "$VERIFIER_FILE" ]; then
    echo "  Verifiers already deployed (found $VERIFIER_FILE)"
    V2_2=$(jq -r '.v2_2' "$VERIFIER_FILE")
    V2_16=$(jq -r '.v2_16' "$VERIFIER_FILE")
    V8_2=$(jq -r '.v8_2' "$VERIFIER_FILE")
    V8_16=$(jq -r '.v8_16' "$VERIFIER_FILE")
else
    VERIFIERS_DIR="$CEREMONY_DIR/verifiers"
    if [ ! -d "$VERIFIERS_DIR" ]; then
        echo "  ERROR: No verifier contracts found at $VERIFIERS_DIR"
        exit 1
    fi

    # Fail-closed: every round-2 *_verifier.sol must hash-match the release
    # SHA256SUMS.txt before deployment (mirrors deploy-full-stack.sh).
    if [ -f "$VERIFIERS_DIR/SHA256SUMS.txt" ]; then
        echo "  Verifying verifier artifacts against SHA256SUMS.txt..."
        for v in poseidon_vanchor_2_2 poseidon_vanchor_2_8 poseidon_vanchor_16_2 poseidon_vanchor_16_8; do
            f="$VERIFIERS_DIR/${v}_verifier.sol"
            [ -f "$f" ] || continue
            expected=$(grep "${v}_verifier.sol" "$VERIFIERS_DIR/SHA256SUMS.txt" | awk '{print $1}')
            actual=$(shasum -a 256 "$f" | awk '{print $1}')
            if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
                echo "  ERROR: $f sha256 mismatch (release=$expected actual=$actual)"
                exit 1
            fi
        done
        echo "  Verifier artifacts verified."
    else
        echo "  ERROR: no SHA256SUMS.txt in $VERIFIERS_DIR — round-2 rehearsal is fail-closed"
        exit 1
    fi

    # NOTE: the release verifier.sol files are raw snarkjs output
    # (`contract Groth16Verifier`). We deploy them byte-exact under that name
    # (rather than sed-renaming to VerifierX_Y like ceremony.sh does for
    # build/trusted-setup) so the deployed source hash-matches SHA256SUMS.txt.
    # The snarkjs verifyProof(uint[2],uint[2][2],uint[2],uint[N]) signature is
    # exactly what VAnchorVerifier's IVAnchorVerifierX_Y interfaces call.
    echo "  Deploying Verifier8_2..."
    V8_2=$(forge create --broadcast --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json \
        --gas-estimate-multiplier 100 \
        "$VERIFIERS_DIR/poseidon_vanchor_2_8_verifier.sol:Groth16Verifier" \
        | jq -r '.deployedTo')

    echo "  Deploying Verifier8_16..."
    V8_16=$(forge create --broadcast --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json \
        --gas-estimate-multiplier 100 \
        "$VERIFIERS_DIR/poseidon_vanchor_16_8_verifier.sol:Groth16Verifier" \
        | jq -r '.deployedTo')

    echo "  Deploying Verifier2_2..."
    V2_2=$(forge create --broadcast --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json \
        --gas-estimate-multiplier 100 \
        "$VERIFIERS_DIR/poseidon_vanchor_2_2_verifier.sol:Groth16Verifier" \
        | jq -r '.deployedTo')

    echo "  Deploying Verifier2_16..."
    V2_16=$(forge create --broadcast --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json \
        --gas-estimate-multiplier 100 \
        "$VERIFIERS_DIR/poseidon_vanchor_16_2_verifier.sol:Groth16Verifier" \
        | jq -r '.deployedTo')

    echo "{\"v2_2\": \"$V2_2\", \"v2_16\": \"$V2_16\", \"v8_2\": \"$V8_2\", \"v8_16\": \"$V8_16\"}" > "$VERIFIER_FILE"
    echo "  Verifier2_2:  $V2_2"
    echo "  Verifier2_16: $V2_16"
    echo "  Verifier8_2:  $V8_2"
    echo "  Verifier8_16: $V8_16"
fi

export VERIFIER_2_2="$V2_2"
export VERIFIER_2_16="$V2_16"
export VERIFIER_8_2="$V8_2"
export VERIFIER_8_16="$V8_16"

# ─── Step 3: Deploy pool stack via Forge script ────────────────────────────
echo ""
echo "Step 3: Deploying pool stack (TokenWrapper, VAnchor, Credits, Gateway)..."

forge script script/DeployShieldedPool.s.sol:DeployShieldedPool \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --slow \
    --gas-estimate-multiplier 100 \
    --libraries "protocol-solidity/hashers/Poseidon.sol:PoseidonT2:$POSEIDON_T2" \
    --libraries "protocol-solidity/hashers/Poseidon.sol:PoseidonT3:$POSEIDON_T3" \
    --libraries "protocol-solidity/hashers/Poseidon.sol:PoseidonT4:$POSEIDON_T4" \
    --libraries "protocol-solidity/hashers/Poseidon.sol:PoseidonT5:$POSEIDON_T5" \
    --libraries "protocol-solidity/hashers/Poseidon.sol:PoseidonT6:$POSEIDON_T6" \
    --libraries "protocol-solidity/libs/VAnchorEncodeInputs.sol:VAnchorEncodeInputs:$VANCHOR_ENCODE_INPUTS" \
    2>&1 | tee "$OUT_DIR/deploy-${CHAIN_ID}.log"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Round-2 Deployment Complete — records in $OUT_DIR"
echo "═══════════════════════════════════════════════════════════════"
