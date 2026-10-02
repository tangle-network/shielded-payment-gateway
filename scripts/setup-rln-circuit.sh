#!/usr/bin/env bash
# Groth16 setup for the RLN payment circuit (circuits/main/rln_payment_2_8.circom).
#
# The RLN circuit composes protocol-solidity's VAnchor Transaction circuit
# with an RLN sub-circuit (rate-limited nullifier + Shamir share). It reuses
# the same public Hermez powers-of-tau as the VAnchor ceremony and gets a
# deterministic dev-only phase-2 contribution.
#
# Prerequisites: circom, snarkjs (npx), protocol-solidity submodule, circomlib
# (see scripts/e2e-local.sh which provisions both).
#
# Output:
#   build/circuits/rln_payment_2_8/
#     rln_payment_2_8_js/rln_payment_2_8.wasm
#     circuit_final.zkey
#     verification_key.json
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PTAU_SIZE="${PTAU_SIZE:-18}"
PTAU_FILE="$ROOT_DIR/build/trusted-setup/powersOfTau28_hez_final_${PTAU_SIZE}.ptau"
OUT_DIR="$ROOT_DIR/build/circuits/rln_payment_2_8"
CIRCUIT="rln_payment_2_8"

if [ -f "$OUT_DIR/circuit_final.zkey" ] && [ -f "$OUT_DIR/verification_key.json" ]; then
    echo "RLN circuit artifacts already present — skipping."
    exit 0
fi

if [ ! -f "$PTAU_FILE" ]; then
    echo "ERROR: powers-of-tau not found at $PTAU_FILE"
    echo "Run scripts/trusted-setup/ceremony.sh first (it downloads the ptau)."
    exit 1
fi

# The RLN circuit includes ../vanchor/transaction.circom et al. relative to
# circuits/ — link them from the protocol-solidity submodule.
for d in vanchor merkle-tree set; do
    ln -sfn "../dependencies/protocol-solidity/circuits/$d" "$ROOT_DIR/circuits/$d"
done

mkdir -p "$OUT_DIR"

if [ ! -f "$OUT_DIR/${CIRCUIT}_js/${CIRCUIT}.wasm" ]; then
    echo "Compiling $CIRCUIT..."
    circom --r1cs --wasm --sym \
        -l "$ROOT_DIR/dependencies/protocol-solidity/node_modules" \
        -o "$OUT_DIR" \
        "$ROOT_DIR/circuits/main/${CIRCUIT}.circom"
fi

if [ ! -f "$OUT_DIR/circuit_final.zkey" ]; then
    echo "Groth16 setup..."
    npx snarkjs groth16 setup "$OUT_DIR/${CIRCUIT}.r1cs" "$PTAU_FILE" "$OUT_DIR/circuit_0000.zkey"

    echo "Contributing (dev-only deterministic entropy)..."
    echo "tangle-rln-setup" | npx snarkjs zkey contribute \
        "$OUT_DIR/circuit_0000.zkey" "$OUT_DIR/circuit_0001.zkey" \
        --name="Tangle RLN contribution" -v

    echo "Applying beacon..."
    npx snarkjs zkey beacon \
        "$OUT_DIR/circuit_0001.zkey" "$OUT_DIR/circuit_final.zkey" \
        0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 \
        -n="Final Beacon phase2"

    npx snarkjs zkey verify "$OUT_DIR/${CIRCUIT}.r1cs" "$PTAU_FILE" "$OUT_DIR/circuit_final.zkey"
    rm -f "$OUT_DIR/circuit_0000.zkey" "$OUT_DIR/circuit_0001.zkey"
fi

npx snarkjs zkey export verificationkey \
    "$OUT_DIR/circuit_final.zkey" "$OUT_DIR/verification_key.json"

echo "RLN circuit artifacts staged in $OUT_DIR"
