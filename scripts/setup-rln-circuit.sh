#!/usr/bin/env bash
# Groth16 setup for the RLN payment circuit (circuits/main/rln_payment_2_8.circom).
#
# The RLN circuit composes protocol-solidity's VAnchor Transaction circuit
# with an RLN sub-circuit (rate-limited nullifier + Shamir share). It reuses
# the same public Hermez powers-of-tau as the VAnchor ceremony and runs the
# same multi-contributor phase-2 chain (real entropy, optional SSH remote
# contribution, drand beacon) via scripts/trusted-setup/lib-ceremony.sh.
#
# Prerequisites: circom, snarkjs (npx or SNARKJS_BIN), protocol-solidity
# submodule, circomlib (see scripts/e2e-local.sh which provisions both).
#
# Output:
#   build/circuits/rln_payment_2_8/
#     rln_payment_2_8_js/rln_payment_2_8.wasm
#     circuit_final.zkey
#     verification_key.json
#     rln_payment_2_8_verifier.sol   (Solidity verifier, contract RlnPaymentVerifier)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PTAU_SIZE="${PTAU_SIZE:-18}"
PTAU_FILE="$ROOT_DIR/build/trusted-setup/ppot_0080_${PTAU_SIZE}.ptau"
OUT_DIR="$ROOT_DIR/build/circuits/rln_payment_2_8"
CIRCUIT="rln_payment_2_8"

export CEREMONY_ATTEST_LOG="${CEREMONY_ATTEST_LOG:-$ROOT_DIR/build/trusted-setup/ceremony-attestation.jsonl}"
# shellcheck source=trusted-setup/lib-ceremony.sh
source "$ROOT_DIR/scripts/trusted-setup/lib-ceremony.sh"

if [ -f "$OUT_DIR/circuit_final.zkey" ] && [ -f "$OUT_DIR/verification_key.json" ] \
    && [ -f "$OUT_DIR/rln_payment_2_8_verifier.sol" ]; then
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
    run_contribution_chain "$CIRCUIT" "$OUT_DIR/${CIRCUIT}.r1cs" "$PTAU_FILE" "$OUT_DIR" \
        "$ROOT_DIR/build/trusted-setup/beacon-proofs"

    echo "Final verification..."
    snarkjs_run zkey verify "$OUT_DIR/${CIRCUIT}.r1cs" "$PTAU_FILE" "$OUT_DIR/circuit_final.zkey"
fi

snarkjs_run zkey export verificationkey \
    "$OUT_DIR/circuit_final.zkey" "$OUT_DIR/verification_key.json"

snarkjs_run zkey export solidityverifier \
    "$OUT_DIR/circuit_final.zkey" "$OUT_DIR/rln_payment_2_8_verifier.sol"
sed_i=(sed -i)
if sed --version 2>/dev/null | grep -q GNU; then sed_i=(sed -i); else sed_i=(sed -i ''); fi
"${sed_i[@]}" -E "s/contract (Groth16Verifier|Verifier) /contract RlnPaymentVerifier /" \
    "$OUT_DIR/rln_payment_2_8_verifier.sol"
"${sed_i[@]}" 's/pragma solidity ^0.6.11;/pragma solidity ^0.8.18;/' \
    "$OUT_DIR/rln_payment_2_8_verifier.sol"

echo "RLN circuit artifacts staged in $OUT_DIR"
