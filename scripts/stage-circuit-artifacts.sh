#!/usr/bin/env bash
# Stage trusted-setup ceremony output into the layout the SDK tests expect.
#
#   build/trusted-setup/circuits/poseidon_vanchor_{i}_{e}/...   (ceremony output)
#   build/trusted-setup/zkeys/poseidon_vanchor_{i}_{e}/circuit_final.zkey
#   build/trusted-setup/verification_keys/poseidon_vanchor_{i}_{e}_verification_key.json
#   build/trusted-setup/verifiers/poseidon_vanchor_{i}_{e}_verifier.sol
#
# becomes:
#
#   build/circuits/vanchor_{i}_{e}/
#     poseidon_vanchor_{i}_{e}_js/poseidon_vanchor_{i}_{e}.wasm
#     circuit_final.zkey
#     verification_key.json
#     Verifier{e}_{i}.sol
#
# Usage: ./scripts/stage-circuit-artifacts.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TS_DIR="$ROOT_DIR/build/trusted-setup"
OUT_DIR="$ROOT_DIR/build/circuits"

for spec in "2 2" "16 2" "2 8" "16 8"; do
    read -r inputs edges <<<"$spec"
    name="poseidon_vanchor_${inputs}_${edges}"
    dst="$OUT_DIR/vanchor_${inputs}_${edges}"

    if [ ! -f "$TS_DIR/zkeys/$name/circuit_final.zkey" ]; then
        echo "ERROR: missing $TS_DIR/zkeys/$name/circuit_final.zkey"
        echo "Run scripts/trusted-setup/ceremony.sh first."
        exit 1
    fi

    mkdir -p "$dst"
    cp -R "$TS_DIR/circuits/$name/${name}_js" "$dst/"
    cp "$TS_DIR/zkeys/$name/circuit_final.zkey" "$dst/"
    cp "$TS_DIR/verification_keys/${name}_verification_key.json" "$dst/verification_key.json"
    cp "$TS_DIR/verifiers/${name}_verifier.sol" "$dst/Verifier${edges}_${inputs}.sol"
    echo "  staged build/circuits/vanchor_${inputs}_${edges}/"
done

# proof-e2e.test.ts looks up the 2_2 verification key one directory up
# (build/circuits/verification_key.json) — keep a copy there.
cp "$TS_DIR/verification_keys/poseidon_vanchor_2_2_verification_key.json" \
    "$OUT_DIR/verification_key.json"

echo "All circuit artifacts staged in $OUT_DIR"
