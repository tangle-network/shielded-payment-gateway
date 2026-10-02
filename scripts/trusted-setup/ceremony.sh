#!/usr/bin/env bash
# Groth16 trusted setup for VAnchor (and optionally RLN payment) circuits.
#
# Phase 1 comes from the PUBLIC Perpetual Powers of Tau ceremony
# (ppot_0080_N.ptau — the PSE/Semaphore community ceremony extending
# the original Hermez parameters — many independent contributors, 1-of-N
# honest assumption). We never run our own phase 1. The ppot_0080 file is
# selected per circuit at the smallest power that fits the constraint
# count, so no multi-GB download is needed (override with --ptau-size).
#
# Phase 2 is circuit-specific and cannot be reused from the public
# ceremony. It runs as a MULTI-CONTRIBUTOR chain via
# scripts/trusted-setup/lib-ceremony.sh: N real-entropy contributions
# (one optionally executed on a second machine over SSH for multi-machine
# independence), finalized with a drand (League of Entropy)
# public-randomness beacon. Every step is recorded in
# build/trusted-setup/ceremony-attestation.jsonl (timestamps, machines,
# contribution hashes, sha256 of every intermediate).
#
# Prerequisites:
#   - Node.js >= 18 (for snarkjs)
#   - Rust toolchain (for circom compiler)
#   - jq + curl (for the drand beacon fetch)
#
# Usage:
#   ./scripts/trusted-setup/ceremony.sh [--skip-compile] [--with-rln]
#                                        [--ptau-size N]
#
# Environment:
#   PTAU_SIZE              Override the per-circuit powers-of-tau power.
#   CEREMONY_CONTRIBUTIONS Local contributions per circuit (default 3).
#   CEREMONY_REMOTE_TARGET ssh target for one remote contribution
#                          (e.g. "root@88.99.85.9"); unset = all local.
#   CEREMONY_REMOTE_INDEX  1-based contribution index executed remotely.
#   See lib-ceremony.sh for the full list of knobs.
#
# Output:
#   build/trusted-setup/
#     ├── circuits/           (compiled R1CS + WASM)
#     ├── zkeys/              (final zkey files)
#     ├── verification_keys/  (JSON verification keys)
#     ├── verifiers/          (Solidity verifier contracts)
#     ├── beacon-proofs/      (raw drand fetch proofs per circuit)
#     └── ceremony-attestation.jsonl
#   build/circuits/           (SDK/e2e-test layout: wasm + zkey + vkey + verifier)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROTOCOL_SOL_DIR="$ROOT_DIR/dependencies/protocol-solidity"
CIRCUITS_DIR="$PROTOCOL_SOL_DIR/circuits"

BUILD_DIR="$ROOT_DIR/build/trusted-setup"
CIRCUITS_OUT="$BUILD_DIR/circuits"
ZKEYS_OUT="$BUILD_DIR/zkeys"
VKEYS_OUT="$BUILD_DIR/verification_keys"
VERIFIERS_OUT="$BUILD_DIR/verifiers"
BEACON_PROOFS_OUT="$BUILD_DIR/beacon-proofs"
SDK_CIRCUITS_OUT="$ROOT_DIR/build/circuits"

# Attestation log for the whole ceremony (JSONL, one event per step).
export CEREMONY_ATTEST_LOG="${CEREMONY_ATTEST_LOG:-$BUILD_DIR/ceremony-attestation.jsonl}"

# shellcheck source=lib-ceremony.sh
source "$SCRIPT_DIR/lib-ceremony.sh"

# Optional override for the powers-of-tau power. By default the smallest
# power that fits each circuit's constraint count is chosen automatically.
PTAU_SIZE="${PTAU_SIZE:-}"
SKIP_COMPILE="${SKIP_COMPILE:-false}"
WITH_RLN="${WITH_RLN:-false}"

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-compile) SKIP_COMPILE=true; shift ;;
        --with-rln)     WITH_RLN=true; shift ;;
        --ptau-size)    PTAU_SIZE="$2"; shift 2 ;;
        --ptau-size=*)  PTAU_SIZE="${1#*=}"; shift ;;
        *)              echo "Unknown flag: $1"; exit 1 ;;
    esac
done

# The four VAnchor circuits needed for VAnchorVerifier:
#   poseidon_vanchor_2_2   (2 inputs, 2 edges)
#   poseidon_vanchor_16_2  (16 inputs, 2 edges)
#   poseidon_vanchor_2_8   (2 inputs, 8 edges)
#   poseidon_vanchor_16_8  (16 inputs, 8 edges)
CIRCUITS=(
    "poseidon_vanchor_2_2"
    "poseidon_vanchor_16_2"
    "poseidon_vanchor_2_8"
    "poseidon_vanchor_16_8"
)

# Optional: the RLN payment circuit (circuits/main/rln_payment_2_8.circom).
# Off-chain verified today; keys are still needed by the RLN prover/verifier.
if [ "$WITH_RLN" = "true" ]; then
    CIRCUITS+=("rln_payment_2_8")
fi

# ============================================================================
# Dependency checks
# ============================================================================

check_deps() {
    echo "Checking dependencies..."

    if ! command -v node &>/dev/null; then
        echo "ERROR: Node.js not found. Install Node.js >= 18."
        exit 1
    fi

    if ! command -v npx &>/dev/null; then
        echo "ERROR: npx not found. Install Node.js >= 18."
        exit 1
    fi

    if ! command -v jq &>/dev/null; then
        echo "ERROR: jq not found (needed for the drand beacon fetch)."
        exit 1
    fi

    # Resolve snarkjs: needs >= 0.7 (older releases crash on modern Node).
    # NOTE: `snarkjs --version` prints the version banner but exits non-zero,
    # so capture output instead of checking exit codes (pipefail is on).
    SNARKJS="${SNARKJS:-}"
    local snarkjs_ok='snarkjs@0\.([7-9]|[1-9][0-9])'
    if [ -z "$SNARKJS" ]; then
        local path_ver=""
        if command -v snarkjs &>/dev/null; then
            path_ver="$(snarkjs --version 2>&1 || true)"
        fi
        if grep -qE "$snarkjs_ok" <<< "$path_ver"; then
            SNARKJS="snarkjs"
        else
            SNARKJS="npx --yes snarkjs@^0.7"
        fi
    fi
    local snarkjs_ver
    snarkjs_ver="$($SNARKJS --version 2>&1 || true)"
    if ! grep -qE "$snarkjs_ok" <<< "$snarkjs_ver"; then
        echo "ERROR: snarkjs >= 0.7 not found. Install: npm install -g snarkjs@latest"
        exit 1
    fi
    echo "  snarkjs: $(head -1 <<< "$snarkjs_ver")"
    # Hand the resolved snarkjs to lib-ceremony.sh's snarkjs_run.
    export SNARKJS_BIN="${SNARKJS_BIN:-$SNARKJS}"

    # Check circom
    CIRCOM_BIN="${CIRCOM_BIN:-}"
    if command -v circom &>/dev/null; then
        CIRCOM_BIN="circom"
    elif [ -x "$HOME/.cargo/bin/circom" ]; then
        CIRCOM_BIN="$HOME/.cargo/bin/circom"
    else
        echo "ERROR: circom not found."
        echo "Install: git clone https://github.com/iden3/circom.git && cd circom && cargo build --release && cargo install --path circom"
        exit 1
    fi
    echo "  circom: $($CIRCOM_BIN --version 2>/dev/null || echo 'installed')"

    # Check protocol-solidity circuits exist
    if [ ! -d "$CIRCUITS_DIR/main" ]; then
        echo "ERROR: protocol-solidity circuits not found at $CIRCUITS_DIR/main"
        echo "Run: git submodule update --init dependencies/protocol-solidity"
        exit 1
    fi
    echo "  circuits: $CIRCUITS_DIR/main"

    # protocol-solidity circuits include ../../node_modules/circomlib/...
    # A fresh submodule checkout has no node_modules, so bootstrap circomlib.
    if [ ! -d "$PROTOCOL_SOL_DIR/node_modules/circomlib/circuits" ]; then
        echo "  Installing circomlib into protocol-solidity (needed by circuit includes)..."
        npm install --prefix "$PROTOCOL_SOL_DIR" --no-save --no-audit --no-fund circomlib@2.0.5
    fi
    echo "  circomlib: $PROTOCOL_SOL_DIR/node_modules/circomlib"

    echo "All dependencies OK."
    echo ""
}

# ============================================================================
# Step 1: Powers-of-tau (public ppot_0080 ceremony, per-circuit size)
# ============================================================================

# Smallest power of two >= n
ceil_log2() {
    local n="$1" p=0
    while (( (1 << p) < n )); do p=$((p + 1)); done
    echo "$p"
}

# Read the constraint count of a compiled R1CS via snarkjs.
r1cs_constraints() {
    $SNARKJS r1cs info "$1" 2>/dev/null | grep -oE "# of Constraints: *[0-9]+" | grep -oE "[0-9]+"
}

# Base URL for public Powers of Tau files. Default: Perpetual Powers of
# Tau (ppot_0080) — the PSE/Semaphore community ceremony, which extends the
# original Hermez ceremony with dozens of additional contributors. The old
# Hermez zkevm GCS mirror (storage.googleapis.com/zkevm/ptau) is dead (403).
# Override via PTAU_BASE_URL (must serve ppot_0080_<N>.ptau naming).
PTAU_BASE_URL="${PTAU_BASE_URL:-https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080}"

# Ensure the public ptau file for the given power exists; echo its path.
ensure_ptau() {
    local power="$1"
    local ptau_file="$BUILD_DIR/ppot_0080_${power}.ptau"

    if [ -f "$ptau_file" ] && [ "$(head -c 4 "$ptau_file")" = "ptau" ]; then
        echo "$ptau_file"
        return
    fi
    rm -f "$ptau_file"

    mkdir -p "$BUILD_DIR"
    local url="${PTAU_BASE_URL}/ppot_0080_${power}.ptau"
    echo "Downloading public powers-of-tau ppot_0080_${power} ($url)..." >&2
    if command -v curl &>/dev/null; then
        curl -sfL --progress-bar -o "$ptau_file" "$url" >&2 || {
            echo "ERROR: download failed: $url" >&2; rm -f "$ptau_file"; exit 1; }
    elif command -v wget &>/dev/null; then
        wget -q --show-progress -O "$ptau_file" "$url" >&2 || {
            echo "ERROR: download failed: $url" >&2; rm -f "$ptau_file"; exit 1; }
    else
        echo "ERROR: curl or wget required to download ptau file." >&2
        exit 1
    fi

    # Sanity-check the binary format before handing it to snarkjs.
    if [ "$(head -c 4 "$ptau_file")" != "ptau" ]; then
        echo "ERROR: downloaded file is not a valid ptau (bad magic): $ptau_file" >&2
        rm -f "$ptau_file"
        exit 1
    fi

    echo "$ptau_file"
}

# ============================================================================
# Step 2: Compile circuits
# ============================================================================

# Extra circom -l flags for circuits whose includes resolve outside their
# own directory (the RLN payment circuit includes circomlib + protocol-solidity's
# vanchor/transaction.circom).
circuit_circom_libs() {
    case "$1" in
        rln_payment_2_8)
            echo "-l $PROTOCOL_SOL_DIR/node_modules -l $CIRCUITS_DIR/main"
            ;;
        *)
            echo ""
            ;;
    esac
}

circuit_source() {
    case "$1" in
        rln_payment_2_8)
            echo "$ROOT_DIR/circuits/main/rln_payment_2_8.circom"
            ;;
        *)
            echo "$CIRCUITS_DIR/main/${1}.circom"
            ;;
    esac
}

compile_circuit() {
    local circuit_name="$1"
    local out_dir="$CIRCUITS_OUT/$circuit_name"

    if [ -f "$out_dir/${circuit_name}.r1cs" ] && [ -f "$out_dir/${circuit_name}_js/${circuit_name}.wasm" ]; then
        echo "  Circuit already compiled: $circuit_name"
        return
    fi

    echo "  Compiling: $circuit_name"
    mkdir -p "$out_dir"

    # shellcheck disable=SC2086
    "$CIRCOM_BIN" \
        --r1cs --wasm --sym \
        -o "$out_dir" \
        $(circuit_circom_libs "$circuit_name") \
        "$(circuit_source "$circuit_name")"

    echo "    R1CS: $out_dir/${circuit_name}.r1cs"
    echo "    WASM: $out_dir/${circuit_name}_js/${circuit_name}.wasm"
}

compile_all_circuits() {
    if [ "$SKIP_COMPILE" = "true" ]; then
        echo "Skipping circuit compilation (--skip-compile)."
        return
    fi

    echo "Compiling circuits..."
    for circuit in "${CIRCUITS[@]}"; do
        compile_circuit "$circuit"
    done
    echo "All circuits compiled."
    echo ""
}

# ============================================================================
# Step 3: Phase 2 ceremony (per circuit)
# ============================================================================

# Portable in-place sed (GNU and BSD).
sed_inplace() {
    sed -i.bak "$1" "$2" && rm -f "$2.bak"
}

phase2_ceremony() {
    local circuit_name="$1"
    local r1cs="$CIRCUITS_OUT/$circuit_name/${circuit_name}.r1cs"
    local zkey_dir="$ZKEYS_OUT/$circuit_name"
    local final_zkey="$zkey_dir/circuit_final.zkey"

    # poseidon_vanchor_2_2  => Verifier2_2   (edges=2, inputs=2)
    # poseidon_vanchor_16_2 => Verifier2_16  (edges=2, inputs=16)
    # poseidon_vanchor_2_8  => Verifier8_2   (edges=8, inputs=2)
    # poseidon_vanchor_16_8 => Verifier8_16  (edges=8, inputs=16)
    local verifier_name
    verifier_name=$(echo "$circuit_name" | sed -E 's/poseidon_vanchor_([0-9]+)_([0-9]+)/Verifier\2_\1/')

    # Only skip when ALL outputs exist: final zkey, verification key, and a
    # renamed Solidity verifier. (A previous run may have died mid-export.)
    if [ -f "$final_zkey" ] \
        && [ -f "$VKEYS_OUT/${circuit_name}_verification_key.json" ] \
        && grep -q "contract ${verifier_name} " "$VERIFIERS_OUT/${circuit_name}_verifier.sol" 2>/dev/null; then
        echo "  Phase 2 already complete: $circuit_name"
        return
    fi

    if [ ! -f "$r1cs" ]; then
        echo "ERROR: R1CS not found: $r1cs"
        echo "Run without --skip-compile first."
        exit 1
    fi

    # Pick the smallest public ppot_0080 ptau that fits this circuit.
    local constraints power
    constraints=$(r1cs_constraints "$r1cs")
    power=$(ceil_log2 "$constraints")
    if [ -n "$PTAU_SIZE" ] && (( PTAU_SIZE > power )); then
        power="$PTAU_SIZE"
    fi
    local ptau_file
    ptau_file=$(ensure_ptau "$power")

    echo "  Running phase 2 for: $circuit_name"
    echo "    constraints: $constraints  (ptau 2^${power})"
    mkdir -p "$zkey_dir"

    # Multi-contributor chain: groth16 setup -> N real-entropy contributions
    # (one remote over SSH when CEREMONY_REMOTE_TARGET is set) -> drand
    # public-randomness beacon. sha256 of every intermediate lands in
    # $CEREMONY_ATTEST_LOG (see lib-ceremony.sh). Skips itself when the
    # final zkey already exists (previous run died during export).
    run_contribution_chain "$circuit_name" "$r1cs" "$ptau_file" "$zkey_dir" "$BEACON_PROOFS_OUT"

    # Final verification against R1CS + ptau
    echo "    Final verification..."
    snarkjs_run zkey verify "$r1cs" "$ptau_file" "$final_zkey"

    echo "    Done: $circuit_name"
}

# Export verification key + Solidity verifier from the final zkey.
# Idempotent: safe to re-run without re-doing the phase-2 contributions.
export_artifacts() {
    local circuit_name="$1"
    local final_zkey="$ZKEYS_OUT/$circuit_name/circuit_final.zkey"

    if [ ! -f "$final_zkey" ]; then
        echo "ERROR: final zkey missing: $final_zkey"
        exit 1
    fi

    # Export verification key
    mkdir -p "$VKEYS_OUT"
    $SNARKJS zkey export verificationkey \
        "$final_zkey" \
        "$VKEYS_OUT/${circuit_name}_verification_key.json"

    # Export Solidity verifier
    mkdir -p "$VERIFIERS_OUT"
    $SNARKJS zkey export solidityverifier \
        "$final_zkey" \
        "$VERIFIERS_OUT/${circuit_name}_verifier.sol"

    # Rename the contract to match protocol-solidity convention.
    # poseidon_vanchor_2_2  => Verifier2_2   (edges=2, inputs=2)
    # poseidon_vanchor_16_2 => Verifier2_16  (edges=2, inputs=16)
    # poseidon_vanchor_2_8  => Verifier8_2   (edges=8, inputs=2)
    # poseidon_vanchor_16_8 => Verifier8_16  (edges=8, inputs=16)
    # snarkjs >= 0.7 exports `contract Groth16Verifier`, older exports `contract Verifier`.
    if [[ "$circuit_name" =~ ^poseidon_vanchor_([0-9]+)_([0-9]+)$ ]]; then
        local verifier_name="Verifier${BASH_REMATCH[2]}_${BASH_REMATCH[1]}"
        sed_inplace "s/contract Groth16Verifier/contract ${verifier_name}/" \
            "$VERIFIERS_OUT/${circuit_name}_verifier.sol"
        sed_inplace "s/contract Verifier /contract ${verifier_name} /" \
            "$VERIFIERS_OUT/${circuit_name}_verifier.sol"
    fi

    # Pre-0.7 snarkjs exports `pragma solidity ^0.6.11;` — bump it so the
    # verifier compiles under the repo's 0.8.x toolchain (no-op for >= 0.7).
    sed_inplace 's/pragma solidity ^0.6.11;/pragma solidity ^0.8.18;/' \
        "$VERIFIERS_OUT/${circuit_name}_verifier.sol"
}

# Copy ceremony artifacts into the layout the SDK and e2e tests expect:
#   build/circuits/vanchor_2_8/
#     ├── poseidon_vanchor_2_8_js/poseidon_vanchor_2_8.wasm
#     ├── circuit_final.zkey
#     ├── verification_key.json
#     └── Verifier8_2.sol
sync_sdk_layout() {
    local circuit_name="$1"
    local out_dir

    if [[ "$circuit_name" =~ ^poseidon_vanchor_([0-9]+)_([0-9]+)$ ]]; then
        out_dir="$SDK_CIRCUITS_OUT/vanchor_${BASH_REMATCH[1]}_${BASH_REMATCH[2]}"
    else
        out_dir="$SDK_CIRCUITS_OUT/$circuit_name"
    fi

    mkdir -p "$out_dir"
    cp -R "$CIRCUITS_OUT/$circuit_name/${circuit_name}_js" "$out_dir/"
    cp "$ZKEYS_OUT/$circuit_name/circuit_final.zkey" "$out_dir/"
    cp "$VKEYS_OUT/${circuit_name}_verification_key.json" "$out_dir/verification_key.json"

    if [[ "$circuit_name" =~ ^poseidon_vanchor_([0-9]+)_([0-9]+)$ ]]; then
        cp "$VERIFIERS_OUT/${circuit_name}_verifier.sol" \
            "$out_dir/Verifier${BASH_REMATCH[2]}_${BASH_REMATCH[1]}.sol"
    fi

    echo "  SDK layout synced: $out_dir"
}

run_all_phase2() {
    echo "Running phase 2 ceremonies..."
    for circuit in "${CIRCUITS[@]}"; do
        phase2_ceremony "$circuit"
        export_artifacts "$circuit"
        sync_sdk_layout "$circuit"
    done
    echo "All phase 2 ceremonies complete."
    echo ""
}

# ============================================================================
# Poseidon deployment instructions
# ============================================================================

print_poseidon_deploy_instructions() {
    cat <<'POSEIDON_INSTRUCTIONS'
============================================================
NEXT STEPS: Deploy Poseidon libraries
============================================================

Poseidon hash functions require bytecode generated by circomlibjs.
They cannot be compiled from Solidity source alone.

Deploy them using this Node.js snippet:

  const { ethers } = require("ethers");
  const { buildPoseidon } = require("circomlibjs");

  async function deployPoseidon(signer) {
    const poseidon = await buildPoseidon();
    for (let nInputs = 1; nInputs <= 5; nInputs++) {
      const abi = poseidon.contract.generateABI(nInputs);
      const bytecode = poseidon.contract.createCode(nInputs);
      const factory = new ethers.ContractFactory(abi, bytecode, signer);
      const contract = await factory.deploy();
      await contract.waitForDeployment();
      console.log(`PoseidonT${nInputs + 1}: ${await contract.getAddress()}`);
    }
  }

Then set the addresses in your deploy-config JSON or env vars.

POSEIDON_INSTRUCTIONS
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    echo "============================================================"
    echo "TRUSTED SETUP COMPLETE"
    echo "============================================================"
    echo ""
    echo "Artifacts:"
    echo "  Circuits:           $CIRCUITS_OUT/"
    echo "  ZKeys:              $ZKEYS_OUT/"
    echo "  Verification keys:  $VKEYS_OUT/"
    echo "  Solidity verifiers: $VERIFIERS_OUT/"
    echo "  Beacon proofs:      $BEACON_PROOFS_OUT/"
    echo "  Attestation log:    $CEREMONY_ATTEST_LOG"
    echo "  SDK/test layout:    $SDK_CIRCUITS_OUT/"
    echo ""
    echo "Trust model:"
    echo "  Phase 1: public Perpetual Powers of Tau ppot_0080 (1-of-N community ceremony)"
    echo "  Phase 2: ${CEREMONY_CONTRIBUTIONS:-3} real-entropy contributions per circuit"
    echo "           (one remote when CEREMONY_REMOTE_TARGET is set) + drand beacon."
    echo "           Keys are safe if at least one participant destroyed their entropy."
    echo ""
    echo "Generated verifier contracts:"
    for circuit in "${CIRCUITS[@]}"; do
        echo "  $VERIFIERS_OUT/${circuit}_verifier.sol"
    done
    echo ""
    echo "To use with DeployShieldedPool.s.sol:"
    echo "  1. Deploy the Solidity verifier contracts above"
    echo "  2. Deploy Poseidon libraries (see instructions above)"
    echo "  3. Set addresses in script/deploy-config/*-shielded.json"
    echo "  4. Run: forge script script/DeployShieldedPool.s.sol:DeployShieldedPool --rpc-url \$RPC --broadcast --slow"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "============================================================"
    echo "Tangle Shielded Pool - Groth16 Setup (public Powers of Tau)"
    echo "============================================================"
    echo ""

    check_deps
    compile_all_circuits
    run_all_phase2
    print_poseidon_deploy_instructions
    print_summary
}

main
