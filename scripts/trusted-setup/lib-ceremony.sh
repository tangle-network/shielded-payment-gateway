#!/usr/bin/env bash
# Shared phase-2 ceremony machinery for the shielded-payment-gateway circuits.
#
# Sourced by scripts/trusted-setup/ceremony.sh (VAnchor circuits) and
# scripts/setup-rln-circuit.sh (RLN payment circuit). Not meant to be run
# directly.
#
# Provides:
#   - multi-contributor zkey chains with REAL entropy
#       (OS CSPRNG mixed by snarkjs + an independent per-contribution
#        -e entropy string built from two separate /dev/urandom reads and
#        machine-unique material)
#   - an optional REMOTE contribution executed over SSH on a second machine
#     for genuine multi-machine independence
#   - a verifiable public-randomness beacon (drand League of Entropy round,
#     with a Bitcoin tip-hash cross-reference), fetch proof saved to disk
#   - a JSONL attestation log recording every step: timestamp, machine,
#     contribution hashes, sha256 of every intermediate zkey
#
# Environment knobs:
#   SNARKJS_BIN                 snarkjs executable (default: "npx snarkjs")
#   CEREMONY_CONTRIBUTIONS      local contributions per circuit (default 3,
#                               one slot is replaced by the remote run when
#                               CEREMONY_REMOTE_TARGET is set)
#   CEREMONY_REMOTE_TARGET      ssh target for the remote contribution
#                               (e.g. "root@88.99.85.9"); unset = all local
#   CEREMONY_REMOTE_SSH_OPTS    ssh/scp options (e.g. "-i ~/.ssh/key -o BatchMode=yes")
#   CEREMONY_REMOTE_DIR         remote work dir containing node + snarkjs
#                               (default /root/spg-ceremony)
#   CEREMONY_REMOTE_INDEX       1-based contribution index executed remotely
#                               (default 2)
#   CEREMONY_ATTEST_LOG         attestation JSONL path (required by callers)

sha256_file() {
    if command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

attest() {
    # attest <json-payload-without-braces>
    printf '{%s}\n' "$1" >> "$CEREMONY_ATTEST_LOG"
}

# Independent user-entropy for one contribution: two SEPARATE /dev/urandom
# reads (each 64 bytes) plus machine-unique material and the contribution
# label, hashed together. snarkjs additionally mixes 64 bytes of its own
# crypto.randomBytes into the RNG seed, so every contribution draws on two
# independent sources. Only the sha256 of the entropy string is attested.
make_entropy() {
    local label="$1"
    local r1 r2 machine
    r1=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
    r2=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
    machine="$(hostname)|$(uname -a)|$(date +%s%N 2>/dev/null || date +%s)|$$"
    printf '%s|%s|%s|%s' "$r1" "$r2" "$machine" "$label" | shasum -a 256 | awk '{print $1}'
}

snarkjs_run() {
    if [ -n "${SNARKJS_BIN:-}" ]; then
        # SNARKJS_BIN may be multi-word (e.g. "npx --yes snarkjs@^0.7").
        # shellcheck disable=SC2086
        $SNARKJS_BIN "$@"
    else
        npx snarkjs "$@"
    fi
}

# Extract a snarkjs multi-line "Contribution Hash:" block (grouped hex over
# several indented lines) into a single hex string.
extract_contrib_hash() {
    awk '
        /Contribution Hash/ { capture=1; next }
        capture && /^[[:space:]]*[0-9a-f]/ { gsub(/[^0-9a-f]/, ""); printf "%s", $0; next }
        capture { capture=0 }
    ' "$1"
}

# local_contribute <in.zkey> <out.zkey> <name> <circuit> <step-label>
local_contribute() {
    local in_z="$1" out_z="$2" name="$3" circuit="$4" step="$5"
    local entropy entropy_sha in_sha out_sha contrib_hash log
    entropy=$(make_entropy "${circuit}/${step}/${name}")
    entropy_sha=$(printf '%s' "$entropy" | shasum -a 256 | awk '{print $1}')
    in_sha=$(sha256_file "$in_z")

    log=$(mktemp)
    snarkjs_run zkey contribute "$in_z" "$out_z" -n="$name" -v -e="$entropy" | tee "$log"
    contrib_hash=$(extract_contrib_hash "$log")
    rm -f "$log"
    # zero the local entropy copy
    entropy=""

    out_sha=$(sha256_file "$out_z")
    attest "\"ts\":\"$(utc_now)\",\"circuit\":\"$circuit\",\"step\":\"$step\",\"type\":\"contribute\",\"machine\":\"$(hostname) (local)\",\"name\":\"$name\",\"entropy\":\"sha256(entropy-string)=$entropy_sha; snarkjs additionally mixed 64B OS CSPRNG\",\"contribution_hash\":\"$contrib_hash\",\"in_sha256\":\"$in_sha\",\"out_sha256\":\"$out_sha\""
}

# remote_contribute <in.zkey> <out.zkey> <name> <circuit> <step-label>
# Ships the intermediate zkey to CEREMONY_REMOTE_TARGET, runs the contribution
# there (entropy generated on the remote box, never transmitted), ships back.
remote_contribute() {
    local in_z="$1" out_z="$2" name="$3" circuit="$4" step="$5"
    local target="$CEREMONY_REMOTE_TARGET"
    local opts="${CEREMONY_REMOTE_SSH_OPTS:-}"
    local rdir="${CEREMONY_REMOTE_DIR:-/root/spg-ceremony}"
    local in_sha out_sha remote_result

    in_sha=$(sha256_file "$in_z")
    local base="${circuit}_${step}"
    # shellcheck disable=SC2086
    ssh $opts "$target" "mkdir -p '$rdir/work'"
    echo "    [remote] uploading $(basename "$in_z") to $target ..."
    # shellcheck disable=SC2086
    scp $opts -q "$in_z" "$target:$rdir/work/${base}_in.zkey"

    echo "    [remote] contributing on $target ..."
    remote_result=$(
        # shellcheck disable=SC2086
        ssh $opts "$target" bash -s <<EOF
set -euo pipefail
cd "$rdir"
export PATH="$rdir/node-v22.20.0-linux-x64/bin:\$PATH"
r1=\$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
r2=\$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
entropy=\$(printf '%s|%s|%s|%s' "\$r1" "\$r2" "\$(hostname)|\$(uname -a)" "$name" | sha256sum | awk '{print \$1}')
echo "REMOTE_HOST=\$(hostname)"
echo "REMOTE_UNAME=\$(uname -srm)"
echo "ENTROPY_SHA=\$(printf '%s' "\$entropy" | sha256sum | awk '{print \$1}')"
./node_modules/.bin/snarkjs zkey contribute "work/${base}_in.zkey" "work/${base}_out.zkey" \
    -n="$name" -v -e="\$entropy" 2>&1 | tee "work/${base}_contrib.log" >/dev/null || true
echo "CONTRIB_HASH=\$(awk '/Contribution Hash/ {c=1; next} c && /^[[:space:]]*[0-9a-f]/ { gsub(/[^0-9a-f]/,""); printf "%s", \$0; next } c { c=0 }' "work/${base}_contrib.log")"
echo "OUT_SHA=\$(sha256sum "work/${base}_out.zkey" | awk '{print \$1}')"
rm -f "work/${base}_in.zkey" "work/${base}_contrib.log"
EOF
    )
    echo "$remote_result" | sed 's/^/    [remote] /'

    echo "    [remote] downloading result ..."
    # shellcheck disable=SC2086
    scp $opts -q "$target:$rdir/work/${base}_out.zkey" "$out_z"
    # shellcheck disable=SC2086
    ssh $opts "$target" "rm -f '$rdir/work/${base}_out.zkey'"

    local remote_host remote_uname remote_entropy_sha remote_out_sha remote_contrib_hash
    remote_host=$(grep '^REMOTE_HOST=' <<<"$remote_result" | cut -d= -f2)
    remote_uname=$(grep '^REMOTE_UNAME=' <<<"$remote_result" | cut -d= -f2)
    remote_entropy_sha=$(grep '^ENTROPY_SHA=' <<<"$remote_result" | cut -d= -f2)
    remote_out_sha=$(grep '^OUT_SHA=' <<<"$remote_result" | cut -d= -f2)
    remote_contrib_hash=$(grep '^CONTRIB_HASH=' <<<"$remote_result" | cut -d= -f2)

    out_sha=$(sha256_file "$out_z")
    if [ "$out_sha" != "$remote_out_sha" ]; then
        echo "ERROR: downloaded zkey sha256 mismatch (local $out_sha != remote $remote_out_sha)"
        exit 1
    fi

    attest "\"ts\":\"$(utc_now)\",\"circuit\":\"$circuit\",\"step\":\"$step\",\"type\":\"contribute\",\"machine\":\"$remote_host (REMOTE $target, $remote_uname)\",\"name\":\"$name\",\"entropy\":\"sha256(entropy-string)=$remote_entropy_sha; generated on remote /dev/urandom, never transmitted; snarkjs additionally mixed 64B remote OS CSPRNG\",\"contribution_hash\":\"$remote_contrib_hash\",\"in_sha256\":\"$in_sha\",\"out_sha256\":\"$out_sha\""
}

# fetch_beacon <proof-file-prefix>
# Fetches the latest drand (League of Entropy, api.drand.sh default chain)
# round — public randomness generated AFTER all contributions for this
# circuit — plus the current Bitcoin tip hash as a cross-reference.
# Saves raw fetch proof to disk and echoes the 32-byte beacon hex.
fetch_beacon() {
    local proof_prefix="$1"
    local drand_json drand_info btc_hash round randomness

    drand_json=$(curl -fsS --max-time 30 https://api.drand.sh/public/latest) || {
        echo "ERROR: failed to fetch drand round"; return 1; }
    drand_info=$(curl -fsS --max-time 30 https://api.drand.sh/info) || {
        echo "ERROR: failed to fetch drand chain info"; return 1; }
    btc_hash=$(curl -fsS --max-time 30 https://blockstream.info/api/blocks/tip/hash) || btc_hash="unavailable"

    round=$(jq -r '.round' <<<"$drand_json")
    randomness=$(jq -r '.randomness' <<<"$drand_json")
    if ! grep -qE '^[0-9a-f]{64}$' <<<"$randomness"; then
        echo "ERROR: unexpected drand randomness: $randomness"; return 1
    fi

    jq -n \
        --arg fetched_at "$(utc_now)" \
        --argjson drand_round "$drand_json" \
        --argjson drand_chain_info "$drand_info" \
        --arg bitcoin_tip_hash "$btc_hash" \
        '{fetched_at: $fetched_at, drand_api: "https://api.drand.sh", drand_round: $drand_round, drand_chain_info: $drand_chain_info, bitcoin_tip_hash_crossref: $bitcoin_tip_hash}' \
        > "${proof_prefix}.json"

    echo "$randomness"
}

# apply_beacon <in.zkey> <out.zkey> <circuit> <beacon-hex> <proof-file>
apply_beacon() {
    local in_z="$1" out_z="$2" circuit="$3" beacon_hex="$4" proof_file="$5"
    local in_sha out_sha round
    in_sha=$(sha256_file "$in_z")
    round=$(jq -r '.drand_round.round' "$proof_file")

    snarkjs_run zkey beacon "$in_z" "$out_z" "$beacon_hex" 10 \
        -n="drand round $round (League of Entropy, api.drand.sh)"

    out_sha=$(sha256_file "$out_z")
    attest "\"ts\":\"$(utc_now)\",\"circuit\":\"$circuit\",\"step\":\"beacon\",\"type\":\"beacon\",\"beacon\":\"drand round $round, randomness=$beacon_hex, proof=$proof_file\",\"in_sha256\":\"$in_sha\",\"out_sha256\":\"$out_sha\""
}

# run_contribution_chain <circuit> <r1cs> <ptau> <zkey_dir> <proof_dir>
# setup -> N contributions (one remote if configured) -> beacon.
# Leaves the final zkey at <zkey_dir>/circuit_final.zkey and removes
# intermediates after hashing them into the attestation log.
run_contribution_chain() {
    local circuit="$1" r1cs="$2" ptau="$3" zkey_dir="$4" proof_dir="$5"
    local n_contribs="${CEREMONY_CONTRIBUTIONS:-3}"
    local remote_index="${CEREMONY_REMOTE_INDEX:-2}"
    local final_zkey="$zkey_dir/circuit_final.zkey"

    mkdir -p "$zkey_dir" "$proof_dir"

    if [ -f "$final_zkey" ]; then
        echo "    Final zkey already exists: $final_zkey (skipping chain)"
        return
    fi

    echo "    Groth16 setup..."
    snarkjs_run groth16 setup "$r1cs" "$ptau" "$zkey_dir/circuit_0000.zkey"
    attest "\"ts\":\"$(utc_now)\",\"circuit\":\"$circuit\",\"step\":\"0000\",\"type\":\"groth16-setup\",\"r1cs_sha256\":\"$(sha256_file "$r1cs")\",\"ptau_sha256\":\"$(sha256_file "$ptau")\",\"out_sha256\":\"$(sha256_file "$zkey_dir/circuit_0000.zkey")\""

    local prev="$zkey_dir/circuit_0000.zkey" i next padded name
    for i in $(seq 1 "$n_contribs"); do
        padded=$(printf '%04d' "$i")
        next="$zkey_dir/circuit_${padded}.zkey"
        name="tangle-spg ${circuit} contribution ${i}/${n_contribs}"
        if [ -n "${CEREMONY_REMOTE_TARGET:-}" ] && [ "$i" = "$remote_index" ]; then
            echo "    Contribution $i/$n_contribs (REMOTE: $CEREMONY_REMOTE_TARGET)..."
            remote_contribute "$prev" "$next" "$name" "$circuit" "$padded"
        else
            echo "    Contribution $i/$n_contribs (local)..."
            local_contribute "$prev" "$next" "$name" "$circuit" "$padded"
        fi
        prev="$next"
    done

    echo "    Fetching public-randomness beacon..."
    local beacon_hex proof_file
    proof_file="$proof_dir/${circuit}_beacon_proof"
    beacon_hex=$(fetch_beacon "$proof_file")

    echo "    Applying beacon (drand round $(jq -r '.drand_round.round' "${proof_file}.json"))..."
    apply_beacon "$prev" "$final_zkey" "$circuit" "$beacon_hex" "${proof_file}.json"

    # Intermediates are no longer needed; their sha256 chain is in the log.
    rm -f "$zkey_dir"/circuit_0*.zkey
}
