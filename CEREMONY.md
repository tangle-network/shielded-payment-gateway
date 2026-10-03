# Phase-2 Trusted Setup Ceremony — Shielded Payment Gateway Circuits

**Ceremony date:** 2026-10-02/03 (UTC timestamps below)
**Operator:** Drew (Tangle launch-gates agent fleet, "CEREMONY" agent)
**Scope:** Groth16 phase-2 for all 5 production circuits of the shielded payments stack:

| Circuit | Constraints | Public signals | Purpose |
|---|---|---|---|
| `poseidon_vanchor_2_2` | 17,682 | 17 | VAnchor join-split, 2 inputs / 2 edges |
| `poseidon_vanchor_2_8` | 17,694 | 17 | VAnchor join-split, 2 inputs / 8 edges |
| `poseidon_vanchor_16_2` | 133,931 | 23 | VAnchor join-split, 16 inputs / 2 edges |
| `poseidon_vanchor_16_8` | 134,027 | 29 | VAnchor join-split, 16 inputs / 8 edges |
| `rln_payment_2_8` | 23,546 | 17 | RLN rate-limited payment (VAnchor + RLN + EdDSA receipt) |

Circuits are compiled from `dependencies/protocol-solidity/circuits/main/*.circom`
(VAnchor) and `circuits/main/rln_payment_2_8.circom` (RLN) with circom 2.1.6;
snarkjs 0.7.5 was used for the whole ceremony on both machines.

## Phase 1 (powers of tau)

Public perpetual powers-of-tau, challenge **ppot_0080** (PSE ceremony: 54+
sequential contributors, finalized with a Bitcoin-block random beacon),
truncated to 2^18:

- File: `ppot_0080_18.ptau` (302,083,218 bytes)
- Source: `https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau`
- sha256: `9693220206afab749e3d88d4ab5fdf5d36120ea102e7e587ccea0e7a5208e711`
- Transcript verified with `snarkjs powersoftau verify` → **"Powers of Tau Ok!"** (2026-10-03)

## Contributors and machines

Each circuit received **3 independent contributions + 1 public-randomness
beacon**, chained sequentially (each contribution builds on the previous
zkey). Contribution #2 of every circuit was executed on a **different
physical machine** over SSH for genuine multi-machine independence.

| # | Machine | Location | Entropy sources (per contribution) |
|---|---|---|---|
| 1 | `Drews-MacBook-Pro.local` (macOS, arm64) | operator workstation | two separate 64-byte `/dev/urandom` reads + machine-unique material, hashed (fed via `snarkjs -e`); snarkjs additionally mixed 64 bytes of OS CSPRNG into the RNG seed |
| 2 | `router-origin-fsn1` (Hetzner CPX32, Falkenstein DE, `88.99.85.9`, Linux 6.8.0-117-generic x86_64, node v22.20.0) | remote, SSH | two separate 64-byte `/dev/urandom` reads **generated on the remote box, never transmitted** + remote machine-unique material; snarkjs additionally mixed 64 bytes of remote OS CSPRNG |
| 3 | `Drews-MacBook-Pro.local` | operator workstation | same construction as #1, fresh independent draws |
| 4 | **drand beacon** (League of Entropy, `api.drand.sh` default chain `8990e7a9…b2ce`) | public randomness network | drand round randomness, fetched **after** all 3 contributions for that circuit were complete; applied via `snarkjs zkey beacon` (2^10 iterations) |

**Honest trust statement.** The security of a Groth16 phase-2 ceremony is
1-of-N: the final keys are toxic-waste-free if **at least one** participant
in each chain destroyed their entropy. Here N = 4 per circuit (3
contributions + the drand beacon). All three human-operated contributions
were run by **a single operator (Drew)** — the remote contribution adds
*machine and environment* independence (different hardware, OS, kernel,
node build, network, and CSPRNG state) but **not** operator independence.
Treat the current keys as **1-of-2 honest parties** in the strongest
reading (the operator, and the drand League of Entropy beacon), not as a
multi-operator ceremony. See "Strengthening the ceremony" below — any
external contribution upgrades the trust assumption immediately.

## Attestation log

Machine-readable log: `ceremony-attestation.jsonl` (attached to the
`circuits-v1.0.0-phase2` GitHub Release). It records, for every step:
UTC timestamp, circuit, step type, machine, contribution hash, and
**sha256 of every intermediate zkey** (`in_sha256`/`out_sha256` chain).
Beacon fetch proofs (raw drand API responses + Bitcoin tip cross-reference)
are in `beacon-proofs/`.

Abbreviated per-circuit chain (contribution hashes are the ones embedded in
the final zkey transcripts, re-printed by `snarkjs zkey verify`):

### poseidon_vanchor_2_2 — final zkey sha256 `4cce5a22734d4078661d86a5cb12dacc732a607fc355bc1d3163d2a4fc2e0d11`

| step | machine | sha256(out) | contribution hash |
|---|---|---|---|
| setup 0000 | local | `e9793100…0e6422` | — |
| contrib 1 | local (MacBook-Pro) | `a46b1e57…5033dc` | `933158f6…faf2598f` |
| contrib 2 | **router-origin-fsn1 (remote)** | `8dced9a9…b5902758` | `840c4df1…03547c46` |
| contrib 3 | local | `1fb64f39…d8220945` | `704f56bf…907bdb07` |
| beacon | drand round **6518808** `1b78f9ec…5fef11` | `4cce5a22…fc2e0d11` | `4f2b2df0…507a5b99` |

### poseidon_vanchor_2_8 — final zkey sha256 `c736da0efcdcd1beb2634333d9ca918a3cedecae99e3d6136e936a5aa067626d`

| step | machine | sha256(out) | contribution hash |
|---|---|---|---|
| setup 0000 | local | `5f93209f…2174f389` | — |
| contrib 1 | local | `b6ca6254…ac98c78a` | `b9a60e05…00698d7a` |
| contrib 2 | **router-origin-fsn1 (remote)** | `71b90231…78142639` | `09188e32…f1a2aaf3` |
| contrib 3 | local | `24233d81…eac036dc` | `6073803e…65713939` |
| beacon | drand round **6518829** `cfb8a2d3…a723910` | `c736da0e…a067626d` | `a513c9aa…e3ac2864` |

### poseidon_vanchor_16_2 — final zkey sha256 `ae2c29f699a86cb67216c12cb9b5a1228edbb406e581472ed261e210ac8b8acb`

| step | machine | sha256(out) | contribution hash |
|---|---|---|---|
| setup 0000 | local | `c32cdd71…f6a4ce77` | — |
| contrib 1 | local | `eca49ec5…0d48f27e` | `009a867d…fba9555f` |
| contrib 2 | **router-origin-fsn1 (remote)** | `e5c3d5aa…1b62620` | `bb198b9c…98bb8f97` |
| contrib 3 | local | `40488dc6…ba869150` | `43351a07…8726e52e` |
| beacon | drand round **6518820** `eb159a0f…348667` | `ae2c29f6…ac8b8acb` | `d446187f…546faad` |

### poseidon_vanchor_16_8 — final zkey sha256 `dd3aa333c5c1bdda125b734077293f04b808b9ddb7b7a1e2f35ab7964b05daa3`

| step | machine | sha256(out) | contribution hash |
|---|---|---|---|
| setup 0000 | local | `16d253d1…30370aee` | — |
| contrib 1 | local | `ebc832f0…97e0cbb7` | `96c1cb48…ee5ebc59` |
| contrib 2 | **router-origin-fsn1 (remote)** | `76989255…561ef651` | `ab63bba9…0cd45019` |
| contrib 3 | local | `f2dd55c2…af6c67db` | `f2c14551…23052b94` |
| beacon | drand round **6518842** `9493384e…471fb54` | `dd3aa333…4b05daa3` | `e8adbcfe…0408477` |

### rln_payment_2_8 — final zkey sha256 `164c1676be0c818e7da891c470cbac0b786a55901416b2eff1461d4e9a6e2ff5`

| step | machine | sha256(out) | contribution hash |
|---|---|---|---|
| setup 0000 | local | `96683695…83b977f` | — |
| contrib 1 | local | `3638ee84…b4bfa35` | `cdd511a9…b88de92e` |
| contrib 2 | **router-origin-fsn1 (remote)** | `a20fe664…d04ecd7f` | `6e5c1834…99168e9f` |
| contrib 3 | local | `dc53b05f…d317ff16` | `6ff1917b…64092ac3` |
| beacon | drand round **6518854** `b55663ca…b36c3f16` | `164c1676…a6e2ff5` | `28b9fe1c…bf9a57d` |

(Full 64-char hashes are in `ceremony-attestation.jsonl` and reproducible
from the released zkeys via `snarkjs zkey verify`.)

## Beacon verification

Each beacon's drand round was fetched live from `https://api.drand.sh`
immediately after that circuit's third contribution; the raw API response
(round, randomness, signature, chain info) is preserved in
`beacon-proofs/<circuit>_beacon_proof.json`. For all five rounds we
verified the drand chain link locally:

```
sha256(hex_decode(signature)) == randomness   # OK for rounds 6518808, 6518820, 6518829, 6518842, 6518854
```

The same proof files record the Bitcoin tip hash at fetch time
(`…0163c1e99e…` / `…00bd29ae24…` from blockstream.info) as an independent
public timestamp cross-reference. The beacon randomness was applied with
`snarkjs zkey beacon <in> <out> <randomness> 10`.

## Verification gates (all run after the ceremony, all passing)

1. **zkey vs R1CS + ptau** — `snarkjs zkey verify <circuit>.r1cs ppot_0080_18.ptau circuit_final.zkey` → **"ZKey Ok!"** for all 5 circuits.
2. **ptau transcript** — `snarkjs powersoftau verify ppot_0080_18.ptau` → **"Powers of Tau Ok!"**.
3. **Contracts** — `forge build` + `forge test`: **103/103 passed**.
4. **SDK e2e on Anvil** (port 8655) — `npx vitest run`: **73/73 passed**, including:
   - `anvil-e2e-real.test.ts` (7/7): full production stack with the ceremony verifiers deployed on-chain; deposit, gateway join-split, and change-withdrawal **real Groth16 proofs verified on-chain** (`poseidon_vanchor_2_8`), plus double-spend rejection.
   - `rln-e2e.test.ts` (9/9): real `rln_payment_2_8` proof generated and verified, EdDSA operator receipt verified in-circuit.
   - `proof-e2e.test.ts` / `proof-8edge.test.ts`: real proofs for the 2-input circuits verified against the exported verification keys.
5. **16-input on-chain spot check** — fresh `poseidon_vanchor_16_2` and `poseidon_vanchor_16_8` proofs (generated 2026-10-03 against the final zkeys) verified **off-chain** with snarkjs and **on-chain** by calling `verifyProof` on `Verifier2_16` / `Verifier8_16` deployed to Anvil → both returned `true`.

## Artifacts

Published on the GitHub Release **`circuits-v1.0.0-phase2`**
(tangle-network/shielded-payment-gateway); nothing large is committed to
git. Per circuit: final zkey, witness wasm, `verification_key.json`,
Solidity verifier (`Verifier2_2`, `Verifier8_2`, `Verifier2_16`,
`Verifier8_16`, `RlnPaymentVerifier`). Plus `SHA256SUMS.txt`,
`ceremony-attestation.jsonl`, and `beacon-proofs/`. The ptau file itself is
not attached (302 MB, fetch from the PSE URL above; check the sha256).

## Verifying the ceremony yourself

```bash
# 1. Check artifact hashes
shasum -a 256 -c SHA256SUMS.txt

# 2. Re-verify a final zkey against the public phase-1 and the circuit r1cs
snarkjs zkey verify poseidon_vanchor_2_2.r1cs ppot_0080_18.ptau poseidon_vanchor_2_2_final.zkey
# -> prints every contribution name + hash (must match this document) and "ZKey Ok!"

# 3. Check a beacon was the drand round claimed
jq . beacon-proofs/poseidon_vanchor_2_2_beacon_proof.json
curl -s https://api.drand.sh/public/6518808   # compare randomness + signature
```

## Strengthening the ceremony (external contributions welcome)

The trust assumption improves with every additional independent
contribution — no coordination required:

```bash
snarkjs zkey contribute poseidon_vanchor_2_2_final.zkey my_contribution.zkey \
    -n="your name or handle" -v          # enter strong entropy when prompted
snarkjs zkey verify poseidon_vanchor_2_2.r1cs ppot_0080_18.ptau my_contribution.zkey
```

Publish the new contribution hash and the sha256 of `my_contribution.zkey`.
Anyone can then confirm the whole prior chain is intact *and* that the new
keys are safe as long as **you** destroyed your entropy. After external
contributions we will cut a new `circuits-v*` release superseding these
zkeys (verifier contracts must be redeployed when zkeys change).

## Reproducing this ceremony

```bash
export SNARKJS_BIN=<path-to-snarkjs-0.7.5> \
  CEREMONY_CONTRIBUTIONS=3 CEREMONY_REMOTE_INDEX=2 \
  CEREMONY_REMOTE_TARGET=root@<second-machine> \
  CEREMONY_REMOTE_SSH_OPTS="-i <key> -o BatchMode=yes" \
  PTAU_SIZE=18
./scripts/trusted-setup/ceremony.sh        # 4 VAnchor circuits
./scripts/setup-rln-circuit.sh             # RLN circuit
./scripts/stage-circuit-artifacts.sh
./scripts/e2e-local.sh                     # full Anvil gate
```

Machinery: `scripts/trusted-setup/lib-ceremony.sh` (entropy generation,
SSH remote contribution, drand beacon, JSONL attestation).
