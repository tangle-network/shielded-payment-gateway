# Deployments

## Base Sepolia (chain 84532) — circuits-v1.0.0-phase2 rehearsal

**Date:** 2026-10-02/03 (UTC) · **Deployer:** `0x2420FFf17c4213A4075cf5f7B6dc33429Aaf22Bb` (shared testnet deployer)
**Circuit artifacts:** GitHub Release `circuits-v1.0.0-phase2` (production ceremony keys — 3 contributions + drand beacon per circuit; all 25 release files sha256-verified against `SHA256SUMS.txt` before use). No dev-generated verifiers were used anywhere in this deployment.
**Stack source:** `main` @ `65f6b40` + the four fixes in the PR that carries this file (each was a hard deploy blocker hit during this run; see "Deploy-blocker fixes" below).
**Verification:** `scripts/verify-deployment.sh` → **8/8 pass** against the final gateway (output below).

### Deployed contracts

| Contract | Address | Deploy tx |
|---|---|---|
| PoseidonT2 | `0x7A3FBB3cE6BDeE6375741Ab4404Ba34c1670069F` | `0x9fc9c1d4cb9ba131d594e4b0dcdc021f16b38429fb2accae8bb92caa98286377` |
| PoseidonT3 | `0xa680Bf4dF59bC14F7750586DCc7587B4330e9408` | `0x645609d05930ef24c2fed58a0acb2e91afdb44dadac0569e01424102a30c8fe0` |
| PoseidonT4 | `0x68952c9E6E969179b179bc0C78dd4E614d82f0b5` | `0x1dc49161a1929a78fcdc940ba2cb4f9de628cc3d64b7891558283acb0c1f9efe` |
| PoseidonT5 | `0x9a76841d690Da3fC288471852dDaa97031D5c366` | `0xd852bf4d9f8a76cd7a6b6d973c5f5ea309544605ce1a58ea11f400a5b870ebaf` |
| PoseidonT6 | `0xc39a7eF7Aa8e390e064Bcf04BDdE12cC4754fa2C` | `0x6f5f1da8495a83be983adfdfb3b5f172aa525ab9523d8bd4ef6b5775b4b0f563` |
| VAnchorEncodeInputs (lib) | `0xF0eD319e9ae80b6e895C644c6bA18396F4af71F0` | `0x1aeb83bd88b212694434546e5e50018d175dff14a3b3dd2e088bee59ba5fbe7f` |
| Verifier2_2 (phase-2) | `0x404a2Ca3207147Ad6E6bDE37e42ec5B0f2993B94` | `0x3d84d8e2fdd7fd39679b77127891a60ff1e7333635b585a8e0a3b7037c75b8a3` |
| Verifier2_16 (phase-2) | `0x272Eba98903c1052da83eFbF1A1a7c72D6e4EBCA` | `0xa424dbac2615041905ecc0c5f98f751389c9398989e2b9e44a96b2076767213a` |
| Verifier8_2 (phase-2) | `0x8e793824c7Cf43F0b915f8242E684dDce593f1b1` | `0xc191e21f5a8c97a397cb4d7b67a98c978890e57a9581cc5b60bca7368d96f20b` |
| Verifier8_16 (phase-2) | `0xe0E0975c9F8b9f8a7b131a3370aA19f0Bdb3546B` | `0xcfedb623f9bc540504fad5135330a8ee270bdc7ad91a05f7d1b2637e4688b16c` |
| PoseidonHasher | `0x012890FEF43203d12188F0F8989Ae81c1e75BeDd` | `0xb95825f1dfa0a841b3ce7411b938c2787e439e1c6c714ae30d4bd792b4bde8ac` |
| VAnchorVerifier | `0x664EbD26d9375E40DE65634524c1fC4b5C6c9E55` | `0x3395150adfa4dbcf853fa870f017c50b9b2e5ad72194e60c8d102ccbaa12301a` |
| TokenWrapperHandler | `0xDE81A09b021C432B198Fce853e3ECd08e8B0EB58` | `0xc727b1d3b6913191523bf4de1c49575296675d680fa711464acaa1fe2504631a` |
| FungibleTokenWrapper (tsUSD) | `0x02B41D209B56C48c4DfB26Ed0274dc06454Ce295` | `0x94377ee11e72d9ce2d58563520c895adfdd3710724eff964473a268af2149815` |
| AnchorHandler | `0x726363B200D9CBBcf2138c4c65c47EE04dF81a8e` | `0xb112331c0175038f21a3b4709dfe028c8b4a66282e70dbe980108266999d94ff` |
| VAnchorTree (pool, 30 levels, maxEdges 7) | `0xd0DC9d10C8d5F5AD75a6D1d01420754ACDAD7A61` | `0xd81ab08cf94d28e251838c4d3fdd7affa4c7058deaea7e8260510952bad7f6d1` |
| ShieldedCredits | `0xE8573a188FE5ED7F49E331E2DE8adAffE3290FDF` | `0xb473de5228659b518968edbb829a938a87898f6b2e4c446a48b779735c6663ef` |
| **ShieldedGateway (canonical)** | `0x12Db03d86A476440Db1D12b949D7De19dF62d23c` | `0x493b4763cbeed35a8ef58b9376aadf7a1030ddad65cec115e4f911e291b4a153` |
| ShieldedGateway (v1 — superseded, do not use) | `0x39c2A0BeC3bB35Ab1F8a79282173eeE2eCBc842d` | `0x1dd8d25b5652a6f57ad7446febd44c8881f95dc554e4ad136bc882ce36b3c58a` |

Setup calls: wrapper `initialize` `0xe24e73e1f38b0facab7751b8a5876714d47f3997569bc6b556058003ac6121cc`, wrapper resource registration `0x864b07648c09532da47a4e917c56d4dfe01e07e7975497a262e2c0a9ed1d4fd4`, USDC registration (Circle native `0x036CbD53842c5426634e7929541eC2318f3dCF7e`) `0x47eee87fd986d57e72ab8c4ff023d5923df1c08a8b67ff9686b1ebe25c34117e`, pool `initialize` (minWithdraw 0, maxDeposit 2^256−1) `0x460b060f25fa23f134032f720a067a59b1843672d481f099b6929fb95cf2bdad`, anchor resource registration `0xaadac12dcb36d54cd5faf70b0ed1de7921c2680aef6b0e90b8c8ca3a99430c11`, pool registration (canonical gateway) `0xd258b10698393101ccfccba31ae2df27e208b503f9f64d321ddec2ea656c874e`.

**TANGLE parameter:** the canonical tnt-core proxy on Base Sepolia, `0x8299d60f373f3a4a8c4878e335cb9d840e6e3730` (per `tnt-core/deployments/base-sepolia/latest.json`, release 20260522). The first gateway (`0x39c2…842d`, superseded) was deployed against the stale address `0xC9b0716a187072be0f38A5D972392C6479b9Cfe3` that older docs/scripts still reference; it is unused — every flow below runs against the canonical gateway. `tangle` is only read by `shieldedRequestService`/`shieldedFundService`; the credits flow never touches it.

**feeBps = 0** kept per rehearsal plan. USDC on Base Sepolia is Circle's real testnet token (6 decimals); no mock is deployed by the script. Test USDC was acquired on-chain by swapping 0.00006 ETH → 9,353 USDC base units on the Uniswap V3 USDC/WETH 0.3% pool (`0x46880b404CD35c165EDdefF7421019F8dD25F4Ad`, tx `0x682947f5f0becaf3ee652d79e53f5519c2cdec579ccc28e43b99a8067cb6cd31`) because the Circle faucet is captcha-gated and not scriptable.

### verify-deployment.sh output (final gateway)

```
ShieldedGateway:
  ✓ tangle() returns non-zero
  ✓ credits() returns Credits address
  ✓ getPool(wrapper) returns Pool address
ShieldedCredits:
  ✓ DOMAIN_SEPARATOR is non-zero
  ✓ SPEND_TYPEHASH is non-zero
VAnchorTree:
  ✓ token() returns Wrapper address
  ✓ maxEdges() returns 7
  ✓ getLastRoot() returns non-zero
Results: 8 passed, 0 failed
```

### End-to-end paid flow (real Groth16 proofs from the phase-2 zkeys)

Credit account: commitment `0x75167c9470213fec521cfbc11e1de24e14030f0eba67c434e33c7923d04d0784`, spending key `0x603f24B0a715b9C624b8B4Bb605694D10dAaf36c` (ephemeral, session-scoped). Amounts in tsUSD base units (6 decimals).

| Step | Tx | Gas | Notes |
|---|---|---|---|
| approve USDC → wrapper | `0x1f35fe05b6cb462153748e3d4c8c9805878fdab2b8ca0f1d3350752496125858` | 55,425 | |
| wrap 9,353 USDC → tsUSD | `0x3954a99ffd11ef6e81bd5756af29fa9c232237921cac636d57b31282f1c0a2a1` | 130,896 | |
| approve tsUSD → pool | `0x4096eb53659c29557e2cf85d71af04aa03498ca418e7131f66d981e01225b9a6` | 26,100 | |
| **deposit 9,000 into VAnchor** | `0x241ba31827dba96ca3946c9893b16b9e79340414d9c85d01895b18909748a607` | 1,747,440 | real `poseidon_vanchor_2_8` proof, verified on-chain (8.1 s to generate) |
| **shieldedFundCredits 6,000** | `0x2738dba1e7139a39d0f37444922bd5de0169caf6e1f0bf81fef0902e127f2a35` | 1,878,531 | join-split proof verified on-chain; funds the credit account atomically (3.5 s to generate) |
| **withdrawCredits 5,378** | `0xe75bc96a58b2e1074db309f475e07e0b99f486003bb0ad2c6b8ceb69d5814e5c` | 55,748 | EIP-712 withdrawal signature; account ends at balance 0 |

Operator (throwaway test identity): `0x0AEf5DD18FDff9C29F6f34BF0c08E4DE921dF598`, registered on blueprint **0** of the canonical tnt-core (`registerOperator` tx `0x8279902a073490aa6340a3c631386d593a0543e5893e661897c92b5d47d29b28`, staked 200 TNT) against the existing InferenceBSM `0x6a0ef9695aafed077202538048c9b933e5d26475` with model `qwen2:0.5b` configured (`0xb551c6e6640965cf88830b970cdd2534a1da49fdc53e24858685e3ec993edda7`). Inference was served by the real `operator-lite` binary (llm-inference-blueprint) backed by local Ollama `qwen2:0.5b`.

| Leg | Step | Tx | Notes |
|---|---|---|---|
| B — operator-native rail | SpendAuth (nonce 0, 60 units) → operator `authorizeSpend` | `0x14a2cfc7ee06d6d028c59a0507640938c074066a54b97c2f6fd8b931b061d0f4` | operator-lite validated the EIP-712 auth and authorized on-chain |
| B | real inference (`qwen2:0.5b`, 17 tokens) → operator `claimPayment` | `0x4441988e12eeee17aa083cb995d8bc244d9c415bbb34048067b808f255a5ba37` | metered cost 19 logged; pinned tangle-inference-core settles full pre-auth on-chain (see findings) |
| A — router rail (#597 pattern) | SpendAuth (nonce 3, 500) → router `authorizeSpend` | `0x752ec294dd4c7e2d59679314e8fdce7c2056f6915b982b654a43394b2f19b850` | local tangle-router, production `/api/chat` handler, chain-synced operator |
| A | inference through router (content "Yes.") → `claimPayment` | `0x408089a1c3e0205f63c4b8ff4fb183b6d28e8e03b7b582ad95c11431d4db2bdf` | router dispatched the claim; its 3-retry window raced stale RPC nodes (AuthNotFound), claim completed with the same operator key one block later |
| C — metered settlement + refund | SpendAuth (nonce 4, 1000) → operator `authorizeSpend` | `0x7ece9d788f888b23e0f90d53545fc11f68944b1ba01c5d540c8be185a8b24efd` | |
| C | real inference (41 tokens, metered 62) → **`settlePayment(authHash, operator, 62)`** | `0xaa4fce3a9ba906b164f56a572aa977880932767aab36770e7edf7a75d430c39c` | **938 units refunded on-chain to the credit account** (`PaymentSettled` event), operator paid exactly metered usage |
| safety net | `releasePayment` of two orphaned auths (router dispatched after authorize) | `0xba36e81716dffefb383aa71cf071ee47895d65cd74d4f160f5b895c1b08205ee`, `0x485c220f5a13ed80270cfbe8eec765c64cad30e975fa0a10cf5624c6d5786399` | both 500-unit auths returned to the credit account |

Final on-chain state: credit account balance 0 / totalFunded 6000 / nonce 6; operator holds 622 tsUSD (60 + 500 + 62); deployer holds 5,731 tsUSD (change + withdrawal). Full trace archive: `~/company/compliance/evidence/shielded-gateway-audit-2026-10/BASE-SEPOLIA-TRACE.md`.

### Deploy-blocker fixes (in the PR carrying this file)

1. `scripts/deploy-full-stack.sh` — honor a caller-supplied `SHIELDED_CONFIG`. The committed wiring exports `deploy/config/<chain>-shielded.json`, whose schema does not match what `DeployShieldedPool.s.sol` reads (`.tangle`, `.poseidon.T2`, …), so the Forge step reverts before broadcast. The script now keeps the default but allows an override.
2. `script/DeployShieldedPool.s.sol` — replaced the try/catch-via-`this` JSON fallback helpers with forge-std 1.9.4's `readAddressOr`/`readUintOr` (`keyExists`-based). The external `this.` call trips forge's "`address(this)` in script" guard under forge 1.8.1, so the config path could not broadcast at all.
3. `sdk/shielded-sdk/src/contract/gateway-client.ts` — named the tuple components in the `VANCHOR_ABI.transact` signature. ethers v6 rejects named-object arguments for unnamed tuple components (`cannot use object value with unnamed components`), so the SDK client's deposit path could not encode a transaction.
4. `sdk/shielded-sdk/src/proof/roots.ts` — `encodeRootsBytes` now ABI-encodes a **fixed** `uint256[N]` array, matching `VAnchorEncodeInputs` (`abi.decode(_args.roots, (uint256[8]))`). The dynamic `uint256[]` encoding put the 0x20 offset word in slot 0 and reverted with "Cannot find your merkle root".

### Config used

`script/deploy-config/base-sepolia-shielded.json` (populated in the same PR) — derived from `deploy/config/base-sepolia-shielded.json` (feeBps 0, treeLevels 30, maxEdges 7, Circle USDC, unlimited wrapping/deposit caps) plus the deployed Poseidon/verifier addresses and the canonical Tangle proxy. `gatewayOwner`/`feeRecipient` = deployer.

### Known gaps / findings from this run

- **Router↔operator settle-path conflict:** tangle-router forwards `X-Payment-Signature` upstream after it settles, and the pinned tangle-inference-core operator-lite re-validates any presented SpendAuth and tries to authorize it again (it also enforces a 1.5× estimated-cost pre-auth cap). Composed, the second authorization reverts (`InvalidNonce`) and the dispatch fails. The router rail must either stop forwarding the header once settled or the operator must treat an already-authorized authHash as settled. Until then the two rails are alternatives, not composable.
- **operator-lite settles the full pre-auth:** pinned tangle-inference-core `c7e1106` logs the metered cost but calls `claimPayment` (full amount), not `settlePayment(partial)`. Leg C above proves the contract-side refund path; wiring it into the operator is a production diff.
- **Public RPC staleness:** `https://sepolia.base.org` is load-balanced with occasionally stale reads (nonce-too-low on fresh nonces, AuthNotFound right after a mined tx). The router's 3-retry claim window (~3.5 s) is tighter than observed staleness (~2 blocks). Production should use a dedicated RPC and/or a longer retry horizon.
- **Chain-sync probe gate:** the local-e2e hatch (`TANGLE_ALLOW_INSECURE_OPERATOR_ENDPOINTS=1`) covers `classifyEndpointUrl` but not the health-probe gate (`isAllowedExternalUrl`), so http loopback operators sync as `suspended` with no health row. Fine for production (https-only by design); the trace run mirrored a passing probe in the DB exactly as the harness would have written it.
- 16-input join-splits not exercised on Base Sepolia (2-input path only, same as Anvil coverage).
- The LayerZero bridge peers are not configured (single-chain deployment; out of MVP scope).
