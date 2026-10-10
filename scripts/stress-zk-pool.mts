/**
 * Phase 2 — zk-pool stress test against the round-2 rehearsal stack on Tempo.
 *
 *   1. N=20 fresh depositor identities, funded pathUSD from the deployer
 *   2. Concurrent deposits: 3 per identity, concurrency 5, REAL 2-input proofs
 *   3. Joinsplits: each identity consolidates two deposit UTXOs, concurrency 3
 *   4. Withdrawals: 20 withdrawals to fresh recipients, concurrency 3
 *   5. Boundary: double-spend, proof replay, tampered proof, max-deposit note
 *
 * Metrics: proof-gen latency p50/p95, tx confirm latency, failure rate,
 * gas per tx, tree-growth integrity (no leaf duplication/loss).
 *
 * Resumable: state is checkpointed to deployments-round2/stress-state.json
 * after every phase; rerun the same command to resume after a crash.
 *
 * Usage:
 *   PRIVATE_KEY=0x... npx tsx scripts/stress-zk-pool.mts
 */
import { ethers } from "ethers";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import {
  ROOT_DIR,
  getProvider,
  loadDeployments,
  proveTransact,
  transactArgs,
  syncTree,
  withRetry,
  pool as promisePool,
  stats,
  Keypair,
  Utxo,
  MerkleTree,
  ChainType,
  typedChainId,
  ERC20_ABI,
  WRAPPER_ABI,
  VANCHOR_ABI,
  TREE_LEVELS,
  type ProverContext,
} from "./round2-lib.mjs";

const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY");

const N = 20;
const DEPOSITS_PER_ID = 3;
const DEPOSIT_AMOUNT = 500_000n; // 0.5 pathUSD (6dp)
const WRAP_PER_ID = DEPOSIT_AMOUNT * BigInt(DEPOSITS_PER_ID); // 1.5 pathUSD
const FUND_PER_ID = 5_000_000n; // 5 pathUSD (wrap + gas)
const DEPOSIT_CONCURRENCY = 5;
const SPEND_CONCURRENCY = 3;

const STATE_PATH = join(ROOT_DIR, "deployments-round2/stress-state.json");
const REPORT_PATH = join(ROOT_DIR, "deployments-round2/stress-report.json");

interface TxMetric {
  kind: string;
  identity?: number;
  txHash: string;
  gasUsed: string;
  confirmMs: number;
  proofMs?: number;
  ok: boolean;
  error?: string;
}

interface IdentityState {
  evmKey: string; // throwaway rehearsal identity key
  address: string;
  shieldedKey: string; // Keypair private key hex
  funded: boolean;
  wrapped: boolean;
  deposits: { utxo: string; txHash: string; leafIndex?: number }[];
  joinsplit?: { combined: string; txHash: string };
  withdrawal?: { recipient: string; txHash: string };
}

interface State {
  phase: string;
  identities: IdentityState[];
  metrics: TxMetric[];
  boundary: Record<string, unknown>;
}

function saveState(s: State) {
  writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
}

function loadState(): State | null {
  if (!existsSync(STATE_PATH)) return null;
  return JSON.parse(readFileSync(STATE_PATH, "utf-8"));
}

const PHASE_ORDER = ["init", "setup", "wrap", "deposits", "joinsplits", "withdrawals", "boundary", "done"];
function phaseDone(state: State, phase: string): boolean {
  // state.phase is set AFTER a phase completes, so equality means done.
  return PHASE_ORDER.indexOf(state.phase) >= PHASE_ORDER.indexOf(phase);
}

async function main() {
  const d = loadDeployments();
  const provider = getProvider();
  const deployer = new ethers.NonceManager(
    new ethers.Wallet(PRIVATE_KEY!, provider)
  ) as unknown as ethers.Wallet;
  const deployerAddr = await deployer.getAddress();
  const typed = typedChainId(ChainType.EVM, d.chainId);

  const pathusd = new ethers.Contract(d.stablecoin, ERC20_ABI, deployer);
  const poolRO = new ethers.Contract(d.vanchorTree, VANCHOR_ABI, provider);
  const wrapperRO = new ethers.Contract(d.fungibleTokenWrapper, WRAPPER_ABI, provider);

  const edgeZero: bigint = await withRetry(() => poolRO.getZeroHash(TREE_LEVELS - 1), { label: "getZeroHash" });

  let state = loadState();
  if (!state) {
    state = {
      phase: "init",
      identities: Array.from({ length: N }, () => {
        const w = ethers.Wallet.createRandom();
        return {
          evmKey: w.privateKey,
          address: w.address,
          shieldedKey: new Keypair().toString(),
          funded: false,
          wrapped: false,
          deposits: [],
        };
      }),
      metrics: [],
      boundary: {},
    };
    saveState(state);
  }

  // Signing objects live outside `state` (state is JSON-checkpointed).
  const wallets = state.identities.map(
    (id) =>
      new ethers.NonceManager(
        new ethers.Wallet(id.evmKey, provider)
      ) as unknown as ethers.Wallet
  );
  const keypairs = state.identities.map((id) => Keypair.fromString(id.shieldedKey));
  const ids = state.identities;

  const mkCtx = (tree: MerkleTree): ProverContext => ({
    tree,
    chainId: typed,
    wrapperAddr: d.fungibleTokenWrapper,
    edgeZero,
  });

  async function sendAndTime(
    label: string,
    txFn: () => Promise<ethers.TransactionResponse>,
    extra: Partial<TxMetric> = {},
    signer?: ethers.Signer
  ): Promise<ethers.TransactionReceipt> {
    const t0 = performance.now();
    const tx = await withRetry(
      async () => {
        try {
          return await txFn();
        } catch (err) {
          // Resync a possibly-drifted NonceManager before the next attempt.
          (signer as unknown as ethers.NonceManager | undefined)?.reset?.();
          throw err;
        }
      },
      { label: `${label} send` }
    );
    // wait() can hang forever if the node silently drops/queues the tx
    // (observed on this RPC). Time out, then poll for the receipt directly —
    // the tx may have landed despite wait() failing.
    let receipt: ethers.TransactionReceipt | null = null;
    try {
      receipt = await Promise.race([
        tx.wait(),
        new Promise<never>((_, rej) =>
          setTimeout(() => rej(new Error("confirm timeout")), 240_000)
        ),
      ]);
    } catch {
      const deadline = Date.now() + 300_000;
      while (!receipt && Date.now() < deadline) {
        receipt = await withRetry(
          () => provider.getTransactionReceipt(tx.hash),
          { label: `${label} receipt poll`, tries: 3, baseMs: 2000 }
        ).catch(() => null);
        if (!receipt) await new Promise((r) => setTimeout(r, 5000));
      }
      if (!receipt)
        throw new Error(`${label}: tx ${tx.hash} never mined (dropped by RPC)`);
    }
    const confirmMs = performance.now() - t0;
    if (receipt.status !== 1)
      throw new Error(`${label} reverted on-chain (tx ${tx.hash})`);
    state!.metrics.push({
      kind: label,
      txHash: tx.hash,
      gasUsed: receipt.gasUsed.toString(),
      confirmMs: Math.round(confirmMs),
      ok: true,
      ...extra,
    });
    return receipt;
  }

  // ── Phase 0: fund identities ───────────────────────────────────────────
  if (!phaseDone(state, "setup")) {
    console.log("Phase 0: funding identities with pathUSD...");
    const res = await promisePool(
      ids.map((_, i) => i).filter((i) => !ids[i].funded),
      3,
      async (i) => {
        await sendAndTime("fund", () => pathusd.transfer(ids[i].address, FUND_PER_ID), { identity: i }, deployer);
        ids[i].funded = true;
        saveState(state!);
      }
    );
    const fails = res.filter((r) => r.status === "rejected");
    for (const r of fails)
      console.error("  funding FAILURE:", String((r as PromiseRejectedResult).reason).slice(0, 300));
    if (fails.length) throw new Error(`funding failures: ${fails.length}`);

    // Sanity: a funded identity can pay its own gas (pathUSD fee token)
    const probeP = new ethers.Contract(d.stablecoin, ERC20_ABI, wallets[0]);
    await sendAndTime("probe-identity-gas", () => probeP.approve(deployerAddr, 1n), { identity: 0 }, wallets[0]);
    console.log("  identity gas probe OK (fresh accounts pay gas in pathUSD) ✓");
    state.phase = "setup";
    saveState(state);
  } else {
    console.log("Phase 0: already done, skipping.");
  }

  // ── Phase 1: wrap pathUSD → tsUSD + approve pool ───────────────────────
  if (!phaseDone(state, "wrap")) {
    console.log("Phase 1: wrap + approve per identity...");
    const res = await promisePool(
      ids.map((_, i) => i).filter((i) => !ids[i].wrapped),
      5,
      async (i) => {
        const pPathusd = new ethers.Contract(d.stablecoin, ERC20_ABI, wallets[i]);
        const pWrapper = new ethers.Contract(d.fungibleTokenWrapper, WRAPPER_ABI, wallets[i]);
        await sendAndTime("approve-wrap", () => pPathusd.approve(d.fungibleTokenWrapper, WRAP_PER_ID), { identity: i }, wallets[i]);
        await sendAndTime("wrap", () => pWrapper.wrap(d.stablecoin, WRAP_PER_ID), { identity: i }, wallets[i]);
        await sendAndTime("approve-pool", () => pWrapper.approve(d.vanchorTree, WRAP_PER_ID), { identity: i }, wallets[i]);
        ids[i].wrapped = true;
        saveState(state!);
      }
    );
    const fails = res.filter((r) => r.status === "rejected");
    for (const r of fails)
      console.error("  wrap FAILURE:", String((r as PromiseRejectedResult).reason).slice(0, 300));
    if (fails.length) throw new Error(`wrap failures: ${fails.length}`);
    state.phase = "wrap";
    saveState(state);
  } else {
    console.log("Phase 1: already done, skipping.");
  }

  // ── Phase 2: concurrent deposits with REAL proofs ──────────────────────
  if (!phaseDone(state, "deposits")) {
    console.log("Phase 2: 60 concurrent deposits (concurrency 5)...");
    // Baseline leaf count (pool is shared with the earlier E2E run).
    if (state.boundary.baseIndex === undefined) {
      state.boundary.baseIndex = Number(
        await withRetry(() => poolRO.getNextIndex(), { label: "getNextIndex" })
      );
      saveState(state);
    }
    const baseIndex = state.boundary.baseIndex as number;
    const emptyTree = await MerkleTree.create(TREE_LEVELS);
    const depCtx = mkCtx(emptyTree);

    const tasks: { idIdx: number; depIdx: number }[] = [];
    ids.forEach((id, idIdx) => {
      for (let k = id.deposits.length; k < DEPOSITS_PER_ID; k++)
        tasks.push({ idIdx, depIdx: k });
    });

    let done = 0;
    const res = await promisePool(tasks, DEPOSIT_CONCURRENCY, async ({ idIdx, depIdx }) => {
      const keypair = keypairs[idIdx];
      const depUtxo = Utxo.create({ chainId: typed, amount: DEPOSIT_AMOUNT, keypair });
      const zeroChange = await Utxo.zero(typed, keypair);
      const zi1 = await Utxo.zero(typed, keypair);
      const zi2 = await Utxo.zero(typed, keypair);
      zi1.index = 0;
      zi2.index = 0;

      // All inputs zero → membership disabled; any known root works.
      const localRoot: bigint = await withRetry(() => poolRO.getLastRoot(), { label: "getLastRoot" });
      const proof = await proveTransact(depCtx, {
        inputs: [zi1, zi2],
        outputs: [depUtxo, zeroChange],
        extAmount: DEPOSIT_AMOUNT,
        recipient: ethers.ZeroAddress,
        localRoot,
      });

      const pPool = new ethers.Contract(d.vanchorTree, VANCHOR_ABI, wallets[idIdx]);
      const receipt = await sendAndTime(
        "deposit",
        () =>
          pPool.transact(
            ...(transactArgs(proof, {
              recipient: ethers.ZeroAddress,
              extAmount: DEPOSIT_AMOUNT,
              relayer: ethers.ZeroAddress,
              fee: 0n,
              refund: 0n,
              token: d.fungibleTokenWrapper,
            }) as never[]),
            { gasLimit: 6_000_000 } as never
          ),
        { identity: idIdx, proofMs: Math.round(proof.proofMs) },
        wallets[idIdx]
      );
      ids[idIdx].deposits.push({ utxo: depUtxo.serialize(), txHash: receipt.hash });
      done++;
      if (done % 10 === 0) console.log(`  deposits: ${done}/${tasks.length}`);
      saveState(state!);
      return receipt.hash;
    });

    let failures = 0;
    for (const [i, r] of res.entries()) {
      if (r.status === "rejected") {
        failures++;
        console.error(`  deposit FAILURE id=${tasks[i].idIdx} dep=${tasks[i].depIdx}:`, String(r.reason).slice(0, 300));
        state.metrics.push({ kind: "deposit", identity: tasks[i].idIdx, txHash: "", gasUsed: "0", confirmMs: 0, ok: false, error: String(r.reason).slice(0, 300) });
      }
    }

    // Tree growth integrity check regardless of failures
    const expectedLeaves = baseIndex + 2 * ids.reduce((a, i) => a + i.deposits.length, 0);
    const nextIdx = Number(await withRetry(() => poolRO.getNextIndex(), { label: "getNextIndex" }));
    const { leaves } = await syncTree(provider, d.vanchorTree);
    console.log(`  on-chain nextIndex=${nextIdx}, synced leaves=${leaves.length}, expected=${expectedLeaves}`);
    if (Number(nextIdx) !== leaves.length || leaves.length !== expectedLeaves)
      throw new Error(`tree growth mismatch: nextIndex=${nextIdx} leaves=${leaves.length} expected=${expectedLeaves}`);
    state.boundary.depositTreeCheck = { nextIndex: nextIdx, leaves: leaves.length, expected: expectedLeaves };

    // Assign leaf indices to deposit UTXOs by commitment match
    const byCommitment = new Map(leaves.map((l) => [l.commitment.toString(), l.leafIndex]));
    for (const id of ids) {
      for (const dep of id.deposits) {
        const u = Utxo.deserialize(dep.utxo);
        const c = await u.getCommitment();
        const idx = byCommitment.get(c.toString());
        if (idx === undefined) throw new Error(`deposit commitment not found on-chain (tx ${dep.txHash})`);
        dep.leafIndex = idx;
      }
    }
    saveState(state);
    if (failures) throw new Error(`deposit failures: ${failures} — rerun to retry after fixing`);
    state.phase = "deposits";
    saveState(state);
  } else {
    console.log("Phase 2: already done, skipping.");
  }

  // ── Phase 3: joinsplits (2-input, consolidate dep0+dep1) ───────────────
  if (!phaseDone(state, "joinsplits")) {
    console.log("Phase 3: 20 joinsplits (concurrency 3)...");
    const { tree } = await syncTree(provider, d.vanchorTree);
    const jsCtx = mkCtx(tree);
    const localRoot = tree.root;

    const res = await promisePool(
      ids.map((_, i) => i).filter((i) => !ids[i].joinsplit),
      SPEND_CONCURRENCY,
      async (i) => {
        const in0 = Utxo.deserialize(ids[i].deposits[0].utxo);
        const in1 = Utxo.deserialize(ids[i].deposits[1].utxo);
        in0.index = ids[i].deposits[0].leafIndex!;
        in1.index = ids[i].deposits[1].leafIndex!;
        const combined = Utxo.create({
          chainId: typed,
          amount: in0.amount + in1.amount,
          keypair: keypairs[i],
        });
        const zeroOut = await Utxo.zero(typed, keypairs[i]);

        const proof = await proveTransact(jsCtx, {
          inputs: [in0, in1],
          outputs: [combined, zeroOut],
          extAmount: 0n,
          recipient: ethers.ZeroAddress,
          localRoot,
        });

        const pPool = new ethers.Contract(d.vanchorTree, VANCHOR_ABI, wallets[i]);
        const receipt = await sendAndTime(
          "joinsplit",
          () =>
            pPool.transact(
              ...(transactArgs(proof, {
                recipient: ethers.ZeroAddress,
                extAmount: 0n,
                relayer: ethers.ZeroAddress,
                fee: 0n,
                refund: 0n,
                token: d.fungibleTokenWrapper,
              }) as never[]),
            { gasLimit: 6_000_000 } as never
            ),
          { identity: i, proofMs: Math.round(proof.proofMs) },
          wallets[i]
        );
        ids[i].joinsplit = { combined: combined.serialize(), txHash: receipt.hash };
        saveState(state!);
        return receipt.hash;
      }
    );

    const fails = res.filter((r) => r.status === "rejected");
    for (const r of res)
      if (r.status === "rejected")
        console.error("  joinsplit FAILURE:", String((r as PromiseRejectedResult).reason).slice(0, 300));
    if (fails.length) throw new Error(`joinsplit failures: ${fails.length}`);

    const nextIdx = Number(await withRetry(() => poolRO.getNextIndex(), { label: "getNextIndex" }));
    const expected = (state.boundary.baseIndex as number) + 2 * N * DEPOSITS_PER_ID + 2 * N;
    if (nextIdx !== expected)
      throw new Error(`tree growth mismatch after joinsplits: ${nextIdx} != ${expected}`);
    state.boundary.joinsplitTreeCheck = { nextIndex: nextIdx, expected };
    state.phase = "joinsplits";
    saveState(state);
  } else {
    console.log("Phase 3: already done, skipping.");
  }

  // ── Phase 4: withdrawals to fresh recipients ───────────────────────────
  if (!phaseDone(state, "withdrawals")) {
    console.log("Phase 4: 20 withdrawals (concurrency 3)...");
    const { tree, leaves } = await syncTree(provider, d.vanchorTree);
    const wdCtx = mkCtx(tree);
    const localRoot = tree.root;
    const byCommitment = new Map(leaves.map((l) => [l.commitment.toString(), l.leafIndex]));

    async function indexOf(u: Utxo): Promise<number> {
      const c = await u.getCommitment();
      const idx = byCommitment.get(c.toString());
      if (idx === undefined) throw new Error("utxo commitment not on-chain");
      return idx;
    }

    const res = await promisePool(
      ids.map((_, i) => i).filter((i) => !ids[i].withdrawal),
      SPEND_CONCURRENCY,
      async (i) => {
        const combined = Utxo.deserialize(ids[i].joinsplit!.combined);
        combined.index = await indexOf(combined);
        const dep2 = Utxo.deserialize(ids[i].deposits[2].utxo);
        dep2.index = ids[i].deposits[2].leafIndex!;

        const total = combined.amount + dep2.amount;
        const recipient = ethers.Wallet.createRandom().address;
        const z1 = await Utxo.zero(typed, keypairs[i]);
        const z2 = await Utxo.zero(typed, keypairs[i]);

        const proof = await proveTransact(wdCtx, {
          inputs: [combined, dep2],
          outputs: [z1, z2],
          extAmount: -total,
          recipient,
          localRoot,
        });

        const pPool = new ethers.Contract(d.vanchorTree, VANCHOR_ABI, wallets[i]);
        const receipt = await sendAndTime(
          "withdrawal",
          () =>
            pPool.transact(
              ...(transactArgs(proof, {
                recipient,
                extAmount: -total,
                relayer: ethers.ZeroAddress,
                fee: 0n,
                refund: 0n,
                token: d.fungibleTokenWrapper,
              }) as never[]),
            { gasLimit: 6_000_000 } as never
            ),
          { identity: i, proofMs: Math.round(proof.proofMs) },
          wallets[i]
        );

        const bal: bigint = await withRetry(() => wrapperRO.balanceOf(recipient), { label: "balanceOf" });
        if (bal !== total)
          throw new Error(`recipient ${recipient} balance ${bal} != ${total}`);
        ids[i].withdrawal = { recipient, txHash: receipt.hash };
        saveState(state!);
        return receipt.hash;
      }
    );

    const fails = res.filter((r) => r.status === "rejected");
    for (const r of res)
      if (r.status === "rejected")
        console.error("  withdrawal FAILURE:", String((r as PromiseRejectedResult).reason).slice(0, 300));
    if (fails.length) throw new Error(`withdrawal failures: ${fails.length}`);

    const nextIdx = Number(await withRetry(() => poolRO.getNextIndex(), { label: "getNextIndex" }));
    const expected = (state.boundary.baseIndex as number) + 2 * N * DEPOSITS_PER_ID + 2 * N + 2 * N;
    if (nextIdx !== expected)
      throw new Error(`tree growth mismatch after withdrawals: ${nextIdx} != ${expected}`);
    state.boundary.withdrawalTreeCheck = { nextIndex: nextIdx, expected };
    state.phase = "withdrawals";
    saveState(state);
  } else {
    console.log("Phase 4: already done, skipping.");
  }

  // ── Phase 5: boundary tests ────────────────────────────────────────────
  if (!phaseDone(state, "boundary")) {
    console.log("Phase 5: boundary tests...");
    const { tree, leaves } = await syncTree(provider, d.vanchorTree);
    const bCtx = mkCtx(tree);
    const actorPool = new ethers.Contract(d.vanchorTree, VANCHOR_ABI, wallets[0]);

    async function expectRevert(label: string, txFn: () => Promise<ethers.TransactionResponse>): Promise<boolean> {
      try {
        const tx = await txFn();
        const rcpt = await tx.wait();
        if (rcpt!.status === 0) return true;
        return false;
      } catch {
        return true;
      }
    }

    // 5a. Double-spend: reuse the (spent) combined UTXO from identity 0's joinsplit.
    {
      const combined = Utxo.deserialize(ids[0].joinsplit!.combined);
      const c = await combined.getCommitment();
      combined.index = leaves.find((l) => l.commitment === c)!.leafIndex;
      const zi = await Utxo.zero(typed, keypairs[0]);
      zi.index = 0;
      const out1 = Utxo.create({ chainId: typed, amount: combined.amount, keypair: keypairs[0] });
      const out2 = await Utxo.zero(typed, keypairs[0]);
      const proof = await proveTransact(bCtx, {
        inputs: [combined, zi],
        outputs: [out1, out2],
        extAmount: 0n,
        recipient: ethers.ZeroAddress,
      });
      const reverted = await expectRevert("double-spend", () =>
        actorPool.transact(
          ...(transactArgs(proof, {
            recipient: ethers.ZeroAddress,
            extAmount: 0n,
            relayer: ethers.ZeroAddress,
            fee: 0n,
            refund: 0n,
            token: d.fungibleTokenWrapper,
          }) as never[]),
            { gasLimit: 6_000_000 } as never
        )
      );
      state.boundary.doubleSpend = { expected: "revert", reverted, pass: reverted };
      console.log(`  double-spend reverts: ${reverted ? "PASS" : "FAIL"}`);
      saveState(state);
    }

    // 5b. Proof replay: resend identity 1's first deposit calldata verbatim.
    {
      const replayTxHash = ids[1].deposits[0].txHash;
      const origTx = await withRetry(() => provider.getTransaction(replayTxHash), { label: "getTransaction" });
      const reverted = await expectRevert("proof-replay", () =>
        wallets[1].sendTransaction({ to: origTx!.to!, data: origTx!.data })
      );
      state.boundary.proofReplay = { expected: "revert", replayOf: replayTxHash, reverted, pass: reverted };
      console.log(`  proof replay reverts: ${reverted ? "PASS" : "FAIL"}`);
      saveState(state);
    }

    // 5c. Tampered proof: valid witness, corrupted proof bytes.
    {
      const zi1 = await Utxo.zero(typed, keypairs[0]);
      const zi2 = await Utxo.zero(typed, keypairs[0]);
      zi1.index = 0;
      zi2.index = 0;
      const depUtxo = Utxo.create({ chainId: typed, amount: 1000n, keypair: keypairs[0] });
      const zc = await Utxo.zero(typed, keypairs[0]);
      const localRoot: bigint = await withRetry(() => poolRO.getLastRoot(), { label: "getLastRoot" });
      const proof = await proveTransact(bCtx, {
        inputs: [zi1, zi2],
        outputs: [depUtxo, zc],
        extAmount: 1000n,
        recipient: ethers.ZeroAddress,
        localRoot,
      });
      proof.proofBytes[10] ^= 0xff; // corrupt the proof
      const reverted = await expectRevert("tampered-proof", () =>
        actorPool.transact(
          ...(transactArgs(proof, {
            recipient: ethers.ZeroAddress,
            extAmount: 1000n,
            relayer: ethers.ZeroAddress,
            fee: 0n,
            refund: 0n,
            token: d.fungibleTokenWrapper,
          }) as never[]),
            { gasLimit: 6_000_000 } as never
        )
      );
      state.boundary.tamperedProof = { expected: "revert", reverted, pass: reverted };
      console.log(`  tampered proof reverts: ${reverted ? "PASS" : "FAIL"}`);
      saveState(state);
    }

    // 5d. Max deposit: pool was initialized with maximumDepositAmount = uint256 max
    state.boundary.maxDeposit = {
      configured: false,
      note: "maximumDepositAmount = type(uint256).max (deploy config) — no cap to exceed; N/A",
      pass: true,
    };
    state.phase = "boundary";
    saveState(state);
  } else {
    console.log("Phase 5: already done, skipping.");
  }

  // ── Report ─────────────────────────────────────────────────────────────
  const m = state.metrics;
  const byKind = (k: string) => m.filter((x) => x.kind === k && x.ok);
  const proofMs = byKind("deposit").concat(byKind("joinsplit"), byKind("withdrawal"))
    .filter((x) => x.proofMs !== undefined)
    .map((x) => x.proofMs!);
  const depConfirm = byKind("deposit").map((x) => x.confirmMs);
  const jsConfirm = byKind("joinsplit").map((x) => x.confirmMs);
  const wdConfirm = byKind("withdrawal").map((x) => x.confirmMs);
  const depGas = byKind("deposit").map((x) => Number(x.gasUsed));
  const jsGas = byKind("joinsplit").map((x) => Number(x.gasUsed));
  const wdGas = byKind("withdrawal").map((x) => Number(x.gasUsed));
  const failed = m.filter((x) => !x.ok);

  const report = {
    generatedAt: new Date().toISOString(),
    chainId: d.chainId,
    pool: d.vanchorTree,
    wrapper: d.fungibleTokenWrapper,
    identities: N,
    totals: { transactions: m.length, succeeded: m.length - failed.length, failed: failed.length },
    proofGenMs: stats(proofMs),
    confirmMs: {
      deposit: stats(depConfirm),
      joinsplit: stats(jsConfirm),
      withdrawal: stats(wdConfirm),
    },
    gas: {
      deposit: stats(depGas),
      joinsplit: stats(jsGas),
      withdrawal: stats(wdGas),
    },
    boundary: state.boundary,
    failures: failed,
    metrics: m,
  };
  writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2));

  const fmt = (s: ReturnType<typeof stats>, unit = "") =>
    `n=${s.n} p50=${s.p50?.toFixed(0)}${unit} p95=${s.p95?.toFixed(0)}${unit} mean=${s.mean?.toFixed(0)}${unit} max=${s.max?.toFixed(0)}${unit}`;
  console.log("\n════════ STRESS REPORT ════════");
  console.log(`txs: ${m.length}, ok: ${m.length - failed.length}, failed: ${failed.length}`);
  console.log(`proof gen (all):    ${fmt(stats(proofMs), "ms")}`);
  console.log(`deposit confirm:    ${fmt(stats(depConfirm), "ms")}  gas ${fmt(stats(depGas))}`);
  console.log(`joinsplit confirm:  ${fmt(stats(jsConfirm), "ms")}  gas ${fmt(stats(jsGas))}`);
  console.log(`withdrawal confirm: ${fmt(stats(wdConfirm), "ms")}  gas ${fmt(stats(wdGas))}`);
  console.log("boundary:", JSON.stringify(state.boundary, null, 2));
  console.log(`\nReport: ${REPORT_PATH}`);

  state.phase = "done";
  saveState(state);
  process.exit(0); // snarkjs worker threads keep the loop alive otherwise
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
