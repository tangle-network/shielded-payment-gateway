/**
 * Shared helpers for the round-2 Tempo rehearsal: proving, transact encoding,
 * leaf sync (Tempo's eth_getLogs ignores topic filters — fetch by address and
 * filter client-side), and RPC retry (the RPC rate-limits often).
 */
import { ethers } from "ethers";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import {
  Keypair,
  Utxo,
  MerkleTree,
  ChainType,
  typedChainId,
} from "../sdk/shielded-sdk/src/protocol/index.js";
import {
  buildWitnessInputs,
  computeExtDataHash,
  computePublicAmount,
} from "../sdk/shielded-sdk/src/proof/witness.js";
import { encodeSolidityProof } from "../sdk/shielded-sdk/src/proof/prover.js";

export { Keypair, Utxo, MerkleTree, ChainType, typedChainId };

const __dirname = dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = join(__dirname, "..");

export const RPC_URL =
  process.env.RPC_URL ?? "https://rpc.moderato.tempo.xyz";
export const PATHUSD = "0x20C0000000000000000000000000000000000000";
export const MAX_EDGES = 7;
export const TREE_LEVELS = 30;

const CIRCUIT_DIR = join(ROOT_DIR, "build/circuits/vanchor_2_8");
export const WASM_PATH = join(
  CIRCUIT_DIR,
  "poseidon_vanchor_2_8_js/poseidon_vanchor_2_8.wasm"
);
export const ZKEY_PATH = join(CIRCUIT_DIR, "circuit_final.zkey");

export const DEPLOYMENTS_PATH = join(ROOT_DIR, "deployments-round2/tempo.json");

export const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address account) external view returns (uint256)",
  "function transfer(address to, uint256 amount) external returns (bool)",
  "function allowance(address owner, address spender) external view returns (uint256)",
];

export const WRAPPER_ABI = [
  ...ERC20_ABI,
  "function wrap(address tokenAddress, uint256 amount) external payable",
  "function valid(address) external view returns (bool)",
];

export const VANCHOR_ABI = [
  "function transact(bytes, bytes, tuple(address,int256,address,uint256,uint256,address), tuple(bytes,bytes,uint256[],uint256[2],uint256,uint256), tuple(bytes,bytes)) external payable",
  "function getLastRoot() external view returns (uint256)",
  "function getZeroHash(uint32) external view returns (uint256)",
  "function getNextIndex() external view returns (uint32)",
  "function isSpent(uint256) external view returns (bool)",
  "function isKnownRoot(uint256) external view returns (bool)",
];

const NEW_COMMITMENT_TOPIC = ethers.id(
  "NewCommitment(uint256,uint256,uint256,bytes)"
);
const IFACE = new ethers.Interface([
  "event NewCommitment(uint256 commitment, uint256 subTreeIndex, uint256 leafIndex, bytes encryptedOutput)",
]);

export interface Deployments {
  chainId: number;
  rpcUrl: string;
  deployer: string;
  tangle: string;
  poseidon: Record<string, string>;
  vanchorEncodeInputs: string;
  verifiers: { v2_2: string; v2_16: string; v8_2: string; v8_16: string };
  poseidonHasher: string;
  vanchorVerifier: string;
  tokenWrapperHandler: string;
  fungibleTokenWrapper: string;
  anchorHandler: string;
  vanchorTree: string;
  shieldedCredits: string;
  shieldedGateway: string;
  stablecoin: string;
  deployBlock?: number;
  ceremony: { release: string; sha256sums: string };
}

export function loadDeployments(): Deployments {
  return JSON.parse(readFileSync(DEPLOYMENTS_PATH, "utf-8"));
}

/// Retry wrapper for rate-limited / flaky RPC calls.
export async function withRetry<T>(
  fn: () => Promise<T>,
  { tries = 10, baseMs = 2500, label = "rpc" } = {}
): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const msg = String((err as Error)?.message ?? err);
      const retryable =
        /rate|429|too many|timeout|timed out|ETIMEDOUT|ECONNRESET|fetch failed|502|503|nonce|replacement/i.test(
          msg
        );
      if (!retryable || i === tries - 1) throw err;
      const wait = baseMs * 2 ** i + Math.floor(Math.random() * 500);
      console.warn(
        `    [retry] ${label} attempt ${i + 1} failed (${msg.slice(0, 120)}); waiting ${wait}ms`
      );
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

/// The Tempo RPC rate-limits aggressively. Serialize all JSON-RPC calls
/// through a single queue with a minimum inter-call gap so concurrent
/// identity wallets don't trip the limiter.
class ThrottledProvider extends ethers.JsonRpcProvider {
  private queue: Promise<unknown> = Promise.resolve();
  private lastCall = 0;
  private minGapMs: number;

  constructor(url: string, chainId: number, minGapMs = 350) {
    super(url, chainId, { staticNetwork: true, polling: true, pollingInterval: 4000 });
    this.minGapMs = minGapMs;
  }

  override async send(method: string, params: Array<unknown>): Promise<unknown> {
    const run = async () => {
      const gap = Date.now() - this.lastCall;
      if (gap < this.minGapMs)
        await new Promise((r) => setTimeout(r, this.minGapMs - gap));
      this.lastCall = Date.now();
      return super.send(method, params);
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }
}

export function getProvider(): ethers.JsonRpcProvider {
  return new ThrottledProvider(RPC_URL, 42431);
}

/// Simple promise-pool for bounded concurrency.
export async function pool<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const i = cursor++;
      try {
        results[i] = { status: "fulfilled", value: await fn(items[i], i) };
      } catch (reason) {
        results[i] = { status: "rejected", reason };
      }
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, worker)
  );
  return results;
}

export interface ProveResult {
  proofBytes: Uint8Array;
  publicInputs: {
    roots: string;
    extensionRoots: string;
    inputNullifiers: bigint[];
    outputCommitments: [bigint, bigint];
    publicAmount: bigint;
    extDataHash: bigint;
  };
  proofMs: number;
}

export interface ProverContext {
  tree: MerkleTree;
  chainId: bigint; // typed chain id
  wrapperAddr: string;
  edgeZero: bigint; // getZeroHash(levels-1) for disabled edges
  maxEdges?: number;
}

export function buildRoots(localRoot: bigint, edgeZero: bigint, maxEdges = MAX_EDGES): bigint[] {
  return [localRoot, ...(Array(maxEdges).fill(edgeZero) as bigint[])];
}

/// Generate a real Groth16 proof and pack it for VAnchor.transact.
export async function proveTransact(
  ctx: ProverContext,
  params: {
    inputs: Utxo[];
    outputs: [Utxo, Utxo];
    extAmount: bigint;
    recipient: string;
    relayer?: string;
    fee?: bigint;
    localRoot?: bigint;
  }
): Promise<ProveResult> {
  const fee = params.fee ?? 0n;
  const extDataHash = computeExtDataHash({
    recipient: params.recipient,
    extAmount: params.extAmount,
    relayer: params.relayer ?? ethers.ZeroAddress,
    fee,
    refund: 0n,
    token: ctx.wrapperAddr,
    encryptedOutput1: new Uint8Array(0),
    encryptedOutput2: new Uint8Array(0),
  });

  const localRoot = params.localRoot ?? ctx.tree.root;
  const roots = buildRoots(localRoot, ctx.edgeZero, ctx.maxEdges);
  const witnessInput = await buildWitnessInputs({
    inputs: params.inputs,
    outputs: params.outputs,
    tree: ctx.tree,
    extDataHash,
    extAmount: params.extAmount,
    fee,
    chainId: ctx.chainId,
    roots,
  });

  const t0 = performance.now();
  const snarkjs = await import("snarkjs");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witnessInput as unknown as Record<string, unknown>,
    WASM_PATH,
    ZKEY_PATH
  );
  const proofMs = performance.now() - t0;

  const { proofBytes } = await encodeSolidityProof({ proof, publicSignals });

  const nullifiers = await Promise.all(
    params.inputs.map((u) => u.getNullifier())
  );
  const commitments = (await Promise.all(
    params.outputs.map((u) => u.getCommitment())
  )) as [bigint, bigint];

  return {
    proofBytes,
    proofMs,
    publicInputs: {
      roots: ethers.AbiCoder.defaultAbiCoder().encode(
        [`uint256[${(ctx.maxEdges ?? MAX_EDGES) + 1}]`],
        [roots]
      ),
      extensionRoots: "0x",
      inputNullifiers: nullifiers,
      outputCommitments: commitments,
      publicAmount: computePublicAmount(params.extAmount, fee),
      extDataHash,
    },
  };
}

/// Assemble the positional args for VAnchorTree.transact.
export function transactArgs(
  p: ProveResult,
  extData: {
    recipient: string;
    extAmount: bigint;
    relayer: string;
    fee: bigint;
    refund: bigint;
    token: string;
  }
): unknown[] {
  return [
    p.proofBytes,
    "0x",
    [
      extData.recipient,
      extData.extAmount,
      extData.relayer,
      extData.fee,
      extData.refund,
      extData.token,
    ],
    [
      p.publicInputs.roots,
      p.publicInputs.extensionRoots,
      p.publicInputs.inputNullifiers,
      p.publicInputs.outputCommitments,
      p.publicInputs.publicAmount,
      p.publicInputs.extDataHash,
    ],
    ["0x", "0x"],
  ];
}

export interface LeafRecord {
  commitment: bigint;
  leafIndex: number;
  txHash: string;
}

/// Fetch NewCommitment logs by address only (Tempo ignores topic filters),
/// parse client-side, and rebuild the local Merkle tree.
export async function syncTree(
  provider: ethers.Provider,
  poolAddr: string,
  levels = TREE_LEVELS,
  fromBlock?: number
): Promise<{ tree: MerkleTree; leaves: LeafRecord[] }> {
  if (fromBlock === undefined) {
    try {
      fromBlock = loadDeployments().deployBlock ?? 0;
    } catch {
      fromBlock = 0;
    }
  }
  const endBlock = await withRetry(() => provider.getBlockNumber(), {
    label: "getBlockNumber",
  });
  // Tempo caps eth_getLogs at 100k blocks per query — batch.
  const BATCH = 50_000;
  const rawLogs: ethers.Log[] = [];
  for (let from = fromBlock; from <= endBlock; from += BATCH) {
    const to = Math.min(from + BATCH - 1, endBlock);
    const batch = await withRetry(
      () => provider.getLogs({ address: poolAddr, fromBlock: from, toBlock: to }),
      { label: "getLogs" }
    );
    rawLogs.push(...batch);
  }

  const leaves: LeafRecord[] = [];
  for (const log of rawLogs) {
    if (log.topics[0] !== NEW_COMMITMENT_TOPIC) continue;
    const parsed = IFACE.parseLog({
      topics: log.topics as string[],
      data: log.data,
    });
    if (!parsed) continue;
    leaves.push({
      commitment: parsed.args[0] as bigint,
      leafIndex: Number(parsed.args[2]),
      txHash: log.transactionHash,
    });
  }
  leaves.sort((a, b) => a.leafIndex - b.leafIndex);

  // Integrity: sequential indices, no duplicates, no gaps.
  for (let i = 0; i < leaves.length; i++) {
    if (leaves[i].leafIndex !== i) {
      throw new Error(
        `Leaf sync integrity failure: expected index ${i}, got ${leaves[i].leafIndex} (tx ${leaves[i].txHash})`
      );
    }
    if (i > 0 && leaves[i].commitment === leaves[i - 1].commitment) {
      throw new Error(
        `Duplicate adjacent leaf commitment at index ${i} (tx ${leaves[i].txHash})`
      );
    }
  }

  const tree = await MerkleTree.fromLeaves(
    levels,
    leaves.map((l) => l.commitment)
  );
  return { tree, leaves };
}

export function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return NaN;
  const idx = Math.min(
    sorted.length - 1,
    Math.ceil((p / 100) * sorted.length) - 1
  );
  return sorted[Math.max(0, idx)];
}

export function stats(values: number[]): {
  n: number;
  min: number;
  p50: number;
  p95: number;
  max: number;
  mean: number;
} {
  const s = [...values].sort((a, b) => a - b);
  const mean = values.reduce((a, b) => a + b, 0) / (values.length || 1);
  return {
    n: s.length,
    min: s[0] ?? NaN,
    p50: pct(s, 50),
    p95: pct(s, 95),
    max: s[s.length - 1] ?? NaN,
    mean,
  };
}
