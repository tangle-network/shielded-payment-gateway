import { existsSync } from "fs";
import { mkdir, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { homedir } from "os";
import type { CircuitArtifacts } from "./prover.js";

/// Historical Webb fixture bucket. NOTE: this bucket no longer exists —
/// downloads from it fail. Prefer locally generated keys (see below).
const DEFAULT_BASE_URL =
  "https://protocol-solidity-fixtures.s3.amazonaws.com/solidity-fixtures";

const DEFAULT_CACHE_DIR = join(homedir(), ".tangle", "circuits");

/// Directory layout produced by scripts/trusted-setup/ceremony.sh:
///   <dir>/vanchor_<inputs>_<maxEdges>/{wasm...,circuit_final.zkey}
/// Resolution order for local keys:
///   1. TANGLE_CIRCUIT_DIR env var
///   2. <repo>/build/circuits (works from both src/ and dist/)
function getLocalDir(override?: string): string | null {
  if (override) return override;
  if (process.env.TANGLE_CIRCUIT_DIR) return process.env.TANGLE_CIRCUIT_DIR;
  const here = dirname(fileURLToPath(import.meta.url));
  const repoBuild = join(here, "../../../../build/circuits");
  return existsSync(repoBuild) ? repoBuild : null;
}

/// Resolve the base URL for circuit artifacts.
/// Override with TANGLE_CIRCUIT_BASE_URL env var or pass explicitly.
function getBaseUrl(override?: string): string {
  return override ?? process.env.TANGLE_CIRCUIT_BASE_URL ?? DEFAULT_BASE_URL;
}

/// Build the URL for a circuit artifact.
function artifactUrl(
  inputs: 2 | 16,
  maxEdges: 2 | 8,
  kind: "wasm" | "zkey",
  baseUrl?: string
): string {
  const base = getBaseUrl(baseUrl);
  const size = maxEdges;
  if (kind === "wasm") {
    return `${base}/vanchor_${inputs}/${size}/poseidon_vanchor_${inputs}_${size}.wasm`;
  }
  return `${base}/vanchor_${inputs}/${size}/circuit_final.zkey`;
}

/// Paths for a circuit inside a local directory (ceremony.sh layout).
function localPaths(dir: string, inputs: 2 | 16, maxEdges: 2 | 8) {
  const subdir = join(dir, `vanchor_${inputs}_${maxEdges}`);
  return {
    wasmPath: join(
      subdir,
      `poseidon_vanchor_${inputs}_${maxEdges}_js`,
      `poseidon_vanchor_${inputs}_${maxEdges}.wasm`
    ),
    zkeyPath: join(subdir, "circuit_final.zkey"),
  };
}

/// Download a file if it doesn't already exist at destPath.
export async function downloadIfMissing(
  url: string,
  destPath: string
): Promise<void> {
  if (existsSync(destPath)) return;

  const dir = destPath.substring(0, destPath.lastIndexOf("/"));
  await mkdir(dir, { recursive: true });

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `Failed to download ${url}: ${response.status} ${response.statusText}. ` +
        `The historical fixture bucket is gone — generate keys locally with ` +
        `scripts/trusted-setup/ceremony.sh (uses the public Hermez Powers of Tau) ` +
        `or set TANGLE_CIRCUIT_DIR / TANGLE_CIRCUIT_BASE_URL.`
    );
  }
  const buffer = new Uint8Array(await response.arrayBuffer());
  await writeFile(destPath, buffer);
}

/// Resolve circuit artifacts, returning paths to the local files.
///
/// Prefers proving keys generated locally by
/// scripts/trusted-setup/ceremony.sh (public Hermez Powers of Tau + local
/// phase 2). Falls back to downloading into the cache dir when no local
/// keys exist.
export async function getCircuitArtifacts(
  inputs: 2 | 16,
  maxEdges: 2 | 8,
  cacheDir: string = DEFAULT_CACHE_DIR,
  baseUrl?: string,
  localDir?: string
): Promise<CircuitArtifacts> {
  const local = getLocalDir(localDir);
  if (local) {
    const paths = localPaths(local, inputs, maxEdges);
    if (existsSync(paths.wasmPath) && existsSync(paths.zkeyPath)) {
      return paths;
    }
  }

  const subdir = join(cacheDir, `vanchor_${inputs}`, `${maxEdges}`);
  const wasmPath = join(subdir, `poseidon_vanchor_${inputs}_${maxEdges}.wasm`);
  const zkeyPath = join(subdir, "circuit_final.zkey");

  await Promise.all([
    downloadIfMissing(artifactUrl(inputs, maxEdges, "wasm", baseUrl), wasmPath),
    downloadIfMissing(artifactUrl(inputs, maxEdges, "zkey", baseUrl), zkeyPath),
  ]);

  return { wasmPath, zkeyPath };
}
