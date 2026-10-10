#!/usr/bin/env node
/**
 * Round-2 rehearsal variant of scripts/deploy-poseidon.mjs.
 * Identical logic, but the output directory is overridable via OUTPUT_DIR
 * so the round-2 run does not touch deploy/output/poseidon-42431.json
 * (which belongs to the live round-1 rehearsal stack).
 */
import { ethers } from "ethers";
import { writeFileSync, mkdirSync, readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  const rpcUrl = process.env.RPC_URL || "http://localhost:8545";
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    console.error("Set PRIVATE_KEY env var");
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.NonceManager(new ethers.Wallet(privateKey, provider));
  const chainId = (await provider.getNetwork()).chainId;

  console.log(`Deploying Poseidon libraries on chain ${chainId}...`);
  console.log(`Deployer: ${await signer.getAddress()}`);

  const circomlibjs = await import("circomlibjs");
  const genContract = circomlibjs.poseidon_gencontract || circomlibjs.default?.poseidon_gencontract;

  if (!genContract) {
    console.error("circomlibjs.poseidon_gencontract not found. Install: npm i circomlibjs@0.0.8");
    process.exit(1);
  }

  const outDir = process.env.OUTPUT_DIR || join(__dirname, "../deploy/output");
  mkdirSync(outDir, { recursive: true });
  const outFile = join(outDir, `poseidon-${chainId}.json`);

  // Resume support: skip libraries already recorded from a partial run.
  let addresses = {};
  try { addresses = JSON.parse(readFileSync(outFile, "utf-8")); } catch {}

  for (let nInputs = 1; nInputs <= 5; nInputs++) {
    const name = `PoseidonT${nInputs + 1}`;
    if (addresses[name]) {
      console.log(`  ${name} already deployed: ${addresses[name]}`);
      continue;
    }
    console.log(`  Deploying ${name} (${nInputs} inputs)...`);

    const abi = genContract.generateABI(nInputs);
    const bytecode = genContract.createCode(nInputs);

    const factory = new ethers.ContractFactory(abi, bytecode, signer);
    // Tempo: 30M tx gas cap. Estimate with a 20% buffer, capped at 29M;
    // estimation can fail on this RPC, so fall back to 29M.
    let gasLimit = 29_000_000n;
    try {
      const deployTx = await factory.getDeployTransaction();
      const est = await provider.estimateGas({ ...deployTx, from: await signer.getAddress() });
      gasLimit = (est * 120n) / 100n;
      if (gasLimit > 29_000_000n) gasLimit = 29_000_000n;
    } catch { /* fall back to 29M */ }
    const contract = await factory.deploy({ gasLimit });
    await contract.waitForDeployment();
    const addr = await contract.getAddress();

    addresses[name] = addr;
    writeFileSync(outFile, JSON.stringify(addresses, null, 2));
    console.log(`    ${name}: ${addr} (gasLimit ${gasLimit})`);
  }

  writeFileSync(outFile, JSON.stringify(addresses, null, 2));

  console.log(`\nAddresses written to: ${outFile}`);
  console.log(JSON.stringify(addresses, null, 2));
}

main().catch(err => { console.error(err); process.exit(1); });
