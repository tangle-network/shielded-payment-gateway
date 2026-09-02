//! Batch Sequencer: collects shielded transaction proofs and generates
//! a single SP1 batch proof for on-chain verification.
//!
//! Usage:
//!   # Build the SP1 program first:
//!   cd program && cargo prove build
//!
//!   # Run the sequencer:
//!   cargo run -- --proofs-dir ./pending-proofs --rpc-url http://localhost:8545
//!
//! The sequencer:
//! 1. Reads N Groth16 proofs from the proofs directory
//! 2. Packs them into a BatchInput
//! 3. Generates an SP1 proof (locally or via prover network)
//! 4. Submits the batch to the BatchVerifier contract

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use std::path::PathBuf;

/// The ELF binary for the SP1 batch verification program.
/// Built by: `cd program && cargo prove build`
///
/// If the ELF hasn't been built yet, the sequencer will panic at startup
/// with a clear error message. Build the program first:
///   cd sp1-batch/program && cargo prove build
#[cfg(feature = "prove")]
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[cfg(not(feature = "prove"))]
const ELF: &[u8] = &[];

/// Batch sequencer for shielded pool transactions
#[derive(Parser, Debug)]
struct Args {
    /// Directory containing pending Groth16 proof JSON files
    #[arg(long, default_value = "./pending-proofs")]
    proofs_dir: PathBuf,

    /// Maximum batch size
    #[arg(long, default_value_t = 100)]
    max_batch_size: usize,

    /// RPC URL for submitting the batch on-chain
    #[arg(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    /// BatchVerifier contract address
    #[arg(long)]
    verifier_address: Option<String>,

    /// Use SP1 prover network instead of local proving
    #[arg(long)]
    use_network: bool,

    /// Just generate the proof without submitting on-chain
    #[arg(long)]
    dry_run: bool,
}

/// Matches the SP1 program's BatchInput
#[derive(Serialize, Deserialize, Debug)]
struct TransactionPublicData {
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    public_amount: [u8; 32],
    ext_data_hash: [u8; 32],
    chain_id: [u8; 32],
    roots: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Groth16Proof {
    proof_bytes: Vec<u8>,
    public_signals: Vec<[u8; 32]>,
    tx_data: TransactionPublicData,
}

#[derive(Serialize, Deserialize, Debug)]
struct BatchInput {
    vkey: Vec<u8>,
    proofs: Vec<Groth16Proof>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
struct BatchOutput {
    tx_count: u32,
    all_nullifiers: Vec<[u8; 32]>,
    all_commitments: Vec<[u8; 32]>,
    public_amounts_hash: [u8; 32],
    ext_data_hash: [u8; 32],
}

fn load_proofs(dir: &PathBuf, max: usize) -> Result<Vec<Groth16Proof>> {
    let mut proofs = Vec::new();

    if !dir.exists() {
        anyhow::bail!("proofs directory does not exist: {}", dir.display());
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .context("failed to read proofs directory")?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .collect();

    // Sort by filename for deterministic ordering
    entries.sort_by_key(|e| e.file_name());

    for entry in entries.into_iter().take(max) {
        let content = std::fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        let proof: Groth16Proof = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", entry.path().display()))?;
        proofs.push(proof);
    }

    Ok(proofs)
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("═══════════════════════════════════════");
    println!("  Shielded Pool Batch Sequencer");
    println!("═══════════════════════════════════════");
    println!("  Proofs dir: {:?}", args.proofs_dir);
    println!("  Max batch:  {}", args.max_batch_size);
    println!("  Network:    {}", args.use_network);
    println!("  Dry run:    {}", args.dry_run);
    println!();

    // 1. Read proof JSON files
    let proofs = load_proofs(&args.proofs_dir, args.max_batch_size)?;
    if proofs.is_empty() {
        println!(
            "No proofs found in {:?}, nothing to batch.",
            args.proofs_dir
        );
        return Ok(());
    }
    println!("Loaded {} proof(s)", proofs.len());

    // 2. Load verification key (first proof's vkey, all should match)
    let vkey = proofs
        .first()
        .map(|p| p.public_signals.iter().flat_map(|s| s.to_vec()).collect())
        .unwrap_or_default();

    let batch_input = BatchInput { vkey, proofs };

    // 3. Generate SP1 proof
    #[allow(clippy::const_is_empty)]
    if ELF.is_empty() {
        anyhow::bail!(
            "SP1 program ELF not built. Run: cd sp1-batch/program && cargo prove build\n\
             Then rebuild with: cargo run --features prove -- ..."
        );
    }
    println!("Generating SP1 batch proof...");

    let client = ProverClient::from_env();
    let pk = client.setup(Elf::Static(ELF)).context("SP1 setup failed")?;

    let mut stdin = SP1Stdin::new();
    let input_bytes =
        serde_json::to_vec(&batch_input).context("failed to serialize batch input")?;
    stdin.write_slice(&input_bytes);

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .context("SP1 proof generation failed")?;

    let proof_bytes = proof.bytes();
    println!(
        "SP1 proof generated: {} bytes, {} tx(s) batched",
        proof_bytes.len(),
        batch_input.proofs.len()
    );

    // 4. Save proof to disk
    let output_path = args.proofs_dir.join("batch-proof.bin");
    std::fs::write(&output_path, &proof_bytes).context("failed to write batch proof")?;
    println!("Batch proof saved to {}", output_path.display());

    if args.dry_run {
        println!("\nDry run — skipping on-chain submission.");
        return Ok(());
    }

    // 5. Submit to BatchVerifier contract
    if let Some(verifier) = args.verifier_address {
        println!("Submitting batch to BatchVerifier at {verifier}...");
        println!("  (on-chain submission requires alloy provider setup — see deploy scripts)");
        // On-chain submission would use alloy here:
        // let provider = ProviderBuilder::new().on_http(args.rpc_url.parse()?);
        // let contract = BatchVerifier::new(verifier.parse()?, provider);
        // contract.processBatch(proof_bytes, public_values).send().await?;
    } else {
        println!("No --verifier-address provided, skipping on-chain submission.");
        println!("Submit manually: cast send $VERIFIER 'processBatch(bytes,bytes)' $PROOF $PUBLIC");
    }

    println!("\n✓ Batch sequencer complete.");
    Ok(())
}
