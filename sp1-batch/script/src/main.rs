//! Batch Sequencer: collects shielded transaction proofs and generates
//! a single SP1 batch proof for on-chain verification.
//!
//! Usage:
//!   cargo run -- --proofs-dir ./pending-proofs --rpc-url http://localhost:8545
//!
//! The sequencer:
//! 1. Reads N Groth16 proofs from the proofs directory
//! 2. Packs them into a BatchInput
//! 3. Generates an SP1 proof (locally or via prover network)
//! 4. Submits the batch to the BatchVerifier contract

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

#[derive(Serialize, Deserialize, Debug)]
struct BatchOutput {
    tx_count: u32,
    all_nullifiers: Vec<[u8; 32]>,
    all_commitments: Vec<[u8; 32]>,
    public_amounts_hash: [u8; 32],
    ext_data_hash: [u8; 32],
}

fn main() {
    let args = Args::parse();

    println!("═══════════════════════════════════════");
    println!("  Shielded Pool Batch Sequencer");
    println!("═══════════════════════════════════════");
    println!("  Proofs dir: {:?}", args.proofs_dir);
    println!("  Max batch:  {}", args.max_batch_size);
    println!("  Network:    {}", args.use_network);
    println!("  Dry run:    {}", args.dry_run);
    println!();

    // TODO: Full implementation requires:
    // 1. Read proof JSON files from proofs_dir
    // 2. Pack into BatchInput
    // 3. Generate SP1 proof:
    //    let client = sp1_sdk::ProverClient::from_env();
    //    let (pk, vk) = client.setup(ELF);
    //    let stdin = sp1_sdk::SP1Stdin::new();
    //    stdin.write(&batch_input);
    //    let proof = client.prove(&pk, &stdin).groth16().run().unwrap();
    // 4. Submit to BatchVerifier contract (if not dry_run)

    println!("  Batch sequencer scaffolded.");
    println!("  Full implementation requires sp1-sdk build with the program ELF.");
    println!("  Build program first: cd program && cargo prove build");
}
