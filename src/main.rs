use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use parth_core::{
    pgoldilocks::QHashOut,
    protocol::core_types::Q256BitHash,
};
use psy_validator::config::{run, Config};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_validator::{
    models::{GenerateProofRequest, GenerateProofResponse, VerifyProofRequest, VerifyProofResponse},
    services::{derive_worker_reward_tag_from_job_id, AppState},
    handler::parse_hex_hash,
};
use serde_json;
use tracing_subscriber::{self, EnvFilter};

/// Psy Validator CLI - Zero Knowledge Proof Generation and Verification
#[derive(Parser, Debug)]
#[command(
    name = "psy-validator",
    version,
    about = "CLI tool for ZK proof generation and verification",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level (e.g. info, debug, trace)
    #[arg(long = "log-level", default_value = "info")]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run http server
    Server {
        /// Listen address (e.g. 0.0.0.0)
        #[arg(long = "listen-addr", default_value = "0.0.0.0")]
        listen_addr: String,

        /// Listening port
        #[arg(long, default_value_t = 4000)]
        port: u16,
    },
    /// Generate zero-knowledge proof
    GenerateProof {
        /// Input JSON file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Worker reward tag (hex string, optional)
        #[arg(long)]
        worker_reward_tag: Option<String>,

        /// Reward tree value (hex string, optional)
        #[arg(long)]
        reward_tree_value: Option<String>,
    },

    /// Verify zero-knowledge proof
    VerifyProof {
        /// Input JSON file path
        #[arg(short, long)]
        input: PathBuf,

        /// Proof file path (hex string or JSON with proof field)
        #[arg(short, long)]
        proof: PathBuf,

        /// Worker reward tag (hex string, optional)
        #[arg(long)]
        worker_reward_tag: Option<String>,

        /// Reward tree value (hex string, optional)
        #[arg(long)]
        reward_tree_value: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .init();

    match cli.command {
        Commands::Server {
            listen_addr,
            port,
        } => {
            let mut config = Config::from_env();
            config.server.host = listen_addr.clone();
            config.server.port = port;

            tracing::info!("Starting psy validator server at {}:{}", listen_addr, port);

            run(config).await
        }
        Commands::GenerateProof {
            input,
            output,
            worker_reward_tag,
            reward_tree_value,
        } => handle_generate_proof(input, output, worker_reward_tag, reward_tree_value),
        Commands::VerifyProof {
            input,
            proof,
            worker_reward_tag,
            reward_tree_value,
        } => handle_verify_proof(input, proof, worker_reward_tag, reward_tree_value),
    }
}

fn handle_generate_proof(
    input_path: PathBuf,
    output_path: Option<PathBuf>,
    worker_reward_tag: Option<String>,
    reward_tree_value: Option<String>,
) -> Result<()> {
    tracing::info!("Reading input from: {}", input_path.display());

    // Read input file
    let input_content = std::fs::read_to_string(&input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let mut request: GenerateProofRequest = serde_json::from_str(&input_content)
        .with_context(|| format!("Failed to parse input JSON: {}", input_path.display()))?;

    // Override with CLI arguments if provided
    if let Some(tag) = worker_reward_tag {
        request.worker_reward_tag = Some(tag);
    }
    if let Some(rtv) = reward_tree_value {
        request.reward_tree_value = Some(rtv);
    }

    // Initialize AppState
    tracing::info!("Initializing circuit library and prover...");
    let state = AppState::new().context("Failed to initialize AppState")?;

    // Convert request to internal format
    let input = request
        .input
        .to_internal()
        .context("Failed to convert input to internal format")?;

    // Get job_id for deriving worker_reward_tag if needed
    let job_id = input.base.job.job_id;

    // Parse worker_reward_tag and reward_tree_value
    let worker_reward_tag = match request.worker_reward_tag.as_deref() {
        Some(tag_hex) => {
            let tag = parse_hex_hash(tag_hex)
                .map_err(|e| anyhow::anyhow!("Invalid worker_reward_tag: {}", e))?;
            Some(tag)
        }
        None => None,
    };

    let reward_tree_value = request
        .reward_tree_value
        .as_deref()
        .map(|hex| {
            parse_hex_hash(hex).map_err(|e| anyhow::anyhow!("Invalid reward_tree_value: {}", e))
        })
        .transpose()?;

    // Generate proof
    tracing::info!("Generating proof...");
    let (proof_bytes, computed_reward_tree_value) = state
        .generate_proof(input, worker_reward_tag, reward_tree_value)
        .context("Proof generation failed")?;

    // Derive worker_reward_tag if not provided (for response)
    // Use the same approach as handler.rs: derive from job_id if not provided
    let final_worker_reward_tag: QHashOut<GoldilocksField> = if let Some(tag) = worker_reward_tag {
        tag
    } else {
        derive_worker_reward_tag_from_job_id(job_id)
            .context("Failed to derive worker_reward_tag")?
    };

    // Convert computed_reward_tree_value to bytes
    // The type is QHashOut<F> where F = GoldilocksField
    let reward_tree_value_bytes: [u8; 32] = computed_reward_tree_value.into_owned_32bytes();

    // Create response
    let response = GenerateProofResponse {
        proof: hex::encode(&proof_bytes),
        worker_reward_tag: hex::encode(final_worker_reward_tag.into_owned_32bytes()),
        reward_tree_value: hex::encode(reward_tree_value_bytes),
    };

    // Output result
    let output_json = serde_json::to_string_pretty(&response)
        .context("Failed to serialize response to JSON")?;

    if let Some(output) = output_path {
        std::fs::write(&output, output_json)
            .with_context(|| format!("Failed to write output file: {}", output.display()))?;
        tracing::info!("Proof written to: {}", output.display());
    } else {
        println!("{}", output_json);
    }

    Ok(())
}

fn handle_verify_proof(
    input_path: PathBuf,
    proof_path: PathBuf,
    worker_reward_tag: Option<String>,
    reward_tree_value: Option<String>,
) -> Result<()> {
    tracing::info!("Reading input from: {}", input_path.display());
    tracing::info!("Reading proof from: {}", proof_path.display());

    // Read input file
    let input_content = std::fs::read_to_string(&input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let mut request: VerifyProofRequest = serde_json::from_str(&input_content)
        .with_context(|| format!("Failed to parse input JSON: {}", input_path.display()))?;

    // Read proof file
    let proof_content = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    // Parse proof file - support both JSON format and plain hex string
    let (proof_hex, proof_reward_tree_value) = parse_proof_file(&proof_content)?;

    // Override with CLI arguments if provided
    if let Some(tag) = worker_reward_tag {
        request.worker_reward_tag = Some(tag);
    }
    if let Some(rtv) = reward_tree_value {
        request.reward_tree_value = Some(rtv);
    } else if let Some(rtv) = proof_reward_tree_value {
        // Use reward_tree_value from proof file if not provided via CLI
        request.reward_tree_value = Some(rtv);
    }

    // Update request with proof from file
    request.proof = proof_hex;

    // Initialize AppState
    tracing::info!("Initializing circuit library and verifier...");
    let state = AppState::new().context("Failed to initialize AppState")?;

    // Convert request to internal format
    let input = request
        .input
        .to_internal()
        .context("Failed to convert input to internal format")?;

    // Parse proof bytes
    let proof_bytes = hex::decode(&request.proof)
        .context("Failed to decode proof hex string")?;

    // Parse worker_reward_tag and reward_tree_value
    let worker_reward_tag = request
        .worker_reward_tag
        .as_deref()
        .map(|tag_hex| {
            parse_hex_hash(tag_hex)
                .map_err(|e| anyhow::anyhow!("Invalid worker_reward_tag: {}", e))
        })
        .transpose()?;

    let reward_tree_value = request
        .reward_tree_value
        .as_deref()
        .map(|hex| {
            parse_hex_hash(hex).map_err(|e| anyhow::anyhow!("Invalid reward_tree_value: {}", e))
        })
        .transpose()?;

    // Verify proof
    tracing::info!("Verifying proof...");
    let verify_result = state.verify_proof(input, &proof_bytes, worker_reward_tag, reward_tree_value);

    // Create response
    let response = match verify_result {
        Ok(()) => VerifyProofResponse {
            valid: true,
            message: Some("Proof is valid".to_string()),
        },
        Err(e) => {
            tracing::warn!("Proof verification failed: {}", e);
            VerifyProofResponse {
                valid: false,
                message: Some(format!("Verification failed: {}", e)),
            }
        }
    };

    // Output result
    let output_json = serde_json::to_string_pretty(&response)
        .context("Failed to serialize response to JSON")?;

    println!("{}", output_json);

    // Return error if verification failed
    if !response.valid {
        std::process::exit(1);
    }

    Ok(())
}

/// Parse proof file - supports both JSON format and plain hex string
fn parse_proof_file(content: &str) -> Result<(String, Option<String>)> {
    let trimmed = content.trim();

    // Try to parse as JSON first
    if let Ok(proof_json) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(obj) = proof_json.as_object() {
            if let Some(proof) = obj.get("proof").and_then(|v| v.as_str()) {
                let reward_tree_value = obj
                    .get("reward_tree_value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                return Ok((proof.to_string(), reward_tree_value));
            }
        }
    }

    // Fallback: treat as plain hex string (may be quoted JSON string)
    let proof_hex = if trimmed.starts_with('"') && trimmed.ends_with('"') {
        serde_json::from_str::<String>(trimmed)
            .unwrap_or_else(|_| trimmed.trim_matches('"').to_string())
    } else {
        trimmed.to_string()
    };

    Ok((proof_hex, None))
}
