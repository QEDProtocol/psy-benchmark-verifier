use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures::future::join_all;
use once_cell::sync::Lazy;
use parth_core::{pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_prover::{
    config::{run, Config},
    handler::parse_hex_hash,
    models::{
        GenerateProofRequest, GenerateProofResponse, PsyProvingJobMetadataJson, PsyProvingJobMetadataWithJobIdJson,
        PsyWorkerGetProvingWorkAPIResponseJson, PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson, VerifyProofRequest, VerifyProofResponse,
    },
    services::{derive_worker_reward_tag_from_job_id, AppState},
};
use serde::{Deserialize, Serialize};
use serde_json;
use tracing_subscriber::{self, EnvFilter};

static REALM_ROOT_JOS_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let content = include_str!("../realm_root_jos_map.json");
    serde_json::from_str::<HashMap<String, String>>(content).expect("Failed to parse realm_root_jos_map.json")
});

/// Psy Validator CLI - Zero Knowledge Proof Generation and Verification
#[derive(Parser, Debug)]
#[command(
    name = "psy-validator",
    version,
    about = "CLI tool and HTTP server for ZK proof generation and verification",
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

    /// Fetch job and dependencies proofs in one click workflow
    FetchJob {
        /// Base URL (format: https://xxx)
        #[arg(short, long)]
        base_url: String,
        /// Proof ID (format: job_id_hex + realm_id_hex, where job_id_hex is 48
        /// chars and realm_id < 1000)
        #[arg(short, long)]
        proof_id: String,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output_dir: Option<PathBuf>,
        /// One click done
        #[arg(short, long, default_value = "true")]
        one_click_done: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt().with_env_filter(EnvFilter::new(&cli.log_level)).init();

    match cli.command {
        Commands::Server { listen_addr, port } => {
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
        Commands::FetchJob {
            base_url,
            proof_id,
            output_dir,
            one_click_done,
        } => fetch_job(base_url, proof_id, output_dir, one_click_done).await,
    }
}

/// Fetch raw_proof.json for a single dependency
/// Returns Some(proof_hex) on success, None on failure (warning already logged)
async fn fetch_dependency_proof(
    client: &reqwest::Client,
    base_url: &str,
    realm_id: u64,
    node_type: u8,
    job: &ParsedJobId,
    dep_job_id: &str,
    output_dir: &Path,
) -> Result<Option<String>> {
    // Format: {base_url}/output/{realm_id}/{dep_job_id}/raw_proof.json
    let raw_proof_url = format!("{}/output/{}/{}/raw_proof.json", base_url, realm_id, dep_job_id);
    tracing::info!("Fetching raw_proof.json for dependency {} from: {}", dep_job_id, raw_proof_url);

    let mut proof_response = client
        .get(&raw_proof_url)
        .send()
        .await
        .with_context(|| format!("Failed to send HTTP request for raw_proof.json of dependency {}", dep_job_id))?;

    if !proof_response.status().is_success() {
        let status = proof_response.status();
        tracing::warn!(
            "Failed to fetch raw_proof.json for dependency {} from {}: HTTP {} {}",
            dep_job_id,
            raw_proof_url,
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        // Retry with dep_realm_id for node_type == 2
        if node_type == 2 {
            let dep_realm_id = job.task_index;
            let retry_url = format!("{}/output/{}/{}/raw_proof.json", base_url, dep_realm_id, dep_job_id);
            tracing::info!(
                "Retrying fetch for dependency {} with realm_id {} (node_type=2) from: {}",
                dep_job_id,
                dep_realm_id,
                retry_url
            );

            proof_response = client.get(&retry_url).send().await.with_context(|| {
                format!(
                    "Failed to send HTTP request for raw_proof.json of dependency {} (retry with realm_id {})",
                    dep_job_id, dep_realm_id
                )
            })?;

            if !proof_response.status().is_success() {
                let retry_status = proof_response.status();
                tracing::warn!(
                    "Failed to fetch raw_proof.json for dependency {} after retry from {}: HTTP {} {}",
                    dep_job_id,
                    retry_url,
                    retry_status.as_u16(),
                    retry_status.canonical_reason().unwrap_or("Unknown")
                );
                return Ok(None);
            }
            tracing::debug!("Successfully fetched proof for dependency {} after retry", dep_job_id);
        } else {
            tracing::debug!("Skipping retry for dependency {} (node_type={}, not 2)", dep_job_id, node_type);
            return Ok(None);
        }
    }

    // Get response text to handle both formats
    let proof_text = proof_response
        .text()
        .await
        .with_context(|| format!("Failed to read response text for dependency {}", dep_job_id))?;
    let proof_text_trimmed = proof_text.trim();

    // Try to parse as JSON object first (format 1: structured JSON)
    let proof_hex = if let Ok(raw_proof) = serde_json::from_str::<RawProofJson>(proof_text_trimmed) {
        // Format 1: JSON object with proof field
        tracing::debug!(
            "Parsed raw_proof.json as JSON object for dependency {} (proof length: {} chars)",
            dep_job_id,
            raw_proof.proof.len()
        );

        // Save raw_proof.json for this dependency (optional, for debugging)
        let dep_proof_path = output_dir.join(format!("raw_proof_{}.json", dep_job_id));
        let raw_proof_json =
            serde_json::to_string_pretty(&raw_proof).with_context(|| format!("Failed to serialize raw_proof.json for dependency {}", dep_job_id))?;
        std::fs::write(&dep_proof_path, &raw_proof_json)
            .with_context(|| format!("Failed to write {} for dependency {}", dep_proof_path.display(), dep_job_id))?;
        tracing::debug!("Saved raw_proof.json for dependency {} to {}", dep_job_id, dep_proof_path.display());

        raw_proof.proof
    } else {
        // Format 2: Plain hex string (may be quoted JSON string or raw hex)
        tracing::debug!(
            "Parsed raw_proof.json as plain hex string for dependency {} (text length: {} chars)",
            dep_job_id,
            proof_text_trimmed.len()
        );

        let hex_string = if proof_text_trimmed.starts_with('"') && proof_text_trimmed.ends_with('"') {
            // Remove JSON string quotes
            serde_json::from_str::<String>(proof_text_trimmed).unwrap_or_else(|_| proof_text_trimmed.trim_matches('"').to_string())
        } else {
            proof_text_trimmed.to_string()
        };

        // Save raw_proof.json for this dependency (save as plain hex string)
        let dep_proof_path = output_dir.join(format!("raw_proof_{}.json", dep_job_id));
        std::fs::write(&dep_proof_path, &hex_string)
            .with_context(|| format!("Failed to write {} for dependency {}", dep_proof_path.display(), dep_job_id))?;
        tracing::debug!(
            "Saved raw_proof.json for dependency {} to {} (plain hex format, length: {} chars)",
            dep_job_id,
            dep_proof_path.display(),
            hex_string.len()
        );

        hex_string
    };

    Ok(Some(proof_hex))
}

async fn fetch_job(base_url: String, proof_id: String, output_dir: Option<PathBuf>, one_click_done: bool) -> Result<()> {
    let start_time = Instant::now();
    tracing::info!("Fetching job with base_url: {}, proof_id: {}", base_url, proof_id);
    tracing::info!("One-click done: {}", one_click_done);

    // Replace proof_id with realm root proof_id if exists in map
    let proof_id = if let Some(root_proof_id) = REALM_ROOT_JOS_MAP.get(&proof_id) {
        tracing::info!("Realm root job found, replacing proof_id: {} -> {}", proof_id, root_proof_id);
        root_proof_id.clone()
    } else {
        proof_id
    };

    // Parse proof_id to extract job_id_hex and realm_id
    // proof_id format: job_id_hex (48 chars) + realm_id_hex
    let (job_id, mut realm_id) = parse_proof_id(&proof_id).context("Failed to parse proof_id")?;

    // Calculate node_type based on realm_id
    let node_type = if realm_id < 999 {
        realm_id += 1;
        1
    } else {
        2
    };
    tracing::info!("Realm ID (parsed from proof_id): {}", realm_id);
    tracing::info!("Job ID (parsed from proof_id): {}", job_id);
    tracing::info!("Node type (calculated): {}", node_type);
    tracing::info!("Base URL: {}", base_url);

    // Determine output directory and create realm_id subdirectory
    let base_output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_dir = base_output_dir.join(realm_id.to_string());
    std::fs::create_dir_all(&output_dir).with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;
    tracing::info!("Output directory: {}", output_dir.display());

    let job = parse_job_id(&hex::decode(&job_id).context("Failed to decode job ID")?);
    if job.is_none() {
        anyhow::bail!("Invalid job ID: {}", job_id);
    }
    let job = job.unwrap();
    tracing::info!("Job: {:?}", job);
    if job.circuit_type == 6 {
        tracing::info!("Job is a user end cap job");
        return Ok(());
    }

    // Construct raw_input_url from base_url, realm_id, and job_id
    // Format: {base_url}/output/{realm_id}/{job_id}/raw_input.json
    let raw_input_url = format!("{}/output/{}/{}/raw_input.json", base_url, realm_id, job_id);
    tracing::info!("Fetching raw_input.json from: {}", raw_input_url);

    // Fetch raw_input.json
    let client = reqwest::Client::new();
    let response = client
        .get(&raw_input_url)
        .send()
        .await
        .context("Failed to send HTTP request for raw_input.json")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Failed to fetch raw_input.json: HTTP {} - {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let raw_input: RawInputJson = response.json().await.context("Failed to parse raw_input.json response")?;

    // Save raw_input.json with job_id in filename
    let raw_input_path = output_dir.join(format!("raw_input_{}.json", job_id));
    let raw_input_json = serde_json::to_string_pretty(&raw_input).context("Failed to serialize raw_input.json")?;
    std::fs::write(&raw_input_path, &raw_input_json).with_context(|| format!("Failed to write raw_input.json: {}", raw_input_path.display()))?;
    tracing::info!("Saved raw_input.json to: {}", raw_input_path.display());

    // Fetch raw_proof.json for each dependency in parallel
    tracing::info!("Fetching {} dependencies in parallel", raw_input.metadata.dependencies.len());
    let fetch_tasks: Vec<_> = raw_input
        .metadata
        .dependencies
        .iter()
        .map(|dep_job_id| fetch_dependency_proof(&client, &base_url, realm_id, node_type, &job, dep_job_id, &output_dir))
        .collect();

    let results = join_all(fetch_tasks).await;

    // Process results and collect proofs or missing dependencies
    let mut input_proofs = Vec::new();
    let mut missing_dependencies = Vec::new();

    for (dep_job_id, result) in raw_input.metadata.dependencies.iter().zip(results) {
        match result {
            Ok(Some(proof_hex)) => {
                let proof_len = proof_hex.len();
                input_proofs.push(proof_hex);
                tracing::debug!("Successfully fetched proof for dependency {} (length: {} chars)", dep_job_id, proof_len);
            }
            Ok(None) => {
                missing_dependencies.push(dep_job_id.clone());
                tracing::warn!(
                    "Failed to fetch proof for dependency {}: HTTP request returned non-success status (details logged above)",
                    dep_job_id
                );
            }
            Err(e) => {
                missing_dependencies.push(dep_job_id.clone());
                tracing::error!("Error fetching proof for dependency {}: {:#}", dep_job_id, e);
            }
        }
    }

    if !missing_dependencies.is_empty() {
        tracing::warn!(
            "Skipping input.json generation: missing dependency proofs for {} out of {} dependencies: {}",
            missing_dependencies.len(),
            raw_input.metadata.dependencies.len(),
            missing_dependencies.join(", ")
        );
        tracing::info!("Job fetch completed in: {:?}", start_time.elapsed());
        return Ok(());
    }

    tracing::info!("Successfully fetched all {} dependency proofs", input_proofs.len());

    // Verify that we have all required proofs
    if input_proofs.len() != raw_input.metadata.dependencies.len() {
        anyhow::bail!(
            "Mismatch: expected {} proofs but got {}",
            raw_input.metadata.dependencies.len(),
            input_proofs.len()
        );
    }

    // Generate input.json from raw_input.json and collected proofs
    // Format: GenerateProofRequest with input field wrapping the response
    let input_data = PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson {
        base: PsyWorkerGetProvingWorkAPIResponseJson {
            job: PsyProvingJobMetadataWithJobIdJson {
                job_id: raw_input.job_id.clone(),
                metadata: raw_input.metadata.clone(),
            },
            child_proof_tag_values: raw_input.child_proof_tag_values.clone(),
            realm_id: raw_input.realm_id,
            realm_sub_id: raw_input.realm_sub_id,
            unique_pending_id: raw_input.unique_pending_id,
            node_type,
            witness: raw_input.witness.clone(),
        },
        input_proofs,
    };

    // Wrap in GenerateProofRequest format (with input field)
    let input_json = GenerateProofRequest {
        input: input_data,
        worker_reward_tag: None, // Will be derived automatically if not provided
        reward_tree_value: None, // Will be computed automatically if not provided
    };

    // Save input.json with job_id in filename
    let input_path = output_dir.join(format!("input_{}.json", job_id));
    let input_json_str = serde_json::to_string_pretty(&input_json).context("Failed to serialize input.json")?;
    std::fs::write(&input_path, &input_json_str).with_context(|| format!("Failed to write input.json: {}", input_path.display()))?;
    tracing::info!("Saved input.json to: {}", input_path.display());

    let elapsed = start_time.elapsed();
    tracing::info!("Job fetch completed in: {:?}", elapsed);

    // One-click workflow: generate_proof -> verify_proof
    if one_click_done {
        tracing::info!("Starting one-click workflow: generate_proof -> verify_proof");

        let proof_path = output_dir.join(format!("proof_{}.json", job_id));

        // Step 1: Generate proof
        tracing::info!("Step 1/2: Generating proof...");
        handle_generate_proof(
            input_path.clone(),
            Some(proof_path.clone()),
            None, // worker_reward_tag (will be derived automatically)
            None, // reward_tree_value (will be computed automatically)
        )
        .context("Failed to generate proof in one-click workflow")?;
        tracing::info!("Proof generated successfully");

        // Step 2: Verify proof
        tracing::info!("Step 2/2: Verifying proof...");
        handle_verify_proof(
            input_path, proof_path, None, // worker_reward_tag (will be extracted from proof.json if needed)
            None, // reward_tree_value (will be extracted from proof.json)
        )
        .context("Failed to verify proof in one-click workflow")?;
        tracing::info!("Proof verified successfully");

        tracing::info!("One-click workflow completed successfully!");
    }

    Ok(())
}

fn handle_generate_proof(
    input_path: PathBuf,
    output_path: Option<PathBuf>,
    worker_reward_tag: Option<String>,
    reward_tree_value: Option<String>,
) -> Result<()> {
    tracing::info!("Reading input from: {}", input_path.display());

    // Read input file
    let input_content = std::fs::read_to_string(&input_path).with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let mut request: GenerateProofRequest =
        serde_json::from_str(&input_content).with_context(|| format!("Failed to parse input JSON: {}", input_path.display()))?;

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
    let input = request.input.to_internal().context("Failed to convert input to internal format")?;

    // Get job_id for deriving worker_reward_tag if needed
    let job_id = input.base.job.job_id;

    // Parse worker_reward_tag and reward_tree_value
    let worker_reward_tag = match request.worker_reward_tag.as_deref() {
        Some(tag_hex) => {
            let tag = parse_hex_hash(tag_hex).map_err(|e| anyhow::anyhow!("Invalid worker_reward_tag: {}", e))?;
            Some(tag)
        }
        None => None,
    };

    let reward_tree_value = request
        .reward_tree_value
        .as_deref()
        .map(|hex| parse_hex_hash(hex).map_err(|e| anyhow::anyhow!("Invalid reward_tree_value: {}", e)))
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
        derive_worker_reward_tag_from_job_id(job_id).context("Failed to derive worker_reward_tag")?
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
    let output_json = serde_json::to_string_pretty(&response).context("Failed to serialize response to JSON")?;

    if let Some(output) = output_path {
        std::fs::write(&output, output_json).with_context(|| format!("Failed to write output file: {}", output.display()))?;
        tracing::info!("Proof written to: {}", output.display());
    } else {
        println!("{}", output_json);
    }

    Ok(())
}

fn handle_verify_proof(input_path: PathBuf, proof_path: PathBuf, worker_reward_tag: Option<String>, reward_tree_value: Option<String>) -> Result<()> {
    tracing::info!("Reading input from: {}", input_path.display());
    tracing::info!("Reading proof from: {}", proof_path.display());

    // Read input file
    let input_content = std::fs::read_to_string(&input_path).with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    // Try to parse as VerifyProofRequest first, then fallback to
    // GenerateProofRequest
    let mut request: VerifyProofRequest = if let Ok(verify_req) = serde_json::from_str::<VerifyProofRequest>(&input_content) {
        verify_req
    } else if let Ok(generate_req) = serde_json::from_str::<GenerateProofRequest>(&input_content) {
        // Convert GenerateProofRequest to VerifyProofRequest
        VerifyProofRequest {
            input: generate_req.input,
            proof: String::new(), // Will be filled from proof_path
            worker_reward_tag: generate_req.worker_reward_tag,
            reward_tree_value: generate_req.reward_tree_value,
        }
    } else {
        anyhow::bail!(
            "Failed to parse input JSON: {}. Expected VerifyProofRequest or GenerateProofRequest format",
            input_path.display()
        );
    };

    // Read proof file
    let proof_content = std::fs::read_to_string(&proof_path).with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

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
    let input = request.input.to_internal().context("Failed to convert input to internal format")?;

    // Parse proof bytes
    let proof_bytes = hex::decode(&request.proof).context("Failed to decode proof hex string")?;

    // Parse worker_reward_tag and reward_tree_value
    let worker_reward_tag = request
        .worker_reward_tag
        .as_deref()
        .map(|tag_hex| parse_hex_hash(tag_hex).map_err(|e| anyhow::anyhow!("Invalid worker_reward_tag: {}", e)))
        .transpose()?;

    let reward_tree_value = request
        .reward_tree_value
        .as_deref()
        .map(|hex| parse_hex_hash(hex).map_err(|e| anyhow::anyhow!("Invalid reward_tree_value: {}", e)))
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
    let output_json = serde_json::to_string_pretty(&response).context("Failed to serialize response to JSON")?;

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
                let reward_tree_value = obj.get("reward_tree_value").and_then(|v| v.as_str()).map(|s| s.to_string());
                return Ok((proof.to_string(), reward_tree_value));
            }
        }
    }

    // Fallback: treat as plain hex string (may be quoted JSON string)
    let proof_hex = if trimmed.starts_with('"') && trimmed.ends_with('"') {
        serde_json::from_str::<String>(trimmed).unwrap_or_else(|_| trimmed.trim_matches('"').to_string())
    } else {
        trimmed.to_string()
    };

    Ok((proof_hex, None))
}

/// Parse proof_id into job_id_hex and realm_id
/// proof_id format: job_id_hex (48 chars) + realm_id_hex (variable length,
/// realm_id < 1000) Returns (job_id_hex, realm_id)
fn parse_proof_id(proof_id: &str) -> Result<(String, u64)> {
    const JOB_ID_HEX_LEN: usize = 48; // 24 bytes = 48 hex chars

    if proof_id.len() < JOB_ID_HEX_LEN {
        anyhow::bail!(
            "proof_id too short: expected at least {} characters, got {}",
            JOB_ID_HEX_LEN,
            proof_id.len()
        );
    }
    // Extract job_id_hex from the beginning (48 chars)
    let job_id_hex = proof_id[..JOB_ID_HEX_LEN].to_string();

    // Extract realm_id_hex from the remaining part
    let realm_id_hex = &proof_id[JOB_ID_HEX_LEN..];

    if realm_id_hex.is_empty() {
        anyhow::bail!("realm_id_hex is empty in proof_id");
    }

    // Parse realm_id_hex to u64
    let realm_id = u64::from_str_radix(realm_id_hex, 16).with_context(|| format!("Failed to parse realm_id_hex '{}' as u64", realm_id_hex))?;

    // Validate realm_id < 1000
    if realm_id >= 1000 {
        anyhow::bail!("realm_id must be < 1000, got {} (from hex: {})", realm_id, realm_id_hex);
    }

    Ok((job_id_hex, realm_id))
}

fn parse_job_id(bytes: &[u8]) -> Option<ParsedJobId> {
    if bytes.len() != 24 {
        return None;
    }

    let topic = bytes[0];
    let goal_id = u64::from_le_bytes(bytes[1..9].try_into().ok()?);
    let circuit_type = bytes[9];
    let group_id = u32::from_le_bytes(bytes[10..14].try_into().ok()?);
    let sub_group_id = u32::from_le_bytes(bytes[14..18].try_into().ok()?);
    let task_index = u32::from_le_bytes(bytes[18..22].try_into().ok()?);
    let data_type = bytes[22];
    let data_index = bytes[23];

    Some(ParsedJobId {
        job_id_hex: hex::encode(bytes),
        topic,
        goal_id,
        circuit_type,
        group_id,
        sub_group_id,
        task_index,
        data_type,
        data_index,
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParsedJobId {
    pub job_id_hex: String,
    pub topic: u8,
    pub goal_id: u64,
    pub circuit_type: u8,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: u8,
    pub data_index: u8,
}

/// raw_input.json structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawInputJson {
    pub job_id: String,
    pub metadata: PsyProvingJobMetadataJson,
    pub child_proof_tag_values: Vec<String>,
    pub witness: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
}

/// raw_proof.json structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawProofJson {
    pub job_id: String,
    pub metadata: PsyProvingJobMetadataJson,
    pub tag: String,
    pub child_proof_tag_values: Vec<String>,
    pub proof: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
}
