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
use crate::{
    models::{
        GenerateProofRequest, GenerateProofResponse, PsyProvingJobMetadataJson, PsyProvingJobMetadataWithJobIdJson,
        PsyWorkerGetProvingWorkAPIResponseJson, PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson, VerifyProofRequest, VerifyProofResponse,
    },
    services::{derive_worker_reward_tag_from_job_id, APP_STATE},
    AppState,
};
use serde::{Deserialize, Serialize};
use serde_json;
use tracing_subscriber::{self, EnvFilter};

pub static REALM_ROOT_JOS_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let content = include_str!("../realm_root_jos_map.json");
    serde_json::from_str::<HashMap<String, String>>(content).expect("Failed to parse realm_root_jos_map.json")
});

/// Fetch raw_proof.json for a single dependency
/// Returns Some(proof_hex) on success, None on failure (warning already logged)
pub async fn fetch_dependency_proof(
    client: &reqwest::Client,
    base_url: &str,
    realm_id: u64,
    node_type: u8,
    job: &ParsedJobId,
    dep_job_id: &str,
) -> Result<Option<String>> {
    // Format: {base_url}/output/{realm_id}/{dep_job_id}/raw_proof.json
    let raw_proof_url = format!("{}/output/{}/{}/raw_proof.json", base_url, realm_id, dep_job_id);
    tracing::debug!("Fetching raw_proof.json for dependency {} from: {}", dep_job_id, raw_proof_url);

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
            tracing::debug!(
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
        hex_string
    };

    Ok(Some(proof_hex))
}

async fn fetch_job(base_url: String, proof_id: String, one_click_done: bool) -> Result<()> {
    let start_time = Instant::now();
    tracing::debug!("Fetching job with base_url: {}, proof_id: {}", base_url, proof_id);
    tracing::debug!("One-click done: {}", one_click_done);

    // Replace proof_id with realm root proof_id if exists in map
    let proof_id = if let Some(root_proof_id) = REALM_ROOT_JOS_MAP.get(&proof_id) {
        tracing::debug!("Realm root job found, replacing proof_id: {} -> {}", proof_id, root_proof_id);
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
    tracing::debug!("Realm ID (parsed from proof_id): {}", realm_id);
    tracing::debug!("Job ID (parsed from proof_id): {}", job_id);
    tracing::debug!("Node type (calculated): {}", node_type);
    tracing::debug!("Base URL: {}", base_url);


    let job = parse_job_id(&hex::decode(&job_id).context("Failed to decode job ID")?);
    if job.is_none() {
        anyhow::bail!("Invalid job ID: {}", job_id);
    }
    let job = job.unwrap();
    tracing::debug!("Job: {:?}", job);
    if job.circuit_type == 6 {
        tracing::debug!("Job is a user end cap job");
        return Ok(());
    }

    // Construct raw_input_url from base_url, realm_id, and job_id
    // Format: {base_url}/output/{realm_id}/{job_id}/raw_input.json
    let raw_input_url = format!("{}/output/{}/{}/raw_input.json", base_url, realm_id, job_id);
    tracing::debug!("Fetching raw_input.json from: {}", raw_input_url);

    // Fetch raw_input.json
    let client = reqwest::Client::new();
    let response = client
        .get(&raw_input_url)
        .send()
        .await
        .context("Failed to send HTTP request for raw input")?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch raw input: {}", response.status());
    }

    let raw_input: RawInputJson = response.json().await.context("Failed to parse raw_input.json response")?;


    // Fetch raw_proof.json for each dependency in parallel
    tracing::debug!("Fetching {} dependencies in parallel", raw_input.metadata.dependencies.len());
    let fetch_tasks: Vec<_> = raw_input
        .metadata
        .dependencies
        .iter()
        .map(|dep_job_id| fetch_dependency_proof(&client, &base_url, realm_id, node_type, &job, dep_job_id))
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
        tracing::debug!("Job fetch completed in: {:?}", start_time.elapsed());
        return Ok(());
    }

    tracing::debug!("Successfully fetched all {} dependency proofs", input_proofs.len());

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


    let elapsed = start_time.elapsed();
    tracing::debug!("Job fetch completed in: {:?}", elapsed);

    // One-click workflow: generate_proof -> verify_proof (in-memory, no file I/O)
    if one_click_done {
        tracing::debug!("Starting one-click workflow: generate_proof -> verify_proof (in-memory)");

        // Step 1: Generate proof from in-memory input_json
        tracing::debug!("Step 1/2: Generating proof...");
        let gen_response = do_generate_proof(input_json.clone(), None, None)
            .context("Failed to generate proof in one-click workflow")?;
        tracing::debug!("Proof generated successfully");

        // Step 2: Verify proof using in-memory input and proof response
        tracing::debug!("Step 2/2: Verifying proof...");
        let verify_request = VerifyProofRequest {
            input: input_json.input.clone(),
            proof: gen_response.proof.clone(),
            worker_reward_tag: Some(gen_response.worker_reward_tag.clone()),
            reward_tree_value: Some(gen_response.reward_tree_value.clone()),
        };
        let verify_response = do_verify_proof(&verify_request).context("Failed to verify proof in one-click workflow")?;
        if !verify_response.valid {
            anyhow::bail!("One-click verify failed: {:?}", verify_response.message);
        }
        tracing::debug!("One-click workflow completed successfully!");
    }

    Ok(())
}

/// Generate proof from in-memory request. No file I/O.
pub fn do_generate_proof(
    mut request: GenerateProofRequest,
    worker_reward_tag_override: Option<String>,
    reward_tree_value_override: Option<String>,
) -> Result<GenerateProofResponse> {
    if let Some(tag) = worker_reward_tag_override {
        request.worker_reward_tag = Some(tag);
    }
    if let Some(rtv) = reward_tree_value_override {
        request.reward_tree_value = Some(rtv);
    }

    let state = APP_STATE.as_ref().map_err(|e| anyhow::anyhow!("Failed to initialize AppState: {}", e))?;

    let input = request.input.to_internal().context("Failed to convert input to internal format")?;
    let job_id = input.base.job.job_id.clone();

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

    tracing::debug!("Generating proof...");
    let (proof_bytes, computed_reward_tree_value) = state
        .generate_proof(input, worker_reward_tag, reward_tree_value)
        .context("Proof generation failed")?;

    let final_worker_reward_tag: QHashOut<GoldilocksField> = if let Some(tag) = worker_reward_tag {
        tag
    } else {
        derive_worker_reward_tag_from_job_id(job_id).context("Failed to derive worker_reward_tag")?
    };

    let reward_tree_value_bytes: [u8; 32] = computed_reward_tree_value.into_owned_32bytes();

    Ok(GenerateProofResponse {
        proof: hex::encode(&proof_bytes),
        worker_reward_tag: hex::encode(final_worker_reward_tag.into_owned_32bytes()),
        reward_tree_value: hex::encode(reward_tree_value_bytes),
    })
}

fn handle_generate_proof(
    input_path: PathBuf,
    output_path: Option<PathBuf>,
    worker_reward_tag: Option<String>,
    reward_tree_value: Option<String>,
) -> Result<()> {
    tracing::debug!("Reading input from: {}", input_path.display());
    let input_content = std::fs::read_to_string(&input_path).with_context(|| format!("Failed to read input file: {}", input_path.display()))?;
    let request: GenerateProofRequest =
        serde_json::from_str(&input_content).with_context(|| format!("Failed to parse input JSON: {}", input_path.display()))?;

    let response = do_generate_proof(request, worker_reward_tag, reward_tree_value)?;
    let output_json = serde_json::to_string_pretty(&response).context("Failed to serialize response to JSON")?;
    if output_path.is_some() {
        println!("{}", output_json);
    } else {
        println!("{}", output_json);
    }
    Ok(())
}

/// Verify proof from in-memory request (request.proof and optional tags must be set). No file I/O.
fn do_verify_proof(request: &VerifyProofRequest) -> Result<VerifyProofResponse> {
    println!("Initializing circuit library...");
    let state = APP_STATE.as_ref().map_err(|e| anyhow::anyhow!("Failed to initialize AppState: {}", e))?;

    let input = request.input.to_internal().context("Failed to convert input to internal format")?;
    let proof_bytes = hex::decode(&request.proof).context("Failed to decode proof hex string")?;

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

    tracing::debug!("Verifying proof...");
    let verify_result = state.verify_proof(input, &proof_bytes, worker_reward_tag, reward_tree_value);

    Ok(match verify_result {
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
    })
}

fn handle_verify_proof(input_path: PathBuf, proof_path: PathBuf, worker_reward_tag: Option<String>, reward_tree_value: Option<String>) -> Result<()> {
    tracing::debug!("Reading input from: {}", input_path.display());
    tracing::debug!("Reading proof from: {}", proof_path.display());

    let input_content = std::fs::read_to_string(&input_path).with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let mut request: VerifyProofRequest = if let Ok(verify_req) = serde_json::from_str::<VerifyProofRequest>(&input_content) {
        verify_req
    } else if let Ok(generate_req) = serde_json::from_str::<GenerateProofRequest>(&input_content) {
        VerifyProofRequest {
            input: generate_req.input,
            proof: String::new(),
            worker_reward_tag: generate_req.worker_reward_tag,
            reward_tree_value: generate_req.reward_tree_value,
        }
    } else {
        anyhow::bail!(
            "Failed to parse input JSON: {}. Expected VerifyProofRequest or GenerateProofRequest format",
            input_path.display()
        );
    };

    let proof_content = std::fs::read_to_string(&proof_path).with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;
    let (proof_hex, proof_reward_tree_value) = parse_proof_file(&proof_content)?;

    if let Some(tag) = worker_reward_tag {
        request.worker_reward_tag = Some(tag);
    }
    if let Some(rtv) = reward_tree_value {
        request.reward_tree_value = Some(rtv);
    } else if let Some(rtv) = proof_reward_tree_value {
        request.reward_tree_value = Some(rtv);
    }
    request.proof = proof_hex;

    let response = do_verify_proof(&request)?;
    let output_json = serde_json::to_string_pretty(&response).context("Failed to serialize response to JSON")?;
    tracing::debug!("output result: {}", output_json);
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
pub fn parse_proof_id(proof_id: &str) -> Result<(String, u64)> {
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

pub fn parse_job_id(bytes: &[u8]) -> Option<ParsedJobId> {
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

pub fn parse_hex_hash(hex_str: &str) -> Result<QHashOut<GoldilocksField>, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Invalid hash length: {} (expected 32)", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(QHashOut::from_owned_32bytes(arr))
}