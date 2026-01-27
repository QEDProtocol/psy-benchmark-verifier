use std::{sync::Arc, time::Instant};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use parth_core::{pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    models::{GenerateProofRequest, GenerateProofResponse, VerifyProofRequest, VerifyProofResponse},
    services::{derive_worker_reward_tag_from_job_id, AppState},
};

/// Create Axum router with validator API endpoints
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .route("/v1/generate_proof", post(handle_generate_proof))
        .route("/v1/verify_proof", post(handle_verify_proof))
        .with_state(state)
}

/// Handler for POST /generate_proof
pub async fn handle_generate_proof(
    State(state): State<Arc<AppState>>,
    Json(request): Json<GenerateProofRequest>,
) -> Result<Json<GenerateProofResponse>, ApiError> {
    let start_time = Instant::now();
    tracing::info!("Received generate_proof request");

    let input = request
        .input
        .to_internal()
        .map_err(|e| ApiError::BadRequest(format!("Invalid input: {}", e)))?;

    let worker_reward_tag = match request.worker_reward_tag.as_deref() {
        Some(tag_hex) => parse_hex_hash(tag_hex).map_err(|e| ApiError::BadRequest(format!("Invalid worker_reward_tag: {}", e)))?,
        None => derive_worker_reward_tag_from_job_id(input.base.job.job_id)
            .map_err(|e| ApiError::InternalError(format!("Failed to derive worker_reward_tag: {}", e)))?,
    };

    let reward_tree_value = request
        .reward_tree_value
        .as_deref()
        .map(|hex| parse_hex_hash(hex).map_err(|e| ApiError::BadRequest(format!("Invalid reward_tree_value: {}", e))))
        .transpose()?;

    let (proof_bytes, computed_reward_tree_value) = state
        .generate_proof(input, Some(worker_reward_tag), reward_tree_value)
        .map_err(|e| ApiError::InternalError(format!("Proof generation failed: {}", e)))?;

    let proof_hex = hex::encode(&proof_bytes);

    let elapsed = start_time.elapsed();
    tracing::info!("Proof generated successfully, length: {} bytes", proof_bytes.len());
    tracing::info!("Generate proof took: {:?}", elapsed);

    Ok(Json(GenerateProofResponse {
        proof: proof_hex,
        worker_reward_tag: hex::encode(worker_reward_tag.into_owned_32bytes()),
        reward_tree_value: hex::encode(computed_reward_tree_value.into_owned_32bytes()),
    }))
}

/// Handler for POST /verify_proof
pub async fn handle_verify_proof(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyProofRequest>,
) -> Result<Json<VerifyProofResponse>, ApiError> {
    tracing::info!("Received verify_proof request");

    let input = request
        .input
        .to_internal()
        .map_err(|e| ApiError::BadRequest(format!("Invalid input: {}", e)))?;

    let proof_bytes = hex::decode(&request.proof).map_err(|e| ApiError::BadRequest(format!("Invalid proof hex: {}", e)))?;

    let worker_reward_tag = request
        .worker_reward_tag
        .as_deref()
        .map(|tag_hex| parse_hex_hash(tag_hex).map_err(|e| ApiError::BadRequest(format!("Invalid worker_reward_tag: {}", e))))
        .transpose()?;

    let reward_tree_value = request
        .reward_tree_value
        .as_deref()
        .map(|hex| parse_hex_hash(hex).map_err(|e| ApiError::BadRequest(format!("Invalid reward_tree_value: {}", e))))
        .transpose()?;

    match state.verify_proof(input, &proof_bytes, worker_reward_tag, reward_tree_value) {
        Ok(()) => {
            tracing::info!("Proof verification successful");
            Ok(Json(VerifyProofResponse {
                valid: true,
                message: Some("Proof is valid".to_string()),
            }))
        }
        Err(e) => {
            tracing::warn!("Proof verification failed: {}", e);
            Ok(Json(VerifyProofResponse {
                valid: false,
                message: Some(format!("Verification failed: {}", e)),
            }))
        }
    }
}

pub fn parse_hex_hash(hex_str: &str) -> Result<QHashOut<plonky2::field::goldilocks_field::GoldilocksField>, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Invalid hash length: {} (expected 32)", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(QHashOut::from_owned_32bytes(arr))
}

/// API error types
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = serde_json::json!({
            "error": message,
        });

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use tower::ServiceExt;

    use super::*;
    use crate::models::PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson;

    fn load_fixture<T: DeserializeOwned>(path: &str) -> T {
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path, e));
        serde_json::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse fixture {}: {}", path, e))
    }

    fn fixture_path(relative_path: &str) -> String {
        format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path)
    }

    fn load_input_fixture() -> PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson {
        load_fixture(&fixture_path("src/input.json"))
    }

    /// New proof.json format: {reward_tree_value: "", proof: ""}
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ProofJson {
        reward_tree_value: String,
        proof: String,
    }

    fn load_proof_fixture() -> String {
        // Try to load as new format first, fallback to old format for backward
        // compatibility
        let content = fs::read_to_string(&fixture_path("src/proof.json")).unwrap_or_else(|e| panic!("Failed to read proof.json fixture: {}", e));

        // Try to parse as new format
        if let Ok(proof_json) = serde_json::from_str::<ProofJson>(&content) {
            proof_json.proof
        } else {
            // Fallback: try to parse as old format (pure hex string)
            // Remove quotes if it's a JSON string
            let trimmed = content.trim();
            if trimmed.starts_with('"') && trimmed.ends_with('"') {
                serde_json::from_str::<String>(trimmed).unwrap_or_else(|_| trimmed.trim_matches('"').to_string())
            } else {
                trimmed.to_string()
            }
        }
    }

    fn load_proof_fixture_with_reward_tree_value() -> (String, String) {
        let content = fs::read_to_string(&fixture_path("src/proof.json")).unwrap_or_else(|e| panic!("Failed to read proof.json fixture: {}", e));

        // Try to parse as new format
        if let Ok(proof_json) = serde_json::from_str::<ProofJson>(&content) {
            (proof_json.proof, proof_json.reward_tree_value)
        } else {
            // Fallback: old format doesn't have reward_tree_value
            let proof = if content.trim().starts_with('"') {
                serde_json::from_str::<String>(content.trim()).unwrap_or_else(|_| content.trim().trim_matches('"').to_string())
            } else {
                content.trim().to_string()
            };
            (proof, String::new())
        }
    }

    async fn post_json<T: DeserializeOwned>(app: Router, uri: &str, payload: serde_json::Value) -> T {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("Failed to build request");

        let response = app.oneshot(request).await.expect("Request failed");
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.expect("Failed to read response body");

        assert!(
            status.is_success(),
            "Expected success status, got {} with body: {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        );

        serde_json::from_slice(&body_bytes).unwrap_or_else(|e| panic!("Failed to parse response body: {}", e))
    }

    #[tokio::test]
    async fn test_generate_proof_then_verify_handler() {
        let state = Arc::new(AppState::new().expect("Failed to init AppState"));
        let input = load_input_fixture();

        let generate_request = GenerateProofRequest {
            input: input.clone(),
            worker_reward_tag: None,
            reward_tree_value: None,
        };
        let generate_response = handle_generate_proof(State(state.clone()), Json(generate_request))
            .await
            .expect("generate_proof failed")
            .0;

        let verify_request = VerifyProofRequest {
            input,
            proof: generate_response.proof,
            worker_reward_tag: Some(generate_response.worker_reward_tag),
            reward_tree_value: Some(generate_response.reward_tree_value),
        };

        let verify_response = handle_verify_proof(State(state), Json(verify_request))
            .await
            .expect("verify_proof failed")
            .0;

        assert!(verify_response.valid, "Verification failed: {:?}", verify_response.message);
    }

    #[tokio::test]
    async fn test_verify_proof_fixture_handler() {
        let state = Arc::new(AppState::new().expect("Failed to init AppState"));
        let input = load_input_fixture();
        let (proof, reward_tree_value) = load_proof_fixture_with_reward_tree_value();

        let verify_request = VerifyProofRequest {
            input,
            proof,
            worker_reward_tag: None,
            reward_tree_value: if reward_tree_value.is_empty() { None } else { Some(reward_tree_value) },
        };
        let verify_response = handle_verify_proof(State(state), Json(verify_request))
            .await
            .expect("verify_proof failed")
            .0;

        assert!(verify_response.valid, "Verification failed: {:?}", verify_response.message);
    }

    #[tokio::test]
    async fn test_generate_proof_then_verify_router() {
        let state = Arc::new(AppState::new().expect("Failed to init AppState"));
        let app = create_router(state);

        let input = load_input_fixture();
        let generate_payload = serde_json::to_value(GenerateProofRequest {
            input: input.clone(),
            worker_reward_tag: None,
            reward_tree_value: None,
        })
        .expect("Failed to build generate payload");

        let generate_response: GenerateProofResponse = post_json(app, "/v1/generate_proof", generate_payload).await;

        let state = Arc::new(AppState::new().expect("Failed to init AppState"));
        let app = create_router(state);
        let verify_payload = serde_json::to_value(VerifyProofRequest {
            input,
            proof: generate_response.proof,
            worker_reward_tag: Some(generate_response.worker_reward_tag),
            reward_tree_value: Some(generate_response.reward_tree_value),
        })
        .expect("Failed to build verify payload");

        let verify_response: VerifyProofResponse = post_json(app, "/v1/verify_proof", verify_payload).await;

        assert!(verify_response.valid, "Verification failed: {:?}", verify_response.message);
    }

    #[tokio::test]
    async fn test_verify_proof_fixture_router() {
        let state = Arc::new(AppState::new().expect("Failed to init AppState"));
        let app = create_router(state);

        let input = load_input_fixture();
        let (proof, reward_tree_value) = load_proof_fixture_with_reward_tree_value();
        let verify_payload = serde_json::to_value(VerifyProofRequest {
            input,
            proof,
            worker_reward_tag: None,
            reward_tree_value: if reward_tree_value.is_empty() { None } else { Some(reward_tree_value) },
        })
        .expect("Failed to build verify payload");

        let verify_response: VerifyProofResponse = post_json(app, "/v1/verify_proof", verify_payload).await;

        assert!(verify_response.valid, "Verification failed: {:?}", verify_response.message);
    }
}
