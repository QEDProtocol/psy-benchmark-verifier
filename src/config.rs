use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{handler, services::AppState};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        dotenv::dotenv().ok();
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
            },
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Start the validator API server
pub async fn run(config: Config) -> Result<()> {
    tracing::info!("Initializing validator service...");

    // Get counter file path from environment or use default
    let counter_file = std::env::var("ACTIVITY_COUNTER_FILE")
        .ok()
        .map(std::path::PathBuf::from);

    let state = Arc::new(AppState::new(counter_file)?);

    tracing::info!("Circuit library and verifier initialized successfully");

    let app = handler::create_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Validator API server listening on {}", addr);
    tracing::info!("Endpoints:");
    tracing::info!("  POST /v1/generate_proof    - Generate zero-knowledge proof");
    tracing::info!("  POST /v1/verify_proof      - Verify zero-knowledge proof");
    tracing::info!("  POST /v1/activity/increment - Increment activity counter");
    tracing::info!("  GET  /v1/activity/count     - Get activity counter value");

    axum::serve(listener, app).await?;

    Ok(())
}
