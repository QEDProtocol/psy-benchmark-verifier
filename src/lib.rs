pub mod config;
pub mod counter;
pub mod handler;
pub mod models;
pub mod services;

// Re-export commonly used types
pub use handler::{handle_generate_proof, handle_verify_proof, parse_hex_hash};
pub use models::*;
pub use services::{derive_worker_reward_tag_from_job_id, AppState};
