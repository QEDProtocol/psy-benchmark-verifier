use psy_validator::config::{Config, run};

use clap::Parser;
use tracing_subscriber::{self, EnvFilter};

/// Psy Validator Service - Zero Knowledge Proof Generation and Verification API
#[derive(Parser, Debug)]
#[command(
    name = "psy-validator",
    version,
    about = "Run the psy validator service for ZK proof generation and verification",
    long_about = None
)]
struct Cli {
    /// Listen address (e.g. 0.0.0.0)
    #[arg(long = "listen-addr", default_value = "0.0.0.0")]
    listen_addr: String,

    /// Listening port
    #[arg(long, default_value_t = 4000)]
    port: u16,

    /// Log level (e.g. info, debug, trace)
    #[arg(long = "log-level", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt().with_env_filter(EnvFilter::new(&cli.log_level)).init();

    let mut config = Config::from_env();

    config.server.host = cli.listen_addr.clone();
    config.server.port = cli.port;

    tracing::info!("Starting psy validator server at {}:{}", cli.listen_addr, cli.port);

    run(config).await
}
