use std::{
    io::{self, BufRead, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use colored::*;
use console::Term;
use futures::future::join_all;
use psy_cli::{
    prove::{do_generate_proof, fetch_dependency_proof, parse_job_id, parse_proof_id, ParsedJobId, RawInputJson, REALM_ROOT_JOS_MAP},
    services::APP_STATE,
    GenerateProofRequest, PsyProvingJobMetadataWithJobIdJson, PsyWorkerGetProvingWorkAPIResponseJson,
    PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson,
};
use psy_core::job::job_id::ProvingJobCircuitType;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::sleep;

const LOGO: &str = r#"
           :*%.
          =@@@                     -@@@@@@@%*=:
          :@@@                     -@@@@@@@@@@@@=
           @@%                     -@@@      =@@@%
:+%@@@.    @@*    +@@=             -@@@       -@@@-
  =@@@:    @@=   .@@@%             -@@@       :@@@=  .*@@@@@@#. #@@*        @@@=
   @@@:    %@-    -@@@.            -@@@       -@@@- :@@@%-:=@@. :@@@:      *@@*
  .@@@.    %@:    .%@@.            -@@@      =@@@%  %@@-         =@@%     :@@@:
  :@@@.    #@:    :%@%             -@@@@@@@@@@@@:   -@@@%         *@@*    #@@=
  .@@@:    %@:    =@@.             -@@@%%%%#**:      :%@@@@@=.     %@@-  =@@#
   *@@@    %@:   :@@.              -@@@                  =@@@@*    :@@@:.@@%
    *@@@*: @@: -%@%.               -@@@                    :@@@.    +@@#%@@-
      =@@@@@@@@@*                  -@@@             %*     -@@@      #@@@@*
          .@@=                     -@@@             @@@@@@@@@%.       %@@@
          :@@*                                         :==-.          @@@:
          +@@%                                                       %@@=
          @@@%                                                      *@@#
                                                                   -@@@:
                                                                   %@@=
"#;

const SPINNER_CHARS: &[char] = &['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

/// Convert HSV to RGB
/// h: 0.0-360.0 (hue in degrees)
/// s: 0.0-1.0 (saturation)
/// v: 0.0-1.0 (value/brightness)
fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let c = v * s;
    let h_prime = h / 60.0;
    let x = c * (1.0 - ((h_prime % 2.0) - 1.0).abs());
    let m = v - c;

    let (r1, g1, b1) = if h_prime < 1.0 {
        (c, x, 0.0)
    } else if h_prime < 2.0 {
        (x, c, 0.0)
    } else if h_prime < 3.0 {
        (0.0, c, x)
    } else if h_prime < 4.0 {
        (0.0, x, c)
    } else if h_prime < 5.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (((r1 + m) * 255.0) as u8, ((g1 + m) * 255.0) as u8, ((b1 + m) * 255.0) as u8)
}

/// Check if terminal likely supports true color (24-bit)
fn supports_truecolor() -> bool {
    if let Ok(colorterm) = std::env::var("COLORTERM") {
        if colorterm == "truecolor" || colorterm == "24bit" {
            return true;
        }
    }
    if let Ok(term) = std::env::var("TERM") {
        if term.contains("256color") || term.contains("truecolor") {
            return true;
        }
    }
    // Default to true for modern terminals
    true
}

#[derive(Parser, Debug)]
#[command(name = "psy-cli")]
#[command(version = "0.7.1 BETA")]
#[command(about = "Psy CLI Prover")]
struct Args {
    /// Job ID (24 bytes hex) - can also be set via JOB_ID env var
    #[arg(long, env = "JOB_ID")]
    job_id: Option<String>,

    /// Realm ID (u32) - can also be set via REALM_ID env var
    #[arg(long, env = "REALM_ID")]
    realm_id: Option<u32>,

    /// Batch mode: read realm_id,job_id pairs from stdin
    #[arg(long, short)]
    batch: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BenchmarkResponse {
    job_id: String,
    realm_id: String,
    spend_time: u64,
}

fn rainbow_psi(frame: usize) -> String {
    // Cycle through full hue spectrum (0-360 degrees)
    // Each frame advances by 8 degrees for a smooth gradient
    // Full rainbow cycle takes 45 frames (~3.6 seconds at 80ms per frame)
    let hue = ((frame * 8) % 360) as f32;

    if supports_truecolor() {
        // True color: smooth gradient through all hues
        // Full saturation and brightness for vivid colors
        let (r, g, b) = hsv_to_rgb(hue, 1.0, 1.0);
        "𝛙".truecolor(r, g, b).to_string()
    } else {
        // Fallback for basic terminals: cycle through available bright colors
        let color_index = (frame % 6) as usize;
        let colored_psi = match color_index {
            0 => "𝛙".bright_red(),
            1 => "𝛙".bright_yellow(),
            2 => "𝛙".bright_green(),
            3 => "𝛙".bright_cyan(),
            4 => "𝛙".bright_blue(),
            _ => "𝛙".bright_magenta(),
        };
        colored_psi.to_string()
    }
}

fn green_psi() -> String {
    "𝛙".green().to_string()
}

struct Spinner {
    running: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
    num_lines: usize,
}

impl Spinner {
    /// Create a spinner with multiple lines
    fn new(lines: Vec<String>) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let num_lines = lines.len();

        let handle = tokio::spawn(async move {
            let mut frame: usize = 0;
            let term = Term::stdout();
            let mut first_print = true;

            while running_clone.load(Ordering::Relaxed) {
                let spinner_char = SPINNER_CHARS[frame % SPINNER_CHARS.len()];
                let psi = rainbow_psi(frame);

                // Move cursor up to overwrite previous output (except on first print)
                if !first_print {
                    for _ in 0..lines.len() {
                        let _ = term.move_cursor_up(1);
                        let _ = term.clear_line();
                    }
                }

                // Print first line with spinner
                if let Some(first) = lines.first() {
                    println!("{} {} {}", spinner_char.to_string().cyan(), psi, first);
                }

                // Print remaining lines with padding to align with first line
                for line in lines.iter().skip(1) {
                    println!("     {}", line);
                }

                let _ = io::stdout().flush();
                first_print = false;
                frame += 1;
                sleep(Duration::from_millis(50)).await;
            }
        });

        Self {
            running,
            handle: Some(handle),
            num_lines,
        }
    }

    /// Create a spinner with a single line
    fn single(message: impl Into<String>) -> Self {
        Self::new(vec![message.into()])
    }

    /// Finish with multiple lines
    async fn finish(mut self, lines: Vec<String>) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }

        let term = Term::stdout();

        // Clear previous spinner lines
        for _ in 0..self.num_lines {
            let _ = term.move_cursor_up(1);
            let _ = term.clear_line();
        }

        // Print first line with checkmark
        if let Some(first) = lines.first() {
            println!("{} {} {}", "✓".green(), green_psi(), first);
        }

        // Print remaining lines with padding
        for line in lines.iter().skip(1) {
            println!("     {}", line);
        }
    }

    /// Finish with a single line
    async fn finish_single(self, message: impl Into<String>) {
        self.finish(vec![message.into()]).await;
    }
}

fn print_logo() {
    println!("{}", LOGO.bright_white());
    println!(" {} Psy CLI Prover: Version 0.7.1 BETA {}", "===".bright_white(), "===".bright_white());
    println!(" {} 𝕏: @PsyProtocol | https://psy.xyz  {}", "===".bright_white(), "===".bright_white());
    println!();
}

async fn initialize_circuits() -> Result<()> {
    let spinner = Spinner::new(vec![
        "Initializing Circuits...".to_string(),
        "(one time run, this may take a few seconds)".to_string(),
    ]);

    let _ = APP_STATE.as_ref().map_err(|e| anyhow::anyhow!("Failed to initialize AppState: {}", e))?;

    spinner.finish_single("Initialized Circuits").await;
    Ok(())
}

const BASE_URL: &str = "https://psy-benchmark-round1-data.psy-protocol.xyz";

async fn receive_proving_request(job_id: &str, realm_id: u32) -> Result<RawInputJson> {
    let spinner = Spinner::new(vec!["Receiving Proving Request".to_string(), format!("JobId: {}", job_id.cyan())]);
    let ret = fetch_job(BASE_URL.to_string(), realm_id, job_id.to_string()).await?;
    spinner
        .finish(vec!["Received Proving Request".to_string(), format!("JobId: {}", job_id.cyan())])
        .await;
    Ok(ret)
}

async fn retrieve_witness(raw_input: RawInputJson, job_id: &str, realm_id: u32) -> Result<GenerateProofRequest> {
    let spinner = Spinner::single("Retrieving Witness from Benchmark Server...");

    let witness = fetch_dependency_proofs(raw_input, BASE_URL, job_id.to_string(), realm_id).await?;

    spinner.finish_single("Retrieved Witness from Benchmark Server").await;
    Ok(witness)
}

async fn prove_job(req: GenerateProofRequest, job_id: &str, circuit_type: &str) -> Result<(Vec<u8>, Duration)> {
    let spinner = Spinner::new(vec![
        format!("Proving JobID {}", job_id.cyan()),
        format!("Circuit type: {}", circuit_type.green()),
    ]);

    let start = Instant::now();

    let ret = do_generate_proof(req, None, None).context("Failed to generate proof")?;

    let elapsed = start.elapsed();

    spinner
        .finish(vec![
            format!("Proved JobID {}", job_id.cyan()),
            format!("Circuit type: {}", circuit_type.green()),
        ])
        .await;

    Ok((hex::decode(&ret.proof)?, elapsed))
}

async fn fetch_benchmark_time(job_id: &str, mut realm_id: u32) -> Result<u64> {
    if realm_id < 999 {
        realm_id += 1;
    }
    let url = format!(
        "https://psy-block-visualizer-counter.team-81c.workers.dev/spend-time?job_id={}&realm_id={}",
        job_id, realm_id
    );

    let spinner = Spinner::single("Fetching benchmark machine proving time...");

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context("Failed to fetch benchmark time")?;

    let benchmark: BenchmarkResponse = response.json().await.context("Failed to parse benchmark response")?;

    spinner.finish_single("Fetched benchmark machine proving time").await;

    Ok(benchmark.spend_time)
}

fn print_results(your_time_ms: u64, benchmark_time_ms: u64) {
    let benchmark_color = if your_time_ms > benchmark_time_ms {
        format!("{}ms", benchmark_time_ms).green().bold()
    } else if your_time_ms < benchmark_time_ms {
        format!("{}ms", benchmark_time_ms).yellow().bold()
    } else {
        format!("{}ms", benchmark_time_ms).yellow().bold()
    };

    println!("Benchmark machine proving time: {}", benchmark_color);

    let delta: i64 = your_time_ms as i64 - benchmark_time_ms as i64;
    let delta_str = if delta < 0 {
        format!("{} faster than the benchmark machine", format!("{}ms", -delta).green()).bold()
    } else if delta > 0 {
        format!("{} slower than the benchmark machine", format!("{}ms", delta).red()).bold()
    } else {
        format!("the same speed as the benchmark machine").white().bold()
    };
    let comparison = format!("Your computer is {} (Benchmark machine is {}ms).", delta_str, benchmark_time_ms);

    println!("{}", comparison);
    println!();
}

async fn process_job(job_id: &str, realm_id: u32, first_run: bool) -> Result<()> {
    if first_run {
        initialize_circuits().await?;
    }

    let raw_input = receive_proving_request(job_id, realm_id).await?;
    let req = retrieve_witness(raw_input, job_id, realm_id).await?;
    let (job, _, node_type, _, _) = get_metadata(job_id.to_string(), realm_id)?;
    let circuit_type = ProvingJobCircuitType::try_from(job.circuit_type)?;
    let (proof, prove_duration) = prove_job(req, job_id, format!("{}", circuit_type).as_str()).await?;
    let your_time_ms = prove_duration.as_millis() as u64;
    println!("--------------------- {} ---------------------", "RESULT".bright_white().bold());
    let result_str = format!("Proved in {}ms", your_time_ms).bright_white().bold();
    let pad_left = (48 - result_str.len()) / 2;
    let pad_right = 48 - result_str.len() - pad_left;
    println!(
        "|{}{}{}|",
        " ".repeat(pad_left),
        format!("Proved in {}", format!("{}ms", your_time_ms).bright_green())
            .bright_white()
            .bold(),
        " ".repeat(pad_right)
    );
    println!("--------------------------------------------------");
    let mut hasher = Sha256::new();
    hasher.update(&proof);
    let hash_result: [u8; 32] = hasher.finalize().into();
    let hash_str = hex::encode(hash_result);
    println!("Proof SHA256: {}", hash_str.bright_yellow());

    let benchmark_time_ms = fetch_benchmark_time(job_id, realm_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch benchmark time: {}", e))?;

    print_results(your_time_ms, benchmark_time_ms);

    Ok(())
}

async fn run_batch_mode() -> Result<()> {
    print_logo();

    let stdin = io::stdin();
    let lines: Vec<String> = stdin.lock().lines().filter_map(|l| l.ok()).collect();

    if lines.is_empty() {
        eprintln!("{} No input provided. Expected format: realm_id,job_id", "Error:".red());
        return Ok(());
    }

    let mut first_run = true;

    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 2 {
            eprintln!(
                "{} Invalid format on line {}: '{}'. Expected: realm_id,job_id",
                "Warning:".yellow(),
                i + 1,
                line
            );
            continue;
        }

        let realm_id: u32 = match parts[0].trim().parse() {
            Ok(id) => id,
            Err(_) => {
                eprintln!("{} Invalid realm_id on line {}: '{}'", "Warning:".yellow(), i + 1, parts[0]);
                continue;
            }
        };

        let job_id = parts[1].trim();

        println!("{} Processing job {}/{}", ">>>".cyan(), i + 1, lines.len());

        if let Err(e) = process_job(job_id, realm_id, first_run).await {
            eprintln!("{} Error processing job: {}", "Error:".red(), e);
        }

        first_run = false;
    }

    println!("{} Batch processing complete!", "✓".green());

    Ok(())
}

async fn run_single_mode(job_id: String, realm_id: u32) -> Result<()> {
    print_logo();
    process_job(&job_id, realm_id, true).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.batch || !atty::is(atty::Stream::Stdin) {
        // Batch mode - read from stdin
        run_batch_mode().await
    } else {
        // Single mode - use env vars or args
        let job_id = args
            .job_id
            .ok_or_else(|| anyhow::anyhow!("JOB_ID is required. Set via --job-id or JOB_ID env var"))?;

        let realm_id = args
            .realm_id
            .ok_or_else(|| anyhow::anyhow!("REALM_ID is required. Set via --realm-id or REALM_ID env var"))?;

        run_single_mode(job_id, realm_id).await
    }
}

pub fn get_proof_id(job_id: String, realm_id: u32) -> Result<String> {
    // realm_id must occupy 2 bytes (4 hex chars), so format as 4 hex digits
    // (zero-padded) job_id must be exactly 48 hex characters (24 bytes)
    let job_id = job_id.trim_start_matches("0x");
    if job_id.len() != 48 {
        anyhow::bail!("job_id must be 48 hex characters (24 bytes), got {}", job_id.len());
    }
    if realm_id > 0xFFFF {
        anyhow::bail!("realm_id too large to fit in 2 bytes: {}", realm_id);
    }
    let proof_id = format!("{}{:04x}", job_id, realm_id);
    Ok(proof_id)
}

fn get_metadata(job_id: String, realm_id: u32) -> Result<(ParsedJobId, u64, u8, String, String)> {
    let proof_id = get_proof_id(job_id, realm_id)?;
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

    let job = parse_job_id(&hex::decode(&job_id).context("Failed to decode job ID")?);
    if job.is_none() {
        anyhow::bail!("Invalid job ID: {}", job_id);
    }
    let job = job.unwrap();
    Ok((job, realm_id, node_type, job_id, proof_id))
}

async fn fetch_job(base_url: String, realm_id: u32, job_id: String) -> Result<RawInputJson> {
    let (job, realm_id, node_type, job_id, proof_id) = get_metadata(job_id, realm_id)?;
    tracing::debug!("Job: {:?}", job);
    if job.circuit_type == 6 {
        bail!("User end cap jobs are not supported");
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

    Ok(raw_input)
}

async fn fetch_dependency_proofs(raw_input: RawInputJson, base_url: &str, job_id: String, realm_id: u32) -> Result<GenerateProofRequest> {
    let (job, realm_id, node_type, job_id, proof_id) = get_metadata(job_id, realm_id)?;
    tracing::debug!("Job: {:?}", job);
    if job.circuit_type == 6 {
        bail!("User end cap jobs are not supported");
    }

    let client = reqwest::Client::new();
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
        anyhow::bail!("Skipping input generation: missing dependency proofs");
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

    Ok(input_json)
}
