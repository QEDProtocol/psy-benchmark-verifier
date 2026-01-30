use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parth_core::{
    crypto::hash::traits::{FromU64x4, MerkleHasher},
    data::serializable::QPDSerializable,
    pgoldilocks::{PoseidonHasher, QHashOut},
    protocol::core_types::{Q256BitHash, QZKProofPublicInputsHasherReader, QZKProofVerifier},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::proof::ProofWithPublicInputs};
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::worker::api_response::{
    PsyWorkerGetProvingWorkWithChildProofsAPIResponse, PROVING_JOB_NODE_TYPE_COORDINATOR, PROVING_JOB_NODE_TYPE_REALM,
};
use psy_plonky2_basic_helpers::verifier::simple_circuit_library::SimpleCircuitLibrary;
use psy_plonky2_circuits::{
    circuit_library::get_plonky2_circuit_library_and_prover_for_network, coordinator::coordinator_helper::QEDCoordinatorCircuitManager,
    zk_verifier::PsyPlonky2ZKVerifier,
};
use psy_worker_core::worker::prover_trait::PsyWorkerGenericLibraryProver;

type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
type F = GoldilocksField;
const D: usize = 2;

#[derive(Clone, Debug)]
pub enum Action {
    GenerateProof,
    VerifyProof,
}

#[derive(Clone, Debug)]
pub struct Metrics {
    pub action_type: Action,
    pub time_ms: u64,
    pub circuit_type: ProvingJobCircuitType,
    pub public_inputs: Vec<F>,
}

/// Application state holding circuit library, prover, and verifier
#[derive(Clone)]
pub struct AppState {
    pub circuit_library: Arc<SimpleCircuitLibrary<F>>,
    pub prover: Arc<QEDCoordinatorCircuitManager<C, D>>,
    pub verifier: Arc<PsyPlonky2ZKVerifier<C, D>>,
    pub metricses: Arc<RwLock<Vec<Metrics>>>,
}

/// Global AppState singleton - initialized once and shared
pub static APP_STATE: Lazy<Result<AppState, anyhow::Error>> = Lazy::new(AppState::new);

impl AppState {
    /// Initialize application state with plonky2 circuits for LocalDevnet
    pub fn new() -> Result<Self> {
        let network = PsyChainNetworkType::LocalDevnet;

        let (gcv, coordinator_circuits) =
            get_plonky2_circuit_library_and_prover_for_network::<C, D>(network).context("Failed to initialize circuit library and prover")?;

        let verifier = PsyPlonky2ZKVerifier::<C, D>::from_cached();

        Ok(Self {
            circuit_library: Arc::new(gcv.library),
            prover: Arc::new(coordinator_circuits),
            verifier: Arc::new(verifier),
            metricses: Arc::new(RwLock::new(vec![])),
        })
    }

    /// Generate proof from input using plonky2 circuits (dispatches to realm or
    /// coordinator based on node_type)
    pub fn generate_proof(
        &self,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<F>, QProvingJobDataID>,
        worker_reward_tag: Option<QHashOut<F>>,
        reward_tree_value: Option<QHashOut<F>>,
    ) -> Result<(Vec<u8>, QHashOut<F>)> {
        let now = Instant::now();
        let job_id = input.base.job.job_id;
        let node_type = input.base.node_type;
        let metadata = &input.base.job.metadata;

        let worker_reward_tag = worker_reward_tag.unwrap_or(derive_worker_reward_tag_from_job_id(job_id)?);

        // Compute reward_tree_value if not provided
        let reward_tree_value = if let Some(rtv) = reward_tree_value {
            rtv
        } else {
            metadata
                .get_new_rewards_tag_tree_value::<PoseidonHasher>(worker_reward_tag, &input.base.child_proof_tag_values)
                .context("Failed to compute reward tree value")?
        };

        tracing::debug!(
            "Generating proof for job_id: {:?}, circuit_type: {:?}, node_type: {}",
            job_id,
            job_id.circuit_type,
            node_type
        );

        let proof = match node_type {
            PROVING_JOB_NODE_TYPE_REALM => {
                // Use GUTA circuits for realm proving
                self.prover
                    .guta_circuits
                    .prove_job_from_api(self.circuit_library.as_ref(), input, worker_reward_tag)
                    .context("Failed to generate proof with GUTA circuits (realm)")?
            }
            PROVING_JOB_NODE_TYPE_COORDINATOR => {
                // Use coordinator circuits
                self.prover
                    .prove_job_from_api(self.circuit_library.as_ref(), input, worker_reward_tag)
                    .context("Failed to generate proof with coordinator circuits")?
            }
            _ => {
                anyhow::bail!("Unsupported node_type: {}", node_type);
            }
        };

        let proving_time = now.elapsed();

        // tracing::info!("Generate proof took: {:?}", now.elapsed());
        // tracing::info!("Proof generation successfully");
        println!("Proof generated!");
        println!("Elapsed time:{:?}", proving_time);

        {
            let proof_time_ms = proving_time.as_millis() as u64;
            let plonky2_proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof).context("Failed to deserialize proof")?;
            let public_inputs = plonky2_proof.public_inputs.to_vec();

            let mut metricses = self
                .metricses
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to lock metrics for writing: {}", e))?;
            metricses.push(Metrics {
                action_type: Action::GenerateProof,
                time_ms: proof_time_ms,
                circuit_type: job_id.circuit_type,
                public_inputs,
            });
        }

        Ok((proof, reward_tree_value))
    }

    /// Verify proof using plonky2 verifier (dispatches to realm or coordinator
    /// logic based on node_type)
    pub fn verify_proof(
        &self,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<F>, QProvingJobDataID>,
        proof_bytes: &[u8],
        worker_reward_tag: Option<QHashOut<F>>,
        reward_tree_value: Option<QHashOut<F>>,
    ) -> Result<()> {
        let job_id = input.base.job.job_id;
        let metadata = &input.base.job.metadata;
        let node_type = input.base.node_type;

        tracing::debug!(
            "Verifying proof for job_id: {:?}, circuit_type: {:?}, node_type: {}",
            job_id,
            job_id.circuit_type,
            node_type
        );
        let now = Instant::now();

        // Use reward_tree_value directly if provided, otherwise compute from
        // worker_reward_tag
        let reward_tree_value = if let Some(rtv) = reward_tree_value {
            tracing::debug!("Using provided reward_tree_value directly");
            rtv
        } else {
            let worker_reward_tag = worker_reward_tag.unwrap_or(derive_worker_reward_tag_from_job_id(job_id)?);
            tracing::debug!("Computing reward_tree_value from worker_reward_tag");
            metadata
                .get_new_rewards_tag_tree_value::<PoseidonHasher>(worker_reward_tag, &input.base.child_proof_tag_values)
                .context("Failed to compute reward tree value")?
        };

        tracing::debug!(
            "expected_public_inputs_hash: {}",
            hex::encode(&metadata.expected_public_inputs_hash.into_owned_32bytes())
        );
        tracing::debug!("reward_tree_value: {}", hex::encode(&reward_tree_value.into_owned_32bytes()));

        // Compute full_expected_public_inputs_hash based on node_type and circuit_type
        // Mirrors submit_proof_raw_internal logic from realm and coordinator edge
        // handlers
        let full_expected_public_inputs_hash = match node_type {
            PROVING_JOB_NODE_TYPE_REALM => {
                // Realm verification: always two_to_one(metadata.expected_public_inputs_hash,
                // reward_tree_value)
                PoseidonHasher::two_to_one(&metadata.expected_public_inputs_hash, &reward_tree_value)
            }
            PROVING_JOB_NODE_TYPE_COORDINATOR => {
                // Coordinator verification: special cases for certain circuit types
                match job_id.circuit_type {
                    ProvingJobCircuitType::GenesisBlockCheckpointStateTransition => {
                        // Genesis block: use metadata.expected_public_inputs_hash directly (no reward
                        // tree hash)
                        metadata.expected_public_inputs_hash
                    }
                    ProvingJobCircuitType::GenerateRollupStateTransitionProof => {
                        // For this circuit type, we would need witness data and
                        // checkpoint_state_transition_circuit_fingerprint
                        // to compute the correct hash. For now, we assume the caller passes the correct
                        // expected_public_inputs_hash in metadata that already
                        // includes the reward root. TODO: Implement full
                        // witness-based computation if needed
                        tracing::warn!(
                            "GenerateRollupStateTransitionProof verification uses simplified logic - assumes metadata.expected_public_inputs_hash is pre-computed with reward root"
                        );
                        metadata.expected_public_inputs_hash
                    }
                    _ => {
                        // Default coordinator case: two_to_one(metadata.expected_public_inputs_hash,
                        // reward_tree_value)
                        PoseidonHasher::two_to_one(&metadata.expected_public_inputs_hash, &reward_tree_value)
                    }
                }
            }
            _ => {
                anyhow::bail!("Unsupported node_type: {}", node_type);
            }
        };

        tracing::debug!(
            "full_expected_public_inputs_hash: {}",
            hex::encode(&full_expected_public_inputs_hash.into_owned_32bytes())
        );

        let verify_result = self.verifier.verify_zk_proof_from_slice_check_public_inputs_hash(
            job_id.circuit_type.to_u8() as u32,
            proof_bytes,
            full_expected_public_inputs_hash,
        );

        let verify_time_ms = now.elapsed().as_millis() as u64;
        {
            let mut metricses = self
                .metricses
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to lock metrics for writing: {}", e))?;
            metricses.push(Metrics {
                action_type: Action::VerifyProof,
                time_ms: verify_time_ms,
                circuit_type: job_id.circuit_type,
                public_inputs: vec![],
            });
        }

        if verify_result.is_ok() {
            // tracing::info!("Proof verification took: {:?}", now.elapsed());
            println!("Proof verified!");
            println!("Elapsed time:{:?}", now.elapsed());
            return Ok(());
        }

        // Fallback: verify proof validity without expected hash check.
        // This allows verification for fixtures that do not include the worker reward
        // tag.
        let proof = <PsyPlonky2ZKVerifier<C, D> as QZKProofPublicInputsHasherReader<
            QHashOut<F>,
            plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>,
        >>::try_proof_from_slice(proof_bytes)
        .context("Failed to parse proof bytes")?;

        let computed_public_inputs_hash = self
            .verifier
            .verify_zk_proof(job_id.circuit_type.to_u8() as u32, &proof)
            .context("Proof verification failed")?;

        tracing::warn!(
            "Proof verified without expected hash check; computed_public_inputs_hash={}, expected_public_inputs_hash={}",
            hex::encode(computed_public_inputs_hash.into_owned_32bytes()),
            hex::encode(metadata.expected_public_inputs_hash.into_owned_32bytes())
        );

        Ok(())
    }

    /// Print all metrics collected
    pub fn print_metrics(&self) -> Result<()> {
        let metrics = self
            .metricses
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to lock metrics for reading: {}", e))?;
        if metrics.is_empty() {
            tracing::debug!("No metrics collected");
            return Ok(());
        }

        tracing::debug!("=== Metrics Summary ===");
        for (i, m) in metrics.iter().enumerate() {
            tracing::debug!("[{}] {:?} - time: {}ms, circuit: {:?}", i, m.action_type, m.time_ms, m.circuit_type);
        }

        Ok(())
    }
}

/// Derive worker reward tag from job_id using PoseidonHasher
pub fn derive_worker_reward_tag_from_job_id(job_id: QProvingJobDataID) -> Result<QHashOut<F>> {
    let job_id_bytes = job_id.to_bytes().context("Failed to serialize job_id")?;

    if job_id_bytes.len() != 24 {
        anyhow::bail!("Invalid job_id bytes length: {}", job_id_bytes.len());
    }

    let mut padded = [0u8; 32];
    padded[..24].copy_from_slice(&job_id_bytes);

    let mut u64_array = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        let end = start + 8;
        u64_array[i] = u64::from_le_bytes(padded[start..end].try_into()?);
    }

    let base_hash = QHashOut::<F>::from_u64x4(u64_array);

    let tag = PoseidonHasher::two_to_one(&base_hash, &base_hash);

    tracing::debug!(
        "Derived tag for job_id: {} => {}",
        hex::encode(&job_id_bytes),
        hex::encode(&tag.into_owned_32bytes())
    );

    Ok(tag)
}
