use anyhow::{Context, Result};
use parth_core::{crypto::hash::traits::FromU64x4, pgoldilocks::QHashOut};
use psy_core::job::job_id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID};
use psy_data::worker::{
    api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse},
    metadata::PsyProvingJobMetadata,
    metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use serde::{Deserialize, Serialize};

/// Job ID JSON structure matching QProvingJobDataID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QProvingJobDataIDJson {
    pub topic: u8,
    pub goal_id: u64,
    pub circuit_type: u8,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: u8,
    pub data_index: u8,
}

impl QProvingJobDataIDJson {
    pub fn to_internal(&self) -> Result<QProvingJobDataID> {
        Ok(QProvingJobDataID {
            topic: QJobTopic::try_from(self.topic).map_err(|_| anyhow::anyhow!("Invalid topic: {}", self.topic))?,
            goal_id: self.goal_id,
            circuit_type: ProvingJobCircuitType::try_from(self.circuit_type)
                .map_err(|_| anyhow::anyhow!("Invalid circuit_type: {}", self.circuit_type))?,
            group_id: self.group_id,
            sub_group_id: self.sub_group_id,
            task_index: self.task_index,
            data_type: ProvingJobDataType::try_from(self.data_type).map_err(|_| anyhow::anyhow!("Invalid data_type: {}", self.data_type))?,
            data_index: self.data_index,
        })
    }
}

/// Metadata JSON structure with hex-encoded hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsyProvingJobMetadataJson {
    pub expected_public_inputs_hash: String,
    pub reward_tree_node_index: u64,
    pub reward_tree_node_level: u8,
    pub reward_tree_hash_mode: u8,
    pub reward_tree_node_children: u16,
    pub dependencies: Vec<String>,
}

impl PsyProvingJobMetadataJson {
    pub fn to_internal<F>(&self) -> Result<PsyProvingJobMetadata<QHashOut<F>, QProvingJobDataID>>
    where
        F: plonky2::field::types::Field,
        QHashOut<F>: FromU64x4,
    {
        let expected_public_inputs_hash = hex_to_hash::<F>(&self.expected_public_inputs_hash)?;

        let dependencies: Result<Vec<QProvingJobDataID>> = self
            .dependencies
            .iter()
            .map(|dep_hex| {
                let bytes = hex::decode(dep_hex).with_context(|| format!("Invalid hex for dependency: {}", dep_hex))?;
                if bytes.len() != 24 {
                    anyhow::bail!("Invalid dependency length: {} (expected 24)", bytes.len());
                }
                parse_job_id_from_bytes(&bytes)
            })
            .collect();

        Ok(PsyProvingJobMetadata {
            expected_public_inputs_hash,
            reward_tree_node_index: self.reward_tree_node_index,
            reward_tree_node_level: self.reward_tree_node_level,
            reward_tree_hash_mode: self.reward_tree_hash_mode,
            reward_tree_node_children: self.reward_tree_node_children,
            dependencies: dependencies?,
        })
    }
}

/// Metadata with job_id JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsyProvingJobMetadataWithJobIdJson {
    // pub job_id: QProvingJobDataIDJson,
    pub job_id: String,
    pub metadata: PsyProvingJobMetadataJson,
}

impl PsyProvingJobMetadataWithJobIdJson {
    pub fn to_internal<F>(&self) -> Result<PsyProvingJobMetadataWithJobId<QHashOut<F>, QProvingJobDataID>>
    where
        F: plonky2::field::types::Field,
        QHashOut<F>: FromU64x4,
    {
        let bytes = hex::decode(&self.job_id).with_context(|| format!("Invalid hex for dependency: {}", self.job_id))?;
        if bytes.len() != 24 {
            anyhow::bail!("Invalid dependency length: {} (expected 24)", bytes.len());
        }
        let job_id = parse_job_id_from_bytes(&bytes)?;
        Ok(PsyProvingJobMetadataWithJobId {
            job_id,
            metadata: self.metadata.to_internal()?,
        })
    }
}

/// Base API response JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsyWorkerGetProvingWorkAPIResponseJson {
    pub job: PsyProvingJobMetadataWithJobIdJson,
    pub child_proof_tag_values: Vec<String>,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
    pub node_type: u8,
    pub witness: String,
}

impl PsyWorkerGetProvingWorkAPIResponseJson {
    pub fn to_internal<F>(&self) -> Result<PsyWorkerGetProvingWorkAPIResponse<QHashOut<F>, QProvingJobDataID>>
    where
        F: plonky2::field::types::Field,
        QHashOut<F>: FromU64x4,
    {
        let child_proof_tag_values: Result<Vec<QHashOut<F>>> = self.child_proof_tag_values.iter().map(|hex| hex_to_hash(hex)).collect();

        let witness = hex::decode(&self.witness).with_context(|| "Invalid hex for witness")?;

        Ok(PsyWorkerGetProvingWorkAPIResponse {
            job: self.job.to_internal()?,
            child_proof_tag_values: child_proof_tag_values?,
            realm_id: self.realm_id,
            realm_sub_id: self.realm_sub_id,
            unique_pending_id: self.unique_pending_id,
            node_type: self.node_type,
            witness,
        })
    }
}

/// Full API response with child proofs JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson {
    pub base: PsyWorkerGetProvingWorkAPIResponseJson,
    pub input_proofs: Vec<String>,
}

impl PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson {
    pub fn to_internal<F>(&self) -> Result<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<F>, QProvingJobDataID>>
    where
        F: plonky2::field::types::Field,
        QHashOut<F>: FromU64x4,
    {
        let input_proofs: Result<Vec<Vec<u8>>> = self
            .input_proofs
            .iter()
            .map(|hex| hex::decode(hex).with_context(|| format!("Invalid hex for input_proof: {}", hex)))
            .collect();

        Ok(PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: self.base.to_internal()?,
            input_proofs: input_proofs?,
        })
    }
}

/// Generate proof request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProofRequest {
    pub input: PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson,
    pub worker_reward_tag: Option<String>,
    pub reward_tree_value: Option<String>,
}

/// Generate proof response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProofResponse {
    pub proof: String,
    pub worker_reward_tag: String,
    pub reward_tree_value: String,
}

/// Verify proof request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofRequest {
    pub input: PsyWorkerGetProvingWorkWithChildProofsAPIResponseJson,
    pub proof: String,
    pub worker_reward_tag: Option<String>,
    pub reward_tree_value: Option<String>,
}

/// Verify proof response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofResponse {
    pub valid: bool,
    pub message: Option<String>,
}

/// Helper: Convert hex string to QHashOut
fn hex_to_hash<F>(hex: &str) -> Result<QHashOut<F>>
where
    F: plonky2::field::types::Field,
    QHashOut<F>: FromU64x4,
{
    let bytes = hex::decode(hex).with_context(|| format!("Invalid hex string: {}", hex))?;
    if bytes.len() != 32 {
        anyhow::bail!("Invalid hash length: {} (expected 32)", bytes.len());
    }

    let mut u64_array = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        let end = start + 8;
        u64_array[i] = u64::from_le_bytes(bytes[start..end].try_into()?);
    }

    Ok(QHashOut::<F>::from_u64x4(u64_array))
}

/// Helper: Parse job_id from 24 bytes
fn parse_job_id_from_bytes(bytes: &[u8]) -> Result<QProvingJobDataID> {
    if bytes.len() != 24 {
        anyhow::bail!("Invalid job_id length: {} (expected 24)", bytes.len());
    }

    let topic = QJobTopic::try_from(bytes[0]).map_err(|_| anyhow::anyhow!("Invalid topic: {}", bytes[0]))?;
    let goal_id = u64::from_le_bytes(bytes[1..9].try_into()?);
    let circuit_type = ProvingJobCircuitType::try_from(bytes[9]).map_err(|_| anyhow::anyhow!("Invalid circuit_type: {}", bytes[9]))?;
    let group_id = u32::from_le_bytes(bytes[10..14].try_into()?);
    let sub_group_id = u32::from_le_bytes(bytes[14..18].try_into()?);
    let task_index = u32::from_le_bytes(bytes[18..22].try_into()?);
    let data_type = ProvingJobDataType::try_from(bytes[22]).map_err(|_| anyhow::anyhow!("Invalid data_type: {}", bytes[22]))?;
    let data_index = bytes[23];

    Ok(QProvingJobDataID {
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
