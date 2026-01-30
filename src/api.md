# Psy Validator API Documentation

This document describes the HTTP APIs exposed by `psy-cli` service.

## Base URL

- Default: `http://<host>:<port>`
- All endpoints are prefixed with `/v1`

## Endpoints

### 1. POST `/v1/generate_proof`

Generate a Plonky2 proof from input data (equivalent to worker's `prove_job_from_api`).

**Request Body**

```json
{
  "input": {
    "base": {
      "job": {
        "job_id": "hex24",
        "metadata": {
          "expected_public_inputs_hash": "hex32",
          "reward_tree_node_index": 0,
          "reward_tree_node_level": 0,
          "reward_tree_hash_mode": 0,
          "reward_tree_node_children": 0,
          "dependencies": ["hex24", "hex24"]
        }
      },
      "child_proof_tag_values": ["hex32", "hex32"],
      "realm_id": 0,
      "realm_sub_id": 0,
      "unique_pending_id": 0,
      "node_type": 1,
      "witness": "hex"
    },
    "input_proofs": ["hex", "hex"]
  },
  "worker_reward_tag": "hex32",
  "reward_tree_value": "hex32"
}
```

**Request Fields**

- `input` (required): Strict `PsyWorkerGetProvingWorkWithChildProofsAPIResponse` JSON structure
  - `base.job.job_id`: Job identifier with all fields
  - `base.job.metadata`: Proof metadata including expected public inputs hash and dependencies
  - `base.child_proof_tag_values`: Reward tree tag values for child proofs (hex strings)
  - `base.node_type`: `1` for REALM, `2` for COORDINATOR
  - `base.witness`: Witness data as hex string
  - `input_proofs`: Array of child proof bytes as hex strings (required for proving)
- `worker_reward_tag` (optional): Worker reward tag as hex string (32 bytes = 64 hex chars)
  - If omitted, validator derives a default tag from `job_id` using PoseidonHasher
  - The derived tag is deterministic based on `job_id`
- `reward_tree_value` (optional): Reward tree value as hex string (32 bytes = 64 hex chars)
  - If provided, used directly for computing `full_expected_public_inputs_hash`
  - If omitted, computed from `worker_reward_tag` and `child_proof_tag_values` using `metadata.get_new_rewards_tag_tree_value`
  - Can be obtained from `raw_proof.json.tag` or `proof.json.reward_tree_value`

**Response**

```json
{
  "proof": "hex",
  "worker_reward_tag": "hex32",
  "reward_tree_value": "hex32"
}
```

**Response Fields**

- `proof`: Generated Plonky2 proof as hex string
- `worker_reward_tag`: The worker reward tag used for proof generation (either provided or derived)
- `reward_tree_value`: The reward tree value computed or provided during proof generation

**Example**

```bash
curl -X POST http://127.0.0.1:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "base": {
        "job": {
          "job_id": "hex24",
          "metadata": {
            "expected_public_inputs_hash": "f0993d6e2d26ff4521db6fa91a9a8307f3cfad490dae2e945de9ad44b9fff1f6",
            "reward_tree_node_index": 0,
            "reward_tree_node_level": 0,
            "reward_tree_hash_mode": 0,
            "reward_tree_node_children": 2,
            "dependencies": ["hex24", "hex24"]
          }
        },
        "child_proof_tag_values": [],
        "realm_id": 47,
        "realm_sub_id": 1,
        "unique_pending_id": 231,
        "node_type": 1,
        "witness": "4099315241a7a067..."
      },
      "input_proofs": []
    }
  }'
```

---

### 2. POST `/v1/verify_proof`

Verify a Plonky2 proof against expected public inputs (equivalent to edge's `submit_proof_raw_internal` verification logic).

**Request Body**

```json
{
  "input": {
    "base": {
      "job": { ...same as generate_proof... },
      "child_proof_tag_values": ["hex32", "hex32"],
      "realm_id": 0,
      "realm_sub_id": 0,
      "unique_pending_id": 0,
      "node_type": 1,
      "witness": "hex"
    },
    "input_proofs": ["hex", "hex"]
  },
  "proof": "hex",
  "worker_reward_tag": "hex32",
  "reward_tree_value": "hex32"
}
```

**Request Fields**

- `input` (required): Same structure as `generate_proof` input
- `proof` (required): Plonky2 proof bytes as hex string
- `worker_reward_tag` (optional): Worker reward tag as hex string
  - If omitted, validator derives a default tag from `job_id`
  - For strict verification, provide the tag returned from `generate_proof` or from `raw_proof.json`
- `reward_tree_value` (optional): Reward tree value as hex string (32 bytes = 64 hex chars)
  - **Recommended**: If provided, used directly for computing `full_expected_public_inputs_hash` (no need to compute from `worker_reward_tag`)
  - If omitted, validator computes it from `worker_reward_tag` and `child_proof_tag_values`
  - Can be obtained from `raw_proof.json.tag` or `proof.json.reward_tree_value`
  - **Note**: Providing `reward_tree_value` directly is more efficient and avoids the need for `worker_reward_tag`

**Response**

```json
{
  "valid": true,
  "message": "Proof is valid"
}
```

**Response Fields**

- `valid`: Boolean indicating whether verification succeeded
- `message`: Human-readable message (present on both success and failure)

**Verification Logic**

1. **Strict verification** (preferred):
   - If `reward_tree_value` is provided: uses it directly
   - If `reward_tree_value` is omitted but `worker_reward_tag` is provided: computes `reward_tree_value` from tag and `child_proof_tag_values`
   - Computes `full_expected_public_inputs_hash` based on `node_type` and `circuit_type`:
     - **REALM**: `hash(metadata.expected_public_inputs_hash, reward_tree_value)`
     - **COORDINATOR**: Special cases for `GenesisBlockCheckpointStateTransition` and `GenerateRollupStateTransitionProof`
   - Verifies proof's public inputs hash matches expected hash

2. **Fallback verification** (if strict verification fails or both `reward_tree_value` and `worker_reward_tag` are missing):
   - Verifies proof validity only (circuit verification)
   - Does not check expected public inputs hash
   - Logs a warning

**Example**

```bash
# Option 1: Using reward_tree_value (recommended)
curl -X POST http://127.0.0.1:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d '{
    "input": { ... },
    "proof": "a1b2c3d4...",
    "reward_tree_value": "e91efc2549f18614..."
  }'

# Option 2: Using worker_reward_tag (fallback)
curl -X POST http://127.0.0.1:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d '{
    "input": { ... },
    "proof": "a1b2c3d4...",
    "worker_reward_tag": "e91efc2549f18614..."
  }'
```

---

## Data Sources

### Input Files

- **`input.json`**: Strict `PsyWorkerGetProvingWorkWithChildProofsAPIResponse` JSON
  - Can be used directly as `input` field in API requests
  - Contains `input_proofs` (child proof bytes)
- **`proof.json`**: JSON object with `reward_tree_value` and `proof`
  ```json
  {
    "reward_tree_value": "hex32",
    "proof": "hex"
  }
  ```
  - `reward_tree_value`: Can be used directly in verify requests (recommended)
  - `proof`: Plonky2 proof bytes as hex string

### Export Files (for reference)

- **`raw_input.json`**: Debug/verification export (does not match API schema)
  - Missing `input_proofs` field
  - Flattened structure for human readability
- **`raw_proof.json`**: Debug/verification export
  - Contains `tag` field (this is the `reward_tree_value`, can be used directly)
  - Contains `proof` field (proof bytes as hex string)

---

## Workflow Examples

### Generate and Verify (using returned reward_tree_value)

```bash
# Step 1: Generate proof
RESPONSE=$(curl -X POST http://127.0.0.1:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json)

PROOF=$(echo $RESPONSE | jq -r '.proof')
REWARD_TREE_VALUE=$(echo $RESPONSE | jq -r '.reward_tree_value')

# Step 2: Verify using returned reward_tree_value (recommended)
curl -X POST http://127.0.0.1:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d "{
    \"input\": $(cat input.json | jq '.input'),
    \"proof\": \"$PROOF\",
    \"reward_tree_value\": \"$REWARD_TREE_VALUE\"
  }"
```

### Verify Existing Proof (from proof.json - recommended)

```bash
# Extract from proof.json (new format)
PROOF=$(cat proof.json | jq -r '.proof')
REWARD_TREE_VALUE=$(cat proof.json | jq -r '.reward_tree_value')

# Verify
curl -X POST http://127.0.0.1:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d "{
    \"input\": $(cat input.json | jq '.input'),
    \"proof\": \"$PROOF\",
    \"reward_tree_value\": \"$REWARD_TREE_VALUE\"
  }"
```

### Verify Existing Proof (from raw_proof.json)

```bash
# Extract from raw_proof.json
PROOF=$(cat raw_proof.json | jq -r '.proof')
REWARD_TREE_VALUE=$(cat raw_proof.json | jq -r '.tag')  # tag is reward_tree_value

# Verify using reward_tree_value (recommended)
curl -X POST http://127.0.0.1:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d "{
    \"input\": $(cat input.json | jq '.input'),
    \"proof\": \"$PROOF\",
    \"reward_tree_value\": \"$REWARD_TREE_VALUE\"
  }"
```

---

### 3. POST `/v1/activity/increment`

Increment the activity counter and return the new value.

**Request Body**

None (no body required)

**Response**

```json
{
  "count": 42
}
```

**Response Fields**

- `count`: The new activity counter value after incrementing

**Example**

```bash
curl -X POST http://127.0.0.1:4000/v1/activity/increment
```

---

### 4. GET `/v1/activity/count`

Get the current activity counter value without incrementing.

**Request**

No body required

**Response**

```json
{
  "count": 42
}
```

**Response Fields**

- `count`: The current activity counter value

**Example**

```bash
curl http://127.0.0.1:4000/v1/activity/count
```

**Note**: The activity counter is persisted to a local file (`activity_counter.json` by default, or specified via `ACTIVITY_COUNTER_FILE` environment variable). The counter is loaded on startup and saved on each increment.

---

## Node Types

- `node_type: 1` (REALM): Uses GUTA circuits for proving/verification
- `node_type: 2` (COORDINATOR): Uses coordinator circuits for proving/verification

The validator automatically dispatches to the correct prover/verifier based on `node_type`.

---

## Error Responses

All errors return JSON with an `error` field:

```json
{
  "error": "Error message here"
}
```

**HTTP Status Codes**

- `200 OK`: Request succeeded (check `valid` field in verify response)
- `400 Bad Request`: Invalid request format or parameters
- `500 Internal Server Error`: Server-side error during proof generation/verification

---

## Notes

1. **Reward Tree Value** (recommended):
   - **Preferred approach**: Provide `reward_tree_value` directly in verify requests
   - Can be obtained from `proof.json.reward_tree_value` or `raw_proof.json.tag`
   - Avoids the need to compute from `worker_reward_tag` and `child_proof_tag_values`
   - More efficient and matches the actual value stored in Redis

2. **Worker Reward Tag**: 
   - If not provided, validator derives a deterministic tag from `job_id`
   - Only needed if `reward_tree_value` is not provided
   - For strict verification matching edge behavior, provide the actual tag from worker or `raw_proof.json`

3. **Input Proofs**:
   - `input_proofs` must contain proof bytes for all dependencies listed in `metadata.dependencies`
   - Missing dependencies will cause proof generation to fail

4. **Verification Fallback**:
   - If strict verification fails (e.g., missing both `reward_tree_value` and `worker_reward_tag`), validator falls back to proof validity check only
   - This allows verification of proofs without complete metadata, but is less strict than edge verification
