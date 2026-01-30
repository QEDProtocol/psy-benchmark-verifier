# Psy Validator CLI User Guide

This guide explains how to deploy and use `psy-cli` to generate and verify zero-knowledge proofs.

## Table of Contents

1. [Installation](#installation)
2. [Deployment](#deployment)
3. [Running the Service](#running-the-service)
4. [Using input.json and proof.json](#using-inputjson-and-proofjson)
5. [Examples](#examples)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/QEDProtocol/psy-benchmark-verifier.git
cd psy-benchmark-verifier

# Build the validator binary
cargo build --release

# Binary will be at: target/release/psy-cli
```

### System Requirements

- Linux/macOS
- Rust toolchain (if building from source)
- Sufficient memory for Plonky2 circuit operations (recommended: 8GB+ RAM)

---

## Deployment

### Option 1: Direct Execution

```bash
./target/release/psy-cli \
  --listen-addr 0.0.0.0 \
  --port 4000 \
  --log-level info
```

### Option 2: Systemd Service (Linux)

1. **Create service file** `/etc/systemd/system/psy-cli.service`:

```ini
[Unit]
Description=Psy Validator CLI Service
After=network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=/opt/psy_validator
ExecStart=/opt/psy_validator/psy-cli --listen-addr 0.0.0.0 --port 4000 --log-level info
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Environment variables
Environment=RUST_LOG=info
Environment=RUST_BACKTRACE=1

[Install]
WantedBy=multi-user.target
```

2. **Install and start**:

```bash
# Copy binary to /opt/psy_validator/
sudo mkdir -p /opt/psy_validator
sudo cp target/release/psy-cli /opt/psy_validator/

# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable psy-cli
sudo systemctl start psy-cli

# Check status
sudo systemctl status psy-cli

# View logs
sudo journalctl -u psy-cli -f
```

---

## Running the Service

### Command Line Options

```bash
psy-cli [OPTIONS]
```

**Options:**

- `--listen-addr <ADDRESS>`: Listen address (default: `0.0.0.0`)
- `--port <PORT>`: Listening port (default: `4000`)
- `--log-level <LEVEL>`: Log level: `error`, `warn`, `info`, `debug`, `trace` (default: `info`)

### Example Commands

```bash
# Default settings (0.0.0.0:4000, info log level)
./psy-cli

# Custom port and log level
./psy-cli --port 8080 --log-level debug

# Listen on specific interface
./psy-cli --listen-addr 127.0.0.1 --port 4000
```

### Verify Service is Running

```bash
# Check if service is listening
curl http://localhost:4000/v1/generate_proof -X POST -H "Content-Type: application/json" -d '{}'

# Should return 400 Bad Request (expected, as request is invalid)
# If you get a connection error, the service is not running
```

---

## Using input.json and proof.json

### File Overview

- **`input.json`**: Complete input data for proof generation
  - Contains job metadata, witness, child proof tag values, and input proofs
  - Can be used directly in API requests
- **`proof.json`**: Generated Plonky2 proof with reward tree value
  - JSON object format: `{reward_tree_value: "", proof: ""}`
  - `reward_tree_value`: Reward tree value (32-byte hash as hex string)
  - `proof`: Plonky2 proof bytes as hex string
  - Used for verification (recommended to use `reward_tree_value` directly)

### Step 1: Generate Proof from input.json

**Prepare your input.json file** (see `psy_validator/src/input.json` for example structure).

**Generate proof:**

```bash
curl -X POST http://localhost:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json
```

**Response:**

```json
{
  "proof": "a1b2c3d4e5f6...",
  "worker_reward_tag": "e91efc2549f18614...",
  "reward_tree_value": "e91efc2549f18614..."
}
```

**Save the response:**

```bash
# Save proof.json in new format (recommended)
curl -X POST http://localhost:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json \
  | jq '{reward_tree_value: .reward_tree_value, proof: .proof}' > proof.json

# Or save individual fields
PROOF=$(curl -s -X POST http://localhost:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json | jq -r '.proof')
REWARD_TREE_VALUE=$(curl -s -X POST http://localhost:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json | jq -r '.reward_tree_value')
echo "{\"reward_tree_value\": \"$REWARD_TREE_VALUE\", \"proof\": \"$PROOF\"}" > proof.json
```

### Step 2: Verify Proof using proof.json

**Prepare verification request:**

Create `verify_request.json`:

```json
{
  "input": { ...contents from input.json... },
  "proof": "...from proof.json.proof...",
  "reward_tree_value": "...from proof.json.reward_tree_value..."
}
```

**Note**: Using `reward_tree_value` is recommended. Alternatively, you can use `worker_reward_tag` (from `generate_proof` response or `raw_proof.json`), but `reward_tree_value` is more direct and efficient.

**Verify proof:**

```bash
curl -X POST http://localhost:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d @verify_request.json
```

**Response:**

```json
{
  "valid": true,
  "message": "Proof is valid"
}
```

### Automated Script Example

```bash
#!/bin/bash

# Generate proof
echo "Generating proof..."
RESPONSE=$(curl -s -X POST http://localhost:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json)

# Extract values
PROOF=$(echo "$RESPONSE" | jq -r '.proof')
REWARD_TREE_VALUE=$(echo "$RESPONSE" | jq -r '.reward_tree_value')

# Save proof.json in new format
jq -n \
  --arg proof "$PROOF" \
  --arg reward_tree_value "$REWARD_TREE_VALUE" \
  '{reward_tree_value: $reward_tree_value, proof: $proof}' > proof.json
echo "Proof saved to proof.json"

# Build verify request (using reward_tree_value - recommended)
INPUT=$(cat input.json | jq '.input')
VERIFY_REQUEST=$(jq -n \
  --argjson input "$INPUT" \
  --arg proof "$PROOF" \
  --arg reward_tree_value "$REWARD_TREE_VALUE" \
  '{input: $input, proof: $proof, reward_tree_value: $reward_tree_value}')

# Verify proof
echo "Verifying proof..."
VERIFY_RESPONSE=$(curl -s -X POST http://localhost:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d "$VERIFY_REQUEST")

VALID=$(echo "$VERIFY_RESPONSE" | jq -r '.valid')
if [ "$VALID" = "true" ]; then
  echo "✓ Proof verification successful!"
else
  echo "✗ Proof verification failed:"
  echo "$VERIFY_RESPONSE" | jq '.message'
  exit 1
fi
```

---

## Examples

### Example 1: Generate Proof (No worker_reward_tag)

If `input.json` does not include `worker_reward_tag`, the validator will derive one automatically:

```bash
# input.json structure (worker_reward_tag is optional)
{
  "input": { ... },
  "worker_reward_tag": null
}

# Generate
curl -X POST http://localhost:4000/v1/generate_proof \
  -H "Content-Type: application/json" \
  -d @input.json
```

### Example 2: Verify with Existing proof.json (Recommended)

If you have `proof.json` in the new format:

```bash
# Extract from proof.json (new format)
PROOF=$(cat proof.json | jq -r '.proof')
REWARD_TREE_VALUE=$(cat proof.json | jq -r '.reward_tree_value')

# Build verify request
INPUT=$(cat input.json | jq '.input')
VERIFY_REQUEST=$(jq -n \
  --argjson input "$INPUT" \
  --arg proof "$PROOF" \
  --arg reward_tree_value "$REWARD_TREE_VALUE" \
  '{input: $input, proof: $proof, reward_tree_value: $reward_tree_value}')

# Verify
curl -X POST http://localhost:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d "$VERIFY_REQUEST"
```

### Example 2b: Verify with raw_proof.json

If you have `raw_proof.json`:

```bash
# Extract from raw_proof.json
PROOF=$(cat raw_proof.json | jq -r '.proof')
REWARD_TREE_VALUE=$(cat raw_proof.json | jq -r '.tag')  # tag is reward_tree_value

# Build verify request (using reward_tree_value - recommended)
INPUT=$(cat input.json | jq '.input')
VERIFY_REQUEST=$(jq -n \
  --argjson input "$INPUT" \
  --arg proof "$PROOF" \
  --arg reward_tree_value "$REWARD_TREE_VALUE" \
  '{input: $input, proof: $proof, reward_tree_value: $reward_tree_value}')

# Verify
curl -X POST http://localhost:4000/v1/verify_proof \
  -H "Content-Type: application/json" \
  -d "$VERIFY_REQUEST"
```

### Example 3: Using jq for Complex Operations

```bash
# Read input.json, modify worker_reward_tag, generate proof
cat input.json | \
  jq '.worker_reward_tag = "your_tag_here"' | \
  curl -X POST http://localhost:4000/v1/generate_proof \
    -H "Content-Type: application/json" \
    -d @-
```

---

## Troubleshooting

### Service Won't Start

**Check logs:**

```bash
# If using systemd
sudo journalctl -u psy-cli -n 50

# If running directly
./psy-cli --log-level debug
```

**Common issues:**

- **Port already in use**: Change port with `--port <different_port>`
- **Permission denied**: Ensure binary has execute permissions (`chmod +x psy-cli`)
- **Missing dependencies**: Ensure all required libraries are installed

### Proof Generation Fails

**Error: "Invalid input"**

- Check that `input.json` matches the expected structure
- Ensure `input_proofs` contains proof bytes for all dependencies
- Verify all hex strings are valid (64 chars for 32-byte hashes, etc.)

**Error: "Proof generation failed"**

- Check logs for detailed error messages
- Ensure circuit library is properly initialized
- Verify `node_type` is correct (1 for REALM, 2 for COORDINATOR)

### Proof Verification Fails

**Error: "Verification failed"**

- Ensure `reward_tree_value` (or `worker_reward_tag`) matches the one used during generation
- Check that `input` structure matches the one used for generation
- Verify `proof` hex string is complete and valid
- **Recommended**: Use `reward_tree_value` from `proof.json` or `raw_proof.json.tag` for verification

**Fallback verification warning:**

If you see: `"Proof verified without expected hash check"`, this means:
- The validator could not compute the expected public inputs hash (likely missing both `reward_tree_value` and `worker_reward_tag`)
- The proof itself is valid, but strict verification was skipped
- For strict verification, provide `reward_tree_value` (recommended) or `worker_reward_tag`

### Performance Issues

**Slow proof generation:**

- Proof generation is computationally intensive (can take minutes)
- This is normal for Plonky2 circuits
- Consider running in `--release` mode for better performance

**High memory usage:**

- Plonky2 circuits require significant memory
- Ensure system has sufficient RAM (8GB+ recommended)
- Monitor with `htop` or `top`

---

## File Structure Reference

### input.json Structure

```json
{
  "input": {
    "base": {
      "job": {
        "job_id": "hex24",
        "metadata": { ... }
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

**Note**: `worker_reward_tag` and `reward_tree_value` are both optional. If `reward_tree_value` is provided, it will be used directly. Otherwise, `reward_tree_value` will be computed from `worker_reward_tag` and `child_proof_tag_values`.

### proof.json Format

`proof.json` is a **JSON object** with two fields:

```json
{
  "reward_tree_value": "e91efc2549f18614d81c4ce0c97fa6f269196a693c7f7a0596f65b849a0754ea",
  "proof": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890..."
}
```

**Fields:**
- `reward_tree_value`: Reward tree value as hex string (32 bytes = 64 hex characters)
  - This is the value stored in Redis as `tag_value`
  - Can be used directly in verify requests (recommended)
- `proof`: Plonky2 proof bytes as hex string

**Note:** The old format (pure hex string) is still supported for backward compatibility, but the new format is recommended as it includes `reward_tree_value` which simplifies verification.

---

## Additional Resources

- **API Documentation**: See `api.md` for detailed API reference
- **Example Files**: Check `psy_validator/src/input.json` and `proof.json` for examples
- **Export Tools**: Use `psy_node_redis/examples/export_from_valkey.rs` to generate input.json/proof.json from Redis

---

## Support

For issues or questions:
1. Check logs with `--log-level debug`
2. Review `api.md` for API details
3. Verify file formats match examples in `psy_validator/src/`
