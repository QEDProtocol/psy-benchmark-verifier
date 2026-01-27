# Psy Validator

A standalone validator service for zero-knowledge proof generation and verification.

## Overview

Psy Validator provides both a REST API service and CLI tool for generating and verifying zero-knowledge proofs using Plonky2 circuits. It supports both realm and coordinator node types for the Psy Protocol.

## Features

- **Proof Generation**: Generate ZK proofs from API requests or CLI commands
- **Proof Verification**: Verify ZK proofs with public inputs hash checking
- **HTTP Server**: REST API for easy integration
- **CLI Tool**: Command-line interface for batch processing and automation
- **One-Click Workflow**: Fetch job data, generate and verify proofs in one command
- **Parallel Dependency Fetching**: Automatically fetches all dependency proofs in parallel
- **Flexible Input Formats**: Supports both JSON and plain hex string proof formats

## API Endpoints

When running as HTTP server:

- `POST /v1/generate_proof` - Generate zero-knowledge proof
- `POST /v1/verify_proof` - Verify zero-knowledge proof

See [API Documentation](src/api.md) for more details.

See [User Guide](src/user.md) for more details.

## Input/Output Formats

### Generate Proof Input Format

The input file should be a JSON file with the following structure:

```json
{
  "input": {
    "base": {
      "job": {
        "job_id": "hex_string",
        "metadata": {
          "expected_public_inputs_hash": "hex_string",
          "reward_tree_node_index": 0,
          "reward_tree_node_level": 0,
          "reward_tree_hash_mode": 0,
          "reward_tree_node_children": 0,
          "dependencies": ["hex_string", ...]
        }
      },
      "child_proof_tag_values": ["hex_string", ...],
      "realm_id": 0,
      "realm_sub_id": 0,
      "unique_pending_id": 0,
      "node_type": 1,
      "witness": "hex_string"
    },
    "input_proofs": ["hex_string", ...]
  },
  "worker_reward_tag": "optional_hex_string",
  "reward_tree_value": "optional_hex_string"
}
```

### Generate Proof Output Format

```json
{
  "proof": "hex_string",
  "worker_reward_tag": "hex_string",
  "reward_tree_value": "hex_string"
}
```

### Verify Proof Input Format

The input file can be either:
1. `GenerateProofRequest` format (same as generate proof input)
2. `VerifyProofRequest` format:

```json
{
  "input": { ... },
  "proof": "hex_string",
  "worker_reward_tag": "optional_hex_string",
  "reward_tree_value": "optional_hex_string"
}
```

### Verify Proof Output Format

```json
{
  "valid": true,
  "message": "Proof is valid"
}
```

### Proof File Formats

The proof file can be in two formats:

1. **JSON format** (recommended):
```json
{
  "proof": "hex_string",
  "reward_tree_value": "hex_string"
}
```

2. **Plain hex string**: Just the proof hex string (may be quoted as JSON string)

## Dependencies

This project depends on the following crates from the [parth-generic-v1](https://github.com/QEDProtocol/parth-generic-v1) repository:

- `psy_core`
- `psy_data`
- `psy_worker_core`
- `psy_plonky2_circuits`
- `psy_plonky2_basic_helpers`
- `parth_core`

These dependencies are specified as Git dependencies pointing to the main repository.

## Building

```bash
cargo build --release
```

## Running

The tool supports multiple modes: HTTP server mode and CLI mode with various subcommands.

### Global Options

- `--log-level <LEVEL>`: Log level (default: `info`, options: `info`, `debug`, `trace`)

### HTTP Server Mode

Run as an HTTP server to provide REST API endpoints:

```bash
cargo run --release -- server --listen-addr 0.0.0.0 --port 4000
```

or run the binary directly:

```bash
./target/release/psy_validator_cli server --listen-addr 0.0.0.0 --port 4000
```

**Server Options:**
- `--listen-addr <ADDRESS>`: Listen address (default: `0.0.0.0`)
- `--port <PORT>`: Listening port (default: `4000`)

**Example:**
```bash
psy-validator --log-level debug server --listen-addr 127.0.0.1 --port 8080
```

### CLI Mode

#### 1. Generate Proof

Generate a zero-knowledge proof from an input JSON file:

```bash
psy-validator generate-proof -i input.json -o proof.json
```

**Options:**
- `-i, --input <PATH>`: Input JSON file path (required)
- `-o, --output <PATH>`: Output file path (optional, defaults to stdout)
- `--worker-reward-tag <HEX>`: Worker reward tag as hex string (optional, will be derived from job_id if not provided)
- `--reward-tree-value <HEX>`: Reward tree value as hex string (optional, will be computed automatically if not provided)

**Example:**
```bash
# Generate proof and save to file
psy-validator generate-proof -i input.json -o proof.json

# Generate proof and output to stdout
psy-validator generate-proof -i input.json

# Generate proof with custom worker_reward_tag
psy-validator generate-proof -i input.json -o proof.json --worker-reward-tag abc123...
```

#### 2. Verify Proof

Verify a zero-knowledge proof:

```bash
psy-validator verify-proof -i input.json -p proof.json
```

**Options:**
- `-i, --input <PATH>`: Input JSON file path (required, can be GenerateProofRequest or VerifyProofRequest format)
- `-p, --proof <PATH>`: Proof file path (required, supports both JSON format `{"proof": "...", "reward_tree_value": "..."}` or plain hex string)
- `--worker-reward-tag <HEX>`: Worker reward tag as hex string (optional)
- `--reward-tree-value <HEX>`: Reward tree value as hex string (optional, will be extracted from proof.json if available)

**Example:**
```bash
# Verify proof
psy-validator verify-proof -i input.json -p proof.json

# Verify proof with custom parameters
psy-validator verify-proof -i input.json -p proof.json --worker-reward-tag abc123...
```

**Exit Code:**
- `0`: Verification successful
- `1`: Verification failed

#### 3. Fetch Job (One-Click Workflow)

Fetch job data and dependencies, then optionally generate and verify proof in one command:

```bash
psy-validator fetch-job -b https://example.com -p <proof_id> -o ./output
```

**Options:**
- `-b, --base-url <URL>`: Base URL (format: `https://xxx`, required)
- `-p, --proof-id <ID>`: Proof ID (format: `job_id_hex` (48 chars) + `realm_id_hex`, where `realm_id < 1000`, required)
- `-o, --output-dir <PATH>`: Output directory (default: `.`)
- `-d, --one-click-done`: Enable one-click workflow: generate_proof -> verify_proof (default: `true`)

**Workflow:**
1. Fetches `raw_input.json` from `{base_url}/output/{realm_id}/{job_id}/raw_input.json`
2. Fetches `raw_proof.json` for all dependencies in parallel
3. Generates `input_{job_id}.json` from fetched data
4. If `--one-click-done` is enabled (default):
   - Generates proof using `generate-proof`
   - Verifies proof using `verify-proof`

**Example:**
```bash
# Fetch job with one-click workflow (default)
psy-validator fetch-job -b https://api.example.com -p 0123456789abcdef...1234567890abcdef1234

# Fetch job without one-click workflow
psy-validator fetch-job -b https://api.example.com -p 0123456789abcdef...1234567890abcdef1234 -d false

# Fetch job to custom output directory
psy-validator fetch-job -b https://api.example.com -p 0123456789abcdef...1234567890abcdef1234 -o ./my_output
```

**Output Files:**
- `{output_dir}/{realm_id}/raw_input_{job_id}.json`: Raw input data
- `{output_dir}/{realm_id}/raw_proof_{dep_job_id}.json`: Raw proof for each dependency
- `{output_dir}/{realm_id}/input_{job_id}.json`: Generated input file for proof generation
- `{output_dir}/{realm_id}/proof_{job_id}.json`: Generated proof (if one-click workflow enabled)

### Environment Variables

- `LOG_LEVEL`: Logging level (default: `info`, can be overridden by `--log-level` CLI option)

## Testing

Run the test suite:

```bash
cargo test --release
```

## License

[Specify your license here]

## Contributing

[Specify contribution guidelines here]
