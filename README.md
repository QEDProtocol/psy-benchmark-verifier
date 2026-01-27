# Psy Validator

A standalone validator service for zero-knowledge proof generation and verification.

## Overview

Psy Validator provides a REST API service for generating and verifying zero-knowledge proofs using Plonky2 circuits. It supports both realm and coordinator node types for the Psy Protocol.

## Features

- **Proof Generation**: Generate ZK proofs from API requests
- **Proof Verification**: Verify ZK proofs with public inputs hash checking
- **Activity Tracking**: Track validator activity with persistent counter
- **REST API**: HTTP/JSON API for easy integration

## API Endpoints

- `POST /v1/generate_proof` - Generate zero-knowledge proof
- `POST /v1/verify_proof` - Verify zero-knowledge proof
- `POST /v1/activity/increment` - Increment activity counter
- `GET /v1/activity/count` - Get activity counter value

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

```bash
cargo run --release -- --listen-addr 0.0.0.0 --port 4000
```

### Environment Variables

- `ACTIVITY_COUNTER_FILE`: Path to the activity counter JSON file (default: `./activity_counter.json`)
- `LOG_LEVEL`: Logging level (default: `info`)

### Command Line Options

- `--listen-addr`: Listen address (default: `0.0.0.0`)
- `--port`: Listening port (default: `4000`)
- `--log-level`: Log level (e.g., `info`, `debug`, `trace`)

## Testing

Run the test suite:

```bash
cargo test
```

## License

[Specify your license here]

## Contributing

[Specify contribution guidelines here]
