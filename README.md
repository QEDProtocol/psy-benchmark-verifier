# Psy CLI Prover

A CLI tool for generating zero-knowledge proofs for Psy Protocol benchmark jobs and comparing proving time with the benchmark machine.

## Overview

Psy CLI Prover fetches job data from the Psy benchmark server, retrieves dependency proofs in parallel, generates Plonky2 ZK proofs, and reports your proving time versus the benchmark machine.

## Features

- **Single-job mode**: Prove one job by `--job-id` and `--realm-id` (or env vars).
- **Batch mode**: Read `realm_id,job_id` pairs from stdin and process multiple jobs.
- **Parallel dependency fetching**: Fetches all dependency proofs in parallel.
- **Benchmark comparison**: Fetches benchmark machine proving time and prints whether you are faster or slower.

## Building

```bash
cargo build --release
```

The binary is produced at `./target/release/psy-cli`.

## Usage

### Options

| Option | Description |
|--------|-------------|
| `--job-id <JOB_ID>` | Job ID (24 bytes = 48 hex chars). Can also be set via `JOB_ID` env var. |
| `--realm-id <REALM_ID>` | Realm ID (u32). Can also be set via `REALM_ID` env var. |
| `-b, --batch` | Batch mode: read `realm_id,job_id` pairs from stdin, one per line. |
| `-h, --help` | Print help. |
| `-V, --version` | Print version. |

### Single-job mode

When stdin is a TTY and `--batch` is not set, both `job_id` and `realm_id` are required (via CLI or environment):

```bash
./target/release/psy-cli --job-id <48_hex_chars> --realm-id <u32>
```

Or using environment variables:

```bash
export JOB_ID=<48_hex_chars>
export REALM_ID=<u32>
./target/release/psy-cli
```

### Batch mode

Read one line per job in the form `realm_id,job_id` (no spaces):

```bash
./target/release/psy-cli --batch <<EOF
1,0123456789abcdef0123456789abcdef0123456789abcdef
2,abcdef0123456789abcdef0123456789abcdef0123456789
EOF
```

Or pipe from a file:

```bash
cat jobs.txt | ./target/release/psy-cli -b
```

If stdin is not a TTY (e.g. piped input), batch mode is used automatically; `-b` is optional in that case.

### Environment variables

- **`JOB_ID`**: Job ID (48 hex chars). Used when `--job-id` is not set.
- **`REALM_ID`**: Realm ID (u32). Used when `--realm-id` is not set.

## Dependencies

This project depends on crates from [parth-generic-v1](https://github.com/QEDProtocol/parth-generic-v1):

- `psy_core`, `psy_data`, `psy_worker_core`
- `psy_plonky2_circuits`, `psy_plonky2_basic_helpers`
- `parth_core`

ZK backend: [plonky2-hwa](https://github.com/PsyProtocol/plonky2-hwa).

## Testing

```bash
cargo test --release
```

## License

[Specify your license here]

## Contributing

[Specify contribution guidelines here]
