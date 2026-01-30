#!/usr/bin/env bash
set -euo pipefail

BIN=./target/release/psy-cli
BASE_URL="https://psy-benchmark-round1-data.psy-protocol.xyz"

jobs=(
  "AggUserRegisterDeployContractsGUTA 004000000000000000280000000000000000000000000000 999"
  "DummyAppendUserRegistrationTreeAggregate 004000000000000000300000000000000000000000000000 999"
  "DummyBatchDeployContractsAggregate 004000000000000000360000000000000000000000000000 999"
  "GenerateRollupStateTransitionProof 000800000000000000200000000000000000000000000000 999"
  "GUTALeftGUTARightEndCap 006f000000000000000a0500000000000000020000000000 38"
  "GUTATwoEndCap 007300000000000000070000000000000000480000000000 3"
  "GUTATwoGUTALinear 007400000000000000390400000000000000000000000000 9"
  "GUTATwoGUTAWithCheckpointUpgrade 004000000000000000370000000000000000320000000000 999"
  "GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint 0040000000000000003b0100000000000000190000000000 999"
  "GUTAVerifyToCapWithCheckpointUpgrade 003800000000000000380000000000000000000000000000 999"
)

for entry in "${jobs[@]}"; do
  name=$(echo "$entry" | awk '{print $1}')
  job_id=$(echo "$entry" | awk '{print $2}')
  realm_id=$(echo "$entry" | awk '{print $3}')

  echo "==> fetching $name ($job_id, $realm_id)"
  "$BIN" --realm-id "$realm_id" --job-id "$job_id"
done

echo "All jobs fetched."