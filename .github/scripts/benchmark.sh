#!/usr/bin/env bash

set -ex

# Create the dataset

pushd etc/datasets
make ds3.zip
popd

# Show httpie version

http --version

# Send

start_time=$(date +%s)
http --ignore-stdin POST localhost:8080/api/v1/dataset "Authorization:$(oidc token trustify -bf)" @etc/datasets/ds3.zip
end_time=$(date +%s)

runtime=$((end_time - start_time))

echo "Runtime: $runtime s"

jq -n --arg i "$runtime" '
[
  {
    "name": "Ingest DS3",
    "unit": "s",
    "value": ($i | tonumber ),
  }
]
' > benchmark.json
