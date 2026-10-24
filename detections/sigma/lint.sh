#!/bin/bash
# Lint all Sigma rules in rules/.
# Requires: uv tool install --with pysigma-backend-opensearch --with pysigma-backend-loki sigma-cli
set -e
cd "$(dirname "$0")"
echo "=== sigma check (validators + parser) ==="
sigma check rules/
echo
echo "=== sigma analyze (rule statistics) ==="
sigma analyze rules/ 2>&1 || true
echo
echo "=== Rule count ==="
ls rules/*.yml | wc -l | tr -d ' '
