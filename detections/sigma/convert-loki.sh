#!/bin/bash
# Convert all Sigma rules to Loki LogQL queries (against Vector→Loki streams).
set -e
cd "$(dirname "$0")"
sigma convert --without-pipeline -t loki rules/
