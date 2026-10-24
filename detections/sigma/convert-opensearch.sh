#!/bin/bash
# Convert all Sigma rules to OpenSearch Lucene queries (executable against
# wazuh-alerts-* via Wazuh dashboard or Grafana OpenSearch datasource).
set -e
cd "$(dirname "$0")"
sigma convert --without-pipeline -t opensearch_lucene rules/
