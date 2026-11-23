#!/usr/bin/env sh
# Offline acceptance for the "real new access" release gate.
# Parses real templates through the real parser and policy analysis; only the
# AWS client boundary is replaced with one shared semantic analyzer double.
set -eu
cd "$(dirname "$0")/.."
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}" \
  TEST_MODE=OFFLINE \
  exec .venv/bin/python -m cfn_policy_validator.tests.policy_analysis_tests.acceptance
