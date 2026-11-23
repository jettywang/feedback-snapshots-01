# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= cfn_policy_validator/tests/cfn_tools_tests/test_yaml_parser.py cfn_policy_validator/tests/cfn_tools_tests/test_schema_validator.py cfn_policy_validator/tests/cfn_tools_tests/test_regex_patterns.py
```

Measured on macOS in 0.877 seconds. Tests use local fixtures and require no external service.

The IAM Identity Center permission set acceptance suite runs entirely offline against two local stacks and a simulated
policy analysis endpoint. It uses the real `parse` and `validate` entry points and asserts on the policy documents handed
to the analyzer, not on resource names:

```sh
AWS_DEFAULT_REGION=us-east-1 TEST_MODE=OFFLINE .venv/bin/python -m pytest -q -o addopts= cfn_policy_validator/tests/acceptance_tests/
```

Fixtures live in `cfn_policy_validator/tests/acceptance_tests/fixtures/`: one stack has an inline policy plus a
template-resolved managed policy and an AWS-managed policy, with two permission sets sharing a display name; the other has
a customer-managed reference whose document is unavailable, a customer-managed reference that is never fetched, and a
permissions boundary. Measurement: 20 tests in ~0.4 seconds, no network.

