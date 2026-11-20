# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= cfn_policy_validator/tests/cfn_tools_tests/test_yaml_parser.py cfn_policy_validator/tests/cfn_tools_tests/test_schema_validator.py cfn_policy_validator/tests/cfn_tools_tests/test_regex_patterns.py
```

Measured on macOS in 0.877 seconds. Tests use local fixtures and require no external service.
