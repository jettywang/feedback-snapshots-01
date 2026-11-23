# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= cfn_policy_validator/tests/cfn_tools_tests/test_yaml_parser.py cfn_policy_validator/tests/cfn_tools_tests/test_schema_validator.py cfn_policy_validator/tests/cfn_tools_tests/test_regex_patterns.py
```

Measured on macOS in 0.877 seconds. Tests use local fixtures and require no external service.

# Offline acceptance: real new access release gate

The release gate for "does this change actually grant new access?" is pinned by
`cfn_policy_validator/tests/policy_analysis_tests/`. It runs the real parser and
the real `policy_analysis` code path, replacing only the AWS client boundary
with one semantic analyzer double shared by every scenario.

Run the acceptance on its own (no AWS credentials, no network):

```sh
AWS_DEFAULT_REGION=us-east-1 .venv/bin/python -m cfn_policy_validator.tests.policy_analysis_tests.acceptance
```

Expected output ends with three `[PASS]` lines and exit code `0`:

- `legacy approved template` — the historical fixture parses and grants exactly
  the approved reference policy.
- `equivalent reorder` — the same policy with resources, statements, actions,
  resources inside a statement, and JSON object keys reordered still passes;
  ordering is never the signal.
- `redirected to another resource` — the same `s3:PutObject`/`s3:PutObjectAcl`
  action names now target `prod-audit-data` instead of `prod-app-data/write/*`,
  and the gate blocks with evidence at
  `Resources.WorkerRole.Properties.Policies[0].PolicyDocument.Statement[2]`.

Run the same suite through pytest:

```sh
TEST_MODE=OFFLINE AWS_DEFAULT_REGION=us-east-1 .venv/bin/python -m pytest -q -o addopts= cfn_policy_validator/tests/policy_analysis_tests
```

The analyzer compares grants semantically: action, resource, condition and
principal, independent of serialization order. It covers `Ref`, `Fn::If`
conditions and generated ARNs (`Fn::GetAtt`, `Fn::Sub`) because those are resolved
by the real parser before the comparison. A same-action change to another target
is a new grant; an action-name-only comparison would wrongly pass it.
