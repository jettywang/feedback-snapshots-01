# Source Policies and Update Audit

Use source policies when selected security-sensitive fields may only be changed
by approved sources. Dynaconf still performs its normal nested merge and still
calls the same loader plugins; governance runs at the single `Settings.set`
boundary used by file, environment-variable, include, and custom loaders.

## Declare allowed sources

```python
from dynaconf import Dynaconf

settings = Dynaconf(
    source_policies={
        "SECURITY": ["baseline.yaml"],
        "SECURITY.TIMEOUT": ["baseline.yaml", "ops-change"],
    }
)
```

Policies can also be declared with `FieldSourcePolicy`:

```python
from dynaconf import FieldSourcePolicy

policy = FieldSourcePolicy(
    "SECURITY.ADMIN",
    allowed_sources=["baseline.yaml", "vault"],
    review_sources=["ops-change"],
)
settings.add_source_policy(policy)
```

Source patterns match the source identifier, loader name, `loader:identifier`,
file basename, or `loader:basename:environment`. Wildcards are supported by
`fnmatch`.

## Nested merges are judged by leaf changes

Write the same parent key from two sources:

```python
settings.set(
    "SECURITY",
    {"timeout": 30, "admin": False},
    loader_identifier="baseline.yaml",
)

settings.set(
    "SECURITY",
    {"timeout": 5, "admin": True},
    loader_identifier="ops-change",
    merge=True,
)
```

The more specific `SECURITY.TIMEOUT` policy accepts the timeout change from
`ops-change`. `SECURITY.ADMIN` only accepts the baseline source, so the admin
change is stored as a pending audit record and the active value remains
`False`. Unchanged leaves produced by a merge are recorded only in the trace,
not as accepted updates.

Read the audit from Python:

```python
settings.pending_updates
settings.accepted_updates
print(settings.audit.explain("SECURITY"))
```

Send structured records to an ops sink or JSONL file:

```python
events = []
settings = Dynaconf(audit_sink=events)

settings = Dynaconf(audit_log_path="/var/log/dynaconf/audit.jsonl")
```

Accepted records are also emitted through the `dynaconf.audit` logger.

## Approve a pending update

```python
record = settings.pending_updates[0]
record.approve(reviewer="sre-oncall")
# or
settings.approve_update(record.id, reviewer="sre-oncall")
```

Approval applies the candidate through the normal settings path with an
internal `policy_approval` source. Reject a candidate with
`settings.reject_update(record.id)`.

## Stable fallback

Pending and rejected candidates are never published. Each audit record keeps
the previous, effective, fallback, and last-approved value. Accepted batches
also create versions in `settings.audit.versions`, including an approved
snapshot. A blocked replacement therefore leaves the previous approved
configuration available to readers.
