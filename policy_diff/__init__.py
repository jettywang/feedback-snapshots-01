"""Offline pre-upgrade diff tooling for oslo.policy based services.

The package builds throwaway :class:`oslo_policy.policy.Enforcer` instances
from local copies of service policy-in-code defaults, operator policy files
and sample credentials. It never mutates the running service's enforcer or
its configuration; see :mod:`policy_diff.engine` for the details.
"""

from policy_diff.engine import (
    ActionEvaluation,
    PolicySnapshot,
    SnapshotContext,
    build_snapshot,
    diff_snapshots,
    explain_action,
)
from policy_diff.loader import (
    CredentialSample,
    load_credentials,
    load_defaults,
    load_target,
)

__all__ = [
    'ActionEvaluation',
    'CredentialSample',
    'PolicySnapshot',
    'SnapshotContext',
    'build_snapshot',
    'diff_snapshots',
    'explain_action',
    'load_credentials',
    'load_defaults',
    'load_target',
]
