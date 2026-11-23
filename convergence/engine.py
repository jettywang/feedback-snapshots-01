"""Core helpers for service-account access convergence planning on top of pycasbin.

A policy *state* is two canonical lists:
  permissions (p rules): [[role, resource, action], ...]
  role edges   (g rules): [[subject, role], ...]

Everything else (fingerprints, in-memory enforcers, decision diffs) is derived
from these two lists so that a plan can be reasoned about without mutating any
on-disk policy until it is explicitly applied.
"""
from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass, field

from casbin import Enforcer, StringAdapter


@dataclass(frozen=True)
class PolicyState:
    permissions: tuple[tuple[str, str, str], ...] = ()
    role_edges: tuple[tuple[str, str], ...] = ()

    def permission_set(self) -> set[tuple[str, str, str]]:
        return set(self.permissions)

    def role_edge_set(self) -> set[tuple[str, str]]:
        return set(self.role_edges)


def parse_policy_file(path: str) -> PolicyState:
    permissions: list[tuple[str, str, str]] = []
    role_edges: list[tuple[str, str]] = []
    with open(path, newline="", encoding="utf-8") as handle:
        for raw in csv.reader(handle, skipinitialspace=True):
            if not raw or not raw[0].strip() or raw[0].strip().startswith("#"):
                continue
            kind = raw[0].strip()
            fields = [cell.strip() for cell in raw[1:]]
            if kind == "p":
                if len(fields) != 3:
                    raise ValueError(f"malformed p rule in {path}: {raw}")
                permissions.append((fields[0], fields[1], fields[2]))
            elif kind == "g":
                if len(fields) != 2:
                    raise ValueError(f"malformed g rule in {path}: {raw}")
                role_edges.append((fields[0], fields[1]))
            else:
                raise ValueError(f"unknown policy kind {kind!r} in {path}: {raw}")
    return PolicyState(tuple(permissions), tuple(role_edges))


def serialize_state(state: PolicyState) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for role, resource, action in sorted(state.permissions):
        writer.writerow(["p", role, resource, action])
    for subject, role in sorted(state.role_edges):
        writer.writerow(["g", subject, role])
    return out.getvalue()


def fingerprint(state: PolicyState) -> str:
    """Stable content hash of every p and g rule in the state.

    Two fingerprints being equal means *none* of the depended-on policies have
    changed; a mismatch is the signal that another approved change landed first
    and the plan's premises must be re-evaluated.
    """
    digest = hashlib.sha256()
    for role, resource, action in sorted(state.permissions):
        digest.update(b"p|")
        digest.update(",".join([role, resource, action]).encode("utf-8"))
        digest.update(b"\n")
    for subject, role in sorted(state.role_edges):
        digest.update(b"g|")
        digest.update(",".join([subject, role]).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_enforcer(model_path: str, state: PolicyState) -> Enforcer:
    enforcer = Enforcer(model_path, StringAdapter(serialize_state(state)))
    enforcer.enable_auto_save(False)
    return enforcer


@dataclass
class Decision:
    subject: str
    resource: str
    action: str
    allowed: bool


def evaluate_matrix(model_path: str, state: PolicyState, matrix) -> list[Decision]:
    enforcer = build_enforcer(model_path, state)
    decisions: list[Decision] = []
    for subject, resource, action in matrix:
        decisions.append(
            Decision(subject, resource, action, bool(enforcer.enforce(subject, resource, action)))
        )
    return decisions


def diff_decisions(before: list[Decision], after: list[Decision]) -> list[dict]:
    """Return only the API decisions that flip, keyed by (sub,obj,act)."""
    after_index = {(d.subject, d.resource, d.action): d.allowed for d in after}
    flips: list[dict] = []
    for decision in before:
        key = (decision.subject, decision.resource, decision.action)
        new_allowed = after_index[key]
        if decision.allowed != new_allowed:
            flips.append(
                {
                    "subject": decision.subject,
                    "resource": decision.resource,
                    "action": decision.action,
                    "before": "ALLOW" if decision.allowed else "DENY",
                    "after": "ALLOW" if new_allowed else "DENY",
                }
            )
    return flips
