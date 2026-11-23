# SPDX-License-Identifier: MIT
"""
Three-worker split for Argon2 credential lifecycle, derived from the real
argon2-cffi interface (src/argon2/_password_hasher.py, _utils.py, exceptions.py).

Capability split:
  - online verify worker : PasswordHasher.verify            (digest + cleartext)
  - offline audit worker : extract_parameters /             (digest only)
                           PasswordHasher.check_needs_rehash
  - upgrade job worker   : admission decision (digest only) +
                           PasswordHasher.hash at login     (cleartext, transient)

The InstrumentedHasher is the local stand-in (替身): it wraps a real
PasswordHasher, records every call and its outcome, and never logs the
secret itself, so the business can replay the log and prove the offline
diagnostics never touched an online secret.
"""

from __future__ import annotations

import json
import time

from dataclasses import asdict, dataclass
from typing import Any, Callable

from argon2 import PasswordHasher
from argon2._utils import Parameters, extract_parameters
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


# --------------------------------------------------------------------------
# Observation layer (本地替身)
# --------------------------------------------------------------------------

class CallLog:
    """Append-only observation sink. Secrets are never written."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, worker: str, call: str, touches_secret: bool,
               outcome: str, detail: str = "") -> None:
        self.entries.append({
            "ts": round(time.time(), 3),
            "worker": worker,
            "call": call,
            "touches_secret": touches_secret,
            "outcome": outcome,
            "detail": detail,
        })

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e, ensure_ascii=False) for e in self.entries)


class InstrumentedHasher:
    """
    Local stand-in wrapping a real PasswordHasher. Every boundary crossing
    is observed; the password argument is only ever recorded as present/absent.
    """

    def __init__(self, hasher: PasswordHasher, worker: str, log: CallLog,
                 profile_name: str) -> None:
        self._hasher = hasher
        self._worker = worker
        self._log = log
        self.profile_name = profile_name

    @property
    def parameters(self) -> Parameters:
        return self._hasher._parameters

    def verify(self, hash: str, password: str) -> bool:
        try:
            result = self._hasher.verify(hash, password)
        except VerifyMismatchError as e:
            self._log.record(self._worker, "verify", True,
                             "VerifyMismatchError", str(e.args[0] if e.args else ""))
            raise
        except VerificationError as e:
            self._log.record(self._worker, "verify", True,
                             "VerificationError", str(e.args[0] if e.args else ""))
            raise
        except InvalidHashError:
            self._log.record(self._worker, "verify", True, "InvalidHashError")
            raise
        self._log.record(self._worker, "verify", True, "ok")
        return result

    def hash(self, password: str) -> str:
        try:
            digest = self._hasher.hash(password)
        except Exception as e:
            self._log.record(self._worker, "hash", True,
                             type(e).__name__, str(e.args[0] if e.args else ""))
            raise
        self._log.record(self._worker, "hash", True, "ok")
        return digest


class DigestOnlyAuditGateway:
    """
    Capability object for the offline audit worker. It deliberately has no
    verify/hash attribute: the cleartext path is removed at construction,
    not merely by convention. Everything here runs on the stored digest alone.
    """

    def __init__(self, reference: InstrumentedHasher, worker: str,
                 log: CallLog) -> None:
        self._reference = reference
        self._worker = worker
        self._log = log

    def extract_parameters(self, hash: str) -> Parameters:
        try:
            params = extract_parameters(hash)
        except InvalidHashError:
            self._log.record(self._worker, "extract_parameters", False,
                             "InvalidHashError")
            raise
        self._log.record(self._worker, "extract_parameters", False, "ok")
        return params

    def check_needs_rehash(self, hash: str) -> bool:
        try:
            needs = self._reference._hasher.check_needs_rehash(hash)
        except InvalidHashError:
            self._log.record(self._worker, "check_needs_rehash", False,
                             "InvalidHashError")
            raise
        self._log.record(self._worker, "check_needs_rehash", False,
                         f"ok:{needs}")
        return needs


# --------------------------------------------------------------------------
# Policy (evaluated on extracted parameters only -- no secret involved)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Policy:
    min_version: int
    allowed_types: tuple[str, ...]
    min_memory_cost: int
    min_time_cost: int
    min_parallelism: int
    min_hash_len: int

    def violations(self, p: Parameters) -> list[str]:
        out = []
        type_name = f"argon2{p.type.name.lower()}"
        if type_name not in self.allowed_types:
            out.append(f"type={type_name}")
        if p.version < self.min_version:
            out.append(f"version={p.version}<{self.min_version}")
        if p.memory_cost < self.min_memory_cost:
            out.append(f"memory_cost={p.memory_cost}<{self.min_memory_cost}")
        if p.time_cost < self.min_time_cost:
            out.append(f"time_cost={p.time_cost}<{self.min_time_cost}")
        if p.parallelism < self.min_parallelism:
            out.append(f"parallelism={p.parallelism}<{self.min_parallelism}")
        if p.hash_len < self.min_hash_len:
            out.append(f"hash_len={p.hash_len}<{self.min_hash_len}")
        return out


# --------------------------------------------------------------------------
# Stage 1: online verification (cleartext present, transient)
# --------------------------------------------------------------------------

def online_verify_worker(gateway: InstrumentedHasher, record_id: str,
                         stored_hash: str, presented_password: str) -> dict:
    try:
        gateway.verify(stored_hash, presented_password)
        return {"stage": "online_verify", "record": record_id,
                "result": "match", "exception": None}
    except (VerifyMismatchError, VerificationError, InvalidHashError) as e:
        return {"stage": "online_verify", "record": record_id,
                "result": "error", "exception": type(e).__name__}


# --------------------------------------------------------------------------
# Stage 2: offline storage audit (digest only, no secret in scope)
# --------------------------------------------------------------------------

def offline_audit_worker(gateway: DigestOnlyAuditGateway, record_id: str,
                         stored_hash: str, policy: Policy) -> dict:
    try:
        params = gateway.extract_parameters(stored_hash)
    except InvalidHashError:
        return {"stage": "offline_audit", "record": record_id,
                "conclusion": "unparseable", "params": None,
                "policy_violations": ["invalid-encoding"]}
    violations = policy.violations(params)
    needs_vs_audit_profile = gateway.check_needs_rehash(stored_hash)
    return {
        "stage": "offline_audit", "record": record_id,
        "conclusion": "violate" if violations else "compliant",
        "params": asdict(params, dict_factory=lambda kv: {
            k: (str(v) if k == "type" else v) for k, v in kv}),
        "policy_violations": violations,
        "needs_rehash_vs_audit_profile": needs_vs_audit_profile,
    }


# --------------------------------------------------------------------------
# Stage 3: upgrade job admission (digest + prior stage outcomes; cleartext
# only transiently at a real login, never in the batch job)
# --------------------------------------------------------------------------

def upgrade_admission_worker(issuer: InstrumentedHasher, record_id: str,
                             audit: dict, online: dict,
                             cleartext_at_login: str | None) -> dict:
    if audit["conclusion"] == "unparseable":
        return {"stage": "upgrade_admission", "record": record_id,
                "admitted": False, "route": "quarantine",
                "reason": "digest not parseable; automatic rehash impossible"}
    if audit["conclusion"] == "compliant":
        return {"stage": "upgrade_admission", "record": record_id,
                "admitted": False, "route": "no-op",
                "reason": "parameters satisfy policy floor; rehash would be churn"}
    # violates policy: automatic rehash-on-login only works if online verify
    # can succeed on this node.
    if online["result"] != "match":
        return {"stage": "upgrade_admission", "record": record_id,
                "admitted": False, "route": "manual-reset",
                "reason": f"online verify cannot succeed ({online['exception']}); "
                          "rehash-on-login will never fire on this node"}
    new_digest = None
    if cleartext_at_login is not None:
        new_digest = issuer.hash(cleartext_at_login)  # transient cleartext
    return {"stage": "upgrade_admission", "record": record_id,
            "admitted": True, "route": "rehash-on-login",
            "reason": "policy violation and verify path healthy",
            "rehash_issued": new_digest is not None}
