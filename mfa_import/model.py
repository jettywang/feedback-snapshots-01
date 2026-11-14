"""Immutable, secret-aware value objects produced by the import planner.

The planner copies every value it needs out of the pyasn1 object graph into
plain Python types held by frozen dataclasses.  Two consequences follow:

* mutating the original ASN.1 object after planning cannot change a plan;
* :meth:`repr` and :meth:`str` are safe to log because seed and PIN material
  are never included.  Callers that are authorized to persist a key obtain
  the raw seed explicitly through :meth:`CredentialEntry.seed_bytes`.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import FrozenSet, Optional, Tuple


@dataclass(frozen=True)
class OtpParameters:
    """Normalized HOTP/TOTP parameters for a single key."""

    mode: str                      # "hotp" or "totp"
    counter: Optional[int] = None
    time_start: Optional[int] = None       # BinaryTime, number of intervals
    time_interval: Optional[int] = None    # seconds
    time_drift: Optional[int] = None
    response_encoding: Optional[str] = None
    response_length: Optional[int] = None
    response_check_digit: Optional[bool] = None
    challenge_encoding: Optional[str] = None
    challenge_min: Optional[int] = None
    challenge_max: Optional[int] = None
    challenge_check_digit: Optional[bool] = None
    suite: Optional[str] = None

    def public_dict(self):
        return {
            "mode": self.mode,
            "counter": self.counter,
            "time_start": self.time_start,
            "time_interval": self.time_interval,
            "time_drift": self.time_drift,
            "response_encoding": self.response_encoding,
            "response_length": self.response_length,
            "response_check_digit": self.response_check_digit,
            "challenge_encoding": self.challenge_encoding,
            "challenge_min": self.challenge_min,
            "challenge_max": self.challenge_max,
            "challenge_check_digit": self.challenge_check_digit,
            "suite": self.suite,
        }


@dataclass(frozen=True)
class PinPolicy:
    """PIN policy for a key.  It never carries a PIN value."""

    usage_mode: str
    pin_key_id: Optional[str] = None
    max_failed_attempts: Optional[int] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pin_encoding: Optional[str] = None

    def public_dict(self):
        return {
            "usage_mode": self.usage_mode,
            "pin_key_id": self.pin_key_id,
            "max_failed_attempts": self.max_failed_attempts,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "pin_encoding": self.pin_encoding,
        }


@dataclass(frozen=True)
class CredentialEntry:
    """One importable credential, decoupled from the ASN.1 object graph."""

    key_id: str
    algorithm: str
    key_usages: FrozenSet[str]
    seed: bytes = field(repr=False, default=b"")
    issuer: Optional[str] = None
    key_profile_id: Optional[str] = None
    key_reference: Optional[str] = None
    friendly_name: Optional[str] = None
    key_user_id: Optional[str] = None
    start_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    number_of_transactions: Optional[int] = None
    otp: Optional[OtpParameters] = None
    pin_policy: Optional[PinPolicy] = None

    def seed_bytes(self):
        """Return the raw symmetric key material for the storage callback."""
        return self.seed

    def public_summary(self):
        """Non-secret metadata suitable for logs, audit records and UI."""
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "key_usages": sorted(self.key_usages),
            "issuer": self.issuer,
            "key_profile_id": self.key_profile_id,
            "key_reference": self.key_reference,
            "friendly_name": self.friendly_name,
            "key_user_id": self.key_user_id,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "number_of_transactions": self.number_of_transactions,
            "otp": self.otp.public_dict() if self.otp else None,
            "pin_policy": self.pin_policy.public_dict() if self.pin_policy else None,
        }

    def __repr__(self):
        return "CredentialEntry(key_id=%r, algorithm=%r)" % (
            self.key_id, self.algorithm)


@dataclass(frozen=True)
class DeviceInfo:
    """Package-level (device) attributes shared by every key in a package."""

    manufacturer: Optional[str] = None
    serial_number: Optional[str] = None
    model: Optional[str] = None
    issue_number: Optional[str] = None
    device_binding: Optional[str] = None
    start_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    module_id: Optional[str] = None
    device_user_id: Optional[str] = None

    def public_dict(self):
        return {
            "manufacturer": self.manufacturer,
            "serial_number": self.serial_number,
            "model": self.model,
            "issue_number": self.issue_number,
            "device_binding": self.device_binding,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "module_id": self.module_id,
            "device_user_id": self.device_user_id,
        }


@dataclass(frozen=True)
class ValidationIssue:
    """A single validation finding.  Never contains secret values."""

    code: str
    scope: str                  # "package" or "key"
    key_id: Optional[str]
    detail: str

    def public_dict(self):
        return {
            "code": self.code,
            "scope": self.scope,
            "key_id": self.key_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ImportPlan:
    """Result of fully validating one :class:`rfc6031.SymmetricKeyPackage`."""

    importable: bool
    version: int
    device: DeviceInfo
    entries: Tuple[CredentialEntry, ...]
    issues: Tuple[ValidationIssue, ...]

    @property
    def credential_count(self):
        return len(self.entries)

    def summary(self):
        """Secret-free description of the plan, safe for logging."""
        return {
            "importable": self.importable,
            "version": self.version,
            "credential_count": self.credential_count,
            "device": self.device.public_dict(),
            "credentials": [entry.public_summary() for entry in self.entries],
            "issues": [issue.public_dict() for issue in self.issues],
        }

    def issues_by_code(self, code):
        return tuple(issue for issue in self.issues if issue.code == code)

    def __repr__(self):
        return "ImportPlan(importable=%r, credential_count=%d, issue_count=%d)" % (
            self.importable, self.credential_count, len(self.issues))


def frozen_strings(values):
    return frozenset(str(value) for value in values)
