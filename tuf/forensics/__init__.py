# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline fork forensics for TUF repositories.

This package provides an offline, read-only interface for deciding whether two
independently observed metadata envelopes prove that a repository publisher
signed conflicting content for the same role and version.

It is intentionally separate from the update client: nothing here performs
network access or mutates repository state. Analysis starts from an explicit
trust anchor and reuses the signature semantics of the rest of python-tuf.

The main entry point is :func:`analyze_fork`. Typical use::

    from tuf.forensics import (
        EnvelopeType,
        ObservationPackage,
        analyze_fork,
    )

    first = ObservationPackage(
        envelope_a, root_bytes, EnvelopeType.METADATA, root_chain
    )
    second = ObservationPackage(
        envelope_b, root_bytes, EnvelopeType.METADATA, root_chain
    )
    report = analyze_fork(first, second)
    if report.fork_proven:
        ...  # publisher misbehavior is cryptographically evidenced

Traditional :class:`~tuf.api.metadata.Metadata` and DSSE
:class:`~tuf.api.dsse.SimpleEnvelope` observations are each handled with their
own signature semantics, selected via
:class:`~tuf.ngclient.config.EnvelopeType`.
"""

from tuf.forensics.analyzer import analyze_fork
from tuf.forensics.evidence import (
    AuthorizationHop,
    AuthorizationPath,
    ConflictFields,
    EvidenceSummary,
    ForkReport,
    ForkStatus,
    ObservationVerdict,
    RefutationReason,
    RootChainHop,
    SignatureEvidence,
)
from tuf.forensics.exceptions import ForensicsError, ObservationError
from tuf.forensics.observation import ObservationPackage, parse_envelope
from tuf.ngclient.config import EnvelopeType

__all__ = [
    "AuthorizationHop",
    "AuthorizationPath",
    "ConflictFields",
    "EnvelopeType",
    "EvidenceSummary",
    "ForensicsError",
    "ForkReport",
    "ForkStatus",
    "ObservationError",
    "ObservationPackage",
    "ObservationVerdict",
    "RefutationReason",
    "RootChainHop",
    "SignatureEvidence",
    "analyze_fork",
    "parse_envelope",
]
