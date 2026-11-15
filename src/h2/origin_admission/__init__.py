"""
Per-stream origin admission for HTTP/2 connections that carry multiple
authorities.

This package provides an application-level adapter that decides, independently
for every HTTP/2 stream, whether the request's origin is acceptable on the
shared connection. Two distinct conditions are evaluated for every request:

1. The TLS connection presented by the peer actually covers the requested
   host (certificate name coverage).
2. The application policy allows the authenticated caller to access that
   origin (the caller-specific allow set).

Certificate coverage alone never implies access permission. A host that is
present on the certificate but absent from the caller's allow set is rejected.

The adapter is deliberately decoupled from the rest of the protocol stack:
the caller supplies both the trusted TLS connection information and the
application allow set, and feeds it decoded request/trailer header blocks
(or the corresponding :mod:`h2.events` objects). Rejecting one stream never
mutates the identity recorded for any other stream, and trailers cannot
rewrite an origin that was fixed when the request headers were admitted.
"""
from __future__ import annotations

from .admission import (
    AdmissionDecision,
    AdmissionError,
    AuditEntry,
    Origin,
    OriginAdmissionAdapter,
    RejectionReason,
    TLSCertificateInfo,
    TrailerDecision,
)

__all__ = [
    "AdmissionDecision",
    "AdmissionError",
    "AuditEntry",
    "Origin",
    "OriginAdmissionAdapter",
    "RejectionReason",
    "TLSCertificateInfo",
    "TrailerDecision",
]
