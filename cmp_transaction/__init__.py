"""Offline CMP (RFC 4210) transaction validation.

The :class:`~cmp_transaction.validator.CMPTransactionValidator` enforces the
transaction-level rules for the four message types used by an offline
initialization registration:

* ``ir``  -- Initialization Request
* ``ip``  -- Initialization Response (including the ``waiting`` state and
  pollReq/pollRep exchanges)
* ``certConf`` -- Certificate Confirmation
* ``pkiconf``  -- PKI Confirmation (final message)

The outer PKIMessage protection (MAC or signature, RFC 4210 section 5.1.3)
is assumed to have been verified by the caller; the validator never inspects
or re-computes it.
"""

from cmp_transaction.validator import (
    CMPTransactionValidator,
    RejectReason,
    TransactionPhase,
    CertReqState,
    ValidationResult,
    TransactionRecord,
    CertRecord,
)

__all__ = [
    "CMPTransactionValidator",
    "RejectReason",
    "TransactionPhase",
    "CertReqState",
    "ValidationResult",
    "TransactionRecord",
    "CertRecord",
]
