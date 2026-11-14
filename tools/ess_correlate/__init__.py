"""Offline S/MIME ESS signed-receipt correlation analysis.

The package provides deterministic fixtures, strict ASN.1 decoding and a
correlation engine whose cryptographic inputs are supplied explicitly by the
caller.  See ``tools/ess_correlate_analysis.py`` for the command line entry
point.
"""

from .model import (
    Attestations,
    DecodeError,
    Envelope,
    MessageRecord,
    ReceiptRecord,
    SignerRecord,
    attestations_from_mapping,
    decode_message,
    decode_receipt,
)

__all__ = [
    "Attestations",
    "DecodeError",
    "Envelope",
    "MessageRecord",
    "ReceiptRecord",
    "SignerRecord",
    "attestations_from_mapping",
    "decode_message",
    "decode_receipt",
]
