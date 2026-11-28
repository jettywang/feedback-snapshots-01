"""Static audit of Twisted stream-server endpoint listening ranges.

The package parses endpoint description strings without constructing
endpoint objects, so it never binds a port, calls listen() or opens TLS
private key material.  See L{endpoint_audit.cli} for the review entry point.
"""

from .audit import AuditResult, audit_declarations
from .extensions import DiscloserRegistry, Disclosure
from .model import (
    Family,
    HostBinding,
    HostKind,
    ListenRange,
    ParsedEntry,
    SourceCoordinate,
    Verdict,
)
from .overlap import PairVerdict, audit_pairs, compare_entries, compare_ranges
from .parser import parse_endpoint

__all__ = [
    "AuditResult",
    "DiscloserRegistry",
    "Disclosure",
    "Family",
    "HostBinding",
    "HostKind",
    "ListenRange",
    "PairVerdict",
    "ParsedEntry",
    "SourceCoordinate",
    "Verdict",
    "audit_declarations",
    "audit_pairs",
    "compare_entries",
    "compare_ranges",
    "parse_endpoint",
]
