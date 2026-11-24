"""Compatibility alias for :mod:`dynaconf.utils.shared` redaction helpers."""

from __future__ import annotations

from dynaconf.utils.inspect import MASK
from dynaconf.utils.inspect import REDACTED
from dynaconf.utils.inspect import REDACTED_LITERAL
from dynaconf.utils.inspect import REDACTED_PLACEHOLDER
from dynaconf.utils.inspect import Redacted
from dynaconf.utils.inspect import RedactionPolicy
from dynaconf.utils.inspect import redact_report
from dynaconf.utils.inspect import resolve_policy
from dynaconf.utils.inspect import shared_view

__all__ = [
    "REDACTED",
    "REDACTED_LITERAL",
    "REDACTED_PLACEHOLDER",
    "MASK",
    "Redacted",
    "RedactionPolicy",
    "redact_report",
    "resolve_policy",
    "shared_view",
]
