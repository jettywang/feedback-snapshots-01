# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Exceptions raised by the offline fork forensics interface.

The forensics interface never raises on *invalid evidence*: an observation
package that fails identity or authorization verification is reported as an
inconclusive :class:`~tuf.forensics.evidence.ForkReport` instead. Exceptions in
this module are reserved for programming errors such as malformed package
construction or unsupported input.
"""

from __future__ import annotations


class ForensicsError(Exception):
    """Base class for all forensics interface errors."""


class ObservationError(ForensicsError):
    """An observation package is structurally unusable.

    Raised when the package itself cannot be assembled (for example missing
    root material or an unknown envelope type), as opposed to containing
    metadata that fails cryptographic verification.
    """
