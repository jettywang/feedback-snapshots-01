"""Compatibility namespace for the offline evidence-receipt API.

The canonical implementation lives in :mod:`cloudevents.core.receipt`.
"""

from cloudevents.core.receipt import *  # noqa: F401,F403
from cloudevents.core.receipt import (  # noqa: F401
    EvidenceReceipt as Evidence,
)
from cloudevents.core.receipt import EvidenceReceipt, __all__ as _all

__all__ = list(_all) + ["Evidence"]
