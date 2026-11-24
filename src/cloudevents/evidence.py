"""Top-level alias for the offline evidence-receipt API."""

from cloudevents.core.receipt import *  # noqa: F401,F403
from cloudevents.core.receipt import EvidenceReceipt as Evidence  # noqa: F401
from cloudevents.core.receipt import __all__ as _all

__all__ = list(_all) + ["Evidence"]
