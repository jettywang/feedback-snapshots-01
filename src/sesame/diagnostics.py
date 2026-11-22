import contextvars
import logging

__all__ = [
    "BAD_FORMAT",
    "EXPIRED",
    "INACTIVE_USER",
    "INVALID_TOKEN",
    "NO_TOKEN",
    "UNKNOWN_USER",
    "get_reason",
    "reset_reason",
    "set_reason",
]

# Machine-readable codes classifying why token authentication failed.
# They never contain tokens or URL parameters, so they're safe to record
# in the logging system and to aggregate for statistics.

NO_TOKEN = "no_token"
BAD_FORMAT = "bad_format"
INVALID_TOKEN = "invalid_token"
EXPIRED = "expired"
UNKNOWN_USER = "unknown_user"
INACTIVE_USER = "inactive_user"

# Dedicated logger for restricted diagnostic records. Operations can route
# it to an internal destination independently of the main "sesame" logger.
logger = logging.getLogger("sesame.diagnostics")

_reason = contextvars.ContextVar("sesame.diagnostics.reason", default=None)


def reset_reason():
    """
    Clear the failure reason before attempting to parse a token.

    """
    _reason.set(None)


def set_reason(reason):
    """
    Record why token authentication failed for the current context.

    """
    _reason.set(reason)


def get_reason():
    """
    Return why token authentication failed in the current context, if known.

    """
    return _reason.get()
