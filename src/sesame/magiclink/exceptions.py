__all__ = [
    "MagicLinkError",
    "MagicLinkNotFound",
    "MagicLinkInvalid",
    "MagicLinkExpired",
    "MagicLinkRevoked",
    "MagicLinkAlreadyConsumed",
    "MagicLinkUnavailable",
]


class MagicLinkError(Exception):
    """Base class for failures while consuming a magic link."""

    def __init__(self, message, link=None):
        super().__init__(message)
        self.link = link


class MagicLinkNotFound(MagicLinkError):
    """No magic link matches the presented token hash."""


class MagicLinkInvalid(MagicLinkError):
    """The cryptographic token no longer authenticates the link's user."""


class MagicLinkExpired(MagicLinkError):
    """The link reached its expiry before being consumed."""


class MagicLinkRevoked(MagicLinkError):
    """The link was revoked before being consumed."""


class MagicLinkAlreadyConsumed(MagicLinkError):
    """The link already produced a session and cannot be reused."""


class MagicLinkUnavailable(MagicLinkError):
    """Another request is currently consuming the link."""
