__all__ = [
    "MagicLink",
    "MagicLinkAlreadyConsumed",
    "MagicLinkError",
    "MagicLinkExpired",
    "MagicLinkInvalid",
    "MagicLinkLoginView",
    "MagicLinkNotFound",
    "MagicLinkRevoked",
    "MagicLinkUnavailable",
    "claim_magic_link",
    "consume_magic_link",
    "hash_token",
    "issue_magic_link",
    "release_magic_link",
    "resend_magic_link",
    "revoke_magic_link",
]


def __getattr__(name):
    # Imports are lazy: models can only be imported once Django apps are ready.
    if name == "MagicLink":
        from .models import MagicLink

        return MagicLink
    if name in {
        "MagicLinkAlreadyConsumed",
        "MagicLinkError",
        "MagicLinkExpired",
        "MagicLinkInvalid",
        "MagicLinkNotFound",
        "MagicLinkRevoked",
        "MagicLinkUnavailable",
    }:
        from . import exceptions

        return getattr(exceptions, name)
    if name == "MagicLinkLoginView":
        from .views import MagicLinkLoginView

        return MagicLinkLoginView
    if name in {
        "claim_magic_link",
        "consume_magic_link",
        "hash_token",
        "issue_magic_link",
        "release_magic_link",
        "resend_magic_link",
        "revoke_magic_link",
    }:
        from . import services

        return getattr(services, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
