import logging

from . import settings

logger = logging.getLogger("sesame")

__all__ = ["create_token", "parse_token"]


def _check_site(module, site):
    if site and not getattr(module, "SUPPORTS_SITES", False):
        raise NotImplementedError(
            f"{module.__name__.rpartition('.')[2]} tokens don't support sites"
        )


def create_token(user, scope="", site=None):
    """
    Create a signed token for a user and an optional scope and site.

    """
    tokens = settings.TOKENS[0]
    _check_site(tokens, site)
    if site:
        return tokens.create_token(user, scope, site)
    # Don't pass site=None to custom token modules that predate sites.
    return tokens.create_token(user, scope)


def parse_token(token, get_user, scope="", max_age=None, site=None):
    """
    Obtain a user from a signed token and an optional scope and site.

    Tokens that don't support sites are ignored when ``site`` is set, so that
    enforcing sites cannot be bypassed with an old token format.

    """
    for tokens in settings.TOKENS:
        # We can detect the version of a token simply by inspecting it:
        # v1 tokens contain a colon; v2 tokens don't.
        if tokens.detect_token(token):
            if site and not getattr(tokens, "SUPPORTS_SITES", False):
                logger.debug(
                    "Bad token: %s tokens don't support sites",
                    tokens.__name__.rpartition(".")[2],
                )
                return None
            if site:
                return tokens.parse_token(
                    token, get_user, scope, max_age, site=site
                )
            return tokens.parse_token(token, get_user, scope, max_age)
    else:
        logger.debug("Bad token: doesn't match a supported format")
        return None
