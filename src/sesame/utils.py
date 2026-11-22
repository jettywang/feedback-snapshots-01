from urllib.parse import urlencode

from django.contrib.auth import authenticate
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from . import settings
from .tokens import create_token

__all__ = ["get_token", "get_parameters", "get_query_string", "get_user"]


def get_token(user, scope="", site=None):
    """
    Generate a signed token to authenticate ``user``.

    Set ``scope`` to create a :ref:`scoped token <Scoped tokens>`.

    Set ``site`` to bind the token to a site. When ``site`` is :obj:`None` and
    :data:`SESAME_SITE_MODE` isn't ``"disabled"``, the site is inferred from
    the database where ``user`` was loaded, then from :data:`SESAME_SITE`.

    Use this function to create a token that :func:`get_user` will accept.

    """
    if site is None:
        site = settings.get_token_site(user)
        if site is None and settings.SITE_MODE == "enforced":
            raise ImproperlyConfigured(
                "cannot determine the site of this user; pass site=..., load "
                "the user from a database listed in SESAME_SITES, or set "
                "SESAME_SITE"
            )
        # In compatible mode, an unmigrated site may still issue unbound
        # tokens. They're accepted only while they map to exactly one user.
    return create_token(user, scope, site)


def get_parameters(user, scope="", site=None):
    """
    Generate a :class:`dict` of query string parameters to authenticate ``user``.

    Set ``scope`` to create a :ref:`scoped token <Scoped tokens>`.

    Set ``site`` to bind the token to a site.

    Use this function to add authentication to a URL that already contains a
    query string.

    """
    return {settings.TOKEN_NAME: get_token(user, scope, site)}


def get_query_string(user, scope="", site=None):
    """
    Generate a complete query string to authenticate ``user``.

    Set ``scope`` to create a :ref:`scoped token <Scoped tokens>`.

    Set ``site`` to bind the token to a site.

    Use this function to add authentication to a URL that doesn't contain a
    query string.

    """
    return "?" + urlencode({settings.TOKEN_NAME: get_token(user, scope, site)})


def get_user(
    request_or_sesame,
    scope="",
    max_age=None,
    *,
    update_last_login=None,
    site=None,
):
    """
    Authenticate a user based on a signed token.

    ``request_or_sesame`` may be a :class:`~django.http.HttpRequest` containing
    a token in the URL or the token itself, created with :func:`get_token`. The
    latter supports use cases outside the HTTP request lifecycle.

    If a valid token is found, return the user. Else, return :obj:`None`.

    :func:`get_user` doesn't log the user in permanently.

    If ``scope`` is set, a :ref:`scoped token <Scoped tokens>` is expected.

    If ``max_age`` is set, override the :data:`SESAME_MAX_AGE` setting.

    If ``site`` is set, a token bound to this site is expected. Else, the site
    is resolved from the request or from :data:`SESAME_SITE`.

    If single-use tokens are enabled, :func:`get_user` invalidates the token by
    updating the user's last login date.

    Set ``update_last_login`` to :obj:`True` or :obj:`False` to always or never
    update the user's last login date, regardless of whether single-use tokens
    are enabled. Typically, if you're going to log the user in with
    :func:`~django.contrib.auth.login`, set ``update_last_login`` to
    :obj:`False` to avoid updating the last login date twice.

    """
    if isinstance(request_or_sesame, str):
        request = None
        sesame = request_or_sesame
    else:
        # request is expected to be a django.http.HttpRequest
        request = request_or_sesame
        try:
            sesame = request_or_sesame.GET.get(settings.TOKEN_NAME)
        except Exception:
            raise TypeError("get_user() expects an HTTPRequest or a token")
        if sesame is None:
            return None

    # Call authenticate() to set user.backend to the value expected by login(),
    # "sesame.backends.ModelBackend" or the dotted path to a subclass.
    credentials = {
        "sesame": sesame,
        "scope": scope,
        "max_age": max_age,
    }
    # Only pass site when it's set, so that custom backends written against the
    # previous signature keep working.
    if site is not None:
        credentials["site"] = site
    user = authenticate(request, **credentials)
    if user is None:
        return None

    if update_last_login is None:
        update_last_login = settings.ONE_TIME
    if update_last_login:
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

    return user
