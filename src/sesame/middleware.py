import logging
from urllib.parse import urlencode

from django.contrib.auth import login
from django.contrib.auth.models import AnonymousUser
from django.shortcuts import redirect

from . import settings
from .backends import use_site
from .utils import get_user

__all__ = ["AuthenticationMiddleware", "SiteMiddleware"]

logger = logging.getLogger("sesame")

# Django's session stores only the user's primary key. When several sites have
# users with the same primary key, a session created on one site must not be
# reloaded as another user on another site.
SESSION_SITE_KEY = "sesame_site"


class SiteMiddleware:
    """
    Resolve the site of each request and bind it for the rest of the request.

    When several sites share one code base, this middleware tells
    :class:`sesame.backends.ModelBackend` which database holds their users.
    It also makes the site available as ``request.sesame_site``.

    Place it before ``"django.contrib.auth.middleware.AuthenticationMiddleware"``
    so that users loaded from the session are read from the correct database:

    .. code-block:: python

        MIDDLEWARE = [
            "django.contrib.sessions.middleware.SessionMiddleware",
            "sesame.middleware.SiteMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            ...,
        ]

    Sessions are bound to the site where they were created. A session that
    presents itself on another site is discarded, because the same primary key
    may designate a different account there.

    It does nothing when :data:`SESAME_SITE_MODE` is ``"disabled"``.

    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.SITE_MODE == "disabled":
            return self.get_response(request)

        request.sesame_site_error = False
        try:
            site = settings.resolve_site(request)
        except Exception:
            # The routing table cannot be consulted. Mark the request so that
            # authentication fails closed instead of treating it as a request
            # that simply doesn't identify a site.
            logger.exception("Site resolver failed")
            request.sesame_site_error = True
            site = None
        if site is None:
            site = settings.SITE
        request.sesame_site = site

        if hasattr(request, "session") and site is not None:
            session_site = request.session.get(SESSION_SITE_KEY)
            if session_site is not None and session_site != site:
                # Never reload a session across sites, even if both sites have
                # a user with the same primary key.
                logger.debug(
                    "Discarding session from site %r on site %r",
                    session_site,
                    site,
                )
                request.session.flush()

        with use_site(site):
            response = self.get_response(request)

        # Record the site after a successful login so that the session can be
        # reloaded safely. SessionMiddleware runs outside this middleware and
        # saves the session when the response is returned.
        if hasattr(request, "session") and site is not None:
            user = getattr(request, "user", None)
            if (
                user is not None
                and user.is_authenticated
                and request.session.get(SESSION_SITE_KEY) != site
            ):
                request.session[SESSION_SITE_KEY] = site

        return response


class AuthenticationMiddleware:
    """
    Look for a signed token in the URL of any request and log a user in.

    After login, remove the token from the URL with an HTTP redirect.

    .. admonition:: This functionality requires additional setup for Safari.
        :class: warning

        :class:`AuthenticationMiddleware` requires the optional ``ua`` extra to
        prevent :ref:`issues with Safari <Safari issues>`:

        .. code-block:: console

            $ pip install 'django-sesame[ua]'

    In the :setting:`MIDDLEWARE` setting,
    ``"sesame.middleware.AuthenticationMiddleware"`` should be placed just after
    ``"django.contrib.auth.middleware.AuthenticationMiddleware"``:

    .. code-block:: python

        MIDDLEWARE = [
            ...,
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "sesame.middleware.AuthenticationMiddleware",
            ...,
        ]

    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # When process_request() returns a response, return that response.
        # Otherwise continue with the next middleware or the view.
        return self.process_request(request) or self.get_response(request)

    def process_request(self, request):
        """
        Log user the in if ``request`` contains a valid token.

        Return an HTTP redirect response that removes the token from the URL
        after a successful login (except on Safari to avoid triggering ITP,
        and only when sessions are enabled).

        """
        # If django.contrib.sessions is enabled, don't update the last login,
        # because login(request, user) will do it.
        # If django.contrib.sessions is disabled, keep the default behavior of
        # updating last login only for one-time tokens.
        user = get_user(
            request,
            update_last_login=False if hasattr(request, "session") else None,
            site=getattr(request, "sesame_site", None),
        )

        # If django.contrib.sessions is enabled and the token is valid,
        # persist the login in session.
        if hasattr(request, "session") and user is not None:
            login(request, user)
            # Once we persist the login in the session, if the authentication
            # middleware is enabled, it will set request.user in future
            # requests. We can get rid of the token in the URL by redirecting
            # to the same URL with the token removed. We only do this for GET
            # requests because redirecting POST requests doesn't work well. We
            # don't do this on Safari because it triggers the over-zealous
            # "Protection Against First Party Bounce Trackers" of ITP 2.0.
            if (
                hasattr(request, "user")
                and request.method == "GET"
                and not self.is_safari(request)
            ):
                return self.get_redirect(request)

        # If django.contrib.auth isn't enabled, set request.user.
        if not hasattr(request, "user"):
            request.user = user if user is not None else AnonymousUser()

    @staticmethod
    def is_safari(request):
        try:
            from ua_parser import user_agent_parser
        except ImportError:  # pragma: no cover
            return None
        else:
            user_agent = request.META.get("HTTP_USER_AGENT", "")
            parsed_ua = user_agent_parser.Parse(user_agent)
            return (
                parsed_ua["user_agent"]["family"] == "Safari"
                or parsed_ua["os"]["family"] == "iOS"
            )

    @staticmethod
    def get_redirect(request):
        """
        Create an HTTP redirect response that removes the token from the URL.

        """
        params = request.GET.copy()
        params.pop(settings.TOKEN_NAME)
        url = request.path
        if params:
            url += "?" + urlencode(params)
        return redirect(url)
