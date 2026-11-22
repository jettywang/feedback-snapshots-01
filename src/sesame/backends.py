import logging
from contextlib import contextmanager
from contextvars import ContextVar

from django.contrib.auth import backends as auth_backends
from django.contrib.auth import get_user_model

from . import settings
from .tokens import parse_token

__all__ = [
    "ModelBackend",
    "SesameBackendMixin",
    "get_current_site",
    "set_current_site",
    "use_site",
]

logger = logging.getLogger("sesame")

# The site resolved by SiteMiddleware for the current request. Django's session
# authentication calls ModelBackend.get_user() without a request, so a
# context variable is the only way to tell it which database to query.
_current_site = ContextVar("sesame_site", default=None)


def get_current_site():
    """
    Return the site for the current request, or :obj:`None`.

    """
    return _current_site.get()


def set_current_site(site):
    """
    Bind ``site`` to the current context and return a token for resetting it.

    """
    return _current_site.set(site)


@contextmanager
def use_site(site):
    """
    Temporarily bind ``site`` to the current context.

    """
    token = _current_site.set(site)
    try:
        yield
    finally:
        _current_site.reset(token)


def _get_user_from_database(backend, database):
    """
    Build a ``get_user(user_id)`` callable querying ``database``.

    """
    User = get_user_model()

    def get_user(user_id):
        try:
            user = User._default_manager.using(database).get(
                **{settings.PRIMARY_KEY_FIELD: user_id}
            )
        except User.DoesNotExist:
            return None
        if backend.user_can_authenticate(user):
            return user
        else:
            return None

    return get_user


class SesameBackendMixin:
    """
    Mix this class in an authentication backend providing ``get_user(user_id)``
    to create an authentication backend usable with django-sesame.

    """

    def authenticate(self, request, sesame, scope="", max_age=None, site=None):
        """
        If ``sesame`` is a valid token, return the user. Else, return :obj:`None`.

        If ``scope`` is set, a :ref:`scoped token <Scoped tokens>` is expected.

        If ``max_age`` is set, override the :data:`SESAME_MAX_AGE` setting.

        ``request`` is an :class:`~django.http.HttpRequest` or :obj:`None`.

        If ``site`` is set, the token must be bound to this site. Else, the
        site is resolved from ``request``, then from :data:`SESAME_SITE`.

        """
        # This check shouldn't be necessary, but it can avoid problems like
        # issue #37 and Django's built-in backends include similar checks.
        if sesame is None:
            return None

        if settings.SITE_MODE == "disabled":
            # Historical behavior: ModelBackend.get_user() reads from the
            # default database because no site is bound to the context.
            return parse_token(sesame, self.get_user, scope, max_age)

        if request is not None and getattr(request, "sesame_site_error", False):
            # The resolver failed upstream. Never fall back to another site.
            logger.debug("Site could not be determined; rejecting token")
            return None

        try:
            site = self.resolve_site(request, site)
        except Exception:
            # A resolver that fails cannot establish routing. Reject the token
            # instead of guessing a database.
            logger.exception("Site resolver failed; rejecting token")
            return None

        if site is not None:
            if site in settings.SITES:
                return self.authenticate_for_site(
                    sesame, site, scope, max_age, request
                )
            if settings.SITE_MODE == "enforced":
                logger.debug("Unknown site: %r", site)
                return None
            # Compatible mode: this site hasn't been migrated yet. It still
            # issues unbound tokens and reads users from the default database.
            return self.authenticate_unmigrated_site(
                sesame, site, scope, max_age, request
            )

        if settings.SITE_MODE == "enforced":
            logger.debug("Site could not be determined; rejecting token")
            return None

        # Compatible mode without any site information: accept the token only
        # if it matches exactly one user across all databases.
        return self.authenticate_without_site(sesame, scope, max_age, request)

    def resolve_site(self, request, site):
        """
        Return the explicit ``site``, else the site resolved for ``request``.

        Raise an exception when :data:`SESAME_SITE_RESOLVER` fails.

        """
        if site is not None:
            return site
        if request is not None:
            if hasattr(request, "sesame_site"):
                site = request.sesame_site
            else:
                site = settings.resolve_site(request)
        else:
            site = settings.SITE
        if site and request is not None:
            request.sesame_site = site
        return site

    def authenticate_for_site(self, sesame, site, scope, max_age, request):
        """
        Authenticate a token against the database mapped to ``site``.

        """
        database = settings.SITES[site]
        get_user = self.get_user_for_database(database)
        user = parse_token(sesame, get_user, scope, max_age, site=site)
        if user is not None:
            if request is not None:
                request.sesame_site = site
            return user
        if settings.SITE_MODE == "compatible":
            # Accept a token generated before site binding only if it maps to
            # exactly one user across all audited databases and that user
            # belongs to this site. A legacy token contains no site, so this is
            # the only way to tell whether it was issued for this site.
            matches = self.find_legacy_matches(
                sesame, scope, max_age, settings.get_legacy_databases()
            )
            if len(matches) != 1:
                if len(matches) > 1:
                    logger.debug(
                        "Ambiguous legacy token: matches %d users; rejecting",
                        len(matches),
                    )
                return None
            user = matches[0]
            if user._state.db != database:
                logger.debug(
                    "Legacy token belongs to database %r, not to site %r",
                    user._state.db,
                    site,
                )
                return None
            if request is not None:
                request.sesame_site = site
            logger.debug("Accepted legacy token for site %r", site)
            return user
        return None

    def authenticate_legacy(self, sesame, scope, max_age, request):
        """
        Accept a legacy token only when it matches one user unambiguously.

        """
        matches = self.find_legacy_matches(
            sesame, scope, max_age, settings.get_legacy_databases()
        )
        if len(matches) == 1:
            user = matches[0]
            site = settings.get_site_for_database(user._state.db)
            if site and request is not None:
                request.sesame_site = site
            logger.debug("Accepted unique legacy token for site %r", site)
            return user
        if len(matches) > 1:
            logger.debug(
                "Ambiguous legacy token: matches %d users; rejecting", len(matches)
            )
        return None

    def authenticate_unmigrated_site(self, sesame, site, scope, max_age, request):
        """
        Authenticate on a site that isn't in :data:`SESAME_SITES` yet.

        Such a site keeps using the default database and unbound tokens, like
        before the migration. Bound tokens are rejected because no database is
        mapped to the site, which avoids attributing a token to the wrong site.

        """
        matches = self.find_legacy_matches(sesame, scope, max_age, ["default"])
        if len(matches) != 1 or matches[0]._state.db != "default":
            logger.debug("No unambiguous legacy token for unmigrated site")
            return None
        if request is not None:
            request.sesame_site = site
        return matches[0]

    def authenticate_without_site(self, sesame, scope, max_age, request):
        """
        Accept a legacy token when it matches exactly one user, in any database.

        This is the compatible-mode behavior for requests that carry no site
        information at all, for example background jobs that only have a token.

        """
        return self.authenticate_legacy(sesame, scope, max_age, request)

    def find_legacy_matches(self, sesame, scope, max_age, databases):
        """
        Return users matching a legacy token in ``databases``.

        Because a legacy token contains no site, the same primary key may exist
        in several databases.

        """
        matches = []
        seen = set()
        for database in databases:
            get_user = self.get_user_for_database(database)
            user = parse_token(sesame, get_user, scope, max_age)
            if user is None:
                continue
            # A custom backend may ignore the database argument, returning the
            # same user for every alias. Don't report it as ambiguous.
            identity = (user.__class__, user.pk, user._state.db)
            if identity not in seen:
                seen.add(identity)
                matches.append(user)
        return matches

    def get_user_for_database(self, database):
        """
        Return a callable fetching a user from ``database`` by primary key.

        Subclasses storing users in several databases must override this.

        """
        return self.get_user


class ModelBackend(SesameBackendMixin, auth_backends.ModelBackend):
    """
    Authentication backend that authenticates users with django-sesame tokens.

    It inherits :class:`SesameBackendMixin` and Django's built-in
    :class:`~django.contrib.auth.backends.ModelBackend`.

    Extending the default value of the :setting:`AUTHENTICATION_BACKENDS` setting
    to add  ``"sesame.backends.ModelBackend"`` looks like:

    .. code-block:: python

        AUTHENTICATION_BACKENDS = [
            "django.contrib.auth.backends.ModelBackend",
            "sesame.backends.ModelBackend",
        ]

    """

    def get_user(self, user_id):
        """
        Fetch user from the database by primary key.

        The field used by django-sesame as a primary key can be configured with
        the :data:`SESAME_PRIMARY_KEY_FIELD` setting.

        The database is selected from the site resolved for the current
        request, then from :data:`SESAME_SITE`. When site handling is
        disabled, the default database is used, preserving historical
        behavior.

        Return :obj:`None` if no active user is found.

        """
        database = settings.get_site_database(get_current_site())
        if database is None:
            return None
        return self.get_user_for_database(database)(user_id)

    def get_user_for_database(self, database):
        """
        Return a callable fetching a user from ``database`` by primary key.

        """
        return _get_user_from_database(self, database)
