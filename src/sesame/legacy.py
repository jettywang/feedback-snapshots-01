import dataclasses

from . import settings
from .backends import ModelBackend
from .tokens import parse_token

__all__ = ["LegacyMatch", "LegacyAudit", "audit_token"]


@dataclasses.dataclass(frozen=True)
class LegacyMatch:
    """
    A user matching an unbound (pre-migration) token.

    """

    database: str
    site: str
    user: object


@dataclasses.dataclass(frozen=True)
class LegacyAudit:
    """
    Result of auditing an unbound token before enabling site binding.

    ``status`` is one of:

    - ``"unique"``: the token matches exactly one user. It may keep working
      during the migration.
    - ``"ambiguous"``: the token matches several users, typically because the
      same primary key exists in several databases. It must not be accepted;
      reissue it.
    - ``"invalid"``: the token matches no active user. It's expired or
      revoked.

    """

    token: str
    matches: tuple

    @property
    def status(self):
        if len(self.matches) == 1:
            return "unique"
        if len(self.matches) > 1:
            return "ambiguous"
        return "invalid"

    @property
    def is_safe(self):
        return self.status == "unique"


def audit_token(token, scope="", max_age=None, databases=None, site=None):
    """
    Check whether an unbound token generated before the migration is safe.

    Tokens generated before site binding contain no site. After the migration,
    they're accepted only when they match exactly one user, because a primary
    key may exist in several user tables. This function performs the same check
    without authenticating the user, so that you can audit stock before
    switching :data:`SESAME_SITE_MODE`.

    ``databases`` defaults to :func:`sesame.settings.get_legacy_databases`:
    every database listed in :data:`SESAME_SITES`, plus ``"default"``, or only
    the databases of the sites in :data:`SESAME_LEGACY_SITES`. Pass an explicit
    list to audit a subset.

    Pass ``site`` to audit the token as it would be used on one site: the token
    is safe only if it uniquely resolves to a user in that site's database.

    Return a :class:`LegacyAudit`.

    """
    if databases is None:
        databases = settings.get_legacy_databases()
    backend = ModelBackend()
    matches = []
    for database in databases:
        get_user = backend.get_user_for_database(database)
        user = parse_token(token, get_user, scope, max_age)
        if user is not None:
            matches.append(
                LegacyMatch(
                    database=database,
                    site=settings.get_site_for_database(database),
                    user=user,
                )
            )
    if site is not None:
        expected = settings.SITES.get(site)
        if expected is None:
            raise ValueError(f"unknown site: {site!r}")
        matches = [match for match in matches if match.database == expected]
    return LegacyAudit(token=token, matches=tuple(matches))
