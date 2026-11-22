import datetime
import hashlib
import importlib
import sys

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import FieldDoesNotExist, ImproperlyConfigured
from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils.module_loading import import_string

DEFAULTS = {
    # Generating URLs
    "TOKEN_NAME": "sesame",
    # Tokens lifecycle
    "MAX_AGE": None,
    "ONE_TIME": False,
    "INVALIDATE_ON_PASSWORD_CHANGE": True,
    "INVALIDATE_ON_EMAIL_CHANGE": False,
    # Custom primary keys
    "PACKER": None,
    "PRIMARY_KEY_FIELD": "pk",
    # Multiple sites
    "SITE": None,
    "SITE_MODE": "disabled",
    "SITES": {},
    "LEGACY_SITES": [],
    "SITE_RESOLVER": None,
    # Tokens
    "TOKENS": ["sesame.tokens_v2", "sesame.tokens_v1"],
    # Tokens v2
    "KEY": "",
    # We want a short signature in order to keep tokens short. A 10-bytes
    # signature has about 1.2e24 possible values, which is sufficient here.
    "SIGNATURE_SIZE": 10,
    # Tokens v1
    "SALT": "sesame",
    # These parameters aren't updated anymore. Tokens v2 are recommended.
    "DIGEST": hashlib.md5,
    "ITERATIONS": 10000,
}

SITE_MODES = ("disabled", "compatible", "enforced")

__all__ = list(DEFAULTS) + [
    "SITE_MODES",
    "get_site_settings",
    "get_site_database",
    "get_site_for_database",
    "get_legacy_databases",
    "get_token_site",
    "resolve_site",
    "is_known_site",
    "validate_sites",
]


def derive_key(secret_key, key, site=""):
    """
    Make a 64-bytes key from Django's ``secret_key``, django-sesame's ``key``,
    and an optional site identifier.

    Include settings in the key to invalidate tokens when these settings change.
    This ensures that tokens generated with one packer cannot be misinterpreted
    by another packer, for example.

    When a site is provided, it's included in the key so that a token generated
    for one site cannot be authenticated on another site, even if both sites
    share ``SECRET_KEY`` and all other settings.

    """
    global MAX_AGE, PACKER, PRIMARY_KEY_FIELD
    parts = [
        # Usually a str but Django also supports bytes.
        str(secret_key),
        # Treat key like secret_key for consistency.
        str(key),
        # Changing MAX_AGE is allowed as long as it is not None.
        "max_age" if MAX_AGE is not None else "",
        PACKER if PACKER is not None else "",
        PRIMARY_KEY_FIELD,
    ]
    # Don't append an empty component: this would change the key for existing
    # tokens generated without a site.
    if site:
        # Length-prefix the site so that a separator inside it cannot collide
        # with a different combination of settings.
        parts.append(f"{len(site)}:{site}")
    return hashlib.blake2b(
        "|".join(parts).encode(),
        person=b"sesame.settings",
    ).digest()


def load():
    module = sys.modules[__name__]
    for name, default in DEFAULTS.items():
        setattr(module, name, getattr(settings, "SESAME_" + name, default))

    global KEY, MAX_AGE, SIGNING_KEY, TOKENS, VERIFICATION_KEYS
    global SITE, SITE_MODE, SITES, SITE_RESOLVER, LEGACY_SITES

    # Support defining MAX_AGE as a timedelta rather than a number of seconds.
    if isinstance(MAX_AGE, datetime.timedelta):
        MAX_AGE = MAX_AGE.total_seconds()

    # Import token creation and parsing modules.
    TOKENS = [importlib.import_module(tokens) for tokens in TOKENS]

    # Derive signing and verification keys for the default site.
    SIGNING_KEY = derive_key(settings.SECRET_KEY, KEY)
    VERIFICATION_KEYS = [SIGNING_KEY] + [
        derive_key(secret_key, KEY)
        for secret_key in getattr(settings, "SECRET_KEY_FALLBACKS", [])
    ]


def validate_sites():
    global SITE, SITE_MODE, SITES, SITE_RESOLVER, LEGACY_SITES
    if SITE_MODE not in SITE_MODES:
        raise ImproperlyConfigured(
            f"invalid configuration: SESAME_SITE_MODE must be one of "
            f"{', '.join(SITE_MODES)}"
        )
    if not isinstance(SITES, dict):
        raise ImproperlyConfigured(
            "invalid configuration: SESAME_SITES must be a dict "
            "mapping site identifiers to database aliases"
        )
    for site, database in SITES.items():
        if not isinstance(site, str) or not site:
            raise ImproperlyConfigured(
                "invalid configuration: SESAME_SITES keys must be "
                "non-empty strings"
            )
        if not isinstance(database, str) or not database:
            raise ImproperlyConfigured(
                f"invalid configuration: SESAME_SITES[{site!r}] must be "
                f"a database alias"
            )
    if SITE and SITE not in SITES:
        raise ImproperlyConfigured(
            f"invalid configuration: SESAME_SITE {SITE!r} isn't in SESAME_SITES"
        )
    unknown_databases = {
        site: database
        for site, database in SITES.items()
        if database not in settings.DATABASES
    }
    if unknown_databases:
        raise ImproperlyConfigured(
            f"invalid configuration: SESAME_SITES references unknown "
            f"databases: {unknown_databases}"
        )
    if SITE_MODE != "disabled" and not SITES:
        raise ImproperlyConfigured(
            f"invalid configuration: set SESAME_SITES when "
            f"SESAME_SITE_MODE is {SITE_MODE!r}"
        )
    if not isinstance(LEGACY_SITES, (list, tuple, set)):
        raise ImproperlyConfigured(
            "invalid configuration: SESAME_LEGACY_SITES must be a list"
        )
    for site in LEGACY_SITES:
        if site not in SITES:
            raise ImproperlyConfigured(
                f"invalid configuration: SESAME_LEGACY_SITES contains "
                f"unknown site {site!r}"
            )


# load() also works for reloading settings, which is useful for testing.


load()
validate_sites()


def get_site_settings(site):
    """
    Return the signing and verification keys for ``site``.

    ``site`` may be :obj:`None` or the empty string for the default site, in
    which case the result is the same as :data:`SIGNING_KEY` and
    :data:`VERIFICATION_KEYS`.

    """
    if not site:
        return SIGNING_KEY, VERIFICATION_KEYS
    if not isinstance(site, str):
        raise ImproperlyConfigured("invalid configuration: site must be a string")

    secret_keys = [settings.SECRET_KEY] + list(
        getattr(settings, "SECRET_KEY_FALLBACKS", [])
    )
    keys = [derive_key(secret_key, KEY, site) for secret_key in secret_keys]
    return keys[0], keys


def get_site_database(site):
    """
    Return the database alias storing users for ``site``.

    When site handling is disabled, always return ``"default"``. Otherwise,
    return ``"default"`` for sites that haven't been migrated in compatible
    mode, and :obj:`None` when no site is identified or when the site is
    unknown in enforced mode.

    """
    if not site:
        return "default" if SITE_MODE == "disabled" else None
    if site in SITES:
        return SITES[site]
    return "default" if SITE_MODE == "compatible" else None


def resolve_site(request):
    """
    Return the site bound to ``request``.

    :data:`SESAME_SITE_RESOLVER` may be a dotted path to a callable or a
    callable that receives ``request`` and returns a site identifier or
    :obj:`None`. :data:`SESAME_SITE` provides a static fallback.

    Return :obj:`None` when the site cannot be determined.

    """
    if SITE_RESOLVER is not None:
        if callable(SITE_RESOLVER):
            resolver = SITE_RESOLVER
        else:
            resolver = import_string(SITE_RESOLVER)
        site = resolver(request)
        if site:
            return site
    if SITE:
        return SITE
    return None


def is_known_site(site):
    """
    Tell whether ``site`` is configured in :data:`SESAME_SITES`.

    """
    return bool(site) and site in SITES


def get_token_site(user):
    """
    Return the site to bind to a token generated for ``user``.

    When :data:`SESAME_SITE_MODE` is ``"disabled"``, tokens aren't bound to a
    site, preserving historical behavior. Otherwise, infer the site from the
    database where ``user`` was loaded, then from :data:`SESAME_SITE`.

    Return :obj:`None` when the site cannot be determined. Generating an
    unbound token while site handling is enabled would silently bypass site
    isolation, so callers should reject this case; :func:`sesame.utils.get_token`
    raises :exc:`~django.core.exceptions.ImproperlyConfigured` instead.

    """
    if SITE_MODE == "disabled":
        return None
    database = getattr(getattr(user, "_state", None), "db", None)
    site = get_site_for_database(database)
    if site is not None:
        return site
    # SITES may map several sites to the same database; in that case, fall back
    # to the static site, if any.
    return SITE or None


def get_site_for_database(database):
    """
    Return the unique site mapped to ``database``, or :obj:`None`.

    """
    sites = [site for site, alias in SITES.items() if alias == database]
    return sites[0] if len(sites) == 1 else None


def get_legacy_databases():
    """
    Return database aliases audited when accepting an unbound token.

    :data:`SESAME_LEGACY_SITES` restricts the audit to the selected sites.
    Otherwise every site in :data:`SESAME_SITES` is audited, plus the default
    database, which may host historical users.

    """
    if LEGACY_SITES:
        return list(dict.fromkeys(SITES[site] for site in LEGACY_SITES))
    return list(dict.fromkeys([*SITES.values(), "default"]))



# Django's checks framework was designed to run such checks. Unfortunately,
# there's no way to guarantee that a check would be discovered, because
# django-sesame never required adding the "sesame" app to INSTALLED_APPS.

# The benefits of writing this check with the checks framework don't justify
# adding another step to the installation instructions. Raising an exception
# is good enough.


def check():
    global MAX_AGE, INVALIDATE_ON_PASSWORD_CHANGE
    if MAX_AGE is None and not INVALIDATE_ON_PASSWORD_CHANGE:
        raise ImproperlyConfigured(
            "insecure configuration: set SESAME_MAX_AGE to a low value "
            "or set SESAME_INVALIDATE_ON_PASSWORD_CHANGE to True"
        )

    global INVALIDATE_ON_EMAIL_CHANGE
    if INVALIDATE_ON_EMAIL_CHANGE:
        User = get_user_model()
        try:
            User._meta.get_field(User.get_email_field_name())
        except FieldDoesNotExist:
            raise ImproperlyConfigured(
                "invalid configuration: set User.EMAIL_FIELD correctly "
                "or set SESAME_INVALIDATE_ON_EMAIL_CHANGE to False"
            )


check()


@receiver(setting_changed)
def reload(*, setting, **kwargs):
    if setting.startswith("SECRET_KEY") or setting.startswith("SESAME_"):
        # Like check(), validate_sites() runs at import time. Overrides may be
        # temporarily invalid, for example while using override_settings().
        load()


    if setting in ["AUTH_USER_MODEL", "SESAME_PACKER", "SESAME_PRIMARY_KEY_FIELD"]:
        from . import packers

        packers.packer = packers.get_packer()

    if setting in ["SESAME_SALT", "SESAME_MAX_AGE"]:
        from . import tokens_v1

        tokens_v1.signer = tokens_v1.get_signer()
        tokens_v1.token_re = tokens_v1.get_token_re()
