"""
Runnable demo: two white-label sites, two SQLite user tables, same primary key.

Run from the repository root:

    .venv/bin/python examples/multi_site/demo.py

It prints what happens when a request carries the right site, no site, or a
site that cannot be resolved, then shows how to audit tokens issued before the
migration.
"""

import logging
import os
import sys
import tempfile

import django
from django.conf import settings

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

workdir = tempfile.mkdtemp(prefix="sesame-sites-")

settings.configure(
    SECRET_KEY="demo-only-secret-key",
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.path.join(workdir, "site_a.sqlite3"),
        },
        "site_b": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.path.join(workdir, "site_b.sqlite3"),
        },
    },
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes"],
    AUTHENTICATION_BACKENDS=["sesame.backends.ModelBackend"],
    USE_TZ=True,
    # Start in compatible mode: old links keep working while you audit them.
    SESAME_SITE_MODE="compatible",
    SESAME_SITES={"site_a": "default", "site_b": "site_b"},
    SESAME_SITE_RESOLVER="resolvers.site_from_header",
)
django.setup()

from django.contrib.auth import get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import RequestFactory  # noqa: E402

from sesame import settings as sesame_settings  # noqa: E402
from sesame.backends import ModelBackend  # noqa: E402
from sesame.legacy import audit_token  # noqa: E402
from sesame.tokens import create_token  # noqa: E402
from sesame.utils import get_parameters  # noqa: E402

for alias in ("default", "site_b"):
    call_command("migrate", database=alias, verbosity=0)

# Keep the demo output readable; the same failures are logged in production.
logging.getLogger("sesame").setLevel(logging.CRITICAL)

User = get_user_model()


def create_user(username, using):
    user = User(username=username, is_active=True)
    user.set_password("letmein")
    user.save(using=using)
    return user


alice = create_user("alice", "default")  # site_a's table
bob = create_user("bob", "site_b")  # site_b's table
# Same primary key, different accounts. Same password hash, so even the token
# revocation key is identical: the hardest case for unbound tokens.
bob.password = alice.password
bob.save(using="site_b")

print(f"site_a: pk={alice.pk} username={alice.username} db={alice._state.db}")
print(f"site_b: pk={bob.pk} username={bob.username} db={bob._state.db}")
print()


def request_for(site, **extra):
    return RequestFactory().get("/", HTTP_X_SITE=site, **extra)


def try_request(label, token, request):
    user = ModelBackend().authenticate(request, sesame=token["sesame"])
    if user is None:
        print(f"{label}: rejected")
    else:
        print(f"{label}: {user.username} (db={user._state.db})")


# 1. Correct site: the token was issued by site_b and the request says site_b.
token_b = get_parameters(bob, site="site_b")
try_request("correct site      ", token_b, request_for("site_b"))

# 2. Request doesn't identify a site. The bound token must not be guessed.
try_request("no site           ", token_b, RequestFactory().get("/"))

# 3. Routing cannot be confirmed: the resolver raises. Authentication fails
#    closed instead of falling back to the default database.
sesame_settings.SITE_RESOLVER = "resolvers.failing_resolver"
try_request("unresolvable site ", token_b, RequestFactory().get("/"))
sesame_settings.SITE_RESOLVER = "resolvers.site_from_header"

print()

# Tokens issued before the migration contain no site. Audit them before
# switching SESAME_SITE_MODE from "compatible" to "enforced".
legacy_token = create_token(alice)  # no site= argument

audit = audit_token(legacy_token)
print(f"legacy token (two users share pk={alice.pk}): {audit.status}")
print("  reissue this link: it cannot be attributed to one site")

# After removing the collision, the same legacy token is unambiguous.
bob.delete(using="site_b")
audit = audit_token(legacy_token)
print(f"legacy token after collision removed: {audit.status}")
print(
    f"  -> {audit.matches[0].user.username} on site {audit.matches[0].site!r}, "
    f"database {audit.matches[0].database!r}"
)
print(f"  safe for site_a: {audit_token(legacy_token, site='site_a').is_safe}")

# Compatible mode accepts this unambiguous legacy token.
try_request("legacy, unique    ", {"sesame": legacy_token}, request_for("site_a"))

# Once the audit is clean, switch to enforced mode. No legacy token is
# accepted anymore, and every request must identify a site.
token_a = get_parameters(alice, site="site_a")
sesame_settings.SITE_MODE = "enforced"
try_request("enforced, legacy  ", {"sesame": legacy_token}, request_for("site_a"))
try_request("enforced, bound   ", token_a, request_for("site_a"))
try_request("enforced, no site ", token_a, RequestFactory().get("/"))

print()
print("Demo databases were created in:", workdir)
