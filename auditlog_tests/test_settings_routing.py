"""Test settings that put audited models on a second database.

Run only the routing tests with::

    DJANGO_SETTINGS_MODULE=test_settings_routing \
        python auditlog_tests/manage.py test test_transaction_semantics_routing
"""

from test_settings import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
    "business": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

DATABASE_ROUTERS = ["test_app.routers.BusinessRouter"]
