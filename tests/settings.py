# Include the sesame backend first to avoid bogus database queries caused by
# https://code.djangoproject.com/ticket/30556 and simplify assertNumQueries.

AUTHENTICATION_BACKENDS = [
    "sesame.backends.ModelBackend",
    "django.contrib.auth.backends.ModelBackend",
]

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3"},
    # Declared so the connection exists for Django's system checks. The
    # concurrency tests repoint this alias at a fresh file at runtime and route
    # only the MagicLink model to it; the test runner otherwise leaves it alone
    # thanks to TEST.MIGRATE.
    "magiclink_file": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "",
        "TEST": {"MIGRATE": False},
    },
}

DATABASE_ROUTERS = ["tests.db_routers.MagicLinkRouter"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "sesame.magiclink",
    "tests",
]

LOGIN_REDIRECT_URL = "/login/redirect/url/"

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

ROOT_URLCONF = "tests.urls"

SECRET_KEY = "Anyone who finds a URL will be able to log in. Seriously."

SESSION_ENGINE = "django.contrib.sessions.backends.cache"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "OPTIONS": {
            "context_processors": ["django.contrib.auth.context_processors.auth"]
        },
    }
]

USE_TZ = True
