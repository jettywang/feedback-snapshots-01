"""
Self-contained, re-runnable demo of the permission audit.

Runs without pytest: configures Django in-process, creates the table with
the schema editor, drives real requests through the router-bound URLconf
and prints every permission check plus every business-method entry.

    .venv/bin/python -m tests.permission_audit.run_demo
"""
import django
from django.conf import settings

settings.configure(
    DEBUG_PROPAGATE_EXCEPTIONS=True,
    DATABASES={'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }},
    INSTALLED_APPS=(
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'rest_framework',
        # Report carries app_label='tests' (see models.py), so install the
        # tests package to create its table via run_syncdb, as the pytest
        # suite does under --no-migrations.
        'tests',
    ),
    ROOT_URLCONF='tests.permission_audit.urls',
    SECRET_KEY='permission-audit-demo',
    DEFAULT_AUTO_FIELD='django.db.models.AutoField',
)
django.setup()

from django.contrib.auth.models import User  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.db import connection  # noqa: E402

from rest_framework.test import APIClient  # noqa: E402

from .models import Report  # noqa: E402
from .permissions import PERMISSION_CALL_LOG, reset_permission_log  # noqa: E402
from .views import BUSINESS_CALL_LOG, reset_business_log  # noqa: E402


def _setup_table():
    # auth/contenttypes ship migrations; the unmigrated tests app (which
    # hosts Report) is synced directly.
    call_command('migrate', run_syncdb=True, verbosity=0)


def _show(title):
    print(f'\n=== {title} ===')
    print('  permission checks:')
    for entry in PERMISSION_CALL_LOG:
        obj = f" obj_pk={entry['obj_pk']}" if entry['obj_pk'] is not None else ''
        print(f"    - {entry['kind']:<22} {entry['permission']:<38} "
              f"{entry['method']:<6} action={entry['action']}{obj}")
    print('  business handler:')
    for entry in BUSINESS_CALL_LOG:
        print(f"    - {entry}")
    if not BUSINESS_CALL_LOG:
        print('    - (handler never ran)')


def _run(label, method, url, client, **kwargs):
    reset_permission_log()
    reset_business_log()
    response = getattr(client, method)(url, **kwargs)
    print(f'\n{label}: {method.upper()} {url} -> {response.status_code}')
    _show(label)
    return response


def main():
    _setup_table()
    report = Report.objects.create(title='quarterly', body='data')

    anon = APIClient()
    clerk = APIClient()
    clerk.force_authenticate(
        User.objects.create_user(username='clerk', password='x'))
    boss = APIClient()
    boss.force_authenticate(
        User.objects.create_user(username='boss', password='x', is_staff=True))

    print('# Router-generated patterns and method maps')
    from .urls import router
    for pattern in router.urls:
        print(f"  {pattern.name:<18} {pattern.pattern.regex.pattern} "
              f"-> {pattern.callback.actions}")

    _run('1a. public list GET (anon)', 'get', '/reports/', anon)
    _run('1b. restricted POST same URL (anon)', 'post', '/reports/',
         anon, data={'title': 'x'}, format='json')
    _run('1c. restricted POST same URL (auth)', 'post', '/reports/',
         clerk, data={'title': 'x'}, format='json')
    _run('2a. inherited detail GET (anon)', 'get', f'/reports/{report.pk}/', anon)
    _run('2b. inherited detail PATCH (anon)', 'patch', f'/reports/{report.pk}/',
         anon, data={'title': 'renamed'}, format='json')
    _run('3a. self-loading publish POST (anon)', 'post',
         f'/reports/{report.pk}/publish/', anon)
    _run('3b. self-loading publish POST (staff)', 'post',
         f'/reports/{report.pk}/publish/', boss)
    _run('3c. get_object archive POST (staff)', 'post',
         f'/reports/{report.pk}/archive/', boss)


if __name__ == '__main__':
    main()
