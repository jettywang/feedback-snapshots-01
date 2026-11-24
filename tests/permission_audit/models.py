from django.db import models


class Report(models.Model):
    title = models.CharField(max_length=100)
    body = models.TextField(default='')
    confidential = models.BooleanField(default=False)

    class Meta:
        # Table creation (pytest --no-migrations) only covers installed apps;
        # the test suite installs the top-level ``tests`` app, so audit models
        # attach to it, matching tests/models.py.
        app_label = 'tests'
