"""
Fake third-party extension, approved by the platform allowlist in managed mode tests.

The module-level marker records every import of this file (including imports in
multiprocessing child processes), so tests can verify whether this extension's
code was executed.
"""
import os
import re

from detect_secrets.plugins.base import RegexBasedDetector


_marker_file = os.environ.get('DETECT_SECRETS_MANAGED_TEST_MARKER')
if _marker_file:
    with open(_marker_file, 'a') as f:
        f.write('approved_extension\n')


class ApprovedFakeScanner(RegexBasedDetector):
    """Scans for approved fake secrets."""
    secret_type = 'Approved Fake Secret'
    denylist = (
        re.compile(r'(approved-fake-secret)'),
    )


def should_exclude_approved_fake(secret: str) -> bool:
    return secret == 'allowlisted-approved-fake-secret'
