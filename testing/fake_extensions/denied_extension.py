"""
Fake third-party extension, NOT approved by the platform allowlist in managed mode
tests. Its module-level marker must never execute while managed mode is enabled.
"""
import os
import re

from detect_secrets.plugins.base import RegexBasedDetector


_marker_file = os.environ.get('DETECT_SECRETS_MANAGED_TEST_MARKER')
if _marker_file:
    with open(_marker_file, 'a') as f:
        f.write('denied_extension\n')


class DeniedFakeScanner(RegexBasedDetector):
    """Scans for denied fake secrets."""
    secret_type = 'Denied Fake Secret'
    denylist = (
        re.compile(r'(denied-fake-secret)'),
    )


def should_exclude_denied_fake(secret: str) -> bool:
    return secret == 'allowlisted-denied-fake-secret'
