"""
Deterministic stand-ins for the OSV service used by the disclosure examples.

The fixture is injected at the same seam the real service uses
(`pip_audit._service.osv.caching_session`), so the examples exercise the real
CLI, auditor, formatters, error handling, and report writers.
"""

from __future__ import annotations

import json

import requests

# A public package with a public advisory that mentions a private package.
# The description is deliberately sensitive so the evidence shows it is kept
# out of the public report even though the package name is publishable.
PUBLIC_ADVISORY_TEXT = (
    "ADVISORY-DESCRIPTION-MARKER: affects public-lib; internal mitigation notes "
    "reference internal-payments-lib and /srv/private/advisories"
)

# A private package advisory.
PRIVATE_ADVISORY_TEXT = "PRIVATE-ADVISORY-MARKER: internal only, see /srv/private/runbook"

PAYLOADS = {
    "public-lib": {
        "vulns": [
            {
                "id": "PYSEC-2099-0001",
                "summary": PUBLIC_ADVISORY_TEXT,
                "aliases": ["CVE-2099-0001"],
                "affected": [
                    {
                        "package": {"name": "public-lib", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"fixed": "1.0.1"}],
                            }
                        ],
                    }
                ],
            }
        ]
    },
    "internal-payments-lib": {
        "vulns": [
            {
                "id": "PYSEC-2099-0002",
                "summary": PRIVATE_ADVISORY_TEXT,
                "aliases": [],
                "affected": [
                    {
                        "package": {"name": "internal-payments-lib", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"fixed": "1.2.4"}],
                            }
                        ],
                    }
                ],
            }
        ]
    },
}


class _Response:
    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


class FakeSession:
    """An OSV session that answers from `PAYLOADS` or fails on demand."""

    def __init__(self, fail_after: int | None = None):
        self.fail_after = fail_after
        self.calls = 0

    def post(self, url, data=None, timeout=None):
        self.calls += 1
        if self.fail_after is not None and self.calls >= self.fail_after:
            raise requests.ConnectTimeout("simulated timeout while contacting OSV")
        query = json.loads(data)
        name = query["package"]["name"]
        return _Response(PAYLOADS.get(name, {}))
