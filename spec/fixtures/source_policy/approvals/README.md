# Approved sources and exemptions

This directory records the approved exceptions used by the source-policy
regression. It is intentionally data, not code, so the reasons and expiry
stay reviewable next to the fixtures.

| Advisory | Gem | Scope | Approved by | Approved on | Expires | Ticket | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-0001 | testgem | version-only | security-team | 2026-03-01 | 2026-12-31 | SEC-2026-0042 | vendor patch shipped in the application image |
| GHSA-aaaa-bbbb-0002 | testgem | version-only | security-team | 2026-03-01 | 2026-12-31 | SEC-2026-0042 | vendor patch shipped in the application image |

The `scope` is `version-only` on purpose. Neither approval covers an insecure
or unidentifiable source.

`registry.json` is the machine-readable form used by the regression.
