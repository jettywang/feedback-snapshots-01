Offline patch attestation sample
================================

Two bundles ship ``libffi.so.5`` with the same version. Only ``distro-a``
contains the reviewed patch. The attestation identifies reviewed builds by
content hash, so the SONAME and version being equal does not decide anything.

Observed results (``coverage-distro-a.json`` / ``coverage-distro-b.json``)::

  distro-a  libffi.so.5  external  approved  distro-a-patched  passed=true
  distro-b  libffi.so.5  external  rejected  distro-b-unpatched  passed=false

``distro-b`` is listed as ``reviewed: false``; selecting it stops
``auditwheel repair`` before anything is copied.

Reproduce with the bundled cffi wheel (absolute paths matter for ``--ldpaths``)::

  auditwheel show --json \
      --patch-attestation examples/patch-attestation/attestation.json \
      --patch-report /tmp/coverage.json \
      --ldpaths "$PWD/examples/patch-attestation/distro-a" \
      "$PWD/tests/bundled-wheels/cffi-1.5.0-cp27-none-linux_x86_64.whl"

Swap ``distro-a`` for ``distro-b`` to see the blocked result (exit code 1).

Backport case
-------------

The distro-b build is a different content hash, so with the current
attestation it is rejected. To approve it as a backport, replace its candidate
with::

  {
    "id": "distro-b-backport",
    "path": "distro-b/libffi.so.5",
    "sha256": "6242b1c3d116736bde1d8e9e1c15fb10af1f14ca0134161d82aa7d38300dd1a3",
    "backport": true,
    "patch": "CVE-2026-0001",
    "ext_version": "3.4.2",
    "upstream_version": "3.4.2"
  }

The version is intentionally unchanged. The verdict becomes
``approved-backport`` only because ``backport`` and ``patch`` are explicit.
Without ``"backport": true`` a candidate that carries a ``patch`` and keeps
the version is reported as ``stale``, not approved.

The two sample files are copies of the offline fixtures; the larger one has a
trailing byte appended to simulate a different distro build.
