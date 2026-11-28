Patch coverage review
=====================

``auditwheel repair`` grafts shared libraries from the build host into the
wheel. When two distributions ship a library with the same SONAME, auditwheel's
``ldd``-style search picks whichever file the configured search order resolves
first. The name alone therefore says nothing about whether the selected build
contains the patch that was reviewed.

The patch coverage check records which concrete file auditwheel selected,
compares it with an offline attestation, and writes a report for release
review. The check runs *before* anything is copied into the wheel.

Attestation format
------------------

The attestation is a JSON document. Each SONAME lists the reviewed builds:

.. code-block:: json

   {
     "version": 1,
     "patches": [
       {
         "soname": "libfoo.so.1",
         "candidates": [
           {
             "id": "distro-a-patched",
             "path": "/srv/offline/distro-a/libfoo.so.1",
             "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
             "ext_version": "3.4.2",
             "upstream_version": "3.4.2"
           },
           {
             "id": "distro-b-backport",
             "path": "/srv/offline/distro-b/libfoo.so.1",
             "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
             "backport": true,
             "patch": "CVE-2026-0001",
             "ext_version": "3.4.2",
             "upstream_version": "3.4.2"
           }
         ]
       }
     ]
   }

Candidate fields:

``id``
    Stable identifier used in reports. Defaults to ``<soname>#<n>``.
``path``
    Path of the reviewed build, absolute or relative to the attestation file.
``sha256``
    Content hash of the reviewed build. Required for approval; without it the
    candidate can only be matched by path and the report says so.
``backport``
    Set to ``true`` when the reviewed patch was backported without changing the
    upstream version.
``patch``
    Patch or advisory identifier (for example a CVE). Required for backports.
``ext_version`` / ``upstream_version``
    Distribution version and the upstream version it is based on.

Rules
-----

- The selected file is approved only when it matches a reviewed candidate by
  path or by content hash.
- A matching path whose content hash differs is ``stale``: the build changed
  after review and must be reviewed again.
- A candidate with a ``patch`` and an unchanged version must be marked as a
  ``backport``. Otherwise the result is ``stale``; silently assuming "same
  version" is not enough.
- A backport must carry ``patch``, ``ext_version`` and ``upstream_version``,
  and both versions must be equal.
- SONAMEs that resolve to different files within one wheel are a ``conflict``.
- External (grafted) and already bundled libraries are reported with separate
  ``scope`` values: ``external`` and ``bundled``.
- When a SONAME is both required externally and already present in the wheel,
  the external entry carries ``shadowed: true``. At runtime the wheel copy wins,
  but the external entry is still checked so a reviewer can see the selection
  auditwheel would have grafted.

Commands
--------

Write a report before repairing:

.. code-block:: bash

   auditwheel show --patch-attestation attestation.json \
       --patch-report coverage.json \
       --require-patch-coverage \
       wheel.whl

Repair only the approved selection:

.. code-block:: bash

   auditwheel repair --patch-attestation attestation.json \
       --patch-report coverage.json \
       --require-patch-coverage \
       -w wheelhouse/ wheel.whl

Without ``--patch-attestation`` the commands behave as before. With an
attestation, any attested SONAME whose selected file is not approved stops the
command before a wheel is written. ``--require-patch-coverage`` additionally
fails when a grafted library has no attestation entry at all.

After writing the repaired wheel, auditwheel re-reads the archive and verifies
that each approved library that was grafted is present and still matches the
reviewed content. The report records this under ``repaired``.

The check keeps three hashes per grafted file: the approved source content,
the copy immediately after grafting (before auditwheel rewrites
SONAME/RPATH/NEEDED), and the final file. A grafted copy that does not match
the approved source fails even if the later hashes agree, so a corrupted or
substituted copy cannot pass as a legitimate ELF rewrite. A final file that
differs from the copy made just before packaging also fails. On failure the
output wheel is removed.

Report fields
-------------

.. code-block:: text

   version                  Report schema version.
   wheel                    Input wheel filename.
   policy                   Policy whose selection was evaluated.
   attestation              Attestation path.
   require_patch_coverage   Whether missing entries are fatal.
   coverage_complete        Whether every external library is attested.
   passed                   Whether the selection is allowed.
   summary                  Counts by verdict.
   libraries[]              One entry per selected SONAME and scope:
     soname, scope, functions, selected_path, selected_sha256,
     status (approved, approved-backport, unapproved, stale, rejected,
             unresolved, uncovered, conflict), accepted, reason,
     attested, shadowed, candidate {id, path, backport, ext_version,
                                    upstream_version, patch}
   repaired                 Post-packaging verification:
     passed, libraries[] {soname, scope, candidate_id, member, sha256,
                          modified, delivered, reason}
