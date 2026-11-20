KV v2 Retention Inventory
=========================

:py:class:`hvac.api.secrets_engines.kv_v2_retention.KvV2RetentionAuditor`

This helper produces a minimal inventory of KV v2 versions that still exist.  It
only calls ``read_secret_metadata`` for explicit paths and, when using
``audit_mount``, ``list_secrets`` for metadata path discovery.  It never calls
``read_secret`` or ``read_secret_version``, so a Vault policy only needs
``read`` on ``{mount_point}/metadata/*`` and, for discovery, ``list`` on the same
metadata prefix.

The ``mount_point`` parameter follows the same convention as the rest of
:py:class:`hvac.api.secrets_engines.KvV2`; it defaults to ``secret``.

.. code:: python

    import hvac
    from hvac.api.secrets_engines.kv_v2_retention import (
        KvV2RetentionAuditor,
        RetentionPolicy,
    )

    client = hvac.Client()
    auditor = KvV2RetentionAuditor(
        client=client,
        mount_point="team-kv",
        policy=RetentionPolicy(max_versions=5),
        approved_custom_metadata_keys=["owner"],
    )

    report = auditor.audit(["apps/payments/config", "apps/search/config"])
    print(report.inventory)
    print(report.unverifiable)

Discover every secret under the mount using metadata LIST calls only:

.. code:: python

    report = auditor.audit_mount("apps")

Classify each version from its metadata as ``accessible``, ``soft_deleted``, or
``destroyed``.  A metadata shape that cannot be verified safely is reported as
``unverifiable`` with a specific reason instead of being silently included or
excluded.  Path-level failures retain distinct statuses for ``forbidden``,
``unauthorized``, ``not_found``, ``invalid_request``, ``vault_error``,
``malformed_metadata``, and ``unexpected_error``; mount discovery uses
separate ``list_*`` statuses for the same cases.

Custom metadata is excluded by default.  The only custom metadata values that
can appear in ``report.to_dict()`` are keys explicitly passed through
``approved_custom_metadata_keys``; everything else is discarded before the
report is assembled.
