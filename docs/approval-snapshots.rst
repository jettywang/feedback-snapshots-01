Approval snapshots
==================

Internal approval workflows can capture an allow-listed, immutable snapshot of
any :class:`gitlab.base.RESTObject`. The original object is not changed:
one-time values remain available through the normal python-gitlab API, while
the exported approval document contains only fields named by the caller.

Each exported field records its provenance:

* ``server``: present in the server-confirmed ``_attrs`` mapping.
* ``pending``: present in the uncommitted ``_updated_attrs`` mapping.
* ``parent``: supplied by the manager's parent context.

The document also contains a stable ``state_id`` digest for the complete
captured object state. Later local edits, successful refreshes, failed refresh
attempts, or :meth:`~gitlab.base.RESTObject.discard_updates` calls do not alter
an existing snapshot.

.. code-block:: python

    allowed = ("id", "name", "project_id", "configuration")
    snapshot = project_token.approval_snapshot(allowed)

    approval_document = snapshot.read()
    audit_log_entry = snapshot.to_json()

    # The current business object remains fully usable through its usual API.
    project_token.rotate()

Dotted field names can project nested values:

.. code-block:: python

    document = project_token.safe_export(
        ("name", "project_id", "configuration.nested.enabled")
    )

.. automodule:: gitlab.snapshots
   :members:
   :show-inheritance:
