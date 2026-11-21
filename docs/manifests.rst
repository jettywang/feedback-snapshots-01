=================
Offline Manifests
=================

When resources are resolved in a production environment which has no network
access, it is useful to be able to state in advance exactly which
dependencies are allowed: both the identity each one is expected to declare
and the digest of the contents which may be used.

A `referencing.manifest.Manifest` records exactly that, and can verify a
`Registry` without retrieving anything. It can be built from a registry or
imported in bulk from local files, serialized to JSON for review, and checked
before deployment.

.. testcode::

    from referencing import Registry
    from referencing.manifest import Manifest

    contents = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.com/schema",
        "type": "object",
    }
    registry = Registry().with_contents(
        [("https://example.com/schema", contents)],
    )

    manifest = Manifest.from_registry(registry)
    verification = manifest.verify(registry)

    assert verification
    assert verification.registry is registry

Building a manifest
-------------------

`Manifest.from_registry` crawls a registry, recording an entry for each
resource (including subresources discovered via their declared identities).
This is the simplest way for a package which already ships a set of resources
to produce the manifest it will later be verified against.

Several local files can be imported in bulk instead. `Manifest.from_directory`
reads every matching JSON file, keys it by its absolute declared ``$id`` (or
legacy ``id``) when it has one, and otherwise by its path relative to the
directory. Its expected identity is the declared identity resolved against
that key -- i.e. exactly what a local cross-reference from a sibling file
would resolve to. `Manifest.from_files` does the same for an explicit list of
files. Files can be excluded with glob patterns, e.g. to leave out the
manifest's own serialized form.

Because identities are resolved relative to each other, a set of local files
which reference one another can be verified with no network access at all.
`Manifest.to_registry` imports the manifest's local files, and
`Manifest.verify` can be called with no argument to both import and check
them.

Serializing and importing
-------------------------

`Manifest.to_file` (or `Manifest.to_json`) serializes a manifest for review or
distribution, and `Manifest.from_file` imports it again. The JSON form is a
versioned object mapping each URI to the expected ``id`` and ``digest``:

.. code:: json

    {
      "version": 1,
      "resources": {
        "https://example.com/schema": {
          "id": "https://example.com/schema",
          "digest": "sha256:..."
        }
      }
    }

Entries may also be written as a bare digest string, or with the digest
nested as ``{"sha256": "..."}``. `Manifest.from_dict` and `Manifest.from_json`
are available when the data is already in memory.

What is checked
---------------

Verification checks each manifest entry independently:

* **Missing** -- the dependency is not present in the registry.
* **Content changed** -- its contents do not match the allowed digest.
* **Identity changed** -- it declares a different identity than expected.

A resource is normally looked up under the key the manifest recorded. If it
is gone from there, an unclaimed resource elsewhere whose contents still have
exactly the allowed digest is treated as the same dependency, so an identity
change which also moved a resource is still reported as an identity mismatch
rather than as a missing dependency.

The digest excludes the dependency's own top-level identity keyword. That is
what keeps the content and identity checks independent: changing only an
``$id`` is reported as an identity mismatch, changing anything else is
reported as a content mismatch, and doing both reports both.

Digests are computed over a canonical JSON serialization (sorted keys, no
insignificant whitespace), so harmless reformatting of the files does not
invalidate a manifest.

.. testcode::

    from referencing import Registry, Resource
    from referencing.manifest import VerificationKind

    changed = Resource.from_contents(dict(contents, type="integer"))
    registry = Registry().with_resource(
        "https://example.com/schema",
        changed,
    )

    verification = manifest.verify(registry)
    assert verification.kind == VerificationKind.CONTENT
    assert not verification

The result is available from `Verification`, whose `kind` is one of
``"ok"``, ``"content"``, ``"identity"``, ``"missing"`` or ``"multiple"``,
with the corresponding details in ``content_mismatches``,
``identity_mismatches`` and ``missing``. `Verification.raise_for_errors`
raises `VerificationError` (whose ``result`` attribute holds the full
result) when anything failed.

Verification never modifies the registry it inspects, and never consults any
retrieval function, so a rejected registry remains exactly as it was --
running your existing resolution again against it produces unchanged output.

Using a manifest at runtime
---------------------------

A manifest is callable, and `Manifest.retrieve` can be used as a `Registry`
retrieval function. Contents are checked before being returned, so a tampered
or incorrectly identified local file is rejected rather than used:

.. code:: python

    registry = Registry(retrieve=manifest)  # or retrieve=manifest.retrieve

For an offline deployment, `Manifest.to_registry` imports every local file
under its manifest URI, and `Manifest.verify` can then be used to check the
result before any resolution happens.
