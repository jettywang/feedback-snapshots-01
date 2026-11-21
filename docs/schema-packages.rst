===============
Schema Packages
===============

The `Registry` object is a useful way to ship Python packages which essentially bundle a set of JSON Schemas for use at runtime from Python.

In order to do so, you likely will want to:

* Collect together the JSON files you wish to ship
* Put them inside a Python package (one you possibly tag with the ``jsonschema`` keyword for easy discoverability).
  Remember to ensure you have configured your build tool to include the JSON files in your built package distribution -- for e.g. :hatch:`hatch </>` this is likely automatic, but for `setuptools <setuptools:index>` may involve creating a suitable :file:`MANIFEST.in`.
* Instantiate a `Registry` object somewhere globally within the package
* Call `Registry.crawl` at import-time, such that users of your package get a "fully ready" registry to use

For an example of such a package, see `jsonschema-specifications <jsonschema-specifications:index>`, which bundles the JSON Schema "official" schemas for use.

Replacing Packages
------------------

A package which ships schemas may itself be retired, or may need to be swapped for a newer version at runtime without restarting the process.
Registering resources one at a time is not enough in that case: crawling a package's roots may discover nested resources identified by their own IDs (e.g. by an :kw:`$id` in a subschema), and those derived resources have to be withdrawn together with the package's roots.

`Registry.with_package` registers a named package and records exactly which resources it contributed -- including those discovered by crawling.
`Registry.replace` then withdraws that entire snapshot and registers a replacement under the same name:

.. testcode::

    from referencing import Registry, Specification

    specification = Specification(
        name="ids",
        id_of=lambda contents: contents.get("ID"),
        subresources_of=lambda contents: contents.get("children", []),
        anchors_in=lambda specification, contents: [],
        maybe_in_subresource=lambda segments, resolver, subresource: resolver,
    )

    old = specification.create_resource(
        {
            "ID": "urn:example:package",
            "children": [{"ID": "urn:example:package:old"}],
        },
    )
    registry = Registry().with_package("example", [old])
    print(sorted(registry))

.. testoutput::

    ['urn:example:package', 'urn:example:package:old']

Replacing the package removes both the root and its derived nested resource:

.. testcode::

    new = specification.create_resource(
        {
            "ID": "urn:example:package",
            "children": [{"ID": "urn:example:package:new"}],
        },
    )
    replaced = registry.replace("example", [new])
    print(sorted(replaced))

.. testoutput::

    ['urn:example:package', 'urn:example:package:new']

Because registries are immutable, the original ``registry`` (and any `Resolver` constructed from it) is a snapshot which continues to resolve references as it did before the replacement.
Code creating a new resolver from ``replaced`` sees the replacement's resources and anchors.

Shared dependencies are not withdrawn.
If a resource is also provided by the base registry, or is used by another registered package, `Registry.replace` leaves it in place.
Withdrawn URIs are remembered as unavailable, so a ``retrieve`` callable will not silently bring a retired resource back into circulation; use `Registry.withdraw` to retire a package with no replacement at all.
