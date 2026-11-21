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

Checking the size of a package's reference graph
================================================

When importing a package, the resources reachable from its entry points may be
shipped locally within the package, may already be present in a pre-populated
`Registry`, or may require dynamic (e.g. remote) retrieval.

If you are only willing to accept reference graphs up to some finite size, you
can check the full graph *before* any business validation runs, and learn up
front whether it fits within your budget. `referencing.budget.check_budget`
walks every resource reachable from one or more entry points, charges each
distinct resource a single time even when it is shared across entry points,
and returns a `~referencing.budget.BudgetReport` describing how the cost is
split across local, preinstalled, and externally retrieved resources.

.. testcode::

    from referencing import Registry
    from referencing.budget import (
        BudgetExceeded,
        check_budget,
        json_schema_references,
    )
    from referencing.jsonschema import DRAFT202012

    entry = DRAFT202012.create_resource(
        {"$id": "urn:entry", "$ref": "https://example.com/remote-schema"},
    )

    def retrieve(uri):  # A real retriever would fetch the URI.
        return DRAFT202012.create_resource({"$id": uri, "type": "object"})

    registry = Registry(retrieve=retrieve)
    try:
        report = check_budget(
            entries=[entry],
            registry=registry,
            budget=10,
            references_of=json_schema_references,
        )
    except BudgetExceeded as error:
        print(f"Refusing to import the package: {error}")
    else:
        print(
            report.total,
            len(report.local),
            len(report.preinstalled),
            len(report.external),
        )

.. testoutput::

    2 1 0 1

If walking the graph would exceed the budget, `~referencing.budget.BudgetExceeded`
is raised *before* the resource that would overflow the budget is retrieved, so
no further dynamic retrieval takes place. The exception carries the partial
`~referencing.budget.BudgetReport` built up to that point and the reference
which could not be accounted for.

