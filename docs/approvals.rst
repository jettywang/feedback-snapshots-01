.. _approvals-chapter:

=================================
Reviewing Policy Approvals
=================================

Some sources are allowed only because a named party approved them.  A partner CDN, for
example, may be permitted on one site, for one directive, on a specific set of pages, and
only in the enforced policy.  django-csp can keep those approvals next to the policy and
produce a review report that shows which approvals still hold after a policy change.

The approval layer is additive.  It does not change how headers are built or how the
decorators merge policies; ``CONTENT_SECURITY_POLICY`` and the decorators keep working
exactly as before.

Approval rows
=============

An approval binds four facts together:

* the **site** the approval applies to,
* the **directive** it permits,
* the **mode** (``enforce`` or ``report-only``), and
* the **source** tokens that were approved.

It can also be limited to one or more page prefixes.  An approval without a scope applies to
the whole site, but it never crosses a site or mode boundary.  Rows can be dictionaries, so
they can be loaded from a table or a CSV export:

.. code-block:: python

    CSP_POLICY_APPROVALS = [
        {
            "id": "AP-SHOP-IMG",
            "site": "shop.example",
            "directive": "img-src",
            "source": "cdn.partner.example",
            "mode": "enforce",
            "scope": ["/checkout/"],
        },
        {
            "id": "AP-SUPPORT-JS",
            "site": "support.example",
            "directive": "script-src",
            "source": "js.partner.example",
            "mode": "enforce",
        },
    ]

Page scopes are URL prefixes matched on path segment boundaries: ``/checkout/`` covers
``/checkout/thanks/`` but not ``/checkoutx``.

Capturing policy evidence
=========================

The middleware can capture what a page actually delivers, including a local override made
with ``@csp_update``, ``@csp_replace`` or ``@csp``.  The capture is read-only and records the
origin of each source (``settings`` or ``view``):

.. code-block:: python

    from csp.approvals import ApprovalRegistry
    from csp.middleware import CSPMiddleware

    registry = ApprovalRegistry.from_settings()
    middleware = CSPMiddleware(get_response)

    def view(request):
        response = render(request, "checkout.html")
        registry.record_snapshot(middleware.get_policy_snapshot(request, response))
        return response

The site identifier comes from ``request.csp_site`` when set, otherwise the
``CSP_POLICY_SITE`` setting, otherwise the request host.  Use ``request.csp_site`` when one
Django process serves several sites.

Reviewing the report
====================

``registry.review()`` returns a report.  Each approval gets one status:

``valid``
    Every captured page that the approval applies to still contains the approved source(s).

``needs_review``
    At least one applicable page no longer contains an approved source.  The page decision
    includes the missing sources and their original origin, which is the evidence for
    re-approval.

``pending``
    There is no usable evidence: no page was captured, the policy is not delivered on any
    captured page, or the capture is incomplete.

The report also lists **unapproved uses**: a controlled source that appears on a page in a
directive/mode combination without an approval covering that page.  Controlled sources are
the sources named by the approval table, or an explicit ``CSP_POLICY_MANAGED_SOURCES`` list.

.. code-block:: python

    report = registry.review()
    print(report.summary())
    audit_json = report.to_json()

    if report.needs_review:
        ...  # request re-approval for the affected pages

The report never widens a page-scoped approval: a source approved for ``/checkout/`` on
``shop.example`` in the enforced policy will not satisfy the same source on another page,
another site, or the report-only policy.

Deploy-time validation
======================

``CSP_POLICY_APPROVALS`` is validated by ``python manage.py check``.  Invalid rows produce
``csp.E003`` (table has the wrong shape) or ``csp.E004`` (a row is invalid or duplicated).
