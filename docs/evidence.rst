.. _evidence-chapter:

=============================
Exporting CSP Policy Evidence
=============================

When a CSP configuration needs to be reviewed outside your organization, you may need to share how
each directive was decided without disclosing internal hostnames, runtime nonces, or other values
that appear only in code.

The ``csp.evidence`` module produces two complementary exports from the same request and response:

* A **public report** containing directive names, policy modes (enforced or report-only), how each
  directive was decided, and every source. Private-network sources and runtime-generated values are
  replaced by keyed identifiers.
* An **internal receipt** containing the values behind those identifiers, the exact policy strings,
  and the response headers that were observed.

The export is read-only: it does not write headers, generate a nonce, or modify the response.

Public report
=============

.. code-block:: python

    from csp.evidence import export_policy_evidence


    def review_view(request):
        response = render(...)
        evidence = export_policy_evidence(request, response)
        return JsonResponse(evidence.public)

Each directive entry records:

``directive`` and ``mode``
    The directive name and whether it belongs to the enforced or report-only policy.

``from_approved_settings``
    ``True`` when the directive comes directly from the policy settings.

``changed``, ``change_source``, and ``change_sources``
    Whether a view decorator changed the directive, and which decorator (``csp``,
    ``csp_replace``, or ``csp_update``) supplied it.

``present`` and ``removed``
    Whether the directive is in the delivered policy. A ``csp_replace`` that sets a directive to
    ``None`` is still listed, with ``removed: true``, so reviewers can see that a decision changed.

``basis``
    The setting name, whether the value came from settings, a default, or a view, and a
    human-readable description of the decision.

``sources``
    Each source with its ``kind`` and ``origin``. Private-network sources are marked
    ``redacted: true`` and show an ``hmac-sha256:...`` identifier instead of the hostname.
    ``NONCE`` sources are reported as ``dynamic-nonce``; if the nonce had not been generated when
    the evidence was exported, the entry shows ``available: false`` and no value.

Each policy also includes ``policy_redacted``, the policy string with the same replacements applied.

Internal receipt
================

.. code-block:: python

    evidence = export_policy_evidence(request, response)
    store_internal_receipt(evidence.receipt)

The receipt includes the unredacted policy strings and response headers, plus a ``redactions`` list
mapping each public marker to its original value, directive, mode, and origin. It also contains
``public_report_fingerprint``, a keyed fingerprint of the public report against which a copy can be
checked.

Fingerprints use the Django ``SECRET_KEY`` by default. Pass ``key=...`` to use a dedicated review
key instead. The same key and value always produce the same identifier, so a reviewer can confirm
that two reports refer to the same private value without learning what it is.

Identifying site-specific internal names
========================================

Loopback, private, link-local, and reserved IP addresses, single-label hostnames, ``.localhost``,
and common internal domains such as ``.internal``, ``.intranet``, ``.local``, and ``.corp`` are
treated as private automatically. If your site uses another internal naming convention, pass it
explicitly:

.. code-block:: python

    evidence = export_policy_evidence(
        request,
        response,
        private_hosts=["api.prod.example"],
        private_suffixes=[".example.internal"],
    )

Use the same middleware class as your project when it customizes the policy. For example:

.. code-block:: python

    from csp.contrib.rate_limiting import RateLimitedCSPMiddleware
    from csp.evidence import export_policy_evidence

    evidence = export_policy_evidence(request, response, middleware=RateLimitedCSPMiddleware())

.. warning::

    The public report is designed to be shareable, but redaction depends on recognizing private
    values. Review the generated report before sending it, and add site-specific ``private_hosts``
    or ``private_suffixes`` for any internal names the detector cannot infer. Never send the
    internal receipt outside the organization.
