=============================
endpoint_audit - cold-start listening-range review
=============================

This package answers one deployment-review question without ever starting a
service: **which network addresses does each Twisted endpoint description
actually cover, and do any two services claim intersecting ranges?**

It is a pure static analysis tool. It never calls ``listen()``, never binds a
socket, never resolves a hostname and never opens a TLS private key.

Why not ``serverFromString``?
=============================

Twisted's built-in string parsers are unsafe for a cold review machine:

* ``ssl:`` and ``tls:`` parsers read PEM private key material *during
  parsing* (``_parseSSL`` / ``_TLSServerEndpointParser``);
* a parsed endpoint is one ``listen()`` call away from binding a port.

``endpoint_audit`` instead re-implements only the address-relevant part of
the strports grammar. The tokenizer is cross-checked byte-for-byte against
``twisted.internet.endpoints._parse`` in the test suite.

Address rules (shared by tcp, tls/ssl and haproxy)
==================================================

``tcp`` / ``ssl`` construct an IPv4 endpoint; ``tcp6`` / ``tls`` construct an
IPv6 endpoint. The wrapper layer (TLS certificate options, HAProxy PROXY
options) carries no address information, so ``tcp:8080``,
``ssl:8080:privateKey=...`` and ``haproxy:tcp:8080`` resolve to the *same*
listening range. Wrapper names are recorded on the entry but excluded from
comparison.

* No ``interface``: wildcard of the scheme family (``0.0.0.0`` for tcp/ssl,
  ``::`` for tcp6/tls).
* IP literal: a concrete binding; a literal whose family disagrees with the
  scheme raises a ``FAMILY_MISMATCH`` issue while keeping the scheme family.
* Hostname: resolution happens at runtime, so the range stays uncertain.
* Port 0: the OS chooses the port at runtime, so the range stays uncertain.
* ``unix:`` ranges are compared by socket path and can never overlap IP
  ranges.

Unknown schemes and runtime-only plugins
========================================

A scheme with no static rule (for example a custom runtime plugin) is kept
**uncertain** and flagged ``UNKNOWN_SCHEME`` - the tool never guesses.

A plugin may *voluntarily* ship a side-effect-free discloser module exposing::

    prefix = "metricsd"

    def disclose(args, kwargs):
        # inspect description text only; no reactor, socket or key file
        return Disclosure(family=..., host=..., port=...)

Register it with ``--extension module.name`` (or
``DiscloserRegistry.load_module``). Returning ``None`` keeps the uncertainty.

Verdict categories
==================

Every service pair lands in exactly one bucket:

* **CONFIRMED OVERLAP** - the ranges provably share an address (same port,
  same family, intersecting hosts; a wildcard contains every concrete host).
* **CONFIRMED SEPARATE** - provably disjoint, e.g. different ports, different
  concrete addresses of the same family, or unix vs IP.
* **NEEDS REVIEW (uncertain)** - hostname bindings, port 0, unknown schemes,
  or IPv4/IPv6 cross-family pairs (dual-stack ``IPV6_V6ONLY`` behaviour is a
  runtime property). Address-family ambiguity is never collapsed into a
  definite answer.

Every entry and every issue carries a ``SourceCoordinate`` (file, line,
service) so any finding can be traced back to the original declaration.

Usage
=====

Text manifest (``#`` comments, one ``service  endpoint`` per line) or JSON
(``[{"service": ..., "endpoint": ..., "line": ...}]``, ``.json`` suffix)::

    python -m endpoint_audit.cli examples/services.manifest \
        --extension examples.runtime_plugin
    python -m endpoint_audit.cli examples/services.json --json
    python -m endpoint_audit.cli manifest --only-conflicts

Exit codes: ``0`` clean, ``1`` malformed manifest/declaration, ``2`` at least
one confirmed overlap. Uncertain pairs alone do not fail the run but are
listed for manual review.

Tests
=====

::

    python -m unittest discover -s endpoint_audit/test

``test_safety`` replaces socket, bind, listen, DNS and file-open primitives
with blockers while running the whole pipeline, proving no sample can bind,
listen, resolve names or read key files. ``test_twisted_crosscheck`` builds
real Twisted endpoint objects (constructors only - never ``listen``, never
the key-reading string parsers) and asserts the static ranges match their
stored address fields.
