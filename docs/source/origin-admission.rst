Per-Stream Origin Admission
===========================

An HTTP/2 connection is multiplexed: many independent request streams share
one TCP and TLS connection, and each stream may target a different
``:authority``. The authorization established for the first request on a
connection must therefore never be silently reused for the other streams on
that connection. Origin admission has to be evaluated **per stream**.

The :mod:`h2.origin_admission` package provides a small, stateful adapter that
performs this evaluation. It deliberately stays outside the protocol state
machine: the caller supplies both the trusted TLS connection information and
the application allow set for the authenticated caller, and feeds the adapter
decoded request and trailer header blocks (or the corresponding h2 events).

Two distinct conditions
-----------------------

For every request the adapter computes an :rfc:`6454` origin from the
``:scheme`` pseudo-header and the ``:authority`` (or ``Host``) header, split
into ``scheme``, ``host`` and ``port``. Default ports are normalized
(``https`` -> 443, ``http`` -> 80), and two origins only compare equal when all
three components match. It then checks two independent conditions:

1. **Certificate name coverage** -- do the DNS names and IP addresses of the
   trusted certificate presented on this TLS connection cover the requested
   host? Wildcard DNS names match a single left-most label only, and never an
   IP literal. This is a property of the *connection*.
2. **Caller access** -- is the computed origin in the application allow set
   for the caller authenticated on this connection? This is a property of the
   *caller* and the *stream*.

Certificate coverage never implies access permission. A host that appears on
the certificate but is absent from the allow set is rejected with
``403 Forbidden`` and is never dispatched.

Rejection reasons and status codes
-----------------------------------

Rejections are returned as data (an :class:`~h2.origin_admission.AdmissionDecision`)
rather than raised, so one bad stream cannot tear down the shared connection.

* malformed ``:authority``/``Host``, missing or duplicated pseudo-headers, an
  invalid scheme, or an ``:authority``/``Host`` conflict -> ``400``;
* a host the trusted certificate does not cover -> ``421 Misdirected Request``;
* a certificate-covered origin outside the caller's allow set -> ``403``.

Rejecting a stream only records that stream's decision; the identities fixed
for the other multiplexed streams are untouched.

Trailers cannot rewrite an origin
---------------------------------

The origin of a stream is fixed when its request headers are admitted. A
trailer block carrying a pseudo-header (including ``:authority``) or a ``Host``
header is rejected with ``400``; ordinary trailers are accepted and leave the
recorded origin unchanged. Every decision is appended to an immutable audit
trail, so any request that reaches a business handler can be traced back to
the exact admission result for its own stream.

Example
-------

.. code-block:: python

    from h2.origin_admission import (
        Origin, OriginAdmissionAdapter, TLSCertificateInfo,
    )

    # Names extracted from the already-verified leaf certificate.
    certificate = TLSCertificateInfo.create(
        dns_names=["api.example.com", "cdn.example.com", "shared-cert.example.net"],
    )

    # The allow set for the caller authenticated on this connection.
    allowed = {
        Origin("https", "api.example.com", 443),
        Origin("https", "cdn.example.com", 443),
    }

    adapter = OriginAdmissionAdapter(certificate, allowed)

    for event in connection.receive_data(data):
        if isinstance(event, h2.events.RequestReceived):
            decision = adapter.admit_request_event(event)
            if not decision.allowed:
                respond(event.stream_id, decision.status_code)
            else:
                dispatch(event.stream_id, decision.origin)
        elif isinstance(event, h2.events.TrailersReceived):
            adapter.inspect_trailer_event(event)

A runnable, socket-free demonstration that interleaves two allowed origins and
one certificate-covered but unauthorized origin on a single connection lives
at ``examples/origin_admission_demo.py``.

API reference
-------------

.. automodule:: h2.origin_admission
   :members:
   :member-order: bysource
