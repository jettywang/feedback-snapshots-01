Remote identity and trust boundaries
====================================

``LogEntry.remote_addr`` and ``LogEntry.remote_port`` are often read as "the
client's IP and port". That reading is only valid for some deployment
topologies. This page records what the middleware actually reads, what each
topology can prove, and where a trust boundary has to be placed.

What the middleware reads
-------------------------

:py:class:`auditlog.middleware.AuditlogMiddleware` derives the values from two
places only:

``remote_addr``
    * ``AUDITLOG_DISABLE_REMOTE_ADDR=True`` -> ``None``.
    * No ``X-Forwarded-For`` header -> ``REMOTE_ADDR`` (the socket peer).
    * ``X-Forwarded-For`` present -> the **leftmost** comma-separated value,
      with a trailing port stripped (``x.x.x.x:port`` or ``[v6]:port``).

``remote_port``
    * ``X-Forwarded-Port`` only, parsed as an integer; anything non-numeric
      becomes ``None``.
    * ``REMOTE_PORT`` / the socket source port is never read.
    * There is no ``0..65535`` range check.

The middleware performs no proxy allow-listing, no hop counting, no header
sanitisation and no consistency check between the two headers. It also does
not strip whitespace, so a header value such as ``" 203.0.113.9"`` is stored
with the leading space on backends that do not validate the value.

Evidence
--------

The behaviour below is asserted in
``auditlog_tests/test_remote_identity.py``. Each case runs through the real
middleware and writes a real ``LogEntry``; no request has an authenticated
user, so ``actor`` is ``None`` in every row.

================================================  ================  ===========  ==========================
Request                                           stored addr       stored port  Notes
================================================  ================  ===========  ==========================
direct, no forwarding headers                     ``203.0.113.9``   ``NULL``     socket peer
direct, client sends ``X-Forwarded-For``          ``198.51.100.7``  ``NULL``     header wins over peer
one proxy, one ``X-Forwarded-For`` value          ``203.0.113.9``   ``51234``    proxy-asserted
two proxies, ``client, proxy1``                   ``203.0.113.9``   ``51234``    only if the edge sanitises
client pre-fills ``X-Forwarded-For``              ``1.2.3.4``       ``NULL``     leftmost is attacker input
``X-Forwarded-Port`` without ``X-Forwarded-For``  ``REMOTE_ADDR``   ``51234``    port trusted on its own
two hops, no ``X-Forwarded-Port``                 ``203.0.113.9``   ``NULL``     port is not inferred
``X-Forwarded-Port: not-a-port``                  ``203.0.113.9``   ``NULL``     silently dropped
``AUDITLOG_DISABLE_REMOTE_ADDR=True``             ``NULL``          ``51234``    port is still written
================================================  ================  ===========  ==========================

A few further edge cases are worth knowing:

* ``X-Forwarded-Port: -1`` passes ``int()`` and then fails the database
  ``CHECK`` constraint on ``PositiveIntegerField``. The exception propagates
  out of the audit write after the model row has been saved, so the change is
  persisted but its audit row is missing and the request returns 500. A client
  that can reach the app directly can therefore produce unaudited changes by
  sending this header; only a surrounding transaction would roll back the
  model write as well.
* ``X-Forwarded-Port: 70000`` is stored as-is on SQLite; the value is not a
  valid TCP port.
* A non-IP value such as ``X-Forwarded-For: unknown`` is passed through
  unchanged; validation is left to the database backend.

What each topology proves
-------------------------

Direct connection
    ``remote_addr`` proves the TCP peer of the application process, and only
    that. It does not prove the end-user device: an upstream NAT or a
    misconfigured proxy that does not add ``X-Forwarded-For`` still appears as
    the peer. ``remote_port`` is always ``NULL``, because the socket source
    port is never read.

One proxy with a sanitised header
    ``remote_addr`` proves what the proxy asserted, provided the application
    is reachable only from that proxy and the proxy overwrites (rather than
    appends to) any inbound ``X-Forwarded-For``. ``remote_port`` is the value
    the proxy put in ``X-Forwarded-Port``. The header name and the code do not
    define whether that is the client's source port or the destination port
    the client connected to; proxies commonly emit the destination port (for
    example ``443``). Do not use the value to match client-side NAT or
    firewall logs until you have confirmed the proxy's documented meaning.

Two trusted hops
    The middleware still returns the leftmost value. That is the client only
    when every proxy appends after stripping client-supplied headers. With
    plain append semantics the trustworthy value is the rightmost entry that
    is not a known proxy, walking from the right; the middleware does not do
    that. Adding one attacker-controlled prefix is enough to replace the
    recorded client with an arbitrary address.

Unknown provenance
    If the application accepts connections from more than the expected proxy
    range, or if any hop forwards a client-supplied ``X-Forwarded-For``, the
    stored value is "some address someone claimed". It is not evidence of the
    client, and it is not even evidence of the proxy, because the header can
    be set by the client when no proxy strips it.

Where to put the trust boundary
-------------------------------

Establish trust at the first component that terminates the client connection
(the edge load balancer or reverse proxy), not in Django and not in auditlog.
That component should:

1. Overwrite ``X-Forwarded-For`` with the single observed client address and
   strip any inbound copy, rather than appending to it.
2. Overwrite ``X-Forwarded-Port`` with a value whose meaning is documented
   (destination port or source port), and strip any inbound copy.
3. Strip or overwrite other identity headers (``Forwarded``, ``X-Real-IP``)
   so there is exactly one source of truth.
4. Reject or normalise values that are not valid IP addresses and ports.
5. Be the only network path to the application; enforce that with a firewall,
   security group or listener binding, not with application code.

If hop counting is unavoidable, add one normalisation middleware **before**
``AuditlogMiddleware``. It should parse ``X-Forwarded-For`` from the right,
skip an explicit list of trusted proxy CIDRs, write the resulting address to
``request.META["REMOTE_ADDR"]`` and remove the forwarding headers. This makes
the single trust decision visible and testable in one place. Do not rely on
the default leftmost behaviour for multi-hop paths.

The edge proxy should also keep its own access log with the raw headers and
the peer address. That log is the authoritative record; the audit row is a
convenience copy. Note that ``cid`` is read from a client-supplied header by
default, so it is only a reliable join key if the edge overwrites it too.

Reading historical rows
-----------------------

Older rows cannot be interpreted with today's rules. The relevant changes
are:

* ``remote_addr`` was added in 0.3.0 (2015-07). Rows older than that have no
  address at all.
* Before 3.0.0-beta.1 (2023-08-29, fix #484) the address was written only for
  authenticated users. Anonymous rows from that era have ``remote_addr``
  ``NULL`` even when the request had one.
* Before 2.2.1 (2022-11-28, fix #457) IPv6 values taken from
  ``X-Forwarded-For`` were cut at the first colon, so such rows can contain a
  truncated value such as ``2001`` instead of the full address.
* ``remote_port`` was added in 3.1.0 (2025-04-15). Every row written before
  that has ``NULL`` port; this includes rows where the connection had a port.
* ``cid`` was added in 3.0.0-beta.1 (2023-08-29) and ``actor_email`` in 3.1.0
  (2025-04-15); older rows cannot be joined to proxy logs through either
  field.

Consequently, for a row with ``remote_addr IS NULL`` you cannot tell whether
the address was disabled by ``AUDITLOG_DISABLE_REMOTE_ADDR``, absent from the
request, or never collected because the row predates the field or the
anonymous-request fix. For a row with ``remote_port IS NULL`` you cannot tell
whether the connection was direct, the proxy omitted the header, the value was
not numeric, or the row predates 3.1.0 (2025-04-15). Queries that need these
distinctions must also filter on ``timestamp`` against the deployment's
upgrade dates.

Audit-row interpretation policy
-------------------------------

Use the following wording when documenting or querying audit rows:

* ``remote_addr`` is one of: *socket peer* (no forwarding header), *proxy-
  asserted client* (sanitised forwarding header), or *unverified claim*
  (forwarding header of unknown provenance). Store which mode applied at
  write time in ``additional_data`` if the distinction matters.
* ``remote_port`` is never a client source port unless the proxy is explicitly
  configured that way; treat it as proxy metadata and leave it out of
  client-attribution queries.
* A missing value is not evidence of absence. Check the field's introduction
  date and the deployment's upgrade dates before drawing conclusions.
* Rows written before the edge normalisation was deployed are not
  retroactively trustworthy, even if their values look plausible.

Verification
------------

Run the diagnostics from the repository root::

    cd auditlog_tests
    ../.venv/bin/python manage.py test --noinput test_remote_identity

The test file is intentionally assertion-based rather than print-based so a
future change to the middleware shows up as a failing expectation.
