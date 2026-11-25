mTLS channel diagnostics (Requests transport)
=============================================

This page explains which layer owns the client certificate when
:class:`google.auth.transport.requests.AuthorizedSession` is used, and gives an
offline procedure for telling a real mTLS channel from a plain HTTPS one.

Three layers that must not be confused
--------------------------------------

``AuthorizedSession`` has two independent HTTP paths.

Business sends
   ``AuthorizedSession.request()`` calls ``requests.Session.request()`` on the
   session itself.  Adapter selection is therefore determined by
   ``AuthorizedSession.adapters``.  ``configure_mtls_channel()`` mounts a
   ``_MutualTlsAdapter`` at the ``https://`` prefix, and that adapter is the
   layer that actually owns the certificate and private key for business
   sends.

Credential refreshes
   ``AuthorizedSession`` creates ``_auth_request_session = requests.Session()``
   unless an ``auth_request`` is passed in.  That private session gets its own
   ``HTTPAdapter(max_retries=3)`` at ``https://``.  ``credentials.refresh()``
   and ``credentials.before_request()`` receive ``self._auth_request``, which
   wraps the private session.  Token refreshes therefore do not use the mTLS
   adapter, even after mTLS is configured.

The ``is_mtls`` flag
   ``AuthorizedSession.is_mtls`` is only a boolean snapshot written by
   ``configure_mtls_channel()``.  It is not derived from the mounted adapter.
   It can disagree with the channel after a failed reconfiguration or after the
   environment switch is changed on a live session.

Certificate selection on the 401 path
-------------------------------------

On a 401, ``AuthorizedSession.request()`` does two independent things:

1. If ``is_mtls`` is true, it calls
   ``_mtls_helper.check_parameters_for_unauthorized_response()``.  That helper
   calls ``call_client_cert_callback()``, which reads the *default* certificate
   source.  It does not replay the callback originally passed to
   ``configure_mtls_channel()``.
2. It compares the cached certificate fingerprint with the fingerprint of the
   certificate just read.  If they differ, it calls
   ``configure_mtls_channel(lambda: (new_cert, new_key))`` and mounts a new
   ``_MutualTlsAdapter`` at ``https://``.

This means the first business send and the post-401 retry can legitimately use
different certificates when the original callback and the default source
return different material.  The second send uses the newly mounted adapter;
the refresh request still uses the private ``_auth_request_session``.

Adapter precedence
------------------

``requests.Session.get_adapter()`` chooses the longest matching prefix.  A
global ``https://`` mount from ``configure_mtls_channel()`` does not override an
application mount for a longer prefix such as a full URL or a host-specific
``https://api.example.com``.  Always check the adapter returned for the exact
business URL rather than assuming the latest mount is in effect.

Offline matrix
--------------

``tests/transport/test_mtls_channel_diagnostics.py`` is an offline test matrix.
It uses synthetic certificates and request doubles; no certificate files,
network access, or real credentials are needed.  The matrix covers:

===============================================  ==========================================================
Scenario                                          Evidence that is asserted
===============================================  ==========================================================
Switch unset / ``false`` / empty                  Certificate callback is never called; plain adapter sends
Certificate config present, switch absent          Channel is enabled and the mTLS adapter owns business sends
Initial load                                       Business send carries certificate A; refresh session untouched
First request already stale                        Refresh POST goes to ``_auth_request_session``, not business adapter
401 with changed certificate                       Post-401 send uses certificate B from the default source
401 with unchanged certificate                     Adapter identity and certificate identity stay on A
Switch turned off before the 401                    A is retained; no new adapter is mounted
401 while ``is_mtls`` is false                      No certificate comparison at all; refresh still happens
Initial load failure in the certificate source      Plain adapter remains the business channel
Initial adapter construction failure                ``is_mtls`` is true while the plain adapter still sends
401 reconfiguration failure                         A remains mounted and credential refresh is skipped
Initial certificate read failure on 401             Error propagates; A remains mounted; no refresh
Default source missing on 401                       TypeError before refresh; A remains mounted
Live switch changed from true to false              Flag says false while the old mTLS adapter still sends
URL-specific application adapter                     It wins over the global mTLS ``https://`` mount
Refresh session adapter                             Plain ``HTTPAdapter`` with retries, distinct from business
401 without mTLS                                    Plain adapter sends twice; refresh uses private session
403                                                 Neither certificate check nor refresh happens
===============================================  ==========================================================

Run it with::

    pytest tests/transport/test_mtls_channel_diagnostics.py

Blind spots of single-signal checks
-----------------------------------

``is_mtls`` alone
   It can be true after ``_MutualTlsAdapter`` construction failed, and it can be
   false while an older mTLS adapter is still mounted and still handling
   traffic.  It says what the last configuration attempt intended, not which
   adapter requests will use.

Session configuration alone
   ``configure_mtls_channel()`` can succeed and mount an adapter that a longer
   URL-specific mount later shadows.  It can also be a no-op when
   ``GOOGLE_API_USE_CLIENT_CERTIFICATE`` is ``false``, including when the flag
   used to be true earlier in the process.

The final 401 alone
   A 401 proves only that the server rejected the request.  It does not say
   whether a client certificate was presented, which certificate was presented,
   or whether the retry was sent on a different connection.  The 401 path may
   even be skipped when ``is_mtls`` is false.

Where operations can confirm the real channel
---------------------------------------------

1. Reproduce with the offline matrix to establish the expected adapter and
   certificate for the exact business URL.
2. In the failing process, inspect ``session.get_adapter(business_url)``.  This
   is the layer that owns the certificate for business sends.  Confirm the
   adapter type and instance identity; a ``_MutualTlsAdapter`` carries two
   private SSL contexts (``_ctx_poolmanager`` and ``_ctx_proxymanager``) that
   were built from the certificate and key at mount time.  The SSL contexts
   are not introspectable for the certificate, so correlate the adapter
   instance with the ``_cached_cert`` bytes recorded when it was mounted, or
   compare the peer certificate observed at the network boundary.
3. Compare the ``session._cached_cert`` fingerprint with the certificate read
   by the default source.  A difference is normal before the post-401
   reconfiguration and is the signal that certificate rotation occurred.
4. Trace the refresh path separately: ``session._auth_request.session`` should
   be the private ``_auth_request_session``, not the business session.  A token
   refresh appearing on the business adapter indicates a custom
   ``auth_request`` was supplied.
5. Inspect ``session.adapters`` for a longer prefix that could shadow the
   global ``https://`` mTLS mount.
