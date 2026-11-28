==========================
Scoped Portal Walkthrough
==========================

A self-contained ``twisted.cred`` example in which one ``Portal`` fronts two
application identity sources.  The same avatar ID may exist at both sources
with different capabilities, so checkers carry the proved *source* and
*scopes* into the realm instead of returning a bare avatar ID.

Flow
====

1. The caller presents credentials implementing one of the marker
   interfaces in ``interfaces.py`` (``IAppPasswordCredentials`` for the
   internal source, ``IAppTokenCredentials`` for the federated partner).
2. ``Portal.login`` routes them to the checker registered for that
   interface.  A successful check resolves to a ``ScopedIdentity``
   (``identity.py``) holding ``(source, avatarId, scopes)``.  ``Portal``
   passes that object unchanged to ``IRealm.requestAvatar``; no framework
   change is needed.
3. ``InMemoryScopedRealm`` (``realm.py``) walks the requested interfaces in
   order and grants the first whose required scope set is fully covered by
   *this credential check*.  Scope is never inferred from the avatar name or
   borrowed from another source.
4. Sessions are cached only after a grant, keyed by ``(source, avatarId)``.
   Rejected logins raise before any session exists, and checkers cache
   nothing, so a wrong query path cannot leave a reusable login result.
5. Checkers returning a plain ``bytes`` avatar ID still work: the realm
   wraps them in a legacy identity limited to ``ILegacyAvatar`` with no
   resource scopes.

The ``PendingCancellationChecker`` never resolves on its own and is used to
observe login cancellation (``Deferred.cancel`` -> ``CancelledError``).

Layout
======

- ``interfaces.py``  resource interfaces, scope tokens, credential markers
- ``identity.py``    ``ScopedIdentity`` value object and legacy wrapper
- ``checkers.py``    two synthetic source checkers + cancellation checker
- ``credentials.py`` concrete username/secret credential classes
- ``avatars.py``     per-session avatar and per-interface aspects
- ``realm.py``       in-memory scope-enforcing realm
- ``test/``          Trial tests covering success, denial and cancellation

Run
===

::

    .venv/bin/python -m twisted.trial scopedportal
    .venv/bin/python -m pytest -q -o addopts= scopedportal
