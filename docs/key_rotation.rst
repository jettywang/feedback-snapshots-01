.. _key_rotation:

Signing key rotation
====================

Simple JWT ships with an explicit signing key lifecycle in
``rest_framework_simplejwt.key_rotation``. It lets you rotate the key used to
sign new tokens while keeping already-issued tokens verifiable for a bounded
transition window.

Key states
----------

Every named signing key (a :class:`~rest_framework_simplejwt.key_rotation.SigningKeyEntry`)
is in exactly one of three states:

* ``KeyStatus.ACTIVE``: the single key used to sign every newly issued token.
* ``KeyStatus.RETAINED``: a previous active key that is still trusted to verify
  historical tokens during the transition window.
* ``KeyStatus.RETIRED``: a key that no longer verifies anything. Tokens signed
  with it are rejected even when their signature is cryptographically valid.

Only one key may be active at a time. Activating a replacement automatically
moves the current active key into the retained state.

Defining a policy
-----------------

A :class:`~rest_framework_simplejwt.key_rotation.KeyRotationPolicy` is the single
source of truth shared by issuing and verification. A
:class:`~rest_framework_simplejwt.key_rotation.RotatingTokenBackend` delegates
both operations to that policy::

    from rest_framework_simplejwt import state
    from rest_framework_simplejwt.key_rotation import (
        KeyRotationPolicy,
        KeyStatus,
        RotatingTokenBackend,
        SigningKeyEntry,
    )

    policy = KeyRotationPolicy(
        SigningKeyEntry("old", old_secret, KeyStatus.ACTIVE),
        SigningKeyEntry("new", new_secret, KeyStatus.RETIRED),
    )
    state.token_backend = RotatingTokenBackend(policy, "HS256")

For asymmetric algorithms, pass the private key as ``signing_key`` and the
matching public key as ``verifying_key``.

Performing a rotation
---------------------

::

    # 1. Promote the new key. The old key becomes retained automatically.
    policy.activate("new")

    # 2. Wait for the transition window to pass, then close it.
    policy.retire("old")

During the window, new tokens are signed by the active key and carry its ``kid``
in the JWT header, while tokens signed by the retained key remain verifiable.
After ``retire`` the old key is rejected outright. If a problem is discovered
during the window, ``activate("old")`` rolls back.

Verification follows real signatures
------------------------------------

The ``kid`` header is only a hint. A token is accepted only after a real
signature check against an active or retained key. A token whose header names a
retired or unknown key, or whose claimed ``kid`` does not match its actual
signing key, is never trusted on the identifier alone.

Because issue, refresh and verify all consult the same policy object, a refresh
that happens across a rotation point produces a token signed by the then-active
key while the historical refresh token is still accepted under the same policy.
