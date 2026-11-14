ecdsa.hkdf module
=================

Example of deriving separate, direction-specific traffic keys and explicit
key confirmation from an ECDH shared secret. It is built only on the standard
library :mod:`hashlib` and :mod:`hmac` modules (RFC 5869 HKDF) together with
the existing :class:`~ecdsa.ecdh.ECDH` class.

This module does **not** authenticate the peers. Both identities are assumed
to already be authenticated by a layer above, for example by validating a
certificate or a signature over the exchanged ephemeral public keys.

.. automodule:: ecdsa.hkdf
   :members:
   :undoc-members:
   :show-inheritance:

ecdsa.hkdf_handshake_demo module
================================

Runnable, in-memory demonstration. Start it with::

    python -m ecdsa.hkdf_handshake_demo

.. automodule:: ecdsa.hkdf_handshake_demo
   :members:
   :undoc-members:
   :show-inheritance:
