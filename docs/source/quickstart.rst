===============
Getting started
===============

The library has just one mandatory dependency: ``six``.
If you install ``python-ecdsa`` through pip, it should automatically
install ``six`` too.

To install it you can run the following command:

.. code:: bash

    pip install ecdsa

The high level API provided by the library is primarily in the
:py:class:`~ecdsa.keys` module.
There you will find the :py:class:`~ecdsa.keys.SigningKey` (the class
that enables handling of the private keys) and the
:py:class:`~ecdsa.keys.VerifyingKey` (the class that enables handling of
the public keys).

To handle shared key derivation, the :py:class:`~ecdsa.ecdh.ECDH` class
is used.

Finally, in case use of custom elliptic curves is necessary, the
:py:class:`~ecdsa.curves.Curve` class may be needed.

Key generation
==============

To generate a key, import the :py:class:`~ecdsa.keys.SigningKey` and
call the :py:func:`~ecdsa.keys.SigningKey.generate` function in it:

.. code:: python

    from ecdsa.keys import SigningKey

    key = SigningKey.generate()

By default, that will create a key that uses the NIST P-192 curve. To
select a more secure curve, like NIST P-256, import it from the
:py:mod:`ecdsa.curves` or from the :py:mod:`ecdsa` module:

.. code:: python

    from ecdsa import SigningKey, NIST256p

    key = SigningKey.generate(curve=NIST256p)

Private key storage and retrieval
=================================

To store a key as string or file, you can serialise it using many formats,
in general we recommend the PKCS#8 PEM encoding.

If you have a :py:class:`~ecdsa.keys.SigningKey` object in ``key`` and
want to save it to a file like ``priv_key.pem`` you can run the following
code:

.. code:: python

    with open("priv_key.pem", "wb") as f:
        f.write(key.to_pem(format="pkcs8"))

.. warning::

    Not specifying the ``format=pkcs8`` will create a file that uses the legacy
    ``ssleay`` file format which is most commonly used by applications
    that use OpenSSL, as that was originally the only format supported by it.
    For a long time though OpenSSL supports the PKCS# 8 format too.

To read that file back, you can run code like this:

.. code:: python

    from ecdsa import SigningKey

    with open("priv_key.pem") as f:
        key = SigningKey.from_pem(f.read())

.. tip::

    As the format is self-describing, the parser will automatically detect
    if the provided file is in the ``ssleay`` or the ``pkcs8`` format
    and process it accordingly.

Public key derivation
=====================

To get the public key associated with the given private key, either
call the :py:func:`~ecdsa.keys.SigningKey.get_verifying_key` method or
access the ``verifying_key`` attribute in
:py:class:`~ecdsa.keys.SigningKey` directly:

.. code:: python

    from ecdsa import SigningKey, NIST256p

    private_key = SigningKey.generate(curve=NIST256p)

    public_key = private_key.verifying_key

Public key storage and retrieval
================================

Similarly to private keys, public keys can be stored in files:

.. code:: python

    from ecdsa import SigningKey

    private_key = SigningKey.generate()

    public_key = private_key.verifying_key

    with open("pub_key.pem", "wb") as f:
        f.write(public_key.to_pem())

And read from files:

.. code:: python

    from ecdsa import VerifyingKey

    with open("pub_key.pem") as f:
        public_key = VerifyingKey.from_pem(f.read())

Signing
=======

To sign a byte string stored in variable ``message`` using SigningKey in
``private_key``, SHA-256, get a signature in the DER format and save it to a
file, you can use the following code:

.. code:: python

    from hashlib import sha256
    from ecdsa.util import sigencode_der

    sig = private_key.sign_deterministic(
        message,
        hashfunc=sha256,
        sigencode=sigencode_der
    )

    with open("message.sig", "wb") as f:
        f.write(sig)

.. note::

    As cryptographic hashes (SHA-256, SHA3-256, etc.) operate on *bytes* not
    text strings, any text needs to be serialised into *bytes* before it can
    be signed. This is because encoding of string "text" results in very
    different bytes when it's encoded using UTF-8 and when it's encoded using
    UCS-2.

Verifying
=========

To verify a signature of a byte string in ``message`` using a VerifyingKey
in ``public_key``, SHA-256 and a DER signature in a ``message.sig`` file,
you can use the following code:

.. code:: python

    from hashlib import sha256
    from ecdsa import BadSignatureError
    from ecdsa.util import sigdecode_der

    with open("message.sig", "rb") as f:
        sig = f.read()

    try:
        ret = public_key.verify(sig, message, sha256, sigdecode=sigdecode_der)
        assert ret
        print("Valid signature")
    except BadSignatureError:
        print("Incorrect signature")

EdDSA modes (Ed25519, Ed25519ctx, Ed25519ph, Ed448, Ed448ph)
===========================================================

By default, EdDSA keys use PureEdDSA: ``sign()``, ``sign_deterministic()``
and ``verify()`` behave exactly as before and do not take a context.

RFC 8032 also defines a contextual mode (Ed25519ctx) and the prehashed
modes (Ed25519ph, Ed448ph). They must be selected explicitly with the
variants from :mod:`ecdsa.eddsa`; the library never guesses the mode from
the size of the message or of a digest.

.. code:: python

    from ecdsa import SigningKey
    from ecdsa.curves import Ed25519
    from ecdsa.eddsa import Ed25519ctx, Ed25519ph, Ed448ph

    private_key = SigningKey.generate(Ed25519)
    public_key = private_key.get_verifying_key()

    # contextual Ed25519: the context is part of the signed domain
    sig = private_key.sign_eddsa(message, Ed25519ctx, context=b"proto-1")
    assert public_key.verify_eddsa(sig, message, Ed25519ctx, b"proto-1")

    # prehashed Ed25519: the message is PH(M), not SHA-512(M) fed to Pure
    sig = private_key.sign_eddsa(message, Ed25519ph, context=b"proto-1")
    assert public_key.verify_eddsa(sig, message, Ed25519ph, b"proto-1")

Messages for the prehashed modes can be supplied in chunks. The returned
state is one-shot: after it is finalised it cannot be extended or reused.

.. code:: python

    state = private_key.eddsa_prehash(Ed25519ph)
    state.update(first_chunk)
    state.update(second_chunk)
    sig = state.sign(private_key, context=b"proto-1")

If a digest was computed elsewhere, sign it with ``sign_prehash``. That
method only accepts the prehashed variants and requires a 64-byte digest;
it never treats its input as a message:

.. code:: python

    from hashlib import sha512

    digest = sha512(message).digest()
    sig = private_key.sign_prehash(digest, Ed25519ph, context=b"proto-1")
    assert public_key.verify_prehash(sig, digest, Ed25519ph, b"proto-1")
