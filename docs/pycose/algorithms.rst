COSE Algorithms
===============

Overview
--------

All :class:`~pycose.algorithms.CoseAlgorithm` have a `fullname` and `identifier` attribute. Both attributes can be used in
COSE headers and COSE keys.

.. doctest::
    :pyversion: >= 3.6

    >>> from pycose.messages import Enc0Message
    >>> from pycose.algorithms import A128GCM

    >>> msg1 = Enc0Message(phdr={'ALG': A128GCM})
    >>> msg2 = Enc0Message(phdr={'ALG': 'A128GCM'})
    >>> msg3 = Enc0Message(phdr={'ALG': 1})

    >>> # encoded protected header
    >>> msg1.phdr_encoded
    b'\xa1\x01\x01'

    >>> msg1.phdr_encoded == msg2.phdr_encoded == msg3.phdr_encoded
    True

The full list with COSE algorithms and their identifiers can be found at the
`IANA registry <https://www.iana.org/assignments/cose/cose.xhtml>`_

AES-CCM
-------

Each AES-CCM algorithm number binds its own CCM parameters, as listed in
RFC 9053, Section 4.2, Table 6. ``ccm_L`` is the CCM length field size in
bits, ``ccm_M`` is the authentication tag size in bits, and
``ccm_key_length`` is the AES key size in bits. The nonce length is derived
from L (``15 - L/8`` bytes), and the message length limit is ``2^L - 1``
bytes.

.. list-table::
    :header-rows: 1

    * - Algorithm
      - Identifier
      - L (bits)
      - M (bits)
      - Key (bits)
      - Nonce (bytes)
    * - ``AES_CCM_16_64_128``
      - 10
      - 16
      - 64
      - 128
      - 13
    * - ``AES_CCM_16_64_256``
      - 11
      - 16
      - 64
      - 256
      - 13
    * - ``AES_CCM_64_64_128``
      - 12
      - 64
      - 64
      - 128
      - 7
    * - ``AES_CCM_64_64_256``
      - 13
      - 64
      - 64
      - 256
      - 7
    * - ``AES_CCM_16_128_128``
      - 30
      - 16
      - 128
      - 128
      - 13
    * - ``AES_CCM_16_128_256``
      - 31
      - 16
      - 128
      - 256
      - 13
    * - ``AES_CCM_64_128_128``
      - 32
      - 64
      - 128
      - 128
      - 7
    * - ``AES_CCM_64_128_256``
      - 33
      - 64
      - 128
      - 256
      - 7

A key, nonce, or message length that does not match the selected algorithm
number is rejected with :class:`~pycose.exceptions.CoseInvalidParameter`
before the AES-CCM backend is called. Authentication failures, including
truncated tags, raise :class:`~pycose.exceptions.CoseInvalidTag`; decryption
never returns unauthenticated plaintext.

API
---

.. module:: pycose.algorithms

.. autoclass:: Shake256

.. autoclass:: Sha512

.. autoclass:: Sha384

.. autoclass:: Es512
    :members: get_hash_func, get_curve

.. autoclass:: Es384
    :members: get_hash_func, get_curve

.. autoclass:: EcdhSsA256KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhSsA192KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhSsA128KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhEsA256KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhEsA192KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhEsA128KW
    :members: get_hash_func, get_key_wrap_func, get_key_length
