Classes
=======

.. py:currentmodule:: pgpy

:py:class:`PGPKey`
------------------

.. autoclass:: PGPKey
    :members:

    .. py:attribute:: ascii_headers
        :annotation:

        An :py:obj:`~collections.OrderedDict` of headers that appear, in order, in the ASCII-armored form of this object.

    .. py:classmethod:: from_file(filename)

        Create a new :py:obj:`PGPKey` object, with contents loaded from a file. May be binary or ASCII armored.

        :param filename: The path to the file to load.
        :type filename: ``str``
        :raises: :py:exc:`ValueError` if a properly formed PGP block was not found in the file at ``filename``
        :raises: :py:exc:`~exceptions.PGPError` if de-armoring or parsing failed
        :returns: A two element ``tuple`` of :py:obj:`PGPKey`, :py:obj:`~collections.OrderedDict`.
                  The :py:obj:`~collections.OrderedDict` has the following format::

                    key, others = PGPKey.from_file('path/to/keyfile')
                    # others: { (Fingerprint, bool(key.is_public)): PGPKey }

    .. py:classmethod:: from_blob(blob)

        Create a new :py:obj:`PGPKey` object, with contents loaded from a blob. May be binary or ASCII armored.

        :param blob: The data to load.
        :type blob: ``str``, ``bytes``, ``unicode``, ``bytearray``
        :raises: :py:exc:`TypeError` if blob is not in the expected types above
        :raises: :py:exc:`ValueError` if a properly formed PGP block was not found in ``blob``
        :raises: :py:exc:`~exceptions.PGPError` if de-armoring or parsing failed
        :returns: A two element ``tuple`` of :py:obj:`PGPKey`, :py:obj:`~collections.OrderedDict`.
                  The :py:obj:`~collections.OrderedDict` has the following format::

                    key, others = PGPKey.from_file('path/to/keyfile')
                    # others: { (Fingerprint, bool(key.is_public)): PGPKey }


:py:class:`PGPKeyring`
----------------------

.. autoclass:: PGPKeyring()
    :members:

    .. py:attribute:: ascii_headers

        An :py:obj:`~collections.OrderedDict` of headers that appear, in order, in the ASCII-armored form of this object.


:py:class:`PGPMessage`
----------------------

.. autoclass:: PGPMessage
    :members:

    .. py:attribute:: ascii_headers

        An :py:obj:`~collections.OrderedDict` of headers that appear, in order, in the ASCII-armored form of this object.

    .. py:classmethod:: from_file(filename)

        Create a new :py:obj:`PGPMessage` object, with contents loaded from a file. May be binary or ASCII armored.

        :param filename: The path to the file to load.
        :type filename: ``str``
        :raises: :py:exc:`ValueError` if a properly formed PGP block was not found in the file at ``filename``
        :raises: :py:exc:`~exceptions.PGPError` if de-armoring or parsing failed
        :returns: :py:obj:`PGPMessage`

    .. py:classmethod:: from_blob(blob)

        Create a new :py:obj:`PGPMessage` object, with contents loaded from a blob. May be binary or ASCII armored.

        :param blob: The data to load.
        :type blob: ``str``, ``bytes``, ``unicode``, ``bytearray``
        :raises: :py:exc:`TypeError` if blob is not in the expected types above
        :raises: :py:exc:`ValueError` if a properly formed PGP block was not found in ``blob``
        :raises: :py:exc:`~exceptions.PGPError` if de-armoring or parsing failed
        :returns: :py:obj:`PGPMessage`


:py:class:`PGPSignature`
------------------------

.. autoclass:: PGPSignature
    :members:

    .. py:attribute:: ascii_headers

        An :py:obj:`~collections.OrderedDict` of headers that appear, in order, in the ASCII-armored form of this object.

    .. py:classmethod:: from_file(filename)

        Create a new :py:obj:`PGPSignature` object, with contents loaded from a file. May be binary or ASCII armored.

        :param filename: The path to the file to load.
        :type filename: ``str``
        :raises: :py:exc:`ValueError` if a properly formed PGP block was not found in the file at ``filename``
        :raises: :py:exc:`~exceptions.PGPError` if de-armoring or parsing failed
        :returns: :py:obj:`PGPSignature`

    .. py:classmethod:: from_blob(blob)

        Create a new :py:obj:`PGPSignature` object, with contents loaded from a blob. May be binary or ASCII armored.

        :param blob: The data to load.
        :type blob: ``str``, ``bytes``, ``unicode``, ``bytearray``
        :raises: :py:exc:`TypeError` if blob is not in the expected types above
        :raises: :py:exc:`ValueError` if a properly formed PGP block was not found in ``blob``
        :raises: :py:exc:`~exceptions.PGPError` if de-armoring or parsing failed
        :returns: :py:obj:`PGPSignature`


:py:class:`PGPUID`
------------------

.. autoclass:: PGPUID
    :members:


Certificate Merging
===================

.. py:currentmodule:: pgpy

A public key directory can receive many independently observed copies of the same
certificate, possibly out of order, truncated, duplicated, or even containing forged
material. The merge entry point combines those copies without modifying any of the
input objects and without letting unverified updates erase previously verifiable
history.

Copies are combined only when their primary key packets express the exact same
identity: the full fingerprint must match *and* the rendered public key material must
be byte-identical. A matching short key id is never sufficient. Self-issued signatures
are cryptographically verified against the primary key material before being treated
as facts; anything that cannot be verified (for example a third-party certification,
or a forged revocation) is either retained as an observation or quarantined in the
result report rather than merged blindly.

.. autofunction:: merge_certificates

.. autofunction:: merge

:py:class:`MergeResult`
-----------------------

.. autoclass:: MergeResult
    :members:

:py:class:`MergeConflict`
-------------------------

.. autoclass:: MergeConflict
    :members:


Other Objects
=============

.. py:currentmodule:: pgpy.types

These are objects that are returned during certain operations, but are probably not useful to instantiate directly.


:py:class:`~types.SignatureVerification`
----------------------------------------

.. autoclass:: SignatureVerification
    :members:


:py:class:`~types.Fingerprint`
------------------------------

.. autoclass:: Fingerprint
    :members:

