Ole10Native (OLE Package) parsing
=================================

``olefile.ole_native`` provides a read-only view of the bytes stored in an
``\x01Ole10Native`` stream. Such a stream is normally found inside an OLE
Package storage (storage CLSID ``0003000C-0000-0000-C000-000000000046``). It
was originally used to carry an OLE 1.0 embedded object converted to OLE 2.0;
see [MS-OLEDS] section 2.3.6.

The parser never resolves a link, never executes an embedded object, never
writes a file, and never turns a self-reported name into a path.

Quick start
-----------

.. code-block:: python

    import hashlib
    import olefile
    from olefile import ole_native

    with olefile.OleFileIO('sample.doc') as ole:
        for package in ole_native.iter_ole10native(ole):
            print(package.display_name)          # self-reported, untrusted
            print(package.declared_form)         # 'linked' / 'embedded'
            print(package.native_data_range)     # declared byte range
            if package.native_data is not None:
                print(hashlib.sha256(package.native_data).hexdigest())
            for issue in package.issues:
                print(issue.code, issue.offset, issue.length)

To parse bytes that were already read elsewhere:

.. code-block:: python

    from olefile.ole_native import parse_ole10native
    package = parse_ole10native(stream_bytes)

Interpretation
--------------

``declared_form``
    Value from the ``FormatID`` field: ``'linked'`` (1), ``'embedded'`` (2) or
    ``'unknown'``.

``effective_form``
    How the payload should be handled. When no native-data length is present
    the object is reference-only, even if ``FormatID`` was 2. A linked object
    has no native bytes; its ``link_target`` is the self-reported source path
    and is never opened.

``native_data`` / ``native_data_range``
    The native bytes and the declared ``(start, end)`` byte range in the
    stream. ``native_data_complete`` is false when the declared range extends
    past the available stream bytes; in that case ``native_data`` contains
    only the available prefix and ``native_data_available_range`` records what
    was actually present.

``trailer``
    Bytes after the declared native data inside the declared region. They are
    retained (and opportunistically decoded as count-prefixed UTF-16 strings),
    but never folded into ``native_data`` or its digest.

``outer_trailer``
    Bytes after ``4 + declared_container_length``.

``issues``
    Machine-readable evidence. ``severity`` is ``error`` for structural
    contradictions (missing NUL, lengths beyond the stream, invalid
    ``FormatID``), ``warning`` for unexpected but readable shapes, and
    ``info`` for things such as an optional metadata trailer. An error does
    not discard the bytes that could be read; check
    ``native_data_complete`` and the other completeness flags.

Names
-----

``display_name``, ``source_path`` and ``temp_path`` are chosen by the document
author. They are decoded as Latin-1 for display and the exact bytes are
exported as ``*_raw``. They are not content types and must not be trusted:
``content_type``/``native_content_hint`` is derived only from the native
bytes, while ``reported_extension`` only echoes the self-reported name.

Convenience methods
-------------------

``OleFileIO`` also exposes ``list_ole10native_streams()`` and
``open_ole10native(path)``; both are read-only wrappers around the functions
above.

Safety
------

``evidence()['safety']`` always reports that the link was not resolved or
contacted, no object was executed, and no file was written. The optional CLI
prints JSON evidence to stdout:

.. code-block:: bash

    python -m olefile.ole_native sample.doc

Use ``--include-native-hex`` to include the complete native bytes in the JSON;
the default only includes offsets, lengths, SHA-256 and a short hex preview.
