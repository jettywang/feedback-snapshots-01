==================================
Static VBA Project Inventory (MS-OVBA)
==================================

.. note::

    The VBA inventory is a *static* analysis feature.  It only parses
    on-disk structures.  It never executes macros, and it never classifies a
    document as malicious from its file name or from strings found in source
    code (for example an ``AutoOpen`` routine).  Its output is structural
    evidence meant for an analyst or a later analysis stage.

Overview
--------

VBA projects embedded in an OLE/CFB file store their description in the
``VBA`` storage defined by `MS-OVBA
<https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/>`__:

* the ``dir`` stream is a compressed CompressedContainer holding
  version-independent project information, external references and module
  records;
* each MODULE record names a Module Stream that contains a performance cache
  followed by the compressed source code, with the boundary given by the
  MODULEOFFSET record.

:func:`olefile.vba_inventory` decompresses and interprets the ``dir`` stream
and correlates every MODULE record with the stream that actually exists in the
OLE file.  All work is bounded so that a malformed file cannot force
unbounded memory or parsing work.

Basic usage
-----------

.. code-block:: python

    import olefile
    from olefile import vba_inventory

    ole = olefile.OleFileIO('document.doc')
    try:
        inventory = vba_inventory(ole)
    finally:
        ole.close()

    if not inventory.has_vba_project:
        print('No VBA storage')
    else:
        print(inventory.to_text())
        # machine-readable form, JSON serializable:
        data = inventory.to_dict()

The same report is available from the command line::

    python -m olefile.olefile --vba document.doc

What is reported
----------------

* **Project information**: PROJECTNAME, PROJECTCODEPAGE and the Python codec
  derived from it, system kind, LCID, version, constants and documentation
  strings.
* **External references**: REFERENCEREGISTERED, REFERENCEPROJECT,
  REFERENCECONTROL and REFERENCEORIGINAL records, including Libid paths,
  GUIDs and versions.  Each reference keeps the byte range of its directory
  records.
* **Modules**: module name and type, the MODULESTREAMNAME, MODULEOFFSET and
  every other record's byte range in the decompressed ``dir`` stream, plus the
  correlated stream name, stream size, performance-cache range and compressed
  source range.  A bounded, code-page-decoded preview of the source is
  included; the full source is never stored in the inventory.
* **Findings**: explicit structural findings with a stable code, severity,
  message and the directory offset where the problem was observed.

Bounded processing
------------------

The limits can be overridden through the ``limits`` argument; see
:func:`olefile.vba.default_limits` for the names and defaults:

.. code-block:: python

    inventory = vba_inventory(ole, limits={
        'max_decompressed': 16 * 1024 * 1024,
        'max_records': 10000,
    })

When a limit is reached, parsing stops, a finding is recorded and
``inventory.complete`` is ``False``.

Findings and the ``complete`` flag
----------------------------------

The inventory distinguishes a complete interpretation from a partial one.
``complete`` is only ``True`` when the whole ``dir`` stream was interpreted,
every module and reference parsed without a structural finding and every limit
was respected.  In particular:

* an unknown record id is recorded as a ``dir.unknown_record`` finding and the
  inventory is marked incomplete - unknown bytes are never silently treated as
  a finished scan;
* a MODULE record whose named stream does not exist raises
  ``module.stream_missing``;
* two MODULE records mapping to the same stream raise
  ``module.duplicate_stream_mapping``;
* a MODULEOFFSET outside the stream raises ``module.offset_out_of_range``;
* a compressed copy token that would read outside the data produced so far
  raises ``compression.copy_out_of_bounds`` during decompression and is
  surfaced as ``module.compression_error`` (or ``dir.compression_error`` for
  the ``dir`` stream itself).

The finding constants are exported from :mod:`olefile.vba` (the ``F_*``
names) so callers can match on stable codes rather than message text.
