hpack API
=========

This document provides the HPACK API.

.. autoclass:: hpack.Encoder
   :members: header_table_size, encode

.. autoclass:: hpack.Decoder
   :members: header_table_size, decode

.. autoclass:: hpack.HeaderBlockInterpreter
   :members: interpret, source_chain, mark_history_gap, discard_block,
             block_sequence, uncertain, uncertain_reason, decoder

.. autoclass:: hpack.InterpretationResult
   :members:

.. autoclass:: hpack.FieldProvenance
   :members:

.. autoclass:: hpack.TableSizeUpdateRecord
   :members:

.. autoclass:: hpack.TableReference
   :members:

.. autoclass:: hpack.DynamicEntryOrigin
   :members:

.. autoclass:: hpack.SizeUpdate
   :members:

.. autoclass:: hpack.WireString
   :members:

.. autoclass:: hpack.ByteRange
   :members:

.. autoclass:: hpack.HeaderTuple
   :members: indexable

.. autoclass:: hpack.NeverIndexedHeaderTuple
   :members: indexable

.. autoclass:: hpack.HPACKError

.. autoclass:: hpack.HPACKDecodingError

.. autoclass:: hpack.InvalidTableIndexError

.. autoclass:: hpack.InvalidTableIndex

.. autoclass:: hpack.OversizedHeaderListError

.. autoclass:: hpack.InvalidTableSizeError
