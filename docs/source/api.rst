hpack API
=========

This document provides the HPACK API.

.. autoclass:: hpack.Encoder
   :members: header_table_size, encode

.. autoclass:: hpack.Decoder
   :members: header_table_size, max_decode_work, connection_usable, decode, decode_discard

.. autoclass:: hpack.HeaderTuple
   :members: indexable

.. autoclass:: hpack.NeverIndexedHeaderTuple
   :members: indexable

.. autoclass:: hpack.HPACKError

.. autoclass:: hpack.HPACKDecodingError

.. autoclass:: hpack.InvalidTableIndexError

.. autoclass:: hpack.InvalidTableIndex

.. autoclass:: hpack.DecodeMode

.. autoclass:: hpack.DiscardedHeaderList

.. autoclass:: hpack.DecodeStats

.. autoclass:: hpack.DecodeWorkBudgetExceeded

.. autoclass:: hpack.OversizedHeaderListError

.. autoclass:: hpack.InvalidTableSizeError
