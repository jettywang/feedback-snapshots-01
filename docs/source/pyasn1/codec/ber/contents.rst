Basic Encoding Rules
--------------------

.. autofunction:: pyasn1.codec.ber.encoder.encode(value, asn1Spec=None, defMode=True, maxChunkSize=0)

.. autofunction:: pyasn1.codec.ber.decoder.decode(substrate, asn1Spec=None)

Bounded fragment consumption
----------------------------

.. automodule:: pyasn1.codec.ber.bounded

.. autoclass:: pyasn1.codec.ber.bounded.FragmentBudget
   :members:

.. autoclass:: pyasn1.codec.ber.bounded.ConsumptionStats
   :members:

.. autoclass:: pyasn1.codec.ber.bounded.FragmentSink
   :members:

.. autoclass:: pyasn1.codec.ber.bounded.BoundedFragmentDecoder
   :members:

.. autofunction:: pyasn1.codec.ber.bounded.decodeBounded(substrate, expectedType, budget=None)
