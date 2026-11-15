
Basic Encoding Rules
--------------------

.. autofunction:: pyasn1.codec.ber.encoder.encode(value, asn1Spec=None, defMode=True, maxChunkSize=0)

.. autofunction:: pyasn1.codec.ber.streaming_encoder.encodeStream(value, asn1Spec=None)

.. autofunction:: pyasn1.codec.ber.streaming_encoder.encodeStreamTo(sink, value, asn1Spec=None)

.. autoclass:: pyasn1.codec.ber.streaming_encoder.StreamingEncoder

.. autofunction:: pyasn1.codec.ber.decoder.decode(substrate, asn1Spec=None)
