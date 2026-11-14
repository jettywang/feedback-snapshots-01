hpack: Pure-Python HTTP/2 Header Encoding
=========================================

hpack provides a simple Python interface to the `HPACK`_ compression algorithm,
used to encode HTTP headers in HTTP/2. Used by some of the most popular
HTTP/2 implementations in Python, the hpack library offers a great and simple
Python interface without any dependencies, strictly confirming to `RFC 7541`_..

Using hpack is easy:

.. code-block:: python

    from hpack import Decoder, Encoder

    headers = [
        (':method', 'GET'),
        (':path', '/jimiscool/'),
        ('X-Some-Header', 'some_value'),
    ]

    e = Encoder()
    encoded_bytes = e.encode(headers)

    d = Decoder()
    decoded_headers = d.decode(encoded_bytes)

For HTTP/2 servers that want to reject one oversized header list at the
stream level without closing the connection, use discard mode. The whole block
is still validated and its dynamic table updates are applied, but no business
headers are returned::

    d = Decoder(max_header_list_size=65536)
    result = d.decode_discard(encoded_bytes)
    if isinstance(result, DiscardedHeaderList):
        # Reject just this stream; the HPACK context is still usable.
        ...

The same behaviour is available as ``d.decode(encoded_bytes,
mode=DecodeMode.DISCARD)``. Fatal compression errors, exhausted decoding work
budgets and illegal table sizes still raise ``HPACKDecodingError`` subclasses
in either mode, and then the connection must be closed.


Contents
--------

.. toctree::
   :maxdepth: 2

   installation
   api
   security/index


.. _HPACK: https://tools.ietf.org/html/rfc7541
.. _RFC 7541: https://tools.ietf.org/html/rfc7541
