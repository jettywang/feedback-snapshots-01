.. currentmodule:: aiohttp

.. _aiohttp-multipart-reference:

Multipart reference
===================

.. class:: MultipartResponseWrapper(resp, stream)
   :canonical: aiohttp.multipart.MultipartResponseWrapper

   Wrapper around the :class:`MultipartReader` to take care about
   underlying connection and close it when it needs in.


   .. method:: at_eof()

      Returns ``True`` when all response data had been read.

      :rtype: bool

   .. method:: next()
      :async:

      Emits next multipart reader object.

   .. method:: release()
      :async:

      Releases the connection gracefully, reading all the content
      to the void.


.. class:: BodyPartReader(boundary, headers, content)
   :canonical: aiohttp.multipart.BodyPartReader

   Multipart reader for single body part.

   .. method:: read(*, decode=False)
      :async:

      Reads body part data.

      :param bool decode: Decodes data following by encoding method
                          from ``Content-Encoding`` header. If it
                          missed data remains untouched

      :rtype: bytearray

   .. method:: read_chunk(size=chunk_size)
      :async:

      Reads body part content chunk of the specified size.

      :param int size: chunk size

      :rtype: bytearray

   .. method:: readline()
      :async:

      Reads body part by line by line.

      :rtype: bytearray

   .. method:: release()
      :async:

      Like :meth:`read`, but reads all the data to the void.

      :rtype: None

   .. method:: text(*, encoding=None)
      :async:

      Like :meth:`read`, but assumes that body part contains text data.

      :param str encoding: Custom text encoding. Overrides specified
                           in charset param of ``Content-Type`` header

      :rtype: str

   .. method:: json(*, encoding=None)
      :async:

      Like :meth:`read`, but assumes that body parts contains JSON data.

      :param str encoding: Custom JSON encoding. Overrides specified
                           in charset param of ``Content-Type`` header

   .. method:: form(*, encoding=None)
      :async:

      Like :meth:`read`, but assumes that body parts contains form
      urlencoded data.

      :param str encoding: Custom form encoding. Overrides specified
                           in charset param of ``Content-Type`` header

   .. method:: at_eof()

      Returns ``True`` if the boundary was reached or ``False`` otherwise.

      :rtype: bool

   .. method:: decode(data)

      Decodes data synchronously according the specified ``Content-Encoding``
      or ``Content-Transfer-Encoding`` headers value.

      Supports ``gzip``, ``deflate`` and ``identity`` encodings for
      ``Content-Encoding`` header.

      Supports ``base64``, ``quoted-printable``, ``binary`` encodings for
      ``Content-Transfer-Encoding`` header.

      :param bytearray data: Data to decode.

      :raises: :exc:`RuntimeError` - if encoding is unknown.

      :rtype: bytes

      .. note::

         For large payloads, consider using :meth:`decode_iter` instead
         to avoid blocking the event loop during decompression.

   .. method:: decode_iter(data)
      :async:

      Decodes data asynchronously according the specified ``Content-Encoding``
      or ``Content-Transfer-Encoding`` headers value.

      This is an async iterator and will return decoded data in chunks. This
      can be used to avoid loading large payloads into memory.

      This method offloads decompression to an executor for large payloads
      to avoid blocking the event loop.

      Supports ``gzip``, ``deflate`` and ``identity`` encodings for
      ``Content-Encoding`` header.

      Supports ``base64``, ``quoted-printable``, ``binary`` encodings for
      ``Content-Transfer-Encoding`` header.

      :param bytearray data: Data to decode.

      :raises: :exc:`RuntimeError` - if encoding is unknown.

      :rtype: bytes

      .. versionadded:: 3.13.4

   .. method:: get_charset(default=None)

      Returns charset parameter from ``Content-Type`` header or default.

   .. attribute:: name

      A field *name* specified in ``Content-Disposition`` header or ``None``
      if missed or header is malformed.

      Readonly :class:`str` property.

   .. attribute:: filename

      A field *filename* specified in ``Content-Disposition`` header or ``None``
      if missed or header is malformed.

      Readonly :class:`str` property.


.. class:: MultipartBudget(*, max_fields=0, max_files=0, max_bytes=0, error_cls=None)
   :canonical: aiohttp.multipart.MultipartBudget

   Resource budget shared by every part of a single multipart request.

   The three limits are independent and the counters accumulate across all
   ordinary fields, file parts and nested multiparts; a new part never
   restarts them. A limit of ``0`` or a negative value disables that budget.

   Bytes are counted from the underlying stream's received wire bytes
   (including framing and per-part headers), not the decoded content.

   .. attribute:: max_fields
                  max_files
                  max_bytes

      The configured limits (:class:`int`); non-positive values disable the
      corresponding budget.

   .. attribute:: fields
                  files

      Number of ordinary fields and file parts accounted for so far.

   .. attribute:: bytes

      Raw wire bytes received from the bound stream so far (:class:`int`).

   .. method:: add_field()

      Account for one ordinary form field, raising when ``max_fields`` is
      exceeded.

   .. method:: add_file()

      Account for one uploaded file part, raising when ``max_files`` is
      exceeded.

   .. method:: check_bytes(observed=None)

      Raise if the shared received-byte budget is exceeded. Without an
      argument the bound stream's counter is used.

   When ``error_cls`` is supplied, an over-limit call raises an instance of
   that class (for example :class:`~aiohttp.web.HTTPRequestEntityTooLarge`)
   carrying ``limit_kind``, ``limit`` and ``observed`` attributes; otherwise
   :class:`MultipartLimitExceeded` is raised.

.. class:: MultipartLimitExceeded
   :canonical: aiohttp.multipart.MultipartLimitExceeded

   Raised when a request-wide multipart budget is exceeded.

   .. attribute:: limit_kind

      One of the :class:`MultipartLimitKind` members (``FIELDS``, ``FILES``
      or ``BYTES``), identifying which budget tripped. Middleware can branch
      on this instead of parsing the error message.

   .. attribute:: limit

      The configured limit that was exceeded (:class:`int`).

   .. attribute:: observed

      The counter value observed when the limit tripped (:class:`int`).

.. class:: MultipartLimitKind
   :canonical: aiohttp.multipart.MultipartLimitKind

   Enum identifying a multipart budget: ``FIELDS``, ``FILES`` and ``BYTES``.


.. class:: MultipartReader(headers, content)
   :canonical: aiohttp.multipart.MultipartReader

   Multipart body reader.

   .. classmethod:: from_response(cls, response)

      Constructs reader instance from HTTP response.

      :param response: :class:`~aiohttp.ClientResponse` instance

   .. attribute:: budget

      The :class:`MultipartBudget` shared by every part emitted by this
      reader and its nested readers. A reader created without an explicit
      budget builds one from ``client_max_size``.

   .. method:: at_eof()

      Returns ``True`` if the final boundary was reached or
      ``False`` otherwise.

      :rtype: bool

   .. method:: next()
      :async:

      Emits the next multipart body part.

   .. method:: release()
      :async:

      Reads all the body parts to the void till the final boundary.

   .. method:: fetch_next_part()
      :async:

      Returns the next body part reader.


.. class:: MultipartWriter(subtype='mixed', boundary=None, close_boundary=True)
   :canonical: aiohttp.multipart.MultipartWriter

   Multipart body writer.

   ``boundary`` may be an ASCII-only string.

   .. attribute:: boundary

      The string (:class:`str`) representation of the boundary.

      .. versionchanged:: 3.0

         Property type was changed from :class:`bytes` to :class:`str`.

   .. method:: append(obj, headers=None)

      Append an object to writer.

   .. method:: append_payload(payload)

      Adds a new body part to multipart writer.

   .. method:: append_json(obj, headers=None)

      Helper to append JSON part.

   .. method:: append_form(obj, headers=None)

      Helper to append form urlencoded part.

   .. attribute:: size

      Size of the payload.

   .. method:: write(writer, close_boundary=True)
      :async:

      Write body.

      :param bool close_boundary: The (:class:`bool`) that will emit
                                  boundary closing. You may want to disable
                                  when streaming (``multipart/x-mixed-replace``)

      .. versionadded:: 3.4

         Support ``close_boundary`` argument.
