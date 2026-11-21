.. _advanced_usage:

**************
Advanced usage
**************

Extract selected members
========================

:meth:`~py7zr.SevenZipFile.extract` takes a collection of member names as
``targets``. Combine it with :meth:`~py7zr.SevenZipFile.getnames` to select
members by pattern:

.. code-block:: python

    import re
    from py7zr import SevenZipFile

    filter_pattern = re.compile(r'scripts.*')
    with SevenZipFile('archive.7z', 'r') as archive:
        allfiles = archive.getnames()
        targets = [f for f in allfiles if filter_pattern.match(f)]
        archive.extract(path='out', targets=targets)

With ``recursive=True``, a target also selects every member whose name starts
with it, so naming a directory extracts its whole subtree:

.. code-block:: python

    with SevenZipFile('archive.7z', 'r') as archive:
        archive.extract(path='out', targets=['scripts'], recursive=True)

An archive can be extracted only once per open. To extract again from the same
:class:`~py7zr.SevenZipFile` object, call :meth:`~py7zr.SevenZipFile.reset`
first, or reopen the archive.


.. _restrict-allowed-methods:

Restrict allowed compression methods
====================================

An import service may only accept compression methods that operations has
validated. Pass ``allowed_methods`` to :class:`~py7zr.SevenZipFile` with the
``FILTER_*`` IDs that are approved for decoding:

.. code-block:: python

    from py7zr import FILTER_DEFLATE, FILTER_LZMA2, SevenZipFile

    approved = [FILTER_LZMA2, FILTER_DEFLATE]
    with SevenZipFile('incoming.7z', 'r', allowed_methods=approved) as archive:
        names = archive.getnames()   # header only: always available
        archive.extractall(path='out')

The policy is evaluated from the archive header before any decoder or
:class:`~py7zr.WriterFactory` product is created. A member whose folder uses a
method outside the list -- including a method py7zr cannot decode at all --
raises :class:`~py7zr.UnsupportedCompressionMethodError`, and no data is
decompressed. Because the header is parsed independently,
:meth:`~py7zr.SevenZipFile.list`, :meth:`~py7zr.SevenZipFile.getnames` and
:meth:`~py7zr.SevenZipFile.archiveinfo` keep working, so an archive can be
inspected and triaged even when its payload is rejected.

Build the full capability list with
:meth:`~py7zr.SupportedMethods.supported_filter_ids`. With no argument
(the default) every method py7zr supports remains allowed. With targeted
:meth:`~py7zr.SevenZipFile.extract`, only the folders behind the selected
members are checked, so an allowed member in an otherwise non-compliant
archive can still be read. :meth:`~py7zr.SevenZipFile.testzip` enforces the
same policy before decompressing.


.. _stream-7z-content:

Stream 7z content
=================

:meth:`~py7zr.SevenZipFile.extract` and :meth:`~py7zr.SevenZipFile.extractall`
accept a ``factory`` argument: an object implementing the
:class:`py7zr.WriterFactory` interface. When it is given, py7zr does not write
files to disk. For each regular file or symbolic link in the archive it calls
the factory's ``create`` method with the output file name, and writes the
member's data to the returned object. Directories and special files are skipped.

The object returned by ``create`` must implement the :class:`py7zr.Py7zIO`
interface, which is similar to Python's standard :class:`typing.BinaryIO`
with an additional ``size`` method:

``write(data)``
    Called repeatedly, on the fly, with successive chunks of the member's data
    while it is decompressed. Append each chunk; py7zr never holds the whole
    archive in memory, so this is where data can be streamed elsewhere.

``read``, ``seek``, ``flush``, ``size``
    Standard stream operations; ``size`` returns the number of bytes written.

``close()``
    Called once when the member is complete. It is optional to override; use it
    to release per-member resources or to finalize an upload before py7zr
    moves on to the next member.

.. note::

   py7zr may extract members in worker threads, so your classes should be
   thread-safe.


Example: keep data in memory
----------------------------

This factory keeps at most ``limit`` bytes of each member in memory.

.. code-block:: python

    from typing import Optional, Union

    from py7zr import Py7zIO, SevenZipFile, WriterFactory


    class MyIO(Py7zIO):
        def __init__(self, limit: int):
            self._limit = limit
            self._buffer = bytearray()

        def write(self, s: Union[bytes, bytearray]) -> int:
            """Keep only the first ``limit`` bytes."""
            room = self._limit - len(self._buffer)
            if room > 0:
                self._buffer += s[:room]
            return len(s)

        def read(self, size: Optional[int] = None) -> bytes:
            if size is None:
                return bytes(self._buffer)
            return bytes(self._buffer[:size])

        def seek(self, offset: int, whence: int = 0) -> int:
            return 0

        def flush(self) -> None:
            pass

        def size(self) -> int:
            return len(self._buffer)


    class MyFactory(WriterFactory):
        def __init__(self, limit: int):
            self.limit = limit
            self.products = {}

        def create(self, filename: str) -> Py7zIO:
            product = MyIO(self.limit)
            self.products[filename] = product
            return product


    factory = MyFactory(10)
    with SevenZipFile('archive.7z', 'r') as archive:
        archive.extractall(factory=factory)
    for filename, fileobj in factory.products.items():
        print(f'{filename}: {fileobj.read()}...')


Example: extract into network storage
-------------------------------------

Here is pseudo code that streams contents to cloud storage.
To keep the example simple, authentication, bucket operations and
mandatory headers are omitted.

.. code-block:: python

    from typing import Optional, Union

    import requests

    import py7zr


    class StreamIO(py7zr.Py7zIO):
        """Example network storage writer."""

        def __init__(self, fname: str):
            self.fname = fname
            self.length = 0

        def write(self, data: Union[bytes, bytearray]) -> int:
            # py7zr calls write multiple times, so append the data.
            self.length += len(data)
            requests.put("https://your.custom.network.storage.example.com/append/to/file/command/", data=data)
            return len(data)

        def read(self, size: Optional[int] = None) -> bytes:
            return b''

        def seek(self, offset: int, whence: int = 0) -> int:
            return offset

        def flush(self) -> None:
            pass

        def size(self) -> int:
            return self.length

        def close(self) -> None:
            # The member is complete; commit the upload here.
            pass


    class StreamIOFactory(py7zr.WriterFactory):
        """Factory class returning StreamIO objects."""

        def __init__(self):
            self.products = {}

        def create(self, filename: str) -> py7zr.Py7zIO:
            product = StreamIO(filename)
            self.products[filename] = product
            return product


    def extract_stream():
        factory = StreamIOFactory()
        with py7zr.SevenZipFile("target.7z") as archive:
            archive.extractall(factory=factory)
