# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Defines layers for containing data.

One layer may combine other layers, map data based on the data itself,
or map a procedure (such as decryption) across another layer of data.
"""

import collections.abc
import functools
import logging
import math
import multiprocessing
import multiprocessing.managers
import multiprocessing.pool
import traceback
from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces

vollog = logging.getLogger(__name__)

ProgressValue = Union["DummyProgress", multiprocessing.managers.ValueProxy]
# A chunk is described by the data segments that make it up, together with the
# logical offset the chunk starts at within the scanned layer.  Each segment is
# (layer_name, segment_address, segment_length).  Segments only ever cover
# readable, contiguous ranges, so a missing physical range always ends a chunk
# and starts a new one rather than being stitched together.
ChunkSegment = Tuple[str, int, int]
IteratorValue = Tuple[List[ChunkSegment], int]


class ScanLocation(collections.namedtuple("ScanLocation", ("offset", "layer_name"))):
    """Logical location of a single scanner result.

    ``offset`` is the absolute offset within the layer that was asked to be
    scanned (the logical address), while ``layer_name`` is the data layer that
    physically supplied the bytes that matched.  For a linearly mapped layer the
    two addresses differ by the layer's translation offset; for a non-linear
    layer ``layer_name`` is the scanned layer itself.

    A match that straddles a chunk boundary always resolves to a single,
    unambiguous location because adjacent chunks share an overlap of readable
    bytes.  A match can never straddle a missing physical range, since holes end
    a chunk and are never concatenated into the data handed to a scanner.
    """

    __slots__ = ()


class ScannerInterface(
    interfaces.configuration.VersionableInterface, metaclass=ABCMeta
):
    """Class for layer scanners that return locations of particular values from
    within the data.

    These are designed to be given a chunk of data and return a generator which yields
    any found items.  They should NOT perform complex/time-consuming tasks, these should
    be carried out by the consumer of the generator on the items returned.

    They will be provided all *available* data (therefore not necessarily contiguous)
    in ascending offset order, in chunks no larger than chunk_size + overlap where
    overlap is the amount of data read twice once at the end of an earlier chunk and
    once at the start of the next chunk.

    Chunking result contract:

    * Chunks walk the scanned address space in ascending logical offset order.
      Adjacent chunks share an ``overlap`` region so that a rule longer than one
      chunk cannot be missed when it straddles a chunk boundary.
    * Each logical address is therefore presented to a scanner at most twice,
      but must be reported at most once.  Results whose *logical* start offset
      falls inside the overlap (i.e. at/after the start of the next chunk) are
      owned by that next chunk.  The framework enforces this centrally in
      :meth:`DataLayerInterface._scan_chunk`, so individual scanners only need
      to yield every match they find in the data they are given.
    * Only readable, contiguous bytes are ever joined into a chunk.  A missing
      physical range (a hole) terminates the current chunk and begins a new one;
      the bytes on either side of a hole are never concatenated, so a rule
      cannot be stitched together across unmapped memory.
    * Every result carries its logical offset (the offset in the scanned layer)
      and the name of the data layer that actually supplied the matching bytes.
      The first element yielded by a scanner must always be the logical offset,
      which the framework uses both for de-duplication and for locating the
      underlying layer.

    The contract is identical regardless of whether the scanner is run serially
    or through the parallel pool: changing ``chunk_size``/``overlap`` or the
    parallelism setting must never change the set of reported results.

    It should be noted that the scanner can maintain state if necessary.
    Scanners should balance the size of chunk based on the amount of time
    scanning the chunk will take (ie, do not set an excessively large chunksize
    and try not to take a significant amount of time in the __call__ method).

    Scanners should not return results found *after* self.chunk_size (ie,
    entirely contained within the overlap); the framework discards any such
    duplicate results as a safety net, but a scanner that can filter cheaply
    (see :class:`~volatility3.framework.layers.scanners.BytesScanner`) is
    expected to do so itself.

    Scanners can mark themselves as thread_safe, if they do not require state
    in either their own class or the context.  This will allow the scanner to be run
    in parallel against multiple blocks.
    """

    thread_safe = False

    _required_framework_version = (2, 0, 0)

    def __init__(self) -> None:
        super().__init__()
        self.chunk_size = 0x1000000  # Default to 16Mb chunks
        self.overlap = 0x1000  # A page of overlap by default
        self._context: Optional[interfaces.context.ContextInterface] = None
        self._layer_name: Optional[str] = None

    @property
    def context(self) -> Optional["interfaces.context.ContextInterface"]:
        return self._context

    @context.setter
    def context(self, ctx: "interfaces.context.ContextInterface") -> None:
        """Stores the context locally in case the scanner needs to access the
        layer."""
        self._context = ctx

    @property
    def layer_name(self) -> Optional[str]:
        return self._layer_name

    @layer_name.setter
    def layer_name(self, layer_name: str) -> None:
        """Stores the layer_name being scanned locally in case the scanner
        needs to access the layer."""
        self._layer_name = layer_name

    @abstractmethod
    def __call__(self, data: bytes, data_offset: int) -> Iterable[Any]:
        """Searches through a chunk of data for a particular value/pattern/etc
        Always returns an iterator of the same type of object (need not be a
        volatility object)

        data is the chunk of data to search through data_offset is the
        offset within the layer that the data being searched starts at
        """


class DataLayerInterface(
    interfaces.configuration.ConfigurableInterface, metaclass=ABCMeta
):
    """A Layer that directly holds data (and does not translate it).

    This is effectively a leaf node in a layer tree. It directly
    accesses a data source and exposes it within volatility.
    """

    _direct_metadata: Mapping = {"architecture": "Unknown", "os": "Unknown"}

    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path)
        self._name = name
        self._metadata = metadata or {}

    # Standard attributes

    @property
    def name(self) -> str:
        """Returns the layer name."""
        return self._name

    @property
    @abstractmethod
    def maximum_address(self) -> int:
        """Returns the maximum valid address of the space."""

    @property
    @abstractmethod
    def minimum_address(self) -> int:
        """Returns the minimum valid address of the space."""

    @functools.cached_property
    def address_mask(self) -> int:
        """Returns a mask which encapsulates all the active bits of an address
        for this layer."""
        return (1 << int(math.ceil(math.log2(self.maximum_address)))) - 1

    @abstractmethod
    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns a boolean based on whether the entire chunk of data (from
        offset to length) is valid or not.

        Args:
            offset: The address to start determining whether bytes are readable/valid
            length: The number of bytes from offset of which to test the validity

        Returns:
             Whether the bytes are valid and accessible
        """

    @abstractmethod
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of
        length size.

        If there is a fault of any kind (such as a page fault), an exception will be thrown
        unless pad is set, in which case the read errors will be replaced by null characters.

        Args:
            offset: The offset at which to being reading within the layer
            length: The number of bytes to read within the layer
            pad: A boolean indicating whether exceptions should be raised or bad bytes replaced with null characters

        Returns:
            The bytes read from the layer, starting at offset for length bytes
        """

    @abstractmethod
    def write(self, offset: int, data: bytes) -> None:
        """Writes a chunk of data at offset.

        Any unavailable sections in the underlying bases will cause an exception to be thrown.
        Note: Writes are not guaranteed atomic, therefore some data may have been written, even if an exception is thrown.
        """

    def destroy(self) -> None:
        """Causes a DataLayer to close any open handles, etc.

        Systems that make use of Data Layers should call destroy when
        they are done with them. This will close all handles, and make
        the object unreadable (exceptions will be thrown using a
        DataLayer after destruction)
        """

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of Requirement objects for this type of layer."""
        return super().get_requirements()

    @property
    def dependencies(self) -> List[str]:
        """A list of other layer names required by this layer.

        Note:
            DataLayers must never define other layers
        """
        return []

    # ## General scanning methods

    def scan(
        self,
        context: interfaces.context.ContextInterface,
        scanner: ScannerInterface,
        progress_callback: constants.ProgressCallback = None,
        sections: Optional[Iterable[Tuple[int, int]]] = None,
        locate_results: bool = False,
        use_overlap_cache: bool = True,
    ) -> Iterable[Any]:
        """Scans a Translation layer by chunk.

        Note: this will skip missing/unmappable chunks of memory

        Args:
             context: The context containing the data layer
             scanner: The constructed Scanner object to be applied
             progress_callback: Method that is called periodically during scanning to update progress
             sections: A list of (start, size) tuples defining the portions of the layer to scan
             locate_results: When True, each scanner result is paired with the
                 :class:`ScanLocation` describing its logical offset and the data
                 layer that physically supplied the matching bytes, yielding
                 ``(result, scan_location)``.  When False (the default) the
                 scanner's own results are yielded unchanged.
             use_overlap_cache: When True (the default) the serial scan reuses
                 the overlap bytes read by the previous chunk instead of reading
                 them a second time.  Set to False to force a fresh read of every
                 chunk, which produces identical results but performs more I/O;
                 this is mainly useful for measuring the read-volume saving.

        Returns:
             The output iterable from the scanner object having been run against the layer
        """
        if progress_callback is not None and not callable(progress_callback):
            raise TypeError("Progress_callback is not callable")

        if scanner.chunk_size <= 0:
            raise ValueError("Scanner chunk_size must be a positive integer")
        if scanner.overlap < 0:
            raise ValueError("Scanner overlap must not be negative")
        if scanner.overlap >= scanner.chunk_size:
            # A forward step of chunk_size - overlap would make no progress and
            # would re-scan the same bytes forever, so reject it up front rather
            # than hanging inside the chunk iterator.
            raise ValueError(
                "Scanner overlap must be strictly smaller than chunk_size so "
                "that chunked scanning always advances through the layer"
            )

        scanner.context = context
        scanner.layer_name = self.name

        if sections is None:
            sections = [
                (self.minimum_address, self.maximum_address - self.minimum_address)
            ]

        sections = list(self._coalesce_sections(sections))

        try:
            progress: ProgressValue = DummyProgress()
            scan_iterator = functools.partial(self._scan_iterator, scanner, sections)
            scan_metric = self._scan_metric(scanner, sections)
            if (
                not scanner.thread_safe
                or constants.PARALLELISM == constants.Parallelism.Off
            ):
                progress = DummyProgress()
                # Chunks are produced in ascending logical order, so the overlap
                # read at the end of one chunk is exactly the prefix read again at
                # the start of the next.  Cache the segments read for a chunk and
                # reuse the matching segments of the following chunk, removing the
                # duplicate physical reads.  This stays serial; the parallel path
                # below cannot share this state, so it simply reads each chunk.
                overlap_cache: Optional[Dict[Tuple[str, int, int], bytes]] = (
                    {} if use_overlap_cache else None
                )
                for value in scan_iterator():
                    if progress_callback:
                        progress_callback(
                            scan_metric(progress.value),
                            f"Scanning {self.name} using {scanner.__class__.__name__}",
                        )
                    fill_cache: Dict[Tuple[str, int, int], bytes] = {}
                    yield from self._scan_chunk(
                        scanner,
                        progress,
                        value,
                        reuse_cache=overlap_cache,
                        fill_cache=fill_cache,
                        locate_results=locate_results,
                    )
                    # Only the most recent chunk's segments can overlap the next
                    # one, so a single-entry cache is sufficient and bounded.
                    overlap_cache = fill_cache if use_overlap_cache else None
            else:
                if constants.PARALLELISM == constants.Parallelism.Threading:
                    # A thread pool lives inside this process, so it needs
                    # neither a shared-memory Manager nor process spawning.
                    progress = DummyProgress()
                    pool_class = multiprocessing.pool.ThreadPool
                else:
                    progress = multiprocessing.Manager().Value("Q", 0)
                    pool_class = multiprocessing.Pool
                scan_chunk = functools.partial(
                    self._scan_chunk,
                    scanner,
                    progress,
                    locate_results=locate_results,
                )
                with pool_class() as pool:
                    result = pool.map_async(scan_chunk, scan_iterator())
                    while not result.ready():
                        if progress_callback:
                            # Run the progress_callback
                            progress_callback(
                                scan_metric(progress.value),
                                f"Scanning {self.name} using {scanner.__class__.__name__}",
                            )
                        # Ensures we don't burn CPU cycles going round in a ready waiting loop
                        # without delaying the user too long between progress updates/results
                        result.wait(0.1)
                    for result_value in result.get():
                        yield from result_value
        except Exception as e:
            # We don't care the kind of exception, so catch and report on everything, yielding nothing further
            vollog.debug(f"Scan Failure: {str(e)}")
            vollog.log(
                constants.LOGLEVEL_VVV,
                "\n".join(
                    traceback.TracebackException.from_exception(e).format(chain=True)
                ),
            )

    def _coalesce_sections(
        self, sections: Iterable[Tuple[int, int]]
    ) -> Iterable[Tuple[int, int]]:
        """Take a list of (start, length) sections and coalesce any adjacent
        sections."""
        result: List[Tuple[int, int]] = []
        position = 0
        for start, length in sorted(sections):
            if result and start <= position:
                initial_start, _ = result.pop()
                result.append((initial_start, (start + length) - initial_start))
            else:
                result.append((start, length))
            position = start + length

        while result and result[0] < (self.minimum_address, 0):
            first_start, first_length = result[0]
            if first_start + first_length < self.minimum_address:
                result = result[1:]
            elif first_start < self.minimum_address:
                result[0] = (
                    self.minimum_address,
                    (first_start + first_length) - self.minimum_address,
                )
        while result and result[-1] > (self.maximum_address, 0):
            last_start, last_length = result[-1]
            if last_start > self.maximum_address:
                result.pop()
            elif last_start + last_length > self.maximum_address:
                result[1] = (last_start, self.maximum_address - last_start)
        return result

    def _scan_iterator(
        self, scanner: "ScannerInterface", sections: Iterable[Tuple[int, int]]
    ) -> Iterable[IteratorValue]:
        """Iterator that indicates which blocks in the layer are to be read by
        for the scanning.

        Returns a list of blocks (potentially in lower layers) that make
        up this chunk contiguously. Chunks can be no bigger than
        scanner.chunk_size + scanner.overlap DataLayers by default are
        assumed to have no holes.  The second element of each yielded value is
        the logical offset the chunk starts at in the scanned layer.
        """
        for section_start, section_length in sections:
            offset, mapped_offset, length, layer_name = (
                section_start,
                section_start,
                section_length,
                self.name,
            )
            while length > 0:
                chunk_size = min(length, scanner.chunk_size + scanner.overlap)
                yield [(layer_name, mapped_offset, chunk_size)], offset
                # If we've got more than the scanner's chunk_size, only move up by the chunk_size
                if chunk_size > scanner.chunk_size:
                    chunk_size -= scanner.overlap
                length -= chunk_size
                mapped_offset += chunk_size
                offset += chunk_size

    # We ignore the type due to the iterator_value, actually it only needs to match the output from _scan_iterator
    def _scan_read_segments(
        self,
        segments: List[ChunkSegment],
        reuse_cache: Optional[Dict[Tuple[str, int, int], bytes]] = None,
        fill_cache: Optional[Dict[Tuple[str, int, int], bytes]] = None,
    ) -> Tuple[bytes, List[Tuple[str, int]]]:
        """Reads the data segments that make up a scan chunk.

        Segments describe contiguous, readable ranges, so the bytes of a hole
        are never requested here.  ``reuse_cache`` may supply bytes that were
        read for a previous chunk (the shared overlap), avoiding a second read
        of the same physical bytes; ``fill_cache`` records every segment read so
        the following chunk can reuse its overlap.

        The iterator advances by ``chunk_size`` while reading
        ``chunk_size + overlap``, so the overlap is the *tail* of a chunk's read
        and becomes the *head* of the next chunk's first segment.  A segment can
        therefore be partly or wholly covered by the tail of a cached range that
        ends inside it; only the uncovered suffix is read from the layer.  Reads
        that fail because the address is not mappable are skipped, matching the
        historical scanning behaviour of simply skipping unreadable memory.

        Returns the concatenated data together with a mapping, in data order, of
        ``(layer_name, segment_length)`` for each successfully read segment.
        The logical offset of a match is derived from the chunk's logical start
        plus its offset within the concatenated data, so segment addresses (which
        are mapped addresses for linear layers) are not needed here.
        """
        data = b""
        read_map: List[Tuple[str, int]] = []
        for layer_name, address, segment_length in segments:
            segment_end = address + segment_length
            segment_data: Optional[bytes] = None
            if reuse_cache is not None:
                # The iterator advances by chunk_size while reading
                # chunk_size + overlap, so a chunk's trailing ``overlap`` bytes
                # reappear as the *head* of the next chunk's first segment in
                # the same layer.  Take the exact intersection of this segment
                # with a cached range (which must cover the segment's head) and
                # read only the uncovered suffix, never returning fewer bytes
                # than the segment asked for.
                for (
                    cached_layer,
                    cached_address,
                    cached_length,
                ), cached_data in reuse_cache.items():
                    cached_end = cached_address + cached_length
                    if cached_layer != layer_name:
                        continue
                    overlap_start = max(address, cached_address)
                    overlap_end = min(segment_end, cached_end)
                    if overlap_start != address or overlap_end <= address:
                        # The cache can only supply bytes at the segment's head.
                        continue
                    head_length = overlap_end - address
                    slice_start = address - cached_address
                    segment_data = cached_data[
                        slice_start : slice_start + head_length
                    ]
                    break
            try:
                if segment_data is None:
                    segment_data = self.context.layers[layer_name].read(
                        address, segment_length
                    )
                elif len(segment_data) < segment_length:
                    # Only the head was reused; read the remaining suffix.
                    segment_data += self.context.layers[layer_name].read(
                        address + len(segment_data),
                        segment_length - len(segment_data),
                    )
                elif len(segment_data) > segment_length:
                    # A cache bookkeeping mistake must never hand extra bytes to
                    # a scanner; trim to exactly the requested segment.
                    segment_data = segment_data[:segment_length]
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Invalid address in layer {layer_name} found scanning "
                    f"{self.name} at address {address:x}"
                )
                continue
            if fill_cache is not None:
                fill_cache[(layer_name, address, segment_length)] = segment_data
            read_map.append((layer_name, segment_length))
            data += segment_data
        return data, read_map

    @staticmethod
    def _match_location(
        match_offset: int,
        chunk_logical_start: int,
        read_map: List[Tuple[str, int]],
    ) -> ScanLocation:
        """Resolves a match's data-relative offset to its logical location.

        ``match_offset`` is the offset inside the concatenated chunk data.  The
        logical address is the chunk start plus that offset; the layer that
        physically supplied the matching bytes is found by walking the ordered
        segment map.
        """
        logical_offset = chunk_logical_start + match_offset
        location_layer = read_map[0][0] if read_map else None
        consumed = 0
        for layer_name, segment_length in read_map:
            if consumed + segment_length > match_offset:
                location_layer = layer_name
                break
            consumed += segment_length
        return ScanLocation(logical_offset, location_layer)

    def _scan_chunk(
        self,
        scanner: "ScannerInterface",
        progress: "ProgressValue",
        iterator_value: IteratorValue,
        reuse_cache: Optional[Dict[Tuple[str, int, int], bytes]] = None,
        fill_cache: Optional[Dict[Tuple[str, int, int], bytes]] = None,
        locate_results: bool = False,
    ) -> List[Any]:
        data_to_scan, chunk_logical_start = iterator_value
        data, read_map = self._scan_read_segments(
            data_to_scan, reuse_cache=reuse_cache, fill_cache=fill_cache
        )

        if len(data) > scanner.chunk_size + scanner.overlap:
            vollog.debug(f"Scan chunk too large: {hex(len(data))}")

        # Progress is tracked against the logical address immediately after the
        # requested chunk, independent of how many bytes were actually readable.
        requested_length = sum(
            segment_length for _, _, segment_length in data_to_scan
        )
        progress.value = chunk_logical_start + requested_length

        # A full-sized chunk owns logical addresses in [chunk_start,
        # chunk_start + chunk_size); matches starting in the trailing overlap are
        # re-scanned at the start of the next chunk and are dropped here.  The
        # final chunk of a section is shorter than chunk_size and has no
        # successor, so its ownership extends to the end of the data actually
        # read: clamping the boundary keeps every match that has nowhere else to
        # be reported, while still making the result set independent of
        # chunk_size and of serial versus parallel scheduling.
        ownership_boundary = min(
            chunk_logical_start + scanner.chunk_size,
            chunk_logical_start + len(data),
        )
        results: List[Any] = []
        for result in scanner(data, chunk_logical_start):
            # Scanners may yield either a bare logical offset (BytesScanner,
            # RegExScanner) or a tuple whose first element is the logical offset.
            if isinstance(result, int):
                match_logical_offset = result
            elif isinstance(result, (tuple, list)) and result and isinstance(
                result[0], int
            ):
                match_logical_offset = result[0]
            else:
                vollog.debug(
                    f"Scanner {scanner.__class__.__name__} returned a result "
                    "without a leading logical offset; overlap de-duplication "
                    "could not be applied"
                )
                results.append(result)
                continue
            if match_logical_offset >= ownership_boundary:
                # Owned by the following chunk; do not report it twice.
                continue
            if locate_results:
                location = self._match_location(
                    match_logical_offset - chunk_logical_start,
                    chunk_logical_start,
                    read_map,
                )
                results.append((result, location))
            else:
                results.append(result)
        return results

    def _scan_metric(
        self, _scanner: "ScannerInterface", sections: List[Tuple[int, int]]
    ) -> Callable[[int], float]:
        if not sections:
            raise ValueError("Sections have no size, nothing to scan")
        last_section, last_length = sections[-1]
        min_address, _ = sections[0]
        max_address = last_section + last_length

        def _actual_scan_metric(value: int) -> float:
            return max(0, ((value - min_address) * 100) / (max_address - min_address))

        return _actual_scan_metric

    def build_configuration(self) -> interfaces.configuration.HierarchicalDict:
        config = super().build_configuration()

        # Translation Layers are constructable, and therefore require a class configuration variable
        config["class"] = self.__class__.__module__ + "." + self.__class__.__name__
        return config

    # ## Metadata methods

    @property
    def metadata(self) -> Mapping:
        """Returns a ReadOnly copy of the metadata published by this layer."""
        maps = [
            self.context.layers[layer_name].metadata for layer_name in self.dependencies
        ]
        return interfaces.objects.ReadOnlyMapping(
            collections.ChainMap(self._metadata, self._direct_metadata, *maps)
        )


class TranslationLayerInterface(DataLayerInterface, metaclass=ABCMeta):
    """Provides a layer that translates or transforms another layer or layers.

    Translation layers always depend on another layer (typically
    translating offsets in a virtual offset space into a smaller
    physical offset space).
    """

    @abstractmethod
    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        ignore_errors will provide all available maps with gaps, but
        their total length may not add up to the requested length This
        allows translation layers to provide maps of contiguous regions
        in one layer
        """
        return []

    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        """Returns a list of layer names that this layer translates onto."""
        return []

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        """Decodes any necessary data.  Note, additional data may need to be read from the lower layer, such as lookup
        tables or similar.  The data provided to this layer is purely that data which encompasses the requested data
        range.

        Args:
            data: The bytes of data necessary for decoding
            mapped_offset: The offset in the underlying layer where the data would begin
            offset: The offset in the higher-layer where the data would begin
            output_length: The expected length of the returned data

        Returns:
             The data to be read from the underlying layer."""
        return data

    def _encode_data(
        self, layer_name: str, mapped_offset: int, offset: int, value: bytes
    ) -> bytes:
        """Encodes any necessary data.

        Args:
            layer_name: The layer to write data back to
            mapped_offset: The offset in the underlying layer where the data would begin
            offset: The offset in the higher-layer where the data would begin
            value: The new value to encode

        Returns:
             The data to be rewritten at mapped_offset."""
        return value

    # ## Read/Write functions for mapped pages

    @functools.lru_cache(maxsize=512)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of
        length size."""
        current_offset = offset
        output: bytes = b""
        for (
            layer_offset,
            sublength,
            mapped_offset,
            mapped_length,
            layer,
        ) in self.mapping(offset, length, ignore_errors=pad):
            if not pad and layer_offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )
            elif layer_offset > current_offset:
                output += b"\x00" * (layer_offset - current_offset)
                current_offset = layer_offset
            # The layer_offset can be less than the current_offset in non-linearly mapped layers
            # it does not suggest an overlap, but that the data is in an encoded block
            if mapped_length > 0:
                unprocessed_data = self._context.layers.read(
                    layer, mapped_offset, mapped_length, pad
                )
                processed_data = self._decode_data(
                    unprocessed_data, mapped_offset, layer_offset, sublength
                )
                if len(processed_data) != sublength:
                    raise ValueError(
                        "ProcessedData length does not match expected length of chunk"
                    )
                output += processed_data
                current_offset += sublength
        return output + (b"\x00" * (length - len(output)))

    def write(self, offset: int, value: bytes) -> None:
        """Writes a value at offset, distributing the writing across any
        underlying mapping."""
        current_offset = offset
        length = len(value)
        for (
            layer_offset,
            sublength,
            mapped_offset,
            mapped_length,
            layer,
        ) in self.mapping(offset, length):
            if layer_offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )

            value_chunk = value[
                layer_offset - offset : layer_offset - offset + sublength
            ]
            new_data = self._encode_data(
                layer, mapped_offset, layer_offset, value_chunk
            )
            self._context.layers.write(layer, mapped_offset, new_data)

            current_offset += len(new_data)

    def _scan_iterator(
        self,
        scanner: "ScannerInterface",
        sections: Iterable[Tuple[int, int]],
        linear: bool = False,
    ) -> Iterable[IteratorValue]:
        """Iterator that indicates which blocks in the layer are to be read by
        for the scanning.

        Returns a list of blocks (potentially in lower layers) that make
        up this chunk contiguously. Chunks can be no bigger than
        scanner.chunk_size + scanner.overlap DataLayers by default are
        assumed to have no holes.  The second element of each yielded value is
        the logical offset the chunk starts at in the scanned layer.

        Each yielded chunk only ever spans readable, contiguous memory: a hole
        in the mapping ships the current chunk and opens a fresh one, so bytes on
        either side of an unmapped range are never presented to a scanner as
        adjacent data.
        """
        for section_start, section_length in sections:
            output: List[ChunkSegment] = []

            # Hold the offsets of each chunk (including how much has been filled)
            chunk_start = chunk_position = 0
            # Logical offset (in the scanned layer) that the current chunk begins at
            chunk_logical_start = chunk_start

            # For each section, find out which bits of its exists and where they map to
            # This is faster than cutting the entire space into scan_chunk sized blocks and then
            # finding out what exists (particularly if most of the space isn't mapped)
            for mapped in self.mapping(
                section_start, section_length, ignore_errors=True
            ):
                offset, sublength, mapped_offset, mapped_length, layer_name = mapped

                # Setup the variables for this block
                block_start = offset
                block_end = offset + sublength

                # Setup the necessary bits for non-linear mappings
                # For linear we give one layer down and mapped offsets (therefore the conversion)
                # This saves an tiny amount of time not have to redo lookups we've already done
                # For non-linear layers, we give the layer name and the offset in the layer name
                # so that the read/conversion occurs properly
                conversion = mapped_offset - offset if linear else 0
                return_name = layer_name if linear else self.name

                # If this isn't contiguous, start a new chunk
                if chunk_position < block_start:
                    if output:
                        yield output, chunk_logical_start
                    output = []
                    chunk_start = chunk_position = block_start
                    chunk_logical_start = block_start

                # Halfway through a chunk, finish the chunk, then take more
                if chunk_position != chunk_start:
                    chunk_size = min(
                        chunk_position - chunk_start,
                        scanner.chunk_size + scanner.overlap,
                    )
                    output += [(return_name, chunk_position + conversion, chunk_size)]
                    chunk_start = chunk_position + chunk_size
                    chunk_position = chunk_start

                # Pack chunks, if we're enter the loop (starting a new chunk) and there's already chunk there, ship it
                for chunk_start in range(chunk_position, block_end, scanner.chunk_size):
                    if output:
                        yield output, chunk_logical_start
                        output = []
                        chunk_position = chunk_start
                        chunk_logical_start = chunk_start
                    # Take from chunk_position as far as the block can go,
                    # or as much left of a scanner chunk as we can
                    chunk_size = min(
                        block_end - chunk_position,
                        scanner.chunk_size
                        + scanner.overlap
                        - (chunk_position - chunk_start),
                    )
                    output += [(return_name, chunk_position + conversion, chunk_size)]
                    chunk_start = chunk_position + chunk_size
                    chunk_position = chunk_start

            # Ship anything that might be left
            if output:
                yield output, chunk_logical_start


class LayerContainer(collections.abc.Mapping):
    """Container for multiple layers of data."""

    def __init__(self) -> None:
        self._layers: Dict[str, DataLayerInterface] = {}

    def read(self, layer: str, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from a particular layer at offset for length bytes.

        Returns 'bytes' not 'str'

        Args:
            layer: The name of the layer to read from
            offset: Where to begin reading within the layer
            length: How many bytes to read from the layer
            pad: Whether to raise exceptions or return null bytes when errors occur

        Returns:
            The result of reading from the requested layer
        """
        return self[layer].read(offset, length, pad)

    def __eq__(self, other):
        return dict(self) == dict(other)

    def write(self, layer: str, offset: int, data: bytes) -> None:
        """Writes to a particular layer at offset for length bytes."""
        self[layer].write(offset, data)

    def add_layer(self, layer: DataLayerInterface) -> None:
        """Adds a layer to memory model.

        This will throw an exception if the required dependencies are not met

        Args:
            layer: the layer to add to the list of layers (based on layer.name)
        """
        if layer.name in self._layers:
            raise exceptions.LayerException(
                layer.name, f"Layer already exists: {layer.name}"
            )
        if isinstance(layer, TranslationLayerInterface):
            missing_list = [
                sublayer
                for sublayer in layer.dependencies
                if sublayer not in self._layers
            ]
            if missing_list:
                raise exceptions.LayerException(
                    layer.name,
                    f"Layer {layer.name} has unmet dependencies: {', '.join(missing_list)}",
                )
        self._layers[layer.name] = layer

    def del_layer(self, name: str) -> None:
        """Removes the layer called name.

        This will throw an exception if other layers depend upon this layer

        Args:
            name: The name of the layer to delete
        """
        for layer in self._layers:
            if name in self._layers[layer].dependencies:
                raise exceptions.LayerException(
                    self._layers[layer].name,
                    f"Layer {name} is depended upon by {layer}",
                )
        # Otherwise, wipe out the layer
        self._layers[name].destroy()
        del self._layers[name]

    def free_layer_name(self, prefix: str = "layer") -> str:
        """Returns an unused layer name to ensure no collision occurs when
        inserting a layer.

        Args:
            prefix: A descriptive string with which to prefix the layer name

        Returns:
            A string containing a name, prefixed with prefix, not currently in use within the LayerContainer
        """
        if prefix not in self:
            return prefix
        count = 1
        while f"{prefix}_{count}" in self:
            count += 1
        return f"{prefix}_{count}"

    def __getitem__(self, name: str) -> DataLayerInterface:
        """Returns the layer of specified name."""
        return self._layers[name]

    def __len__(self) -> int:
        return len(self._layers)

    def __iter__(self):
        return iter(self._layers)

    def check_cycles(self) -> None:
        """Runs through the available layers and identifies if there are cycles
        in the DAG."""
        # TODO: Is having a cycle check necessary?
        raise NotImplementedError("Cycle checking has not yet been implemented")


class DummyProgress:
    """A class to emulate Multiprocessing/threading Value objects."""

    def __init__(self) -> None:
        self.value = 0
