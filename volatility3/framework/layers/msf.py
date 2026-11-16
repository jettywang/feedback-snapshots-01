# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import math
from typing import Optional, Dict, Any, List, Iterable, Tuple

from volatility3.framework import interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed


class PDBFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying MSF file format."""


class PdbMultiStreamFormat(linear.LinearlyMappedLayer):
    _headers = {
        "MSF_HDR": "Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47",
        "BIG_MSF_HDR": "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53",
    }

    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]

        self._pdb_symbol_table = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", "pdb"
        )
        response = self._check_header()
        if response is None:
            raise PDBFormatException(name, "Could not find a suitable header")
        self._version, self._header = response
        self._streams: Dict[int, str] = {}

    @property
    def pdb_symbol_table(self) -> str:
        return self._pdb_symbol_table

    def _read_pages(self, pages: List[int], length: int, description: str) -> bytes:
        """Reads ``length`` logical bytes from a list of MSF page numbers.

        The read is bounded by both the requested length and the supplied page
        list.  A short list or a page outside the base layer is reported against
        this MSF layer rather than silently borrowing bytes from the surrounding
        container or another stream.
        """
        page_size = self.page_size
        base_layer = self.context.layers[self._base_layer]
        base_size = base_layer.maximum_address + 1
        output = bytearray()
        for page in pages:
            if len(output) >= length:
                break
            page = int(page)
            page_start = page * page_size
            chunk_size = min(page_size, length - len(output))
            if (
                page < 0
                or page_start >= base_size
                or page_start + chunk_size > base_size
            ):
                raise PDBFormatException(
                    self.name,
                    f"{description} page number {page} is outside the base layer",
                )
            try:
                output += base_layer.read(page_start, chunk_size)
            except exceptions.InvalidAddressException as exc:
                raise PDBFormatException(
                    self.name, f"{description} page {page} could not be read"
                ) from exc
        if len(output) != length:
            raise PDBFormatException(
                self.name,
                f"{description} is truncated: expected {length} bytes from "
                f"{len(pages)} pages, read {len(output)}",
            )
        return bytes(output)

    def read_streams(self):
        # Shortcut in case they've already been read
        if self._streams:
            return None

        directory_size = int(self._header.StreamInfo.StreamInfoSize)
        if directory_size <= 0:
            raise PDBFormatException(self.name, "Stream directory is empty")

        # Recover the root table, by recovering the root table index table...
        module = self.context.module(self.pdb_symbol_table, self._base_layer, offset=0)
        entry_size = module.get_type("unsigned long").size

        directory_page_count = math.ceil(directory_size / self.page_size)
        root_index_count = math.ceil(
            (directory_page_count * entry_size) / self.page_size
        )
        root_index_offset = self._header.vol.size
        root_index_length = root_index_count * entry_size
        try:
            root_index_data = self.context.layers.read(
                self._base_layer, root_index_offset, root_index_length
            )
        except exceptions.InvalidAddressException as exc:
            raise PDBFormatException(
                self.name, "Stream directory index extends beyond the base layer"
            ) from exc
        if len(root_index_data) != root_index_length:
            raise PDBFormatException(
                self.name,
                f"Stream directory index is truncated: expected "
                f"{root_index_length} bytes, read {len(root_index_data)}",
            )
        root_index_pages = [
            int.from_bytes(
                root_index_data[offset : offset + entry_size], byteorder="little"
            )
            for offset in range(0, len(root_index_data), entry_size)
        ]

        page_list_data = self._read_pages(
            root_index_pages,
            directory_page_count * entry_size,
            "Stream directory page list",
        )
        directory_pages = [
            int.from_bytes(
                page_list_data[offset : offset + entry_size], byteorder="little"
            )
            for offset in range(0, len(page_list_data), entry_size)
        ]
        directory = self._read_pages(
            directory_pages, directory_size, "Stream directory"
        )

        def directory_entry(offset: int) -> int:
            return int.from_bytes(
                directory[offset : offset + entry_size], byteorder="little"
            )

        num_streams = directory_entry(0)
        max_streams = (directory_size // entry_size) - 1
        if num_streams > max_streams:
            raise PDBFormatException(
                self.name,
                f"Stream directory is truncated: it declares {num_streams} streams "
                f"but can only contain {max_streams} stream sizes",
            )

        stream_sizes = [
            directory_entry((index + 1) * entry_size) for index in range(num_streams)
        ]

        current_offset = (num_streams + 1) * entry_size
        stream_pages: Dict[int, Optional[List[int]]] = {}
        page_count_needed = 0
        for stream_size in stream_sizes:
            if stream_size not in (0, 0xFFFFFFFF):
                page_count_needed += math.ceil(stream_size / self.page_size)
        page_list_bytes = page_count_needed * entry_size
        directory_end = current_offset + page_list_bytes
        if directory_end > directory_size:
            raise PDBFormatException(
                self.name,
                f"Stream page lists require {page_list_bytes} bytes but only "
                f"{directory_size - current_offset} remain in the "
                f"{directory_size}-byte stream directory",
            )
        if directory_end != directory_size:
            # A producer may pad the directory tail, but the padding must not
            # look like another stream's page numbers hidden in unused space.
            if directory_end > directory_size or any(
                directory[directory_end:directory_size]
            ):
                raise PDBFormatException(
                    self.name,
                    f"Stream page lists end at {directory_end} but the stream "
                    f"directory is {directory_size} bytes; stream sizes and page "
                    f"lists disagree",
                )

        # Validate the entire directory before constructing any stream layers, so
        # that a truncated page list cannot consume another stream's page numbers.
        for stream in range(num_streams):
            stream_size = stream_sizes[stream]
            list_size = math.ceil(stream_size / self.page_size)
            if list_size == 0 or stream_size == 0xFFFFFFFF:
                stream_pages[stream] = None
                continue
            stream_pages[stream] = [
                directory_entry(current_offset + (page * entry_size))
                for page in range(list_size)
            ]
            current_offset += list_size * entry_size

        for stream, pages in stream_pages.items():
            if pages is None:
                self._streams[stream] = None
            else:
                self._streams[stream] = self.create_stream_from_pages(
                    "stream" + str(stream), stream_sizes[stream], pages
                )

    def create_stream_from_pages(
        self, stream_name: str, maximum_size: int, pages: List[int]
    ) -> str:
        # Construct a root layer based on a number of pages
        layer_name = self.name + "_" + stream_name
        path_join = interfaces.configuration.path_join
        config_path = path_join(self.config_path, stream_name)
        self.context.config[path_join(config_path, "base_layer")] = self.name
        self.context.config[path_join(config_path, "pages")] = pages
        self.context.config[path_join(config_path, "maximum_size")] = maximum_size
        layer = PdbMSFStream(self.context, config_path, layer_name)
        self.context.layers.add_layer(layer)
        return layer_name

    def _check_header(self) -> Optional[Tuple[str, interfaces.objects.ObjectInterface]]:
        """Verifies the header of the PDB file and returns the version of the
        file."""
        for header in self._headers:
            header_type = self.pdb_symbol_table + constants.BANG + header
            current_header = self.context.object(header_type, self._base_layer, 0)
            if utility.array_to_string(current_header.Magic) == self._headers[header]:
                if not (
                    current_header.PageSize < 0x100
                    or current_header.PageSize > (128 * 0x10000)
                ):
                    return header, current_header
        return None

    @property
    def page_size(self):
        return self._header.PageSize

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layers that this layer is dependent
        upon."""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name="base_layer", optional=False)
        ]

    @property
    def maximum_address(self) -> int:
        return self.context.layers[self._base_layer].maximum_address

    @property
    def minimum_address(self) -> int:
        return self.context.layers[self._base_layer].minimum_address

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.context.layers[self._base_layer].is_valid(offset, length)

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        yield offset, length, offset, length, self._base_layer

    def get_stream(self, index) -> Optional["PdbMSFStream"]:
        self.read_streams()
        if index not in self._streams:
            raise PDBFormatException(self.name, "Stream not present")
        if self._streams[index]:
            layer = self.context.layers[self._streams[index]]
            if isinstance(layer, PdbMSFStream):
                return layer
        return None


class PdbMSFStream(linear.LinearlyMappedLayer):
    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]
        self._pages = self.config.get("pages", [])
        self._pages_len = len(self._pages)
        if not self._pages:
            raise PDBFormatException(name, "Invalid/no pages specified")
        if not isinstance(self._pdb_layer, PdbMultiStreamFormat):
            raise TypeError("Base Layer must be a PdbMultiStreamFormat layer")
        self._maximum_size = int(self.config.get("maximum_size", 0))
        if self._maximum_size < 0:
            raise PDBFormatException(
                name, f"Invalid stream size: {self._maximum_size}"
            )
        expected_pages = math.ceil(self._maximum_size / self._pdb_layer.page_size)
        if self._pages_len != expected_pages:
            raise PDBFormatException(
                name,
                f"Stream size {self._maximum_size} requires {expected_pages} pages "
                f"but {self._pages_len} page numbers were supplied",
            )

    @property
    def pdb_symbol_table(self) -> Optional[str]:
        layer = self._context.layers[self._base_layer]
        if isinstance(layer, PdbMultiStreamFormat):
            return layer.pdb_symbol_table
        else:
            return None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ListRequirement(
                name="pages", element_type=int, min_elements=1
            ),
            requirements.TranslationLayerRequirement(name="base_layer"),
            requirements.IntRequirement(name="maximum_size"),
        ]

    def _map_offset(self, stream_offset: int) -> int:
        """Translates a logical stream offset to a physical container offset.

        Raises InvalidAddressException against this stream for offsets outside
        the declared size, page numbers outside the stream's page list, and page
        numbers that map outside the MSF container.
        """
        if stream_offset < 0 or stream_offset >= self._maximum_size:
            raise exceptions.InvalidAddressException(self.name, stream_offset)
        page_size = self._pdb_layer.page_size
        page = stream_offset // page_size
        if page >= self._pages_len:
            raise exceptions.InvalidAddressException(self.name, stream_offset)
        page_number = int(self._pages[page])
        page_position = stream_offset % page_size
        mapped_offset = page_number * page_size + page_position
        physical_size = self._pdb_layer.maximum_address + 1
        if page_number < 0 or mapped_offset < 0 or mapped_offset >= physical_size:
            raise exceptions.InvalidAddressException(
                self.name,
                stream_offset,
                f"Stream page {page} maps outside the MSF container",
            )
        return mapped_offset

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        if length < 0:
            if not ignore_errors:
                raise exceptions.InvalidAddressException(self.name, offset)
            return
        if length == 0:
            # A zero-length mapping keeps translate() and boundary probes
            # working without yielding any bytes that belong to another stream.
            try:
                if (
                    offset == self._maximum_size
                    and self._maximum_size > 0
                    and self._pages_len
                ):
                    page_size = self._pdb_layer.page_size
                    mapped_offset = (
                        int(self._pages[-1]) * page_size
                        + (self._maximum_size % page_size or page_size)
                    )
                else:
                    mapped_offset = self._map_offset(offset)
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return
            yield offset, 0, mapped_offset, 0, self._base_layer
            return
        page_size = self._pdb_layer.page_size
        returned = 0
        while length > 0:
            stream_offset = offset + returned
            try:
                mapped_offset = self._map_offset(stream_offset)
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return
            chunk_size = min(
                page_size - (stream_offset % page_size),
                length,
                self._maximum_size - stream_offset,
            )
            if mapped_offset + chunk_size > self._pdb_layer.maximum_address + 1:
                if not ignore_errors:
                    raise exceptions.InvalidAddressException(
                        self.name,
                        stream_offset,
                        f"Stream page {stream_offset // page_size} maps outside "
                        f"the MSF container",
                    )
                return
            yield (
                stream_offset,
                chunk_size,
                mapped_offset,
                chunk_size,
                self._base_layer,
            )
            returned += chunk_size
            length -= chunk_size

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        if offset + length > self._maximum_size:
            return False
        try:
            mapped_length = 0
            for _, chunk_size, mapped_offset, mapped_size, layer in self.mapping(
                offset, length, ignore_errors=True
            ):
                if not self.context.layers[layer].is_valid(mapped_offset, mapped_size):
                    return False
                mapped_length += chunk_size
            return mapped_length == length
        except exceptions.InvalidAddressException:
            return False

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        # Existing PDB consumers (notably pdbconv) treat this as the stream
        # length, so keep the declared size rather than the last valid offset.
        return self._maximum_size

    @property
    def _pdb_layer(self) -> PdbMultiStreamFormat:
        if self._base_layer not in self._context.layers:
            raise PDBFormatException(
                self._base_layer,
                f"No PdbMultiStreamFormat layer found: {self._base_layer}",
            )
        result = self._context.layers[self._base_layer]
        if isinstance(result, PdbMultiStreamFormat):
            return result
        raise TypeError("Base layer is not PdbMultiStreamFormat")
