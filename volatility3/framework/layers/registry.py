# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import dataclasses
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions

vollog = logging.getLogger(__name__)

# Index of the stable (on-disk) storage inside _HHIVE.Storage
STABLE_STORE = 0
# Index of the volatile (memory-only) storage inside _HHIVE.Storage
VOLATILE_STORE = 1
# Bit that marks a cell index as belonging to the volatile storage
VOLATILE_BIT = 0x80000000


@dataclasses.dataclass(frozen=True)
class CellProvenance:
    """Evidence of where a single registry cell was actually read from.

    The registry keeps two independent storage areas: a stable (non-volatile,
    backed by the hive file) store and a volatile (memory-only) store.  A cell
    index's low 31 bits are only meaningful together with the high (volatile)
    bit, so the same low index in the two stores names two different objects.
    This record preserves the full index rather than masking the bit away,
    allowing every read to be traced back to a specific store and memory page.

    Attributes:
        cell_index: The full cell index as referenced by the hive, including
            the volatile high bit when set.
        cell_offset: The hive-relative offset of the cell's data, i.e. the
            index with the volatile bit removed.
        store: ``STABLE_STORE`` (0) or ``VOLATILE_STORE`` (1).
        is_volatile: Whether the index belongs to the volatile store.
        directory_index: Directory entry used by the storage map.
        table_index: Table entry used by the storage map.
        suboffset: Offset within the mapped 4 KiB page.
        mapped_offset: Physical offset in the underlying memory layer that the
            cell maps to.
        memory_layer: Name of the underlying layer supplying the bytes.
        hive_name: Name of the owning hive.
    """

    cell_index: int
    cell_offset: int
    store: int
    is_volatile: bool
    directory_index: int
    table_index: int
    suboffset: int
    mapped_offset: int
    memory_layer: str
    hive_name: str


class RegistryException(exceptions.LayerException):
    """Base Registry Exception class for catching Registry layer errors.

    The optional ``cell_index`` carries the full index (volatile bit included)
    that was being resolved, so failures can be attributed to a specific store
    without ever consulting the other one.
    """

    def __init__(
        self,
        layer_name: str,
        *args: Any,
        cell_index: Optional[int] = None,
        store: Optional[int] = None,
    ) -> None:
        super().__init__(layer_name, *args)
        self.cell_index = cell_index
        self.store = store


class RegistryFormatException(RegistryException):
    """Thrown when an error occurs with the underlying Registry file format."""


class RegistryInvalidIndex(RegistryException):
    """Thrown when an index that doesn't exist or can't be found occurs."""


class RegistryIndexOutOfRange(RegistryInvalidIndex):
    """Thrown when a cell index exceeds the owning store's hive range.

    This is a structural failure: the index names an offset that the store was
    never large enough to hold.  It must not be retried against the other
    storage, because the volatile bit is part of the index and the two stores
    do not share an address space.
    """


class RegistryCellPagedOut(RegistryInvalidIndex):
    """Thrown when a cell index is in range but its map entry is not resident.

    The storage map points at a page that the underlying memory layer cannot
    provide (for example a swapped-out bin).  Distinguishing this from
    :class:`RegistryIndexOutOfRange` and from a genuinely absent key lets an
    investigator tell missing memory apart from missing data.
    """


class RegistryHive(linear.LinearlyMappedLayer):
    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

        self._base_layer = self.config["base_layer"]
        self._hive_offset = self.config["hive_offset"]
        self._table_name = self.config["nt_symbols"]
        self._page_size = 1 << 12

        self._reg_table_name = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", "registry"
        )

        cmhive = self.context.object(
            self._table_name + constants.BANG + "_CMHIVE",
            self._base_layer,
            self._hive_offset,
        )
        self._cmhive_name = cmhive.get_name()
        self.hive = cmhive.Hive

        # TODO: Check the checksum
        if self.hive.Signature != 0xBEE0BEE0:
            raise RegistryFormatException(
                self.name,
                f"Registry hive at {self._hive_offset} does not have a valid signature",
            )

        # Win10 17063 introduced the Registry process to map most hives.  Check
        # if it exists and update RegistryHive._base_layer
        try:
            registry_proc = self._find_registry_process()
            if registry_proc:
                self._base_layer = registry_proc.add_process_layer()
        except ValueError:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                "Error walking process list, results may not be valid.",
            )

        self._base_block = self.hive.BaseBlock.dereference()

        self._minaddr = 0
        try:
            self._hive_maxaddr_non_volatile = self.hive.Storage[0].Length
            self._hive_maxaddr_volatile = self.hive.Storage[1].Length
            self._maxaddr = 0x80000000 | self._hive_maxaddr_volatile
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Setting hive {self.name} max address to {hex(self._maxaddr)}",
            )
        except exceptions.InvalidAddressException:
            self._hive_maxaddr_non_volatile = 0x7FFFFFFF
            self._hive_maxaddr_volatile = 0x7FFFFFFF
            self._maxaddr = 0x80000000 | self._hive_maxaddr_volatile
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Exception when setting hive {self.name} max address, using {hex(self._maxaddr)}",
            )

    def _find_registry_process(self) -> Optional[extensions.EPROCESS]:
        """Walk the active process list and return the Registry process if it exists. Duplicates
        PsList.list_processes() since pulling in the plugin causes problems.

        Returns:
            The Registry EPROCESS object if it exists, or None
        """

        kernel = self.context.modules.get(self.config["kernel_module_name"])

        if not kernel or not kernel.offset:
            raise ValueError(
                "Intel layer does not have an associated kernel virtual offset, failing"
            )

        ps_aph_offset = kernel.get_symbol("PsActiveProcessHead").address
        list_entry = kernel.object(object_type="_LIST_ENTRY", offset=ps_aph_offset)
        reloff = kernel.get_type("_EPROCESS").relative_child_offset(
            "ActiveProcessLinks"
        )
        eproc = kernel.object(
            object_type="_EPROCESS",
            offset=list_entry.vol.offset - reloff,
            absolute=True,
        )

        for proc in eproc.ActiveProcessLinks:
            proc_name = proc.ImageFileName.cast(
                "string", max_length=proc.ImageFileName.vol.count, errors="replace"
            )
            if proc_name == "Registry" and proc.InheritedFromUniqueProcessId == 4:
                return proc

        return None

    def _get_hive_maxaddr(self, volatile):
        return (
            self._hive_maxaddr_volatile if volatile else self._hive_maxaddr_non_volatile
        )

    def get_name(self) -> str:
        return self._cmhive_name or "[NONAME]"

    @property
    def hive_offset(self) -> int:
        return self._hive_offset

    @property
    def address_mask(self) -> int:
        """Return a mask that allows for the volatile bit to be set."""
        return super().address_mask | 0x80000000

    @property
    def root_cell_offset(self) -> int:
        """Returns the offset for the root cell in this hive."""
        with contextlib.suppress(exceptions.InvalidAddressException):
            if (
                self._base_block.Signature.cast(
                    "string", max_length=4, encoding="latin-1"
                )
                == "regf"
            ):
                return self._base_block.RootCell
        return 0x20

    def get_cell(self, cell_offset: int) -> "objects.StructType":
        """Returns the appropriate Cell value for a cell offset."""
        # This would be an _HCELL containing CELL_DATA, but to save time we skip the size of the HCELL
        cell = self._context.object(
            object_type=self._table_name + constants.BANG + "_CELL_DATA",
            offset=cell_offset + 4,
            layer_name=self.name,
        )
        return cell

    def cell_provenance(self, cell_index: int) -> CellProvenance:
        """Resolves a full cell index to the store and memory it reads from.

        The high bit of ``cell_index`` selects the store and is never stripped
        in order to consult the other storage: the same low 31-bit index in the
        stable and volatile stores is a different object.

        Raises:
            RegistryIndexOutOfRange: if the index exceeds the selected store's
                hive range.
            RegistryCellPagedOut: if the storage map entry cannot be read from
                the underlying memory layer.
        """
        volatile = bool(cell_index & VOLATILE_BIT)
        store = VOLATILE_STORE if volatile else STABLE_STORE
        hive_relative = cell_index & 0x7FFFFFFF
        if hive_relative > self._get_hive_maxaddr(volatile):
            vollog.log(
                constants.LOGLEVEL_VVV,
                "Layer {} couldn't translate index {}, greater than {} in {} store of {}".format(
                    self.name,
                    hex(cell_index),
                    hex(self._get_hive_maxaddr(volatile)),
                    "volatile" if volatile else "non-volatile",
                    self.get_name(),
                ),
            )
            raise RegistryIndexOutOfRange(
                self.name,
                "Cell index {} is outside the {} store hive range".format(
                    hex(cell_index), "volatile" if volatile else "stable"
                ),
                cell_index=cell_index,
                store=store,
            )

        storage = self.hive.Storage[store]
        dir_index = self._mask(cell_index, 30, 21) >> 21
        table_index = self._mask(cell_index, 20, 12) >> 12
        suboffset = self._mask(cell_index, 11, 0) >> 0

        try:
            table = storage.Map.Directory[dir_index]
            entry = table.Table[table_index]
            block_offset = entry.get_block_offset()
        except exceptions.InvalidAddressException as excp:
            vollog.log(
                constants.LOGLEVEL_VVV,
                "Layer {} map entry for cell {} ({} store) is not resident: {}".format(
                    self.name,
                    hex(cell_index),
                    "volatile" if volatile else "stable",
                    excp,
                ),
            )
            raise RegistryCellPagedOut(
                self.name,
                "Storage map entry for cell {} in the {} store is not resident".format(
                    hex(cell_index), "volatile" if volatile else "stable"
                ),
                cell_index=cell_index,
                store=store,
            ) from excp

        return CellProvenance(
            cell_index=cell_index,
            cell_offset=hive_relative,
            store=store,
            is_volatile=volatile,
            directory_index=dir_index,
            table_index=table_index,
            suboffset=suboffset,
            mapped_offset=block_offset + suboffset,
            memory_layer=self._base_layer,
            hive_name=self.get_name(),
        )

    def get_node_provenance(
        self, cell_index: int
    ) -> Tuple["objects.StructType", CellProvenance]:
        """Returns a node together with the provenance of its backing cell.

        Raises the same exceptions as :meth:`cell_provenance`, or
        RegistryCellPagedOut if the cell's bytes are unreadable despite a
        resolvable map entry.  A key that simply does not exist is reported by
        callers via KeyError rather than any of these exceptions.
        """
        provenance = self.cell_provenance(cell_index)
        try:
            node = self.get_node(cell_index)
        except (RegistryException, exceptions.InvalidAddressException) as excp:
            if isinstance(excp, RegistryException):
                raise
            raise RegistryCellPagedOut(
                self.name,
                f"Cell at {hex(cell_index)} cannot be read from the underlying memory",
                cell_index=cell_index,
                store=provenance.store,
            ) from excp
        return node, provenance

    def get_node(self, cell_offset: int) -> "objects.StructType":
        """Returns the appropriate Node, interpreted from the Cell based on its
        Signature."""
        cell = self.get_cell(cell_offset)
        try:
            signature = cell.cast("string", max_length=2, encoding="latin-1")
        except (RegistryException, exceptions.InvalidAddressException):
            vollog.debug(
                f"Failed to get cell signature for cell (0x{cell.vol.offset:x})"
            )
            return cell
        if signature == "nk":
            return cell.u.KeyNode
        elif signature == "sk":
            return cell.u.KeySecurity
        elif signature == "vk":
            return cell.u.KeyValue
        elif signature == "db":
            # Big Data
            return cell.u.ValueData
        elif signature == "lf" or signature == "lh" or signature == "ri":
            # Fast Leaf, Hash Leaf, Index Root
            return cell.u.KeyIndex
        else:
            # It doesn't matter that we use KeyNode, we're just after the first two bytes
            vollog.debug(
                f"Unknown Signature {signature} (0x{cell.u.KeyNode.Signature:x}) at offset {cell_offset}"
            )
            return cell

    def get_key(
        self, key: str, return_list: bool = False
    ) -> Union[List[objects.StructType], objects.StructType]:
        """Gets a specific registry key by key path.

        return_list specifies whether the return result will be a single
        node (default) or a list of nodes from root to the current node
        (if return_list is true).

        Raises RegistryFormatException if an invalid structure is encountered
        Raises KeyError if the key is not found
        """
        root_node = self.get_node(self.root_cell_offset)
        if not root_node.vol.type_name.endswith(constants.BANG + "_CM_KEY_NODE"):
            raise RegistryFormatException(
                self.name,
                f"Encountered {root_node.vol.type_name} instead of _CM_KEY_NODE",
            )
        node_key = [root_node]
        if key.endswith("\\"):
            key = key[:-1]
        key_array = key.split("\\")
        found_key: List[str] = []
        while key_array and node_key:
            subkeys = node_key[-1].get_subkeys()
            for subkey in subkeys:
                # registry keys are not case sensitive so compare likewise
                # https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry
                if subkey.get_name().casefold() == key_array[0].casefold():
                    node_key = node_key + [subkey]
                    found_key, key_array = found_key + [key_array[0]], key_array[1:]
                    break
            else:
                node_key = []
        if not node_key:
            raise KeyError(
                "Key {} not found under {}".format(key_array[0], "\\".join(found_key))
            )
        if return_list:
            return node_key
        return node_key[-1]

    def visit_nodes(
        self,
        visitor: Callable[[objects.StructType], None],
        node: Optional[objects.StructType] = None,
    ) -> None:
        """Applies a callable (visitor) to all nodes within the registry tree
        from a given node."""
        if not node:
            node = self.get_node(self.root_cell_offset)
        visitor(node)
        for node in node.get_subkeys():
            self.visit_nodes(visitor, node)

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        high_mask = (2 ** (high_bit + 1)) - 1
        low_mask = (2**low_bit) - 1
        mask = high_mask ^ low_mask
        # print(high_bit, low_bit, bin(mask), bin(value))
        return value & mask

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.IntRequirement(
                name="hive_offset",
                description="Offset within the base layer at which the hive lives",
                default=0,
                optional=False,
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols", description="Windows kernel symbols"
            ),
            requirements.TranslationLayerRequirement(
                name="base_layer",
                description="Layer in which the registry hive lives",
                optional=False,
            ),
        ]

    def _translate(self, offset: int) -> int:
        """Translates a single cell index to a cell memory offset and the
        suboffset within it.

        The store is selected solely from the volatile high bit; the bit is
        never masked off to look the index up in the other storage.  Range
        failures and non-resident map entries surface as the distinct
        RegistryIndexOutOfRange and RegistryCellPagedOut exceptions.
        """
        return self.cell_provenance(offset).mapped_offset

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        if length < 0:
            raise ValueError("Mapping length of RegistryHive must be positive or zero")

        # Return the translated offset without checking bounds within the HBIN.  The check runs into
        # issues when pages are swapped on large HBINs, and did not seem to find any errors on single page
        # HBINs while dramatically slowing performance.
        response = []
        current_offset = offset
        remaining_length = length
        chunk_size = self._page_size - (offset & (self._page_size - 1))
        while remaining_length > 0:
            chunk_size = min(chunk_size, remaining_length, self._page_size)
            try:
                translated_offset = self._translate(current_offset)
                response.append(
                    (
                        current_offset,
                        chunk_size,
                        translated_offset,
                        chunk_size,
                        self._base_layer,
                    )
                )
            except exceptions.LayerException:
                if not ignore_errors:
                    raise
            current_offset += chunk_size
            remaining_length -= chunk_size
            chunk_size = self._page_size
        return response

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of layer names that this layer translates onto."""
        return [self.config["base_layer"]]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns a boolean based on whether the offset is valid or not."""
        with contextlib.suppress(exceptions.InvalidAddressException):
            # Pass this to the lower layers for now
            return all(
                self.context.layers[layer].is_valid(offset, length)
                for (_, _, offset, length, layer) in self.mapping(offset, length)
            )
        return False

    @property
    def minimum_address(self) -> int:
        return self._minaddr

    @property
    def maximum_address(self) -> int:
        return self._maxaddr
