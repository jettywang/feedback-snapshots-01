from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from functools import cached_property, lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO, TypeAlias

from dissect.util.ts import wintimestamp

from dissect.regf.c_regf import (
    KEY,
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ,
    REG_FULL_RESOURCE_DESCRIPTOR,
    REG_LINK,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_RESOURCE_REQUIREMENTS_LIST,
    REG_SZ,
    VALUE,
    c_regf,
)
from dissect.regf.exceptions import (
    Error,
    InvalidLinkError,
    LinkLoopError,
    LinkTargetNotFoundError,
    MountNotFoundError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from datetime import datetime

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_REGF", "CRITICAL"))


CellType: TypeAlias = "IndexLeaf | FastLeaf | HashLeaf | IndexRoot | KeyNode | KeyValue"

STABLE = 0
VOLATILE = 1

# Every registry link target lives under this virtual root, e.g.
# ``\REGISTRY\MACHINE\SOFTWARE\...``.
REGISTRY_ROOT = "REGISTRY"

# Safety bound for link chain resolution. Real chains are only a handful of
# hops; this stops pathological data from looping forever if identity tracking
# were ever bypassed.
MAX_LINK_HOPS = 256


@dataclass(frozen=True, slots=True)
class RegistryLink:
    """The on-disk evidence that a :class:`KeyNode` is a registry link.

    A link is only recognised when the key carries the ``SYM_LINK`` flag, it
    contains a single ``REG_LINK`` value and that value decodes as a
    ``UTF-16-LE`` target string. A plain string value on an ordinary key never
    produces a :class:`RegistryLink`.

    The original value cell offset and raw data are retained so the evidence
    survives even when the target itself cannot be resolved.
    """

    source: KeyNode
    value: KeyValue
    target: str
    raw_target: bytes
    value_offset: int


@dataclass(frozen=True, slots=True)
class LinkHop:
    """One link traversal, recorded for an auditable resolution chain."""

    link: RegistryLink
    source_hive: RegistryHive
    source_cell: int
    target: str
    target_hive: RegistryHive | None


@dataclass(frozen=True, slots=True)
class LinkResolution:
    """The result of following zero or more links from a starting key."""

    target: KeyNode
    target_hive: RegistryHive
    target_path: str
    hops: tuple[LinkHop, ...]

    @property
    def followed_link(self) -> bool:
        return bool(self.hops)


class RegistryHive:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.fh.seek(0)
        data = self.fh.read(len(c_regf._HBASE_BLOCK))
        self.header = c_regf._HBASE_BLOCK(data)
        self.version = self.header.Minor
        self.filename = self.header.FileName.rstrip("\x00")

        self.dirty = xor32_crc(data[:508]) == self.header.CheckSum
        if self.dirty:
            log.warning(
                "Checksum failed, the %r hive is dirty, recovery needed, "
                "may not be able to read keys and values properly",
                self.filename,
            )
        else:
            log.debug("Hive %r checksum OK", self.filename)

        self.in_transaction = self.header.Sequence1 != self.header.Sequence2
        if self.in_transaction:
            log.warning(
                "The hive %r is undergoing a transaction, may not be able to read keys and values properly",
                self.filename,
            )
        else:
            log.debug("Hive %r is not undergoing any transactions", self.filename)

        self._hbin_offset = len(c_regf._HBASE_BLOCK)
        self.cell = lru_cache(4096)(self.cell)
        self._root = self.cell(self.header.RootCell)

    def root(self) -> KeyNode:
        return self._root

    def cell(self, offset: int) -> CellType:
        cell = self.parse_cell_data(self.cell_data(offset))
        cell.offset = offset
        return cell

    def _cell_data(self, offset: int) -> tuple[bool, bytes]:
        self.fh.seek(self._hbin_offset + offset)

        allocated = False
        if (size := struct.unpack("<i", self.fh.read(4))[0]) < 0:
            size = -size
            allocated = True

        return allocated, self.fh.read(size - 4)

    def cell_data(self, offset: int) -> bytes:
        _, data = self._cell_data(offset)
        return data

    def parse_cell_data(self, data: bytes) -> CellType:
        sig = data[:2]

        if cls := _CELL_CLASSES.get(sig):
            return cls(self, data)

        raise NotImplementedError(repr(sig))

    def open(self, path: str) -> CellType:
        path = path.strip("\\")
        parts = path.split("\\") if path else []

        realpath = []
        node = self._root
        for part in parts:
            subkey = node.subkey(part)
            realpath.append(subkey.name)

            node = subkey

        return node

    def walk(self) -> Iterator[tuple[int, bool, CellType | bytes]]:
        next_hbin = self._hbin_offset
        hive_size = self.header.Length + self._hbin_offset

        while next_hbin < hive_size:
            self.fh.seek(next_hbin)
            header = c_regf._HBIN(self.fh)
            if header.Signature != 0x6E696268:
                break

            next_hbin += header.Size

            offset = self.fh.tell()
            while offset < next_hbin:
                allocated, data = self._cell_data(offset - self._hbin_offset)
                cell = _CELL_CLASSES.get(data[:2], lambda hive, buf: buf)(self, data)
                if isinstance(cell, Cell):
                    cell.offset = offset - self._hbin_offset

                yield offset, allocated, cell
                offset += 4 + len(data)

    def inspect_link(self, path: str) -> RegistryLink | None:
        """Open ``path`` and return its link evidence without following it."""
        return self.open(path).inspect_link()

    def resolve_link(self, path: str, mounts: RegistryMounts) -> LinkResolution:
        """Open ``path`` and resolve it as a link using ``mounts``."""
        return self.open(path).resolve_link(mounts)


class RegistryMounts:
    """Caller-provided mapping of virtual registry paths to offline hives.

    A mount maps a virtual path such as ``\\REGISTRY\\MACHINE`` or
    ``HKEY_LOCAL_MACHINE`` to a loaded :class:`RegistryHive`. Mount lookup is
    case-insensitive and uses the longest matching prefix, allowing several
    hives to be mounted beneath one another. Nothing here touches the host
    registry.
    """

    def __init__(self, mounts: Mapping[str, RegistryHive] | None = None):
        self._mounts: dict[tuple[str, ...], RegistryHive] = {}
        if mounts:
            for path, hive in mounts.items():
                self.mount(path, hive)

    @staticmethod
    def normalize_path(path: str) -> tuple[str, ...]:
        # Mount keys are matched case-insensitively, so they are upper-cased.
        return tuple(part.upper() for part in path.strip("\\").replace("/", "\\").split("\\") if part)

    @staticmethod
    def _segments(path: str) -> tuple[str, ...]:
        return tuple(part for part in path.strip("\\").replace("/", "\\").split("\\") if part)

    def mount(self, path: str, hive: RegistryHive) -> None:
        key = self.normalize_path(path)
        if not key:
            raise Error("A mount requires a non-empty registry path")
        self._mounts[key] = hive

    def lookup(self, target_path: str) -> tuple[RegistryHive, tuple[str, ...]]:
        """Resolve ``target_path`` to the most specific mounted hive.

        Returns the hive and the remaining path segments inside that hive,
        preserving their original casing. Raises :class:`MountNotFoundError`
        when no mount covers the target.
        """
        segments = self._segments(target_path)
        if not segments or segments[0].upper() != REGISTRY_ROOT:
            raise MountNotFoundError(f"Link target {target_path!r} is not a virtual registry path")

        upper = tuple(part.upper() for part in segments)
        best: tuple[str, ...] | None = None
        for mount_path in self._mounts:
            if upper[: len(mount_path)] == mount_path and (best is None or len(mount_path) > len(best)):
                best = mount_path

        if best is None:
            raise MountNotFoundError(f"No hive mounted for link target {target_path!r}")

        return self._mounts[best], segments[len(best) :]

    def __len__(self) -> int:
        return len(self._mounts)

    def __contains__(self, path: object) -> bool:
        return self.normalize_path(path) in self._mounts if isinstance(path, str) else False


class LinkResolver:
    """Resolves link keys strictly through offline :class:`RegistryMounts`."""

    def __init__(self, mounts: RegistryMounts):
        self.mounts = mounts

    def resolve(self, start: KeyNode) -> LinkResolution:
        current = start
        current_hive = start.hive
        hops: list[LinkHop] = []
        # Identity of every cell already visited, across every mounted hive,
        # so loops (including a link back to itself) are detected.
        visited: set[tuple[int, int]] = {(id(current_hive), current.offset)}

        while True:
            link = current.link
            if link is None:
                target_path = self._virtual_path(current_hive, current, hops)
                return LinkResolution(
                    target=current,
                    target_hive=current_hive,
                    target_path=target_path,
                    hops=tuple(hops),
                )

            if len(hops) >= MAX_LINK_HOPS:
                raise LinkLoopError(f"Link chain exceeded {MAX_LINK_HOPS} hops", link).with_hops(hops)

            try:
                target_hive, remaining = self.mounts.lookup(link.target)
            except MountNotFoundError as exc:
                exc.link = link
                raise exc.with_hops(hops + [self._hop(link, current_hive, None)]) from exc

            # Record the jump before touching the target so the evidence of
            # every attempted link survives a later failure.
            hops.append(self._hop(link, current_hive, target_hive))

            node = target_hive.root()
            for part in remaining:
                try:
                    node = node.subkey(part)
                except RegistryKeyNotFoundError as exc:
                    error = LinkTargetNotFoundError(
                        f"Link target {link.target!r} does not exist in the mounted hive",
                        link,
                    )
                    raise error.with_hops(hops) from exc

            identity = (id(target_hive), node.offset)
            if identity in visited:
                raise LinkLoopError(f"Link loop detected while resolving {link.target!r}", link).with_hops(hops)
            visited.add(identity)

            current = node
            current_hive = target_hive

    @staticmethod
    def _hop(link: RegistryLink, source_hive: RegistryHive, target_hive: RegistryHive | None) -> LinkHop:
        return LinkHop(
            link=link,
            source_hive=source_hive,
            source_cell=link.source.offset,
            target=link.target,
            target_hive=target_hive,
        )

    @staticmethod
    def _virtual_path(hive: RegistryHive, node: KeyNode, hops: tuple[LinkHop, ...]) -> str:
        if hops:
            # The final hop already names the full virtual path of the node it
            # arrived at; node.path is only relative inside that target hive.
            return hops[-1].target
        return node.path


class Cell:
    __signature__ = b""
    __struct__ = None

    def __init__(self, hive: RegistryHive, data: bytes, strict: bool = True):
        self.hive = hive
        # Hive-relative offset of this cell. Filled in by RegistryHive.cell
        # and RegistryHive.walk; -1 when a cell was constructed directly.
        self.offset = -1

        if data[:2] != self.__signature__:
            raise Error(f"Invalid {self.__class__.__name__} signature {data[:2]!r}, expected {self.__signature__!r}")

        self.cell = self.__struct__(data)


class KeyNode(Cell):
    __signature__ = b"nk"
    __struct__ = c_regf._CM_KEY_NODE

    def __init__(self, hive: RegistryHive, data: bytes):
        super().__init__(hive, data)
        self._cache = {}

        self.class_name = None
        if (class_idx := self.cell.Class) != 0xFFFFFFFF:
            self.class_name = self.hive.cell_data(class_idx)[: self.cell.ClassLength].decode("utf-16-le")

        name_length = self.cell.NameLength
        name_blob = data[len(self.__struct__) :][:name_length]
        self.name = decode_name(name_blob, name_length, KEY.COMP_NAME in self.cell.Flags)

    def __repr__(self) -> str:
        return f"<KeyNode {self.name}>"

    @cached_property
    def timestamp(self) -> datetime:
        return wintimestamp(self.cell.LastWriteTime)

    @property
    def path(self) -> str:
        # As long as we are not the ROOT key, we add our name to the stack.
        #
        # The path is relative to the hive of this key. Adding a name for the
        # ROOT key will lead to issues when this hive is mapped on a subkey of
        # another hive. The full path to this key is constructed using both the
        # path of the subkey in the other hive and this key's path.
        #
        # If ROOT would be part of that path, that part (and thus the whole
        # path) would not be accesible, nor is the presence of the ROOT part in
        # the path expected by the user (it is never visible in e.g. regedit).
        parts = []

        current = self
        parent = self.hive.cell(current.cell.Parent) if KEY.HIVE_ENTRY not in current.cell.Flags else None
        while parent is not None:
            parts.append(current.name)
            current = parent
            parent = self.hive.cell(current.cell.Parent) if KEY.HIVE_ENTRY not in current.cell.Flags else None

        return "\\".join(list(reversed(parts)))

    @cached_property
    def _subkey_list(self) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | None:
        num_sk = self.cell.SubKeyCounts[STABLE]
        if not num_sk:
            return None

        subkey_list: KeyIndex = self.hive.cell(self.cell.SubKeyLists[STABLE])
        if num_sk != subkey_list.count:
            log.debug(
                "KeyNode %s has %d subkeys, while the %s has %d elements",
                self.name,
                num_sk,
                subkey_list.__class__.__name__,
                subkey_list.count,
            )

        return subkey_list

    def subkeys(self) -> Iterator[KeyNode]:
        if self._subkey_list:
            yield from self._subkey_list

    def subkey(self, name: str) -> KeyNode:
        lname = name.lower()

        try:
            return self._cache[lname]
        except KeyError:
            pass

        if self._subkey_list and (sk := self._subkey_list.subkey(name)):
            self._cache[lname] = sk
            return sk

        raise RegistryKeyNotFoundError(name)

    def values(self) -> Iterator[KeyValue]:
        if num_values := self.cell.ValueList.Count:
            data = self.hive.cell_data(self.cell.ValueList.List)

            # Possible slack values
            if len(data) // 4 < num_values:
                num_values = len(data) // 4
                bytes_short = num_values * 4 - len(data)
                if bytes_short:
                    log.debug(
                        "Value list of key %r is %d bytes short reading %d values instead of %d, "
                        "the difference could be due to slack values",
                        self.name,
                        bytes_short,
                        num_values,
                        num_values,
                    )

            yield from ValueList(self.hive, data, num_values)

    def value(self, name: str) -> KeyValue:
        for value in self.values():
            if value.name.lower() == name.lower():
                return value

        raise RegistryValueNotFoundError(name)

    @cached_property
    def is_link(self) -> bool:
        """Whether this key is a valid registry link.

        A link requires the ``SYM_LINK`` key flag, a single ``REG_LINK`` value
        and a ``UTF-16-LE`` encoded target. An ordinary key holding a string
        value (even one named ``SymbolicLinkValue``) is not a link.
        """
        try:
            return self.link is not None
        except InvalidLinkError:
            return False

    @cached_property
    def link(self) -> RegistryLink | None:
        """Return the link evidence, ``None`` for ordinary keys.

        Raises :class:`InvalidLinkError` when the key claims to be a link
        (``SYM_LINK`` flag) but the value type or target encoding is wrong.
        """
        if KEY.SYM_LINK not in self.cell.Flags:
            return None

        values = list(self.values())
        invalid = InvalidLinkError(f"Key {self.name!r} has the SYM_LINK flag but is not a valid link")
        if len(values) != 1 or values[0].type != REG_LINK:
            raise invalid

        value = values[0]
        raw_target = value.data
        target = decode_link_target(raw_target)
        if target is None:
            raise invalid

        return RegistryLink(
            source=self,
            value=value,
            target=target,
            raw_target=raw_target,
            value_offset=value.offset,
        )

    def inspect_link(self) -> RegistryLink | None:
        """Inspect this key without following or mounting anything.

        Returns the :class:`RegistryLink` evidence for a link key, ``None`` for
        an ordinary key and raises :class:`InvalidLinkError` for a malformed
        link while still carrying the best available evidence.
        """
        return self.link

    def resolve_link(self, mounts: RegistryMounts) -> LinkResolution:
        """Follow this link through the caller-supplied hive mount mapping.

        Only the provided offline hives are consulted; the host registry is
        never touched. Every traversed link is recorded so each jump can be
        traced back to its source cell.
        """
        return LinkResolver(mounts).resolve(self)


class ValueList:
    def __init__(self, hive: RegistryHive, data: bytes, count: int):
        self.hive = hive
        self._values = c_regf.int32[count](data)

    def __iter__(self) -> Iterator[KeyValue]:
        for entry in self._values:
            if entry <= 2:
                continue

            data = self.hive.cell_data(entry)
            if data[:2] != KeyValue.__signature__:
                log.warning("Invalid cell signature %r at offset 0x%x", data[:2], entry)
                continue

            value = KeyValue(self.hive, data)
            value.offset = entry
            yield value


class KeyValue(Cell):
    __signature__ = b"vk"
    __struct__ = c_regf._CM_KEY_VALUE

    def __init__(self, hive: RegistryHive, data: bytes):
        super().__init__(hive, data)

        if (name_length := self.cell.NameLength) == 0:
            self.name = "(Default)"
        else:
            name_blob = data[len(self.__struct__) :][:name_length]
            self.name = decode_name(name_blob, name_length, VALUE.COMP_NAME in self.cell.Flags)

    def __repr__(self) -> str:
        return f"<KeyValue {self.name}={self.value!r}>"

    @cached_property
    def type(self) -> int:
        return self.cell.Type

    @cached_property
    def size(self) -> int:
        return self.cell.DataLength & ~0x80000000

    @cached_property
    def is_big_value(self) -> bool:
        # HSYS_WHISTLER_BETA1, CM_KEY_VALUE_SPECIAL_SIZE, CM_KEY_VALUE_BIG
        return self.hive.version > 4 and self.cell.DataLength < 0x80000000 and self.cell.DataLength > 0x3FD8

    @cached_property
    def data(self) -> bytes:
        data_size = self.size
        if self.cell.DataLength & 0x80000000:
            return struct.pack("<I", self.cell.Data)[:data_size]

        if self.is_big_value:
            bd = self.hive.cell(self.cell.Data)
            if not isinstance(bd, BigData):
                raise Error(f"Expected BigData, got {bd.__class__.__name__}")

            return bd.data[:data_size]

        return self.hive.cell_data(self.cell.Data)[:data_size]

    @cached_property
    def value(self) -> int | str | list[str] | bytes:
        return parse_value(self.type, self.data)


class KeyIndex(Cell):
    def __len__(self) -> int:
        raise NotImplementedError

    def __iter__(self) -> Iterator[KeyNode]:
        raise NotImplementedError

    @cached_property
    def count(self) -> int:
        raise NotImplementedError

    def subkey(self, name: str) -> KeyNode | None:
        raise NotImplementedError


class IndexRoot(KeyIndex):
    __signature__ = b"ri"
    __struct__ = c_regf._CM_KEY_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield from self.hive.cell(entry)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        for entry in self.cell.List:
            if sk := self.hive.cell(entry).subkey(name):
                return sk
        return None


class IndexLeaf(KeyIndex):
    __signature__ = b"li"
    __struct__ = c_regf._CM_KEY_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield self.hive.cell(entry)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        for entry in self.cell.List:
            if (sk := self.hive.cell(entry)).name == name:
                return sk
        return None


class HashLeaf(KeyIndex):
    __signature__ = b"lh"
    __struct__ = c_regf._CM_KEY_HASH_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield self.hive.cell(entry.Cell)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        name_hash = hashname(name)
        name = name.lower()

        for entry in self.cell.List:
            if name_hash == entry.HashKey and (sk := self.hive.cell(entry.Cell)).name.lower() == name:
                return sk

        return None


class FastLeaf(KeyIndex):
    __signature__ = b"lf"
    __struct__ = c_regf._CM_KEY_FAST_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield self.hive.cell(entry.Cell)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        name = name.lower()
        name_hint = name[:4]

        for entry in self.cell.List:
            # If names are < 4 characters, the name hint is padded with
            # 0-bytes, the characters are stored from the lowest byte number
            # up.
            # Note that names of keys are only supposed to contain "printable
            # characters except the `\' character", which probably is the
            # printable subset of ascii (MS documentation is inconclusive on
            # this).
            # For non-ASCII names name hint is filled with zeroes, for these cases
            # we need to fall back to regular name comparison
            hint = entry.NameHint.rstrip(b"\x00").decode("ascii").lower()
            if not hint or name_hint == hint:
                sk = self.hive.cell(entry.Cell)
                if sk.name.lower() == name:
                    return sk

        return None


class KeySecurity(Cell):
    __signature__ = b"sk"
    __struct__ = c_regf._CM_KEY_SECURITY


class BigData(Cell):
    __signature__ = b"db"
    __struct__ = c_regf._CM_BIG_DATA

    @property
    def data(self) -> bytes:
        parts = []
        segment_list = self.hive.cell_data(self.cell.List)
        for segment in c_regf.int32[self.cell.Count](segment_list):
            part = self.hive.cell_data(segment)
            parts.append(part[:16344])  # CM_KEY_VALUE_BIG

        return b"".join(parts)


_CELL_CLASSES = {
    KeyNode.__signature__: KeyNode,
    KeyValue.__signature__: KeyValue,
    IndexRoot.__signature__: IndexRoot,
    IndexLeaf.__signature__: IndexLeaf,
    FastLeaf.__signature__: FastLeaf,
    HashLeaf.__signature__: HashLeaf,
    KeySecurity.__signature__: KeySecurity,
    BigData.__signature__: BigData,
}


def decode_name(blob: bytes, size: int, is_comp_name: bool) -> str:
    if is_comp_name:
        try:
            return blob.decode()
        except UnicodeDecodeError:
            pass

        try:
            return blob.decode("latin1")
        except UnicodeDecodeError:
            pass
    else:
        try:
            return c_regf.wchar[size // 2](blob)
        except UnicodeDecodeError:
            pass

    return repr(blob)


def decode_link_target(data: bytes) -> str | None:
    """Strictly decode a ``REG_LINK`` target as ``UTF-16-LE``.

    Registry link targets are always UTF-16-LE strings. Unlike
    :func:`try_decode_sz` (which tolerates legacy byte encodings), this
    rejects anything that is not valid UTF-16-LE with an even byte count so a
    plain or malformed string value can never be mistaken for a jump target.
    Returns ``None`` when the data cannot be interpreted as a link target.
    """
    if not data or len(data) % 2:
        return None

    try:
        target = data.decode("utf-16-le")
    except UnicodeDecodeError:
        return None

    target = target.rstrip("\x00")
    if not target or "\x00" in target:
        return None

    return target


def try_decode_sz(data: bytes) -> str:
    if not len(data):
        return ""

    try:
        if (data.isascii() or data.endswith(b"\x00")) and data[1:2] != b"\x00":
            # This will return the string latin1 decoded up until the first
            # NULL byte.
            return data.split(b"\x00")[0].decode("latin1")

        if len(data) % 2 != 0:
            data = data.ljust(len(data) + 1, b"\x00")

        # This will return the string utf-16-le decoded up until the first
        # double NULL byte.
        # A naive split on two NULL bytes will not work as the possibility
        # exists that the first NULL byte is the high byte of the first
        # character and the second NULL byte the low byte of the second
        # character. So the first NULL byte should start at an even index in
        # the data.
        idx = -1
        while (idx := data.find(b"\x00\x00", idx + 1)) & 1:
            if idx == -1:
                idx = len(data)
                break
        return data[:idx].decode("utf-16-le")

    except UnicodeDecodeError:
        # Last ditch effort, decode the whole bytestring as if it were utf-16,
        # any decoding errors, which incase of utf-16 will be invalid utf-16
        # surrogates, will be ignored.
        return data.decode("utf-16-le", "ignore").strip("\x00")


def parse_value(data_type: int, data: bytes) -> int | str | list[str] | bytes:
    if data_type in (REG_DWORD, REG_DWORD_BIG_ENDIAN):
        if len(data) == 0:
            return 0

        if data_type == REG_DWORD:
            return c_regf.uint32(data[:4])

        if data_type == REG_DWORD_BIG_ENDIAN:
            return struct.unpack(">I", data[:4])[0]

    if data_type == REG_QWORD:
        return c_regf.uint64(data) if len(data) else 0

    if data_type in (REG_SZ, REG_EXPAND_SZ):
        return try_decode_sz(data)

    if data_type in (REG_BINARY, REG_NONE):
        return data

    if data_type == REG_MULTI_SZ:
        data_len = len(data)
        data = BytesIO(data)

        multi_string = []
        while data.tell() < data_len:
            string = read_null_terminated_wstring(data)
            if string == "":
                break

            multi_string.append(string)

        return multi_string

    if data_type == REG_FULL_RESOURCE_DESCRIPTOR:
        log.warning("Unimplemented REG_FULL_RESOURCE_DESCRIPTOR")
        return data

    if data_type == REG_RESOURCE_REQUIREMENTS_LIST:
        log.warning("Unimplemented REG_RESOURCE_REQUIREMENTS_LIST")
        return data

    log.warning("Data type 0x%x not supported", data_type)
    return data


def read_null_terminated_wstring(stream: BinaryIO, encoding: str = "utf-16-le") -> str:
    """Adapted function to read null terminated wide strings.

    The cstruct way raises EOFError when the end of the stream is reached.
    This is fine, but not what we want for this particular implementation.
    """
    wide_string = b""
    while True:
        wide_char = stream.read(2)

        if len(wide_char) != 2 or wide_char == b"\x00\x00":
            break

        wide_string += wide_char

    return wide_string.decode(encoding)


def hashname(name: str) -> int:
    # Note that `name' is a python str(), which means the ord() used to
    # calculate name_hash works (it wouldn't for byte()).
    # Also note that names of keys are only supposed to contain "printable
    # characters except the `\' character", which probably is the printable
    # subset of ascii (MS documentation is inconclusive on this).
    name_hash = 0
    for char in name.upper():
        name_hash = (name_hash * 37 + ord(char)) & 0xFFFFFFFF

    return name_hash


def xor32_crc(data: bytes) -> int:
    crc = 0
    for ii in c_regf.uint32[len(data) // 4](data):
        crc ^= ii

    return crc
