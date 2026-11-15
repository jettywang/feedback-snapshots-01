from __future__ import annotations

import logging
from datetime import datetime
from enum import IntEnum
from struct import calcsize, unpack_from
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID

from dissect.util import ts

if TYPE_CHECKING:
    from typing import BinaryIO

log = logging.getLogger(__name__)

# [MS-OLEPS] 2.2 SerializedPropertyStore
SERIALIZED_PROPERTY_STORE_TERMINATOR = 0x00000000

# [MS-OLEPS] 2.3 SerializedPropertyStorage
SERIALIZED_PROPERTY_STORAGE_VERSION = 0x53505331
SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE = 0x18

# [MS-OLEPS] 2.3.1 Serialized Property Value (String Name)
# [MS-OLEPS] 2.3.2 Serialized Property Value (Integer Name)
SERIALIZED_PROPERTY_VALUE_HEADER_SIZE = 0x09
SERIALIZED_PROPERTY_STRING_NAME_FORMAT_ID = UUID("d5cdd505-2e9c-101b-9397-08002b2cf9ae")

# [MS-OLEPS] 2.15 TypedPropertyValue
TYPED_PROPERTY_VALUE_HEADER_SIZE = 0x04


class PropertyType(IntEnum):
    """Property types from [MS-OLEPS] section 2.16."""

    VT_EMPTY = 0x0000
    VT_NULL = 0x0001
    VT_I2 = 0x0002
    VT_I4 = 0x0003
    VT_R4 = 0x0004
    VT_R8 = 0x0005
    VT_CY = 0x0006
    VT_DATE = 0x0007
    VT_BSTR = 0x0008
    VT_ERROR = 0x000A
    VT_BOOL = 0x000B
    VT_VARIANT = 0x000C
    VT_DECIMAL = 0x000E
    VT_I1 = 0x0010
    VT_UI1 = 0x0011
    VT_UI2 = 0x0012
    VT_UI4 = 0x0013
    VT_I8 = 0x0014
    VT_UI8 = 0x0015
    VT_INT = 0x0016
    VT_UINT = 0x0017
    VT_LPSTR = 0x001E
    VT_LPWSTR = 0x001F
    VT_FILETIME = 0x0040
    VT_BLOB = 0x0041
    VT_STREAM = 0x0042
    VT_STORAGE = 0x0043
    VT_STREAMED_OBJECT = 0x0044
    VT_STORED_OBJECT = 0x0045
    VT_BLOB_OBJECT = 0x0046
    VT_CF = 0x0047
    VT_CLSID = 0x0048
    VT_VERSIONED_STREAM = 0x0049

    # Short aliases, useful for callers that do not want the VT_ prefix.
    EMPTY = 0x0000
    NULL = 0x0001
    I1 = 0x0010
    UI1 = 0x0011
    I2 = 0x0002
    UI2 = 0x0012
    I4 = 0x0003
    UI4 = 0x0013
    I8 = 0x0014
    UI8 = 0x0015
    INT = 0x0016
    UINT = 0x0017
    R4 = 0x0004
    R8 = 0x0005
    BOOL = 0x000B
    BSTR = 0x0008
    LPSTR = 0x001E
    LPWSTR = 0x001F
    FILETIME = 0x0040
    BLOB = 0x0041
    CLSID = 0x0048


class TypedPropertyValue:
    """A bounds-checked [MS-OLEPS] 2.15 TypedPropertyValue.

    The ``raw`` attribute always contains every value byte following the four
    byte type/padding header, including bytes for unknown or malformed types.
    This keeps unsupported values inspectable instead of discarding them.

    Args:
        data: Bytes of the complete typed value, including its type header.
        offset: Absolute or relative offset of this value in the source data.

    """

    _INTEGER_FORMATS: ClassVar[dict[PropertyType, str]] = {
        PropertyType.VT_I1: "<b",
        PropertyType.VT_UI1: "<B",
        PropertyType.VT_I2: "<h",
        PropertyType.VT_UI2: "<H",
        PropertyType.VT_I4: "<i",
        PropertyType.VT_UI4: "<I",
        PropertyType.VT_INT: "<i",
        PropertyType.VT_UINT: "<I",
        PropertyType.VT_I8: "<q",
        PropertyType.VT_UI8: "<Q",
        PropertyType.VT_ERROR: "<I",
        PropertyType.VT_CY: "<q",
    }
    _FLOAT_FORMATS: ClassVar[dict[PropertyType, str]] = {
        PropertyType.VT_R4: "<f",
        PropertyType.VT_R8: "<d",
        PropertyType.VT_DATE: "<d",
    }
    _PLAIN_TYPES: ClassVar[set[PropertyType]] = {PropertyType.VT_EMPTY, PropertyType.VT_NULL}
    _SUPPORTED_TYPES: ClassVar[set[PropertyType]] = (
        set(_INTEGER_FORMATS)
        | set(_FLOAT_FORMATS)
        | _PLAIN_TYPES
        | {
            PropertyType.VT_BOOL,
            PropertyType.VT_BSTR,
            PropertyType.VT_LPSTR,
            PropertyType.VT_LPWSTR,
            PropertyType.VT_FILETIME,
            PropertyType.VT_BLOB,
            PropertyType.VT_CLSID,
        }
    )

    def __init__(self, data: bytes, offset: int = 0):
        self.offset = offset
        self.data = bytes(data)
        self.raw_type: int | None = None
        self.property_type: PropertyType | None = None
        self.type: PropertyType | int | None = None
        self.padding = b""
        self.raw = b""
        self.value: Any = None
        self.error: str | None = None
        self.filetime: int | None = None
        self.datetime: datetime | None = None

        self._parse(self.data)

    def _parse(self, data: bytes) -> None:
        if len(data) < TYPED_PROPERTY_VALUE_HEADER_SIZE:
            # Do not invent a type: a truncated header is unknown, not VT_EMPTY.
            self.raw = data
            self.padding = data[:2]
            self.error = f"typed property value is too small: {len(data)} bytes"
            return

        self.raw_type = unpack_from("<H", data, 0)[0]
        self.padding = data[2:4]
        self.raw = data[TYPED_PROPERTY_VALUE_HEADER_SIZE:]
        self.property_type = self._lookup_type(self.raw_type)
        self.type = self.property_type if self.property_type is not None else self.raw_type

        try:
            self.value = self._parse_value(self.raw)
        except (ValueError, OverflowError) as exc:
            self.error = str(exc)
            self.value = None

        if self.raw_type == PropertyType.VT_FILETIME and isinstance(self.value, int):
            self.filetime = self.value
            try:
                self.datetime = ts.wintimestamp(self.value)
            except (ValueError, OverflowError):
                self.datetime = None

    @staticmethod
    def _lookup_type(value: int) -> PropertyType | None:
        try:
            return PropertyType(value)
        except ValueError:
            return None

    @property
    def is_known(self) -> bool:
        """Whether the type is defined by [MS-OLEPS]."""
        return self.property_type is not None

    @property
    def is_supported(self) -> bool:
        """Whether this parser decoded the type into a Python value."""
        return self.property_type in self._SUPPORTED_TYPES

    @property
    def type_name(self) -> str | None:
        """Name of the property type, or ``None`` for an unknown type."""
        return self.property_type.name if self.property_type is not None else None

    def _need(self, size: int) -> None:
        if len(self.raw) < size:
            raise ValueError(f"typed property value is truncated: need {size} bytes, have {len(self.raw)}")

    def _parse_value(self, payload: bytes) -> Any:
        if self.property_type is None or self.property_type in self._PLAIN_TYPES:
            return None

        if fmt := self._INTEGER_FORMATS.get(self.property_type):
            size = calcsize(fmt)
            self._need(size)
            return unpack_from(fmt, payload, 0)[0]

        if fmt := self._FLOAT_FORMATS.get(self.property_type):
            size = calcsize(fmt)
            self._need(size)
            return unpack_from(fmt, payload, 0)[0]

        if self.property_type == PropertyType.VT_BOOL:
            self._need(2)
            return unpack_from("<H", payload, 0)[0] != 0

        if self.property_type in (PropertyType.VT_LPSTR, PropertyType.VT_LPWSTR):
            return self._parse_string(payload, unicode=self.property_type == PropertyType.VT_LPWSTR)

        if self.property_type == PropertyType.VT_BSTR:
            self._need(4)
            byte_count = unpack_from("<I", payload, 0)[0]
            if byte_count > len(payload) - 4:
                raise ValueError(f"BSTR length {byte_count} exceeds available value bytes {len(payload) - 4}")
            return _decode_utf16(payload[4 : 4 + byte_count])

        if self.property_type == PropertyType.VT_FILETIME:
            self._need(8)
            return unpack_from("<Q", payload, 0)[0]

        if self.property_type == PropertyType.VT_BLOB:
            self._need(4)
            byte_count = unpack_from("<I", payload, 0)[0]
            if byte_count > len(payload) - 4:
                raise ValueError(f"BLOB length {byte_count} exceeds available value bytes {len(payload) - 4}")
            return bytes(payload[4 : 4 + byte_count])

        if self.property_type == PropertyType.VT_CLSID:
            self._need(16)
            return UUID(bytes_le=payload[:16])

        return None

    def _parse_string(self, payload: bytes, unicode: bool) -> str:
        self._need(4)
        count = unpack_from("<I", payload, 0)[0]
        width = 2 if unicode else 1
        byte_count = count * width

        if byte_count > len(payload) - 4:
            raise ValueError(f"string length {count} exceeds available value bytes {(len(payload) - 4) // width}")

        value = payload[4 : 4 + byte_count]
        if unicode:
            return _decode_utf16(value)
        return value.rstrip(b"\x00").decode("cp1252", errors="replace")

    def dumps(self) -> bytes:
        """Return the raw bytes of this typed value, including its type header."""
        return self.data

    def __bytes__(self) -> bytes:
        return self.data

    def __repr__(self) -> str:
        type_name = self.type_name or (hex(self.raw_type) if self.raw_type is not None else "unknown")
        return f"<TypedPropertyValue type={type_name} value={self.value!r}>"


class SerializedPropertyValue:
    """A bounds-checked [MS-OLEPS] 2.3 Serialized Property Value.

    Both string named (2.3.1) and integer named (2.3.2) values are supported.
    ``raw`` contains the complete value, including its header, so a property
    can always be inspected even when its typed value is malformed.

    Args:
        data: Bytes of the complete serialized property value.
        string_names: Parse a string named value instead of an integer named one.
        offset: Absolute or relative offset of this value in the source data.

    """

    def __init__(self, data: bytes, string_names: bool = False, offset: int = 0):
        self.offset = offset
        self.raw = bytes(data)
        self.size = len(self.raw)
        self.string_names = string_names
        self.value_size = 0
        self.name: str | None = None
        self.id: int | None = None
        self.reserved = 0
        self.typed_value: TypedPropertyValue | None = None
        self.error: str | None = None

        self._parse(self.raw)

    def _parse(self, data: bytes) -> None:
        if len(data) < SERIALIZED_PROPERTY_VALUE_HEADER_SIZE:
            self.error = f"serialized property value is too small: {len(data)} bytes"
            return

        self.value_size = unpack_from("<I", data, 0)[0]

        if self.string_names:
            self._parse_string_name(data)
        else:
            self._parse_integer_name(data)

        if self.typed_value is not None and self.typed_value.error and self.error is None:
            self.error = self.typed_value.error

    def _parse_integer_name(self, data: bytes) -> None:
        self.id = unpack_from("<I", data, 4)[0]
        self.reserved = data[8]
        self.typed_value = TypedPropertyValue(
            data[SERIALIZED_PROPERTY_VALUE_HEADER_SIZE:],
            offset=self.offset + SERIALIZED_PROPERTY_VALUE_HEADER_SIZE,
        )

    def _parse_string_name(self, data: bytes) -> None:
        name_size = unpack_from("<I", data, 4)[0]

        if name_size == 0 or name_size % 2:
            self.error = f"invalid serialized property name size: {name_size}"
            return

        name_end = SERIALIZED_PROPERTY_VALUE_HEADER_SIZE + name_size
        if name_end > len(data):
            self.error = f"serialized property name exceeds value: {name_size} bytes"
            return

        self.reserved = data[8]
        self.name = _decode_utf16(data[SERIALIZED_PROPERTY_VALUE_HEADER_SIZE:name_end])
        self.typed_value = TypedPropertyValue(data[name_end:], offset=self.offset + name_end)

    @property
    def identity(self) -> int | str | None:
        """The property identity: its name for string named values, else its ID."""
        if self.name is not None:
            return self.name
        return self.id

    @property
    def property_id(self) -> int | None:
        """Numeric property ID for integer named values."""
        return self.id

    @property
    def property_name(self) -> str | None:
        """Property name for string named values."""
        return self.name

    @property
    def type(self) -> PropertyType | int | None:
        """Property type, as an enum for known types and an ``int`` otherwise."""
        return self.typed_value.type if self.typed_value is not None else None

    @property
    def raw_type(self) -> int | None:
        """The unmodified 16-bit type value."""
        return self.typed_value.raw_type if self.typed_value is not None else None

    @property
    def type_name(self) -> str | None:
        """Name of the property type, or ``None`` for an unknown type."""
        return self.typed_value.type_name if self.typed_value is not None else None

    @property
    def value(self) -> Any:
        """Decoded value, or ``None`` for unsupported or malformed types."""
        return self.typed_value.value if self.typed_value is not None else None

    @property
    def raw_value(self) -> bytes:
        """Raw bytes of the typed value payload, excluding its type header."""
        return self.typed_value.raw if self.typed_value is not None else b""

    @property
    def is_known(self) -> bool:
        """Whether the property type is defined by [MS-OLEPS]."""
        return self.typed_value is not None and self.typed_value.is_known

    @property
    def is_supported(self) -> bool:
        """Whether the property value was decoded into a Python value."""
        return self.typed_value is not None and self.typed_value.is_supported

    def dumps(self) -> bytes:
        """Return the raw bytes of this property, including its header."""
        return self.raw

    def __bytes__(self) -> bytes:
        return self.raw

    def __repr__(self) -> str:
        type_name = self.type_name or (hex(self.raw_type) if self.raw_type is not None else "unknown")
        return f"<SerializedPropertyValue identity={self.identity!r} type={type_name} value={self.value!r}>"


class SerializedPropertyStorage:
    """A bounds-checked [MS-OLEPS] 2.3 SerializedPropertyStorage.

    Args:
        data: Bytes of the complete storage.
        offset: Absolute or relative offset of this storage in the source data.

    """

    def __init__(self, data: bytes, offset: int = 0):
        self.offset = offset
        self.raw = bytes(data)
        self.size = len(self.raw)
        self.storage_size = 0
        self.version = 0
        self.format_id = UUID(int=0)
        self.properties: list[SerializedPropertyValue] = []
        self.errors: list[str] = []
        self.error: str | None = None
        self.consumed = 0
        self.terminated = False

        self._parse(self.raw)

    def _parse(self, data: bytes) -> None:
        if len(data) < SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE:
            self._add_error(f"serialized property storage is too small: {len(data)} bytes")
            return

        self.storage_size = unpack_from("<I", data, 0)[0]
        self.version = unpack_from("<I", data, 4)[0]
        self.format_id = UUID(bytes_le=data[8:24])

        if self.storage_size < SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE:
            self._add_error(f"invalid serialized property storage size: {self.storage_size}")
            return

        # StorageSize bounds every property in this storage. If it claims more
        # bytes than are available, parse what is present and record the error.
        bound = min(self.storage_size, len(data))
        if self.storage_size > len(data):
            self._add_error(
                f"serialized property storage size {self.storage_size} exceeds available bytes {len(data)}"
            )

        string_names = self.format_id == SERIALIZED_PROPERTY_STRING_NAME_FORMAT_ID
        position = SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE

        while position + 4 <= bound:
            value_size = unpack_from("<I", data, position)[0]

            if value_size == 0:
                self.terminated = True
                position += 4
                break

            if value_size < SERIALIZED_PROPERTY_VALUE_HEADER_SIZE:
                self._add_error(f"invalid serialized property value size {value_size} at offset {position}")
                break

            if value_size > bound - position:
                self._add_error(
                    f"serialized property value size {value_size} exceeds storage bytes {bound - position}"
                )
                break

            value = SerializedPropertyValue(
                data[position : position + value_size],
                string_names=string_names,
                offset=self.offset + position,
            )
            self.properties.append(value)

            if value.error:
                self._add_error(f"property at offset {position}: {value.error}")

            # Advance by the declared ValueSize, never by how many bytes the
            # malformed value happened to consume while decoding.
            position += value_size

        self.consumed = position

        if not self.terminated and position < bound:
            remaining = data[position:bound]
            if remaining.strip(b"\x00"):
                self._add_error(f"unterminated serialized property storage with {len(remaining)} trailing bytes")

    def _add_error(self, message: str) -> None:
        self.errors.append(message)
        if self.error is None:
            self.error = message

    def get(self, identity: int | str) -> SerializedPropertyValue | None:
        """Return the first property matching an ID or name."""
        for value in self.properties:
            if value.identity == identity:
                return value
        return None

    def __iter__(self):
        return iter(self.properties)

    def __len__(self) -> int:
        return len(self.properties)

    def __getitem__(self, index: int) -> SerializedPropertyValue:
        return self.properties[index]

    def __repr__(self) -> str:
        return f"<SerializedPropertyStorage format_id={self.format_id} properties={len(self.properties)}>"


class SerializedPropertyStore:
    """A bounded parser for a [MS-OLEPS] 2.2 SerializedPropertyStore.

    A store is a sequence of :class:`SerializedPropertyStorage` structures
    terminated by a zero ``StorageSize``. Every level is parsed against its own
    declared length: the store against the supplied bytes, each storage against
    ``StorageSize`` and each property against ``ValueSize``. A malformed value
    therefore cannot consume bytes that belong to the next property or storage.

    Args:
        fh: Raw bytes, a buffer or a file-like object containing the store.
        size: Optional number of bytes to read from a file-like object.
        offset: Offset of the first store byte in the source stream.
        block_offset: Optional offset of the enclosing LNK extra data block.

    """

    def __init__(
        self,
        fh: BinaryIO | bytes | bytearray | memoryview,
        size: int | None = None,
        offset: int = 0,
        block_offset: int | None = None,
    ):
        if isinstance(fh, (bytes, bytearray, memoryview)):
            data = bytes(fh)
        else:
            data = fh.read() if size is None else fh.read(size)

        self.offset = offset
        self.block_offset = block_offset
        self.raw = bytes(data)
        self.size = len(self.raw)
        self.storages: list[SerializedPropertyStorage] = []
        self.errors: list[str] = []
        self.error: str | None = None
        self.consumed = 0
        self.terminated = False

        self._parse(self.raw)

    def _parse(self, data: bytes) -> None:
        position = 0

        while position + 4 <= len(data):
            storage_size = unpack_from("<I", data, position)[0]

            if storage_size == SERIALIZED_PROPERTY_STORE_TERMINATOR:
                self.terminated = True
                position += 4
                break

            if storage_size < SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE:
                self._add_error(f"invalid serialized property storage size {storage_size} at offset {position}")
                break

            if storage_size > len(data) - position:
                # Keep whatever complete properties are present in the
                # truncated storage, then stop: no further storage boundary
                # can be trusted.
                self._add_error(
                    f"serialized property storage size {storage_size} exceeds remaining bytes "
                    f"{len(data) - position}"
                )
                if len(data) - position >= SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE:
                    storage = SerializedPropertyStorage(data[position:], offset=self.offset + position)
                    self.storages.append(storage)
                    for error in storage.errors:
                        self._add_error(f"storage at offset {position}: {error}")
                position = len(data)
                break

            storage = SerializedPropertyStorage(
                data[position : position + storage_size],
                offset=self.offset + position,
            )
            self.storages.append(storage)

            for error in storage.errors:
                self._add_error(f"storage at offset {position}: {error}")

            position += storage_size

        self.consumed = position

        if not self.terminated and position < len(data):
            remaining = data[position:]
            if remaining.strip(b"\x00"):
                self._add_error(f"unterminated serialized property store with {len(remaining)} trailing bytes")

    def _add_error(self, message: str) -> None:
        self.errors.append(message)
        if self.error is None:
            self.error = message
        log.warning("SerializedPropertyStore: %s", message)

    @property
    def storage_count(self) -> int:
        """Number of serialized property storage structures."""
        return len(self.storages)

    @property
    def first_storage(self) -> SerializedPropertyStorage | None:
        """The first storage, or ``None`` for an empty store."""
        return self.storages[0] if self.storages else None

    @property
    def properties(self) -> list[SerializedPropertyValue]:
        """All properties of all storages, in their original order."""
        return [value for storage in self.storages for value in storage.properties]

    @property
    def storage_size(self) -> int:
        """``StorageSize`` of the first storage (compatibility accessor)."""
        if not self.storages:
            raise AttributeError("SerializedPropertyStore has no storages")
        return self.storages[0].storage_size

    @property
    def version(self) -> int:
        """Version of the first storage (compatibility accessor)."""
        if not self.storages:
            raise AttributeError("SerializedPropertyStore has no storages")
        return self.storages[0].version

    @property
    def format_id(self) -> UUID:
        """Format ID of the first storage (compatibility accessor)."""
        if not self.storages:
            raise AttributeError("SerializedPropertyStore has no storages")
        return self.storages[0].format_id

    @property
    def block_size(self) -> int | None:
        """Size of the enclosing LNK extra data block, including its header."""
        return self.size + 0x08 if self.block_offset is not None else None

    @property
    def end_offset(self) -> int:
        """Offset immediately after the last store byte in the source stream."""
        return self.offset + self.size

    def get(self, format_id: UUID | str) -> SerializedPropertyStorage | None:
        """Return the first storage matching a FormatID."""
        if isinstance(format_id, str):
            format_id = UUID(format_id)

        for storage in self.storages:
            if storage.format_id == format_id:
                return storage
        return None

    def __iter__(self):
        return iter(self.storages)

    def __len__(self) -> int:
        return len(self.storages)

    def __getitem__(self, index: int) -> SerializedPropertyStorage:
        return self.storages[index]

    def dumps(self) -> bytes:
        """Return the raw bytes of this store."""
        return self.raw

    def __bytes__(self) -> bytes:
        return self.raw

    def __repr__(self) -> str:
        return f"<SerializedPropertyStore storages={len(self.storages)} errors={len(self.errors)}>"


# Clearer aliases for callers that prefer shorter class names.
PropertyStore = SerializedPropertyStore
PropertyStorage = SerializedPropertyStorage
PropertyValue = SerializedPropertyValue


def _decode_utf16(value: bytes) -> str:
    text = value.decode("utf-16-le", errors="replace")
    # OLE strings are normally null terminated, but the terminator is not part of the value.
    return text[:-1] if text.endswith("\x00") else text
