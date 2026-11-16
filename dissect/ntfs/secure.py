from __future__ import annotations

import io
import struct
from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util.sid import read_sid

from dissect.ntfs.c_ntfs import ACE_OBJECT_FLAGS, ACE_TYPE, c_ntfs
from dissect.ntfs.exceptions import InvalidSecurityDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs.mft import MftRecord


def _stream_size(fh: BinaryIO) -> int:
    """Return the total size of a seekable stream without changing the current position."""
    offset = fh.tell()
    fh.seek(0, io.SEEK_END)
    size = fh.tell()
    fh.seek(offset)
    return size


def _stream_remaining(fh: BinaryIO) -> int:
    """Return the number of bytes between the current position and the end of the stream."""
    return _stream_size(fh) - fh.tell()


def _read_at(fh: BinaryIO, offset: int, size: int, what: str) -> bytes:
    """Read exactly ``size`` bytes at ``offset`` or fail with a descriptive error."""
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise InvalidSecurityDescriptor(f"{what}: truncated read, expected {size} bytes but got {len(data)}")

    return data


def _read_sid(data: bytes, what: str) -> tuple[str, int]:
    """Parse a SID from the start of ``data`` without reading beyond it.

    Returns:
        A tuple of the SID string and the number of bytes it occupies.
    """
    if len(data) < 8:
        raise InvalidSecurityDescriptor(f"{what}: truncated SID header, expected 8 bytes but got {len(data)}")

    sub_authority_count = data[1]
    sid_size = 8 + (sub_authority_count * 4)
    if sid_size > len(data):
        raise InvalidSecurityDescriptor(
            f"{what}: SID sub-authority count {sub_authority_count} requires {sid_size} bytes, "
            f"but only {len(data)} are available"
        )

    return read_sid(data[:sid_size]), sid_size


class _Cursor:
    """Small bounds-checked cursor used to parse the body of a single ACE."""

    def __init__(self, data: bytes, what: str):
        self.data = data
        self.what = what
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read(self, size: int, item: str) -> bytes:
        if size > self.remaining:
            raise InvalidSecurityDescriptor(
                f"{self.what}: truncated {item}, expected {size} bytes but only {self.remaining} are available"
            )

        data = self.data[self.offset : self.offset + size]
        self.offset += size
        return data

    def read_dword(self, item: str) -> int:
        return struct.unpack("<I", self.read(4, item))[0]

    def read_sid(self, item: str) -> str:
        # Parse from the remaining bytes so a corrupt sub-authority count can never
        # consume the next ACE, and then advance by the actual SID length.
        sid, sid_size = _read_sid(self.data[self.offset :], f"{self.what} {item}")
        self.offset += sid_size
        return sid

    def read_rest(self) -> bytes | None:
        return self.data[self.offset :] or None


class Secure:
    """Lookup security descriptors from the ``$Secure`` file, or optionally just a file-like object of the ``$SDS``.

    Only one the ``record`` or ``sds`` arguments needs to be provided.

    Args:
        record: The MFT record of the ``$Secure`` file, used when opening from a full NTFS volume.
        sds: A file-like object of the ``$SDS`` stream, used when opening from separate system files.
    """

    def __init__(self, record: MftRecord = None, sds: BinaryIO | None = None):
        self.record = record
        self.sds = None
        self.sii = None

        if record:
            self.sds = record.open("$SDS")
            self.sii = record.index("$SII")
        elif sds:
            self.sds = sds

        if not self.sds:
            raise ValueError("Either record or SDS stream is required")

        # Hack for file-like objects that don't have a .size attribute
        if not hasattr(self.sds, "size"):
            self.sds.size = self.sds.seek(0, io.SEEK_END)

        self.lookup = lru_cache(4096)(self.lookup)

    def _iter_entries(self, offset: int = 0) -> Iterator[c_ntfs._SECURITY_DESCRIPTOR_HEADER]:
        """Iterate over all SDS entries, optionally starting from a specific offset.

        Args:
            offset: Optional offset to start iterating from.
        """
        fh = self.sds
        while True:
            fh.seek(offset)

            try:
                entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(fh)
            except EOFError:
                break

            if (
                entry.Length < len(c_ntfs._SECURITY_DESCRIPTOR_HEADER)
                or entry.Offset > self.sds.size
                or entry.Length > 0x10000
            ):
                # The SDS is supposedly duplicated at 0x40000 increments (256k)? Try to parse again from there
                offset += 0x40000 - (offset % 0x40000)
                continue

            yield entry

            offset += entry.Length
            # Align to 16 bytes with some bit magic
            offset += -(offset) & 0xF

    def lookup(self, security_id: int) -> SecurityDescriptor:
        """Lookup a security descriptor by the security ID.

        An index is used if available (``$SII``), otherwise we iterate all entries until we find the correct one.

        Args:
            security_id: The security ID to lookup.

        Raises:
            KeyError: If the security ID can't be found.
        """
        if self.sii:
            # If we have an index, we can land directly at the right offset
            sii_entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(self.sii.search(security_id).data)
            offset = sii_entry.Offset
        else:
            # Otherwise we need to "bruteforce" our way to the correct offset
            offset = 0

        for entry in self._iter_entries(offset):
            if entry.SecurityId == security_id:
                # Jackpot
                return SecurityDescriptor(self.sds, entry.Length - len(c_ntfs._SECURITY_DESCRIPTOR_HEADER))

        raise KeyError(f"Couldn't find security ID: {security_id}")

    def descriptors(self) -> Iterator[SecurityDescriptor]:
        """Return all security descriptors."""
        for entry in self._iter_entries():
            yield SecurityDescriptor(self.sds, entry.Length - len(c_ntfs._SECURITY_DESCRIPTOR_HEADER))


class SecurityDescriptor:
    """Parse a self-relative security descriptor from a file-like object.

    Every component (owner, group, SACL and DACL) is parsed within its own range.
    The optional ``length`` argument is the size of the descriptor, so malformed
    offsets or inner lengths can never consume bytes from a following descriptor
    in an SDS stream.

    Args:
        fh: The file-like object to parse a security descriptor from.
        length: Optional size of the descriptor. Defaults to the remaining stream size.
    """

    def __init__(self, fh: BinaryIO, length: int | None = None):
        self.offset = fh.tell()
        if length is None:
            length = _stream_remaining(fh)

        if length < len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE):
            raise InvalidSecurityDescriptor(
                f"security descriptor at 0x{self.offset:x}: length {length} is smaller than the header"
            )

        self.length = length
        self.end = self.offset + length
        self.header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(
            _read_at(fh, self.offset, len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE), "security descriptor header")
        )

        self.owner = None
        self.group = None
        self.sacl = None
        self.dacl = None

        self.owner_range = None
        self.group_range = None
        self.sacl_range = None
        self.dacl_range = None

        # Offsets are relative to the start of the descriptor. They are also used as
        # independent upper bounds for components that precede another component.
        components = [
            ("owner", self.header.Owner),
            ("group", self.header.Group),
            ("SACL", self.header.Sacl),
            ("DACL", self.header.Dacl),
        ]
        starts = sorted({offset for _, offset in components if offset})
        present = [offset for _, offset in components if offset]
        if len(starts) != len(present):
            raise InvalidSecurityDescriptor(
                f"security descriptor at 0x{self.offset:x}: multiple components point to the same offset"
            )

        def component_bound(start: int, what: str) -> int:
            if start < len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE) or start >= length:
                raise InvalidSecurityDescriptor(
                    f"security descriptor at 0x{self.offset:x}: {what} offset 0x{start:x} is outside the descriptor"
                )

            following = [candidate for candidate in starts if candidate > start]
            return min(following) if following else length

        if self.header.Owner:
            bound = component_bound(self.header.Owner, "owner")
            self.owner, self.owner_range = self._read_relative_sid(fh, self.header.Owner, bound, "owner")

        if self.header.Group:
            bound = component_bound(self.header.Group, "group")
            self.group, self.group_range = self._read_relative_sid(fh, self.header.Group, bound, "group")

        if self.header.Sacl:
            bound = component_bound(self.header.Sacl, "SACL")
            self.sacl = ACL(fh, self.offset + self.header.Sacl, bound - self.header.Sacl, "SACL")
            self.sacl_range = self.sacl.range

        if self.header.Dacl:
            bound = component_bound(self.header.Dacl, "DACL")
            self.dacl = ACL(fh, self.offset + self.header.Dacl, bound - self.header.Dacl, "DACL")
            self.dacl_range = self.dacl.range

    @property
    def range(self) -> tuple[int, int]:
        """The absolute ``(start, end)`` range of this descriptor."""
        return self.offset, self.end

    def _read_relative_sid(
        self, fh: BinaryIO, relative_offset: int, bound: int, what: str
    ) -> tuple[str, tuple[int, int]]:
        start = self.offset + relative_offset
        data = _read_at(fh, start, bound - relative_offset, f"{what} SID")
        sid, size = _read_sid(data, f"{what} SID")
        return sid, (start, start + size)


class ACL:
    """Parse an ACL from a file-like object.

    ACEs are parsed sequentially within ``AclSize`` only. A malformed ``AceCount``
    or ``AceSize`` fails the ACL instead of continuing into a neighbouring ACL or
    descriptor.

    Args:
        fh: The file-like object to parse an ACL from.
        offset: Absolute offset of the ACL in ``fh``. Defaults to the current position.
        length: Optional maximum size available for the ACL. Defaults to the remaining stream size.
        what: Description of this ACL used in error messages.
    """

    def __init__(self, fh: BinaryIO, offset: int | None = None, length: int | None = None, what: str = "ACL"):
        self.offset = fh.tell() if offset is None else offset
        if length is None:
            length = _stream_size(fh) - self.offset

        if length < len(c_ntfs._ACL):
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: length {length} is smaller than the ACL header"
            )

        self.header = c_ntfs._ACL(_read_at(fh, self.offset, len(c_ntfs._ACL), f"{what} header"))
        self.length = self.header.AclSize

        if self.length < len(c_ntfs._ACL):
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: AclSize {self.header.AclSize} is smaller than the ACL header"
            )
        if self.length > length:
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: AclSize {self.header.AclSize} exceeds the "
                f"{length} bytes available for it"
            )

        self.end = self.offset + self.length
        self.ace = []
        ace_offset = self.offset + len(c_ntfs._ACL)
        for index in range(self.header.AceCount):
            if ace_offset >= self.end:
                raise InvalidSecurityDescriptor(
                    f"{what} at 0x{self.offset:x}: AceCount {self.header.AceCount} requires more than "
                    f"AclSize {self.length} allows"
                )

            ace = ACE(fh, ace_offset, self.end - ace_offset, f"{what} ACE[{index}]")
            self.ace.append(ace)
            ace_offset = ace.end

        if ace_offset != self.end:
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: AceCount {self.header.AceCount} does not account for all "
                f"{self.length} bytes of AclSize"
            )

    @property
    def range(self) -> tuple[int, int]:
        """The absolute ``(start, end)`` range of this ACL."""
        return self.offset, self.end


class ACE:
    """Parse an ACE from a file-like object.

    The body is bounded by this ACE's own ``AceSize``. Optional object GUIDs,
    callback/application data and SIDs are only read from these bytes, so a
    malformed inner length can never consume the next ACE.

    Args:
        fh: The file-like object to parse an ACE from.
        offset: Absolute offset of the ACE in ``fh``. Defaults to the current position.
        length: Optional maximum size available for the ACE. Defaults to the remaining stream size.
        what: Description of this ACE used in error messages.
    """

    def __init__(
        self, fh: BinaryIO, offset: int | None = None, length: int | None = None, what: str = "ACE"
    ):
        self.offset = fh.tell() if offset is None else offset
        if length is None:
            length = _stream_size(fh) - self.offset

        if length < len(c_ntfs._ACE_HEADER):
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: only {length} bytes available, smaller than the ACE header"
            )

        self.header = c_ntfs._ACE_HEADER(
            _read_at(fh, self.offset, len(c_ntfs._ACE_HEADER), f"{what} header")
        )
        self.length = self.header.AceSize

        if self.length < len(c_ntfs._ACE_HEADER):
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: AceSize {self.header.AceSize} is smaller than the ACE header"
            )
        if self.length > length:
            raise InvalidSecurityDescriptor(
                f"{what} at 0x{self.offset:x}: AceSize {self.header.AceSize} exceeds the "
                f"{length} bytes available before the end of the ACL"
            )

        self.end = self.offset + self.length
        self.data = _read_at(
            fh, self.offset + len(c_ntfs._ACE_HEADER), self.length - len(c_ntfs._ACE_HEADER), f"{what} body"
        )

        self.mask = None
        self.flags = None
        self.object_type = None
        self.inherited_object_type = None
        self.sid = None
        self.compound_type = None
        self.server_sid = None

        buf = _Cursor(self.data, what)
        if self.is_standard_ace:
            self.mask = buf.read_dword("mask")
            self.sid = buf.read_sid("SID")
        elif self.is_compound_ace:
            self.mask = buf.read_dword("mask")
            self.compound_type = c_ntfs.COMPOUND_ACE_TYPE(buf.read(2, "compound type"))
            buf.read(2, "reserved")
            self.server_sid = buf.read_sid("server SID")
            self.sid = buf.read_sid("client SID")
        elif self.is_object_ace:
            self.mask = buf.read_dword("mask")
            self.flags = buf.read_dword("object flags")
            if self.flags & ACE_OBJECT_FLAGS.ACE_OBJECT_TYPE_PRESENT:
                self.object_type = UUID(bytes_le=buf.read(16, "object type GUID"))
            if self.flags & ACE_OBJECT_FLAGS.ACE_INHERITED_OBJECT_TYPE_PRESENT:
                self.inherited_object_type = UUID(bytes_le=buf.read(16, "inherited object type GUID"))
            self.sid = buf.read_sid("SID")

        self.application_data = buf.read_rest()

    @property
    def range(self) -> tuple[int, int]:
        """The absolute ``(start, end)`` range of this ACE."""
        return self.offset, self.end

    def __repr__(self) -> str:
        if self.is_standard_ace:
            return f"<{self.header.AceType.name} mask=0x{self.mask:x} sid={self.sid}>"
        if self.is_compound_ace:
            return (
                f"<{self.header.AceType.name} mask=0x{self.mask:x} type={self.compound_type.name}"
                f" server_sid={self.server_sid} client_sid={self.sid}>"
            )
        if self.is_object_ace:
            return (
                f"<{self.header.AceType.name} mask=0x{self.mask:x} flags={self.flags} object_type={self.object_type}"
                f" inherited_object_type={self.inherited_object_type} sid={self.sid}>"
            )
        return f"<ACE type={self.header.AceType} flags={self.header.AceFlags} size={self.header.AceSize}>"

    @property
    def type(self) -> ACE_TYPE:
        """Return the ACE type."""
        return self.header.AceType

    @property
    def is_standard_ace(self) -> bool:
        """Return whether this ACE is a standard ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED,
            ACE_TYPE.ACCESS_DENIED,
            ACE_TYPE.SYSTEM_AUDIT,
            ACE_TYPE.SYSTEM_ALARM,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
            ACE_TYPE.ACCESS_DENIED_CALLBACK,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK,
            ACE_TYPE.SYSTEM_MANDATORY_LABEL,
            ACE_TYPE.SYSTEM_RESOURCE_ATTRIBUTE,
            ACE_TYPE.SYSTEM_SCOPED_POLICY_ID,
            ACE_TYPE.SYSTEM_PROCESS_TRUST_LABEL,
            ACE_TYPE.SYSTEM_ACCESS_FILTER,
        )

    @property
    def is_compound_ace(self) -> bool:
        """Return whether this ACE is a compound ACE."""
        return self.header.AceType in (ACE_TYPE.ACCESS_ALLOWED_COMPOUND,)

    @property
    def is_object_ace(self) -> bool:
        """Return whether this ACE is an object ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED_OBJECT,
            ACE_TYPE.ACCESS_DENIED_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_OBJECT,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
            ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK_OBJECT,
        )
