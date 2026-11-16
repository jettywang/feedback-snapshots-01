from __future__ import annotations

import io
import struct
from itertools import pairwise
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

import pytest

from dissect.ntfs.c_ntfs import ACE_TYPE
from dissect.ntfs.exceptions import InvalidSecurityDescriptor
from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.secure import ACE, Secure, SecurityDescriptor

if TYPE_CHECKING:
    from collections.abc import Callable


def test_secure(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    assert fs.secure

    sd = fs.secure.lookup(256)
    assert sd.owner == "S-1-5-18"
    assert sd.group == "S-1-5-32-544"

    assert sd.dacl
    assert len(sd.dacl.ace) == 2
    assert sd.dacl.ace[0].type.name == "ACCESS_ALLOWED"
    assert sd.dacl.ace[0].mask == 0x120089
    assert sd.dacl.ace[0].sid == "S-1-5-18"
    assert sd.dacl.ace[1].type.name == "ACCESS_ALLOWED"
    assert sd.dacl.ace[1].mask == 0x120089
    assert sd.dacl.ace[1].sid == "S-1-5-32-544"

    with pytest.raises(KeyError):
        fs.secure.lookup(1337)

    assert len(list(fs.secure.descriptors())) == 24


def test_secure_file(sds_bin: BinaryIO) -> None:
    secure = Secure(sds=sds_bin)

    sd = secure.lookup(256)
    assert sd.owner == "S-1-5-18"
    assert sd.group == "S-1-5-32-544"


def test_secure_complex_acl(sds_complex_bin: BinaryIO) -> None:
    secure = Secure(sds=sds_complex_bin)

    sd = secure.lookup(259)
    assert sd.owner == "S-1-5-21-3090333131-159632407-777084872-1001"
    assert sd.group == "S-1-5-21-3090333131-159632407-777084872-513"
    assert len(sd.sacl.ace) == 2
    assert list(map(repr, sd.sacl.ace)) == [
        "<SYSTEM_MANDATORY_LABEL mask=0x7 sid=S-1-16-4096>",
        "<SYSTEM_ACCESS_FILTER mask=0x1200a9 sid=S-1-1-0>",
    ]
    assert len(sd.dacl.ace) == 3
    assert list(map(repr, sd.dacl.ace)) == [
        "<ACCESS_ALLOWED_COMPOUND mask=0x1f01ff type=COMPOUND_ACE_IMPERSONATION server_sid=S-1-5-11 client_sid=S-1-5-32-545>",  # noqa: E501
        "<ACCESS_ALLOWED_OBJECT mask=0x1f01ff flags=0 object_type=None inherited_object_type=None sid=S-1-1-0>",
        "<ACCESS_ALLOWED_CALLBACK_OBJECT mask=0x1f01ff flags=3 object_type=01234567-89ab-cdef-1111-111111111111 inherited_object_type=22222222-2222-2222-0123-456789abcdef sid=S-1-5-32-545>",  # noqa: E501
    ]


def test_secure_fail() -> None:
    with pytest.raises(ValueError, match="Either record or SDS stream is required"):
        Secure()


def _sid(*sub_authorities: int, revision: int = 1, authority: int = 5) -> bytes:
    return (
        bytes([revision, len(sub_authorities)])
        + authority.to_bytes(6, "big")
        + b"".join(struct.pack("<I", sub_authority) for sub_authority in sub_authorities)
    )


def _ace(ace_type: int, ace_flags: int = 0, body: bytes = b"", ace_size: int | None = None) -> bytes:
    ace_size = 4 + len(body) if ace_size is None else ace_size
    return struct.pack("<BBH", ace_type, ace_flags, ace_size) + body


def _acl(*aces: bytes, ace_count: int | None = None, acl_size: int | None = None, revision: int = 2) -> bytes:
    ace_data = b"".join(aces)
    acl_size = 8 + len(ace_data) if acl_size is None else acl_size
    ace_count = len(aces) if ace_count is None else ace_count
    return struct.pack("<BBHHH", revision, 0, acl_size, ace_count, 0) + ace_data


def _security_descriptor(
    owner: bytes | None = None,
    group: bytes | None = None,
    sacl: bytes | None = None,
    dacl: bytes | None = None,
    *,
    control: int = 0x8004,
) -> tuple[bytes, dict[str, tuple[int, int]]]:
    """Build a self-relative descriptor and report the actual absolute ranges of its components."""
    header_size = 20
    ranges: dict[str, tuple[int, int]] = {}
    payload = b""

    def append(name: str, data: bytes | None) -> int:
        nonlocal payload
        if data is None:
            return 0

        offset = header_size + len(payload)
        ranges[name] = (offset, offset + len(data))
        payload += data
        return offset

    owner_offset = append("owner", owner)
    group_offset = append("group", group)
    sacl_offset = append("sacl", sacl)
    dacl_offset = append("dacl", dacl)

    header = struct.pack("<BBHIIII", 1, 0, control, owner_offset, group_offset, sacl_offset, dacl_offset)
    return header + payload, ranges


def _parse(data: bytes) -> SecurityDescriptor:
    return SecurityDescriptor(io.BytesIO(data), len(data))


def test_security_descriptor_component_ranges() -> None:
    owner = _sid(21, 3090333131, 159632407, 777084872, 1001)
    group = _sid(21, 3090333131, 159632407, 777084872, 513)
    sacl = _acl(
        _ace(
            ACE_TYPE.SYSTEM_MANDATORY_LABEL,
            0,
            struct.pack("<I", 0x07) + _sid(16, 4096),
        )
    )
    dacl = _acl(
        _ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + _sid(18)),
        _ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(32, 544)),
    )
    data, ranges = _security_descriptor(owner, group, sacl=sacl, dacl=dacl)

    sd = _parse(data)

    assert sd.owner == "S-1-5-21-3090333131-159632407-777084872-1001"
    assert sd.group == "S-1-5-21-3090333131-159632407-777084872-513"
    assert sd.range == (0, len(data))
    assert sd.owner_range == ranges["owner"]
    assert sd.group_range == ranges["group"]
    assert sd.sacl_range == ranges["sacl"]
    assert sd.dacl_range == ranges["dacl"]
    assert sd.sacl.range == ranges["sacl"]
    assert sd.dacl.range == ranges["dacl"]

    # Each ACE independently reports its own absolute range.
    assert [ace.range for ace in sd.sacl.ace] == [(ranges["sacl"][0] + 8, ranges["sacl"][1])]
    first_ace_end = ranges["dacl"][0] + 8 + sd.dacl.ace[0].header.AceSize
    assert [ace.range for ace in sd.dacl.ace] == [
        (ranges["dacl"][0] + 8, first_ace_end),
        (first_ace_end, ranges["dacl"][1]),
    ]

    # Every component stays inside the descriptor and components do not overlap.
    component_ranges = [sd.owner_range, sd.group_range, sd.sacl.range, sd.dacl.range]
    assert all(0 <= start < end <= sd.end for start, end in component_ranges)
    assert component_ranges == sorted(component_ranges)
    assert all(left[1] <= right[0] for left, right in pairwise(component_ranges))


def test_object_ace_and_callback_data_round_trip() -> None:
    object_type = UUID("01234567-89ab-cdef-1111-111111111111")
    inherited_object_type = UUID("22222222-2222-2222-0123-456789abcdef")
    application_data = b"CALLBACK-DATA\x00\xff"
    body = (
        struct.pack("<II", 0x1F01FF, 3)
        + object_type.bytes_le
        + inherited_object_type.bytes_le
        + _sid(32, 545)
        + application_data
    )
    ace = _ace(ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT, 0, body)

    parsed = ACE(io.BytesIO(ace), 0, len(ace))

    assert parsed.type == ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT
    assert parsed.mask == 0x1F01FF
    assert parsed.flags == 3
    assert parsed.object_type == object_type
    assert parsed.inherited_object_type == inherited_object_type
    assert parsed.sid == "S-1-5-32-545"
    assert parsed.application_data == application_data
    assert parsed.range == (0, len(ace))

    # Application data must not leak into a following ACE in the same ACL.
    trailing = _ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(18))
    dacl = _acl(ace, trailing)
    sd = _parse(_security_descriptor(dacl=dacl)[0])

    assert sd.dacl.ace[0].application_data == application_data
    assert sd.dacl.ace[1].type == ACE_TYPE.ACCESS_DENIED
    assert sd.dacl.ace[1].application_data is None
    assert sd.dacl.ace[0].end == sd.dacl.ace[1].offset


def test_callback_application_data_is_not_a_next_ace() -> None:
    application_data = bytes(range(0x10))
    ace = _ace(
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
        0,
        struct.pack("<I", 0x120089) + _sid(18) + application_data,
    )

    parsed = ACE(io.BytesIO(ace), 0, len(ace))

    assert parsed.sid == "S-1-5-18"
    assert parsed.application_data == application_data
    assert parsed.range == (0, len(ace))


def test_unknown_ace_type_preserves_bytes() -> None:
    body = b"\xde\xad\xbe\xef\x00\xff"
    ace = _ace(0x42, 0x03, body)

    parsed = ACE(io.BytesIO(ace), 0, len(ace))

    assert parsed.type.value == 0x42
    assert not parsed.is_standard_ace
    assert not parsed.is_compound_ace
    assert not parsed.is_object_ace
    assert parsed.sid is None
    assert parsed.mask is None
    assert parsed.application_data == body
    assert parsed.data == body
    assert parsed.range == (0, len(ace))
    assert "ACE_TYPE.66" in repr(parsed)


def test_mixed_acl_with_object_callback_and_unknown_ace() -> None:
    object_type = UUID("11111111-2222-3333-4444-555555555555")
    object_ace = _ace(
        ACE_TYPE.ACCESS_ALLOWED_OBJECT,
        0x01,
        struct.pack("<II", 0x120089, 0x01) + object_type.bytes_le + _sid(0),
    )
    callback_ace = _ace(
        ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT,
        0x00,
        struct.pack("<II", 0x120089, 0x03)
        + UUID("01234567-89ab-cdef-1111-111111111111").bytes_le
        + UUID("22222222-2222-2222-0123-456789abcdef").bytes_le
        + _sid(32, 545)
        + b"audit\x00data",
    )
    unknown_ace = _ace(0x42, 0x10, b"\x00\x01\x02\x03")
    dacl = _acl(object_ace, callback_ace, unknown_ace)

    sd = _parse(_security_descriptor(dacl=dacl)[0])

    assert sd.dacl.header.AceCount == 3
    assert [ace.type.value for ace in sd.dacl.ace] == [
        ACE_TYPE.ACCESS_ALLOWED_OBJECT.value,
        ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT.value,
        0x42,
    ]
    assert sd.dacl.ace[0].object_type == object_type
    assert sd.dacl.ace[0].inherited_object_type is None
    assert sd.dacl.ace[1].sid == "S-1-5-32-545"
    assert sd.dacl.ace[1].application_data == b"audit\x00data"
    assert sd.dacl.ace[2].application_data == b"\x00\x01\x02\x03"
    assert sd.dacl.ace[-1].end == sd.dacl.end


@pytest.mark.parametrize(
    ("name", "corrupt", "match"),
    [
        (
            "AceCount beyond AclSize",
            lambda aces, acl: _acl(*aces, ace_count=len(aces) + 1),
            r"AceCount 3 requires more than AclSize",
        ),
        (
            "AclSize beyond descriptor",
            lambda aces, acl: _acl(*aces, acl_size=len(acl) + 32),
            r"AclSize \d+ exceeds the \d+ bytes available",
        ),
        (
            "AclSize shorter than header",
            lambda aces, acl: _acl(*aces, acl_size=4),
            r"AclSize 4 is smaller than the ACL header",
        ),
        (
            "AceSize beyond AclSize",
            lambda aces, acl: _acl(
                _ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + _sid(18), ace_size=0x1000)
            ),
            r"AceSize 4096 exceeds the \d+ bytes available before the end of the ACL",
        ),
        (
            "AceSize shorter than header",
            lambda aces, acl: _acl(_ace(ACE_TYPE.ACCESS_ALLOWED, 0, b"", ace_size=3)),
            r"AceSize 3 is smaller than the ACE header",
        ),
        (
            "AceCount short of AclSize",
            lambda aces, acl: _acl(*aces, ace_count=len(aces) - 1),
            r"AceCount 1 does not account for all \d+ bytes of AclSize",
        ),
        (
            "SID truncated before header",
            lambda aces, acl: _acl(_ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089))),
            r"DACL ACE\[0\] SID: truncated SID header, expected 8 bytes but got 0",
        ),
        (
            "SID sub-authority count beyond ACE",
            lambda aces, acl: _acl(
                _ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + bytes([1, 40]) + b"\x00" * 6)
            ),
            r"DACL ACE\[0\] SID: SID sub-authority count 40 requires 168 bytes, but only 8 are available",
        ),
        (
            "SID sub-authority count beyond object ACE",
            lambda aces, acl: _acl(
                _ace(
                    ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
                    0,
                    struct.pack("<II", 0x120089, 3)
                    + UUID(int=0).bytes_le
                    + UUID(int=0).bytes_le
                    + bytes([1, 40])
                    + b"\x00" * 6,
                )
            ),
            r"DACL ACE\[0\] SID: SID sub-authority count 40 requires 168 bytes, but only 8 are available",
        ),
        (
            "object type GUID truncated",
            lambda aces, acl: _acl(
                _ace(ACE_TYPE.ACCESS_ALLOWED_OBJECT, 0, struct.pack("<II", 0x120089, 0x01) + b"\x00" * 8)
            ),
            r"DACL ACE\[0\]: truncated object type GUID, expected 16 bytes but only 8 are available",
        ),
        (
            "inherited object type GUID truncated",
            lambda aces, acl: _acl(
                _ace(
                    ACE_TYPE.ACCESS_DENIED_OBJECT,
                    0,
                    struct.pack("<II", 0x120089, 0x03) + UUID(int=0).bytes_le + b"\x00" * 8,
                )
            ),
            r"DACL ACE\[0\]: truncated inherited object type GUID, expected 16 bytes but only 8 are available",
        ),
        (
            "object ACE mask truncated",
            lambda aces, acl: _acl(_ace(ACE_TYPE.ACCESS_ALLOWED_OBJECT, 0, b"\x01\x02")),
            r"DACL ACE\[0\]: truncated mask, expected 4 bytes but only 2 are available",
        ),
        (
            "object ACE flags truncated",
            lambda aces, acl: _acl(
                _ace(ACE_TYPE.ACCESS_ALLOWED_OBJECT, 0, struct.pack("<I", 0x120089) + b"\x01")
            ),
            r"DACL ACE\[0\]: truncated object flags, expected 4 bytes but only 1 are available",
        ),
        (
            "compound server SID truncated",
            lambda aces, acl: _acl(
                _ace(
                    ACE_TYPE.ACCESS_ALLOWED_COMPOUND,
                    0,
                    struct.pack("<IHH", 0x120089, 1, 0) + bytes([1, 40]) + b"\x00" * 6,
                )
            ),
            r"DACL ACE\[0\] server SID: SID sub-authority count 40 requires 168 bytes, but only 8 are available",
        ),
        (
            "compound client SID truncated",
            lambda aces, acl: _acl(
                _ace(
                    ACE_TYPE.ACCESS_ALLOWED_COMPOUND,
                    0,
                    struct.pack("<IHH", 0x120089, 1, 0) + _sid(11) + bytes([1, 40]) + b"\x00" * 6,
                )
            ),
            r"DACL ACE\[0\] client SID: SID sub-authority count 40 requires 168 bytes, but only 8 are available",
        ),
        (
            "compound type truncated",
            lambda aces, acl: _acl(
                _ace(ACE_TYPE.ACCESS_ALLOWED_COMPOUND, 0, struct.pack("<I", 0x120089) + b"\x01")
            ),
            r"DACL ACE\[0\]: truncated compound type, expected 2 bytes but only 1 are available",
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_malformed_acl_is_bounded(name: str, corrupt: Callable[[list[bytes], bytes], bytes], match: str) -> None:
    valid_ace = _ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + _sid(18))
    marker_ace = _ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(18))
    broken_dacl = corrupt([valid_ace, marker_ace], _acl(valid_ace, marker_ace))
    broken, _ = _security_descriptor(dacl=broken_dacl)

    with pytest.raises(InvalidSecurityDescriptor, match=match):
        _parse(broken)


def test_owner_sid_does_not_cross_into_group() -> None:
    # The owner SID claims 100 sub-authorities but only has 8 bytes before the group.
    # There is plenty of descriptor data after the group, so an unbounded SID read
    # would silently consume the group and DACL instead of failing.
    owner = bytes([1, 100]) + (5).to_bytes(6, "big")
    group = _sid(32, 544)
    dacl = _acl(_ace(0x42, 0, b"\x00" * 400))
    data, ranges = _security_descriptor(owner, group, dacl=dacl)

    with pytest.raises(InvalidSecurityDescriptor, match=r"owner SID: SID sub-authority count 100 requires 408 bytes"):
        _parse(data)

    # The group is still independently addressable and was not consumed by the owner.
    group_size = 8 + (4 * 2)
    assert ranges["group"] == (ranges["owner"][1], ranges["owner"][1] + group_size)


def test_ace_application_data_does_not_cross_into_next_ace() -> None:
    # A callback ACE with an over-long SID must not read into the following ACE.
    callback = _ace(
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
        0,
        struct.pack("<I", 0x120089) + bytes([1, 40]) + b"\x00" * 6 + b"CALLBACK",
    )
    following = _ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(18))
    dacl = _acl(callback, following)

    with pytest.raises(InvalidSecurityDescriptor, match=r"DACL ACE\[0\] SID"):
        _parse(_security_descriptor(dacl=dacl)[0])


def test_unknown_ace_with_callback_like_bytes_is_not_reinterpreted() -> None:
    # The unknown ACE body starts with bytes that look like a callback ACE. It must
    # stay opaque rather than being parsed as one.
    body = struct.pack("<I", 0x120089) + _sid(18) + b"payload"
    unknown = _ace(0x42, 0, body)
    dacl = _acl(unknown, _ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(18)))

    sd = _parse(_security_descriptor(dacl=dacl)[0])

    assert sd.dacl.ace[0].type.value == 0x42
    assert sd.dacl.ace[0].mask is None
    assert sd.dacl.ace[0].sid is None
    assert sd.dacl.ace[0].application_data == body
    assert sd.dacl.ace[1].sid == "S-1-5-18"
    assert sd.dacl.ace[0].end == sd.dacl.ace[1].offset


def test_malformed_descriptor_does_not_borrow_next_descriptor() -> None:
    valid_dacl = _acl(_ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + _sid(18)))
    broken_sd, broken_ranges = _security_descriptor(dacl=valid_dacl)
    marker_sd, _ = _security_descriptor(
        owner=_sid(21, 3090333131, 159632407, 777084872, 1001),
        dacl=_acl(_ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(18))),
    )

    # Grow the broken descriptor's AclSize (ACL offset + 2) so it would otherwise
    # consume the following descriptor's bytes.
    claimed_size = len(valid_dacl) + len(marker_sd) + 8
    acl_offset = broken_ranges["dacl"][0]
    broken_sd = broken_sd[: acl_offset + 2] + struct.pack("<H", claimed_size) + broken_sd[acl_offset + 4 :]

    stream = io.BytesIO(broken_sd + marker_sd)

    with pytest.raises(InvalidSecurityDescriptor) as exc_info:
        SecurityDescriptor(stream, len(broken_sd))

    message = str(exc_info.value)
    assert "AclSize" in message
    assert f"0x{acl_offset:x}" in message


def test_malformed_ace_error_names_ace_index() -> None:
    valid_ace = _ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + _sid(18))
    broken_ace = _ace(ACE_TYPE.ACCESS_ALLOWED_CALLBACK, 0, struct.pack("<I", 0x120089) + bytes([1, 40]) + b"\x00" * 6)
    dacl = _acl(valid_ace, broken_ace)

    with pytest.raises(InvalidSecurityDescriptor, match=r"DACL ACE\[1\]"):
        _parse(_security_descriptor(dacl=dacl)[0])


def test_sds_lookup_uses_entry_length(sds_complex_bin: BinaryIO) -> None:
    secure = Secure(sds=sds_complex_bin)
    sd = secure.lookup(259)

    assert sd.range[1] - sd.range[0] == 360
    assert sd.dacl.range == (sd.offset + sd.header.Dacl, sd.offset + sd.header.Dacl + sd.dacl.header.AclSize)
    assert sd.sacl.range == (sd.offset + sd.header.Sacl, sd.offset + sd.header.Sacl + sd.sacl.header.AclSize)
    assert sd.owner_range == (sd.offset + sd.header.Owner, sd.offset + sd.header.Owner + 8 + 4 * 5)
    assert sd.group_range == (sd.offset + sd.header.Group, sd.offset + sd.header.Group + 8 + 4 * 5)


def _sds_entry(security_id: int, descriptor: bytes) -> bytes:
    payload = struct.pack("<IIQI", security_id, security_id, 0, 20 + len(descriptor)) + descriptor
    return payload + b"\x00" * (-len(payload) % 16)


def test_sds_stream_fences_descriptors() -> None:
    # Two entries in one SDS stream. The first has a DACL whose AclSize would
    # swallow the second descriptor if the SDS entry length were not enforced.
    first_descriptor = _security_descriptor(
        dacl=_acl(_ace(ACE_TYPE.ACCESS_ALLOWED, 0, struct.pack("<I", 0x120089) + _sid(18)))
    )[0]
    second_descriptor = _security_descriptor(
        owner=_sid(21, 3090333131, 159632407, 777084872, 1001),
        dacl=_acl(_ace(ACE_TYPE.ACCESS_DENIED, 0, struct.pack("<I", 0x120089) + _sid(18))),
    )[0]

    first_entry = _sds_entry(256, first_descriptor)
    stream_data = first_entry + _sds_entry(257, second_descriptor)

    # Corrupt the first entry's AclSize so it claims bytes from the second entry.
    acl_relative = struct.unpack_from("<I", first_descriptor, 16)[0]
    acl_position = 20 + acl_relative
    inflated = len(first_descriptor) - acl_relative + len(second_descriptor) + 20
    stream_data = stream_data[: acl_position + 2] + struct.pack("<H", inflated) + stream_data[acl_position + 4 :]

    secure = Secure(sds=io.BytesIO(stream_data))

    with pytest.raises(InvalidSecurityDescriptor, match=r"AclSize"):
        secure.lookup(256)

    # The second descriptor is still reachable and intact: the failure did not
    # consume or corrupt neighbouring entries.
    sd = secure.lookup(257)
    assert sd.owner == "S-1-5-21-3090333131-159632407-777084872-1001"
    assert sd.dacl.ace[0].sid == "S-1-5-18"
