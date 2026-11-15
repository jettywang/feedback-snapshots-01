from __future__ import annotations

import io
import json

import pytest

from dissect.fve.luks.c_luks import LUKS2_MAGIC_1ST, LUKS2_MAGIC_2ND, c_luks
from dissect.fve.luks.layout import LayoutError
from dissect.fve.luks.luks import LUKS

HDR_SIZE = 0x4000
SECONDARY_OFFSET = 0x4000
METADATA_END = 0x8000  # primary [0, 0x4000) + secondary [0x4000, 0x8000)
KEYSLOT_OFFSET = 0x8000
KEYSLOT_SIZE = 0x20000
SEGMENT_OFFSET = 0x100000
DEVICE_SIZE = 0x200000

UUID = b"12345678-1234-1234-1234-123456789012" + b"\x00" * 4


class CountingStream(io.BytesIO):
    """A stream that records the byte ranges actually read from it."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads: list[tuple[int, int]] = []

    def read(self, size: int = -1) -> bytes:
        start = self.tell()
        data = super().read(size)
        if data:
            self.reads.append((start, start + len(data)))
        return data


def _write_header(img: bytearray, offset: int, magic: bytes) -> None:
    header = c_luks.luks2_hdr_disk()
    header.magic = magic
    header.version = 2
    header.hdr_size = HDR_SIZE
    header.seqid = 1
    header.label = b""
    header.checksum_alg = b"sha256"
    header.salt = bytes(64)
    header.uuid = UUID
    header.subsystem = b""
    header.hdr_offset = offset
    header.csum = bytes(64)
    img[offset : offset + 4096] = bytes(header)


def _build_image(
    *,
    keyslots: dict | None = None,
    segments: dict | None = None,
    device_size: int = DEVICE_SIZE,
) -> bytes:
    if keyslots is None:
        keyslots = {
            "0": {
                "type": "luks2",
                "key_size": 32,
                "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
                "area": {
                    "type": "raw",
                    "offset": str(KEYSLOT_OFFSET),
                    "size": str(KEYSLOT_SIZE),
                    "encryption": "aes-ecb",
                    "key_size": 32,
                },
                "kdf": {
                    "type": "pbkdf2",
                    "hash": "sha256",
                    "iterations": 1000,
                    "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                },
            }
        }
    if segments is None:
        segments = {
            "0": {
                "type": "crypt",
                "offset": str(SEGMENT_OFFSET),
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-ecb",
                "sector_size": 512,
            }
        }

    metadata = {
        "keyslots": keyslots,
        "tokens": {},
        "segments": segments,
        "digests": {},
        "config": {"json_size": "12288", "keyslots_size": str(KEYSLOT_SIZE)},
    }
    json_area = json.dumps(metadata).encode()
    assert len(json_area) <= HDR_SIZE - 4096

    img = bytearray(device_size)
    _write_header(img, 0, LUKS2_MAGIC_1ST)
    _write_header(img, SECONDARY_OFFSET, LUKS2_MAGIC_2ND)
    img[4096 : 4096 + len(json_area)] = json_area
    img[SECONDARY_OFFSET + 4096 : SECONDARY_OFFSET + 4096 + len(json_area)] = json_area
    return bytes(img)


def _keyslot_area(offset: str, size: str) -> dict:
    return {
        "0": {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": offset, "size": size, "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "pbkdf2",
                "hash": "sha256",
                "iterations": 1000,
                "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            },
        }
    }


def _segment(offset: str, size: str, sector_size: int = 512) -> dict:
    return {
        "0": {
            "type": "crypt",
            "offset": offset,
            "size": size,
            "iv_tweak": "0",
            "encryption": "aes-ecb",
            "sector_size": sector_size,
        }
    }


def _assert_reads_confined_to_metadata(fh: CountingStream) -> None:
    """No keyslot or payload bytes may be read while opening the volume."""
    assert fh.reads
    for start, end in fh.reads:
        assert end <= METADATA_END, f"read outside metadata areas: [{start:#x}, {end:#x})"


def test_valid_layout_resolves_physical_ranges() -> None:
    fh = CountingStream(_build_image())
    luks_obj = LUKS(fh)

    regions = {region.field: (region.start, region.end) for region in luks_obj.layout}
    assert regions["metadata(hdr_offset=0x0)"] == (0, HDR_SIZE)
    assert regions[f"metadata(hdr_offset={SECONDARY_OFFSET:#x})"] == (SECONDARY_OFFSET, METADATA_END)
    assert regions["keyslots[0].area"] == (KEYSLOT_OFFSET, KEYSLOT_OFFSET + KEYSLOT_SIZE)
    # "dynamic" size is resolved against the end of the device, in bytes
    assert regions["segments[0]"] == (SEGMENT_OFFSET, DEVICE_SIZE)

    _assert_reads_confined_to_metadata(fh)


def test_segment_pointing_into_metadata_rejected() -> None:
    # Same layout as the valid header, except the data segment points into the metadata area
    fh = CountingStream(_build_image(segments=_segment("4096", "4096")))

    with pytest.raises(LayoutError) as excinfo:
        LUKS(fh)

    message = str(excinfo.value)
    assert "segments[0]" in message
    assert "metadata" in message
    assert "[0x1000, 0x2000)" in message
    assert "[0x0, 0x4000)" in message
    # The diagnostic is a layout conflict, not a passphrase failure
    assert "password" not in message.lower()
    assert "volume key" not in message.lower()

    _assert_reads_confined_to_metadata(fh)


def test_keyslot_area_overlapping_metadata_rejected() -> None:
    fh = CountingStream(_build_image(keyslots=_keyslot_area("4096", str(KEYSLOT_SIZE))))

    with pytest.raises(LayoutError, match=r"metadata.*overlaps keyslots\[0\]\.area"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_keyslot_areas_overlapping_each_other_rejected() -> None:
    keyslots = _keyslot_area(str(KEYSLOT_OFFSET), str(KEYSLOT_SIZE))
    keyslots["1"] = dict(keyslots["0"])
    keyslots["1"]["area"] = dict(keyslots["0"]["area"], offset=str(KEYSLOT_OFFSET + 0x10000))

    fh = CountingStream(_build_image(keyslots=keyslots))

    with pytest.raises(LayoutError) as excinfo:
        LUKS(fh)

    message = str(excinfo.value)
    assert "keyslots[0].area" in message
    assert "keyslots[1].area" in message
    assert "[0x8000, 0x28000)" in message
    assert "[0x18000, 0x38000)" in message

    _assert_reads_confined_to_metadata(fh)


def test_segment_overlapping_keyslot_area_rejected() -> None:
    fh = CountingStream(_build_image(segments=_segment(str(KEYSLOT_OFFSET + 0x1000), "4096")))

    with pytest.raises(LayoutError, match=r"keyslots\[0\]\.area .* overlaps segments\[0\]"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_negative_range_rejected() -> None:
    fh = CountingStream(_build_image(keyslots=_keyslot_area("-32768", str(KEYSLOT_SIZE))))

    with pytest.raises(LayoutError, match=r"keyslots\[0\]\.area has negative offset -32768"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_out_of_bounds_rejected() -> None:
    fh = CountingStream(_build_image(keyslots=_keyslot_area(str(KEYSLOT_OFFSET), str(DEVICE_SIZE))))

    with pytest.raises(LayoutError, match=r"exceeds device size 0x200000"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_dynamic_segment_past_device_end_rejected() -> None:
    fh = CountingStream(_build_image(segments=_segment(str(DEVICE_SIZE + 0x1000), "dynamic")))

    with pytest.raises(LayoutError, match=r"segments\[0\] has negative size"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_invalid_segment_size_string_rejected() -> None:
    fh = CountingStream(_build_image(segments=_segment(str(SEGMENT_OFFSET), "banana")))

    with pytest.raises(LayoutError, match=r"segments\[0\]\.size has invalid value 'banana'"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_invalid_sector_size_rejected() -> None:
    fh = CountingStream(_build_image(segments=_segment(str(SEGMENT_OFFSET), "dynamic", sector_size=1000)))

    with pytest.raises(LayoutError, match=r"segments\[0\]\.sector_size must be a power of two"):
        LUKS(fh)

    _assert_reads_confined_to_metadata(fh)


def test_legitimate_sharing_not_flagged() -> None:
    # Two adjacent (touching) keyslot areas, a segment starting exactly where the
    # keyslot area ends, and a 4096 byte sector size: all legitimate, no conflicts.
    keyslots = _keyslot_area(str(KEYSLOT_OFFSET), "65536")
    keyslots["1"] = dict(keyslots["0"])
    keyslots["1"]["area"] = dict(keyslots["0"]["area"], offset=str(KEYSLOT_OFFSET + 65536))

    segments = _segment(str(KEYSLOT_OFFSET + 2 * 65536), "dynamic", sector_size=4096)

    fh = CountingStream(_build_image(keyslots=keyslots, segments=segments))
    luks_obj = LUKS(fh)

    regions = {region.field: (region.start, region.end) for region in luks_obj.layout}
    assert regions["keyslots[0].area"] == (KEYSLOT_OFFSET, KEYSLOT_OFFSET + 65536)
    assert regions["keyslots[1].area"] == (KEYSLOT_OFFSET + 65536, KEYSLOT_OFFSET + 2 * 65536)
    assert regions["segments[0]"] == (KEYSLOT_OFFSET + 2 * 65536, DEVICE_SIZE)

    _assert_reads_confined_to_metadata(fh)
