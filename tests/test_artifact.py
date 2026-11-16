import io

import pytest

from dissect.cobaltstrike import artifact, utils


class CountingStream(io.BytesIO):
    """BytesIO that counts the total number of bytes handed to ``read`` callers."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.bytes_read = 0
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self.getvalue()) - self.tell()
        data = super().read(size)
        self.bytes_read += len(data)
        self.read_sizes.append(len(data))
        return data


def build_blob(offset: int, payload: bytes, xorkey: bytes = b"\x01\x02\x03\x04", hints: bytes = b"A" * 8) -> bytes:
    """Build a blob containing a complete ArtifactKit header at ``offset``."""
    blob = bytearray(b"\x00" * offset)
    blob += utils.p32(offset)
    blob += utils.p32(len(payload))
    blob += xorkey
    blob += hints
    blob += utils.xor(payload, xorkey)
    return bytes(blob)


def build_blob_with_declared_size(offset: int, encoded_payload: bytes, declared_size: int, xorkey: bytes) -> bytes:
    """Build a blob whose header declares ``declared_size`` but only carries ``encoded_payload``."""
    blob = bytearray(b"\x00" * offset)
    blob += utils.p32(offset)
    blob += utils.p32(declared_size)
    blob += xorkey
    blob += b"H" * 8
    blob += encoded_payload
    return bytes(blob)


def find(blob: bytes, **kwargs) -> list[artifact.ArtifactKitPayload]:
    return list(artifact.iter_artifactkit_payloads(io.BytesIO(blob), **kwargs))


def at(candidates: list[artifact.ArtifactKitPayload], offset: int) -> artifact.ArtifactKitPayload:
    """Return the candidate located at ``offset``."""
    matches = [candidate for candidate in candidates if candidate.offset == offset]
    assert len(matches) == 1
    return matches[0]


def test_complete_candidate_is_decoded_with_bounds() -> None:
    payload = b"MZ" + b"\x90" * 30
    blob = build_blob(0, payload)

    candidates = find(blob)
    assert len(candidates) == 1
    candidate = candidates[0]

    assert candidate.kind is artifact.ArtifactKitCandidateKind.COMPLETE
    assert candidate.is_complete
    assert not candidate.is_truncated
    assert not candidate.is_self_pointer_only
    assert candidate.offset == 0
    assert candidate.size == len(payload)
    assert candidate.declared_size == len(payload)
    assert candidate.payload == payload
    assert candidate.xorkey == b"\x01\x02\x03\x04"
    assert candidate.hints == b"A" * 8


def test_truncated_candidate_keeps_available_bytes_only() -> None:
    payload = b"\xcc" * 16
    xorkey = b"\x01\x02\x03\x04"
    # Header claims 1000 bytes, only the 16 encoded payload bytes are present.
    blob = build_blob_with_declared_size(0, utils.xor(payload, xorkey), declared_size=1000, xorkey=xorkey)

    candidates = find(blob)
    assert len(candidates) == 1
    candidate = candidates[0]

    assert candidate.kind is artifact.ArtifactKitCandidateKind.TRUNCATED
    assert candidate.is_truncated
    assert candidate.declared_size == 1000
    assert candidate.size == 16
    assert candidate.payload == payload


def test_oversized_declared_size_does_not_read_past_eof() -> None:
    payload = b"\xbe" * 8
    xorkey = b"\x09\x08\x07\x06"
    # A forged size of 4 GiB must not result in a multi-gigabyte read.
    blob = build_blob_with_declared_size(0, utils.xor(payload, xorkey), declared_size=2**32 - 1, xorkey=xorkey)
    stream = CountingStream(blob)

    candidates = list(artifact.iter_artifactkit_payloads(stream))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.is_truncated
    assert candidate.declared_size == 2**32 - 1
    # Only the bytes that physically exist may be read, and never the forged length.
    assert stream.bytes_read <= len(blob) * 3
    assert all(read <= len(blob) for read in stream.read_sizes)
    assert candidate.size == len(payload)
    assert candidate.payload == payload


def test_self_pointer_hit_without_full_header() -> None:
    # Offset 4 holds a valid self pointer but the data ends before a full header.
    blob = b"\x01\x02\x03\x04" + utils.p32(4) + b"\x10"
    candidates = find(blob)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.kind is artifact.ArtifactKitCandidateKind.SELF_POINTER
    assert candidate.is_self_pointer_only
    assert candidate.offset == 4
    assert candidate.size == 0
    assert candidate.declared_size == 0
    assert candidate.xorkey == b""
    assert candidate.hints == b""


def test_zero_padding_at_offset_zero_is_self_pointer_only() -> None:
    # A leading run of zero bytes inherently satisfies u32(0) == 0; it must be
    # reported as an explainable self-pointer candidate, never as a payload.
    blob = build_blob(128, b"\x90" * 6)
    candidates = find(blob)

    zero_hit = at(candidates, 0)
    assert zero_hit.is_self_pointer_only
    assert zero_hit.size == 0


def test_zero_size_declaration_is_self_pointer_only() -> None:
    blob = build_blob(12, b"")
    candidates = find(blob)

    candidate = at(candidates, 12)
    assert candidate.is_self_pointer_only
    assert candidate.offset == 12
    assert candidate.size == 0
    assert candidate.declared_size == 0
    assert candidate.xorkey == b""
    assert candidate.hints == b""


def test_overlapping_candidates_are_not_merged() -> None:
    # Two self pointers near the end of the data, where no 20-byte header can
    # fit. Both explainable hits must be reported once and never merged.
    first_offset = 8
    second_offset = 12
    blob = bytearray(b"\x01" * 16)
    blob[first_offset : first_offset + 4] = utils.p32(first_offset)
    blob[second_offset : second_offset + 4] = utils.p32(second_offset)

    candidates = find(bytes(blob))
    offsets = [candidate.offset for candidate in candidates]

    assert offsets == [first_offset, second_offset]
    assert all(candidate.is_self_pointer_only for candidate in candidates)


def test_self_pointer_straddling_chunk_boundary_is_found() -> None:
    # Place the pointer so its 4 bytes straddle a small chunk boundary.
    chunk_size = 32
    offset = chunk_size - 2
    blob = bytearray(b"\x01" * (chunk_size * 3))
    payload = b"shellcode!"
    blob[offset : offset + 4] = utils.p32(offset)
    blob[offset + 4 : offset + 8] = utils.p32(len(payload))
    blob[offset + 8 : offset + 12] = b"\x01\x02\x03\x04"
    blob[offset + 12 : offset + 20] = b"H" * 8
    blob[offset + 20 : offset + 20 + len(payload)] = utils.xor(payload, b"\x01\x02\x03\x04")

    candidates = find(bytes(blob), chunk_size=chunk_size)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.offset == offset
    assert candidate.is_complete
    assert candidate.payload == payload


def test_header_straddling_chunk_boundary_is_read_via_seek() -> None:
    # Pointer fits in one chunk but the rest of the 20-byte header crosses the boundary.
    chunk_size = 16
    offset = chunk_size - 2
    prefix = b"\x01" * offset
    payload = b"P" * 24
    blob = prefix + build_blob(offset, payload)[offset:]

    candidates = find(bytes(blob), chunk_size=chunk_size)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.offset == offset
    assert candidate.is_complete
    assert candidate.size == len(payload)
    assert candidate.payload == payload


def test_chunked_and_linear_scan_agree() -> None:
    payload = b"\x90" * 12
    prefix = b"\x01" * 40
    blob = bytearray(prefix + build_blob(40, payload)[40:])
    # Add a second, overlapping self pointer to exercise de-duplication behaviour.
    blob[60:64] = utils.p32(60)

    for chunk_size in (4, 7, 16, 33, 1024):
        offsets = [c.offset for c in find(bytes(blob), chunk_size=chunk_size)]
        assert offsets == [40, 60]


def test_counting_stream_read_volume_is_bounded_for_short_candidates() -> None:
    prefix = b"\x01" * 8
    payload = b"abcdefgh"
    blob = prefix + build_blob(len(prefix), payload)[len(prefix):]
    stream = CountingStream(blob)
    offset = len(prefix)

    candidates = list(artifact.iter_artifactkit_payloads(stream, chunk_size=16))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.offset == offset
    assert candidate.is_complete
    assert candidate.payload == payload
    # Scan reads cover the blob in chunks; candidate reads are capped to header + payload.
    assert stream.bytes_read < len(blob) * 4
    assert max(stream.read_sizes) <= max(16, artifact.HEADER_SIZE + len(payload))


def test_original_offsets_are_accurate_with_prefix() -> None:
    payload = b"\xcc" * 10
    offset = 128
    blob = build_blob(offset, payload)

    candidates = find(blob, chunk_size=32)

    candidate = at(candidates, offset)
    assert candidate.payload == payload


def test_maxrange_bounds_the_scan_window() -> None:
    payload = b"\x90" * 8
    offset = 64
    # ``build_blob`` lays down the full 64-byte prefix so the absolute self
    # pointer at ``offset`` is the only candidate.
    blob = build_blob(offset, payload)

    below_range = find(blob, maxrange=offset - 1)
    assert offset not in [candidate.offset for candidate in below_range]
    in_range = find(blob, maxrange=offset)
    candidate = at(in_range, offset)
    assert candidate.is_complete


def test_start_offset_is_respected() -> None:
    payload = b"\x90" * 8
    offset = 32
    blob = build_blob(offset, payload)

    assert [c.offset for c in find(blob, start_offset=offset)] == [offset]
    assert find(blob, start_offset=offset + 1) == []


def test_hints_are_evidence_only_and_not_a_beacon_verdict() -> None:
    # A complete header with arbitrary hints must not gain any beacon-specific flag.
    payload = b"not a beacon, just bytes"
    blob = build_blob(0, payload, hints=b"kernel32")

    candidates = find(blob)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.hints == b"kernel32"
    assert candidate.is_complete
    assert not hasattr(candidate, "is_beacon")


def test_backward_compatible_attributes() -> None:
    payload = b"MZ" + b"\x00" * 20
    blob = build_blob(0, payload)
    candidate = find(blob)[0]

    assert candidate.offset == 0
    assert candidate.size == len(payload)
    assert candidate.xorkey == b"\x01\x02\x03\x04"
    assert candidate.hints == b"A" * 8
    assert candidate.payload == payload
    # BytesIO/fh behaviour used by the stage machinery still works.
    assert candidate.read(2) == b"MZ"
    candidate.fh.seek(0)
    assert candidate.fh.read(2) == b"MZ"
    assert "ArtifactKitPayload" in candidate.get_name()
    assert "complete" in repr(candidate)


def test_invalid_chunk_size_raises() -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        list(artifact.iter_artifactkit_payloads(io.BytesIO(b"\x00" * 32), chunk_size=0))
