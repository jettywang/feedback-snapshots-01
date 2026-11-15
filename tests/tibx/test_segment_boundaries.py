"""Cross-page, continuation-boundary and encrypted-segment damage tests.

These complement ``test_segment.py`` with the cases where a segment and its container
disagree: a compressed stream that lands exactly on a page boundary, a continuation page
that is missing or out of order, wrong CBC padding, and a declared length that does not
match what the payload decodes to. Every fixture is small and reproducible -- tens of
KiB of deterministic bytes, no real backup sample.

Each counterexample breaks exactly one thing, and the test says which: a locator, the
continuation relationship, the encryption wrapper, or the decompressed content. None of
them may pass, and none may be rejected only by the segment header's magic check.
"""

from __future__ import annotations

import io
import random
from typing import TYPE_CHECKING

import pytest

from dissect.archive.tibx.c_tibx import (
    ENVELOPE_SIZE,
    PAGE_BODY_SIZE,
    PAGE_SIZE,
    SEGMENT_CBC_HEADER_SIZE,
    SEGMENT_FIRST_PAGE_PAYLOAD,
    SEGMENT_GCM_HEADER_SIZE,
    SEGMENT_HEADER_OFFSET,
    c_tibx,
)
from dissect.archive.tibx.crypto import DataKey
from dissect.archive.tibx.exception import CorruptArchiveError
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.segment import Segment, read_plaintext
from dissect.archive.tibx.stream import TibxVolumeStream
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import (
    CountingIO,
    ExtentSpec,
    arch_page,
    blob_pages,
    build_lsm_archive,
    cbc_blob,
    compressed,
    exact_payload,
    exact_wrapped_payload,
    finalize,
    segment_pages,
)

if TYPE_CHECKING:
    from dissect.archive.tibx.tibx import TibxVolume

DATA_KEY = bytes(range(32))
HEAD = arch_page(1000, 2000, b"\xab" * 16)
PASSWORD = b"dissect"

CODECS = [
    pytest.param(c_tibx.ComprAlg.NONE, id="stored"),
    pytest.param(c_tibx.ComprAlg.LZ4, id="lz4"),
    pytest.param(c_tibx.ComprAlg.ZLIB, id="zlib"),
    pytest.param(c_tibx.ComprAlg.ZSTD, id="zstd"),
]

# (segment cipher alg, cipher prefix before the codec stream, AES block size or 0)
WRAPPERS = [
    pytest.param(3, SEGMENT_CBC_HEADER_SIZE, 16, id="cbc"),
    pytest.param(7, SEGMENT_GCM_HEADER_SIZE, 0, id="gcm"),
]


def _store(*pages: bytes) -> PageStore:
    return PageStore(io.BytesIO(HEAD + b"".join(pages)))


def _rewrite(page: bytes, **fields: int) -> bytes:
    """``page`` with the given segment header fields replaced, envelope CRC fixed up."""
    pg = bytearray(page)
    header = c_tibx.segment_header(bytes(pg[SEGMENT_HEADER_OFFSET:]))
    for name, value in fields.items():
        setattr(header, name, value)
    pg[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + len(c_tibx.segment_header)] = header.dumps()
    return finalize(pg)


def _read(pages: list[bytes], compression: c_tibx.ComprAlg, alg: int | None = None) -> bytes:
    key = None if alg is None else DataKey(alg=alg, key=DATA_KEY)
    return read_plaintext(_store(*pages), 1, data_key=key)


def _assert_not_header_magic(error: CorruptArchiveError) -> None:
    """Fail if the rejection came only from the SG/SE or page-type check.

    Every counterexample keeps a well-formed segment header, so blaming the magic means
    the damage was diagnosed at the wrong layer and the checks under test never ran.
    """
    assert "carries no segment header" not in str(error)
    assert "is not a DATA page" not in str(error)


# --- compressed streams that land exactly on page boundaries -------------------------------


class TestExactPageBoundary:
    @pytest.mark.parametrize("compression", CODECS)
    @pytest.mark.parametrize(
        ("target", "pages"),
        [
            pytest.param(SEGMENT_FIRST_PAGE_PAYLOAD, 1, id="first-page-full"),
            pytest.param(SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE, 2, id="first-cont-full"),
            pytest.param(SEGMENT_FIRST_PAGE_PAYLOAD + 2 * PAGE_BODY_SIZE, 3, id="second-cont-full"),
        ],
    )
    def test_stream_filling_whole_pages(self, compression: c_tibx.ComprAlg, target: int, pages: int) -> None:
        # The stored stream is exactly the payload capacity of N pages: not a byte of the
        # next page may be read, and no continuation may be omitted
        payload = exact_payload(compression, target)
        built = segment_pages(payload, compression=compression)
        assert len(built) == pages
        assert len(compressed(payload, compression)) == target

        assert _read(built, compression) == payload

    @pytest.mark.parametrize("compression", CODECS)
    def test_stream_one_byte_past_a_page(self, compression: c_tibx.ComprAlg) -> None:
        # A single byte over the boundary starts a continuation page; the whole stream is
        # still the segment's, and the last page is all but empty
        payload = exact_payload(compression, SEGMENT_FIRST_PAGE_PAYLOAD + 1)
        built = segment_pages(payload, compression=compression)
        assert len(built) == 2
        assert _read(built, compression) == payload

    @pytest.mark.parametrize("compression", CODECS)
    @pytest.mark.parametrize(("alg", "prefix", "block"), WRAPPERS)
    def test_encrypted_stream_at_page_boundary(
        self, compression: c_tibx.ComprAlg, alg: int, prefix: int, block: int
    ) -> None:
        # The cipher prefix and CBC's PKCS#7 padding move where the boundary falls relative
        # to the codec stream: a GCM stream can end exactly on it, a CBC one cannot (its
        # padding always adds a byte). Both sides of the boundary must read back intact.
        capacity = SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE
        fitting = capacity if not block else capacity - (capacity - prefix) % block
        for target in (fitting, fitting + block if block else fitting + 1):
            payload = exact_wrapped_payload(compression, target, prefix=prefix, block=block)
            built = segment_pages(payload, compression=compression, data_key=DATA_KEY, alg=alg)
            assert len(built) == (2 if target <= capacity else 3), (target, len(built))
            assert _read(built, compression, alg) == payload

    def test_last_page_needs_no_zero_tail(self) -> None:
        # A segment ending exactly at the archive's last page has no trailing zeros for the
        # unused-tail check to look at
        payload = exact_payload(c_tibx.ComprAlg.ZSTD, SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE)
        built = segment_pages(payload, compression=c_tibx.ComprAlg.ZSTD)
        assert _read(built, c_tibx.ComprAlg.ZSTD) == payload


# --- continuation relationship damage ------------------------------------------------------


class TestContinuationDamage:
    @pytest.mark.parametrize("compression", CODECS)
    def test_out_of_order_continuations(self, compression: c_tibx.ComprAlg) -> None:
        # Break: continuation relationship. Swapping two continuation pages keeps the total
        # length intact but scrambles the stream; it must not read as a valid segment.
        payload = exact_payload(compression, SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE + 1000)
        built = segment_pages(payload, compression=compression)
        assert len(built) == 3
        swapped = [built[0], built[2], built[1]]

        with pytest.raises(CorruptArchiveError) as exc:
            _read(swapped, compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_missing_last_continuation_followed_by_another_segment(self, compression: c_tibx.ComprAlg) -> None:
        # Break: continuation relationship. The final page is gone and the next segment's
        # header page sits where it was; the declared zlength would happily read it.
        payload = random.Random(1).randbytes(SEGMENT_FIRST_PAGE_PAYLOAD + 900)
        built = segment_pages(payload, compression=compression)
        assert len(built) == 2
        successor = segment_pages(b"the next segment", compression=compression)

        with pytest.raises(CorruptArchiveError) as exc:
            _read([built[0], *successor], compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_missing_last_page_at_end_of_archive(self, compression: c_tibx.ComprAlg) -> None:
        # Break: continuation relationship. With no successor to borrow from, the missing
        # page must still be an error rather than a short read
        payload = random.Random(3).randbytes(SEGMENT_FIRST_PAGE_PAYLOAD + 100)
        built = segment_pages(payload, compression=compression)
        assert len(built) == 2

        with pytest.raises(CorruptArchiveError) as exc:
            _read(built[:-1], compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_duplicated_continuation(self, compression: c_tibx.ComprAlg) -> None:
        # Break: continuation relationship. The last page is a copy of its predecessor: the
        # stream is the right length and every page is genuine, just not in this segment.
        payload = exact_payload(compression, SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE + 1000)
        built = segment_pages(payload, compression=compression)
        assert len(built) == 3
        duplicated = [built[0], built[1], built[1]]

        with pytest.raises(CorruptArchiveError) as exc:
            _read(duplicated, compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_continuation_from_another_segment(self, compression: c_tibx.ComprAlg) -> None:
        # Break: continuation relationship. A continuation page is replaced by one from a
        # different segment of the same size: same length, wrong bytes
        ours = exact_payload(compression, SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE + 1000)
        theirs = exact_payload(compression, SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE + 2000, lo=600)
        built = segment_pages(ours, compression=compression)
        foreign = segment_pages(theirs, compression=compression)
        assert len(built) == len(foreign) == 3

        with pytest.raises(CorruptArchiveError) as exc:
            _read([built[0], built[1], foreign[2]], compression)
        _assert_not_header_magic(exc.value)


# --- encrypted wrapper damage --------------------------------------------------------------


class TestEncryptedWrapperDamage:
    @pytest.mark.parametrize("compression", CODECS)
    @pytest.mark.parametrize(("alg", "prefix", "block"), WRAPPERS)
    def test_wrong_padding_after_decryption(
        self, compression: c_tibx.ComprAlg, alg: int, prefix: int, block: int
    ) -> None:
        # Break: encryption wrapper. A CBC-wrapped stream is given a bogus padding pattern;
        # ciphertext and header are untouched, so only unpadding can notice
        if not block:
            pytest.skip("GCM has no padding to damage")

        payload = random.Random(30).randbytes(3000)
        raw = compressed(payload, compression)
        missing = -len(raw) % 16
        padded = bytearray(raw + bytes([missing]) * missing)
        padded[-1] = 0  # 0x00 is never a valid PKCS#7 padding byte
        blob = cbc_blob(bytes(padded), DATA_KEY)
        built = blob_pages(blob, len(payload), compression, encrypted=True)

        with pytest.raises(CorruptArchiveError) as exc:
            _read(built, compression, alg)
        _assert_not_header_magic(exc.value)
        assert "padding" in str(exc.value)

    @pytest.mark.parametrize(
        ("compression", "alg", "block"),
        [
            pytest.param(codec, alg, block, id=f"{name}-{alg_name}")
            for codec, name in [
                (c_tibx.ComprAlg.NONE, "stored"),
                (c_tibx.ComprAlg.LZ4, "lz4"),
                (c_tibx.ComprAlg.ZLIB, "zlib"),
                (c_tibx.ComprAlg.ZSTD, "zstd"),
            ]
            for alg, alg_name, block in [(3, "cbc", 16), (7, "gcm", 0)]
            # CBC carries no tag: only a codec that validates its stream can notice a
            # flipped ciphertext byte. Stored and LZ4 data have no such check, and zstd
            # stops at its frame's end, so a flip in the tail after it is invisible.
            if alg == 7 or codec == c_tibx.ComprAlg.ZLIB
        ],
    )
    def test_damaged_ciphertext(self, compression: c_tibx.ComprAlg, alg: int, block: int) -> None:
        # Break: encryption wrapper (GCM) or the content behind it (CBC). One flipped
        # ciphertext byte must not yield a complete, plausible segment
        payload = random.Random(7).randbytes(SEGMENT_FIRST_PAGE_PAYLOAD + 700)
        built = segment_pages(payload, compression=compression, data_key=DATA_KEY, alg=alg)
        damaged = list(built)
        page = bytearray(damaged[1])
        page[ENVELOPE_SIZE + 16] ^= 0xFF
        damaged[1] = finalize(page)

        with pytest.raises(CorruptArchiveError) as exc:
            _read(damaged, compression, alg)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("alg", [3, 7], ids=["cbc", "gcm"])
    def test_ciphertext_not_a_block_multiple(self, alg: int) -> None:
        # Break: encryption wrapper. A CBC ciphertext losing part of a block must not be
        # rounded down silently; the declared length then disagrees with what arrived
        payload = random.Random(8).randbytes(2000)
        built = segment_pages(payload, compression=c_tibx.ComprAlg.NONE, data_key=DATA_KEY, alg=alg)
        zlength = len(payload) + (SEGMENT_CBC_HEADER_SIZE if alg == 3 else SEGMENT_GCM_HEADER_SIZE)
        if alg == 3:
            zlength += -len(payload) % 16
        truncated = _rewrite(built[0], zlength=zlength - 7)

        with pytest.raises(CorruptArchiveError) as exc:
            _read([truncated], c_tibx.ComprAlg.NONE, alg)
        _assert_not_header_magic(exc.value)


# --- locator and declared-length damage ----------------------------------------------------


class TestLocatorAndLength:
    @pytest.mark.parametrize("compression", CODECS)
    def test_declared_length_longer_than_content(self, compression: c_tibx.ComprAlg) -> None:
        # Break: decompressed content. The header promises more plaintext than the codec
        # produces; the gap must not be zero-filled into volume data
        payload = random.Random(9).randbytes(0x800)
        built = segment_pages(payload, compression=compression)
        longer = _rewrite(built[0], length=len(payload) + 1)

        with pytest.raises(CorruptArchiveError) as exc:
            _read([longer, *built[1:]], compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_declared_length_shorter_than_content(self, compression: c_tibx.ComprAlg) -> None:
        # Break: decompressed content. A header promising less than the stream holds must
        # not silently cut the tail off; the codec's bound rejects the mismatch
        payload = random.Random(10).randbytes(0x1000)
        built = segment_pages(payload, compression=compression)
        shorter = _rewrite(built[0], length=len(payload) - 1)

        with pytest.raises(CorruptArchiveError) as exc:
            _read([shorter, *built[1:]], compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_declared_zlength_shorter_than_stream(self, compression: c_tibx.ComprAlg) -> None:
        # Break: decompressed content. A short zlength cuts the stream; the codec or the
        # stored-length check must see the shortfall
        payload = random.Random(11).randbytes(SEGMENT_FIRST_PAGE_PAYLOAD + 400)
        built = segment_pages(payload, compression=compression)
        short = _rewrite(built[0], zlength=len(compressed(payload, compression)) - 8)

        with pytest.raises(CorruptArchiveError) as exc:
            _read([short, *built[1:]], compression)
        _assert_not_header_magic(exc.value)

    @pytest.mark.parametrize("compression", CODECS)
    def test_declared_zlength_longer_than_stream(self, compression: c_tibx.ComprAlg) -> None:
        # Break: decompressed content. A long zlength reaches into the zero tail of the
        # last page. zlib and zstd stop at their stream's end and ignore what follows, so
        # they must still decode exactly; stored and LZ4 must refuse the length mismatch
        payload = exact_payload(compression, SEGMENT_FIRST_PAGE_PAYLOAD + 200)
        built = segment_pages(payload, compression=compression)
        long = _rewrite(built[0], zlength=len(compressed(payload, compression)) + 8)
        trailing_lengths = {c_tibx.ComprAlg.ZLIB, c_tibx.ComprAlg.ZSTD}

        if compression in trailing_lengths:
            assert _read([long, *built[1:]], compression) == payload
        else:
            with pytest.raises(CorruptArchiveError) as exc:
                _read([long, *built[1:]], compression)
            _assert_not_header_magic(exc.value)

    def test_locator_pointing_at_a_continuation_page(self) -> None:
        # Break: locator. The segment_map names a page one past the real header: still a
        # DATA page, but starting mid-stream. The magic check is the only layer that can
        # catch this, which is why this case is allowed to trip it -- and only this one.
        payload = random.Random(12).randbytes(SEGMENT_FIRST_PAGE_PAYLOAD + 1000)
        built = segment_pages(payload, compression=c_tibx.ComprAlg.NONE)
        assert len(built) == 2
        assert built[1][SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + 2] != b"SG"

        with pytest.raises(CorruptArchiveError, match="carries no segment header"):
            read_plaintext(_store(*built), 2)

    def test_locator_pointing_at_a_non_data_page(self) -> None:
        # Break: locator. The segment_map names a page that is not DATA at all
        built = segment_pages(random.Random(13).randbytes(100), compression=c_tibx.ComprAlg.NONE)
        with pytest.raises(CorruptArchiveError, match="is not a DATA page"):
            read_plaintext(_store(*built, bytes(PAGE_SIZE)), 2)

    @pytest.mark.parametrize("compression", CODECS)
    def test_page_count_hint_never_changes_the_bytes(self, compression: c_tibx.ComprAlg) -> None:
        # Break: locator (page count only). The hint sizes the prefetch read and nothing
        # else; the header's zlength decides where the segment ends whatever it says
        payload = random.Random(14).randbytes(SEGMENT_FIRST_PAGE_PAYLOAD + 700)
        built = segment_pages(payload, compression=compression)
        successor = segment_pages(b"a later segment", compression=compression)

        for page_count in (0, 1, 2, 50):
            assert read_plaintext(_store(*built, *successor), 1, page_count=page_count) == payload


# --- the same damage seen through TibxVolume -----------------------------------------------


def _two_volume_archive(
    compression: c_tibx.ComprAlg,
    size: int = 5000,
    *,
    password: bytes | None = None,
    alg: int = 3,
) -> tuple[TIBX, bytes, bytes]:
    """An archive with two volumes whose segments sit back to back.

    The first volume's segment spans pages, so its last continuation page is immediately
    followed by the second volume's segment header page.
    """
    first = random.Random(20).randbytes(size)
    second = random.Random(21).randbytes(size)
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, first, extent_id=1), ExtentSpec(11, 0, second, extent_id=2)],
        compression=compression,
        password=password,
        alg=alg,
    )
    tibx = TIBX(io.BytesIO(archive))
    if password is not None:
        tibx.unlock(password)
    return tibx, first, second


def _volume(tibx: TIBX, volume_id: int) -> TibxVolume:
    return next(volume for volume in tibx.streams() if volume.volume_id == volume_id)


def _damage_page(archive: bytes, page_index: int, body: bytes) -> bytes:
    """``archive`` with the body (past the envelope) of one page replaced, CRC fixed up."""
    page = bytearray(archive[page_index * PAGE_SIZE : (page_index + 1) * PAGE_SIZE])
    page[ENVELOPE_SIZE:] = body
    damaged = bytearray(archive)
    damaged[page_index * PAGE_SIZE : (page_index + 1) * PAGE_SIZE] = finalize(page)
    return bytes(damaged)


class TestThroughVolume:
    @pytest.mark.parametrize("compression", CODECS)
    @pytest.mark.parametrize("use_ctree", [False, True], ids=["memtree", "ctree"])
    def test_whole_and_sliced_reads_agree(self, compression: c_tibx.ComprAlg, use_ctree: bool) -> None:
        # A cross-page extent read through the volume, whole and in slices. Every slicing
        # must agree with one full read and with the source bytes
        first = random.Random(22).randbytes(3 * PAGE_SIZE)
        second = random.Random(23).randbytes(2 * PAGE_SIZE)
        archive = build_lsm_archive(
            [ExtentSpec(10, 0, first, extent_id=1), ExtentSpec(10, len(first), second, extent_id=2)],
            compression=compression,
            use_ctree=use_ctree,
        )
        volume = _volume(TIBX(io.BytesIO(archive)), 10)
        expected = first + second
        assert volume.read(0, len(expected)) == expected

        for size in (1, 7, 512, PAGE_SIZE, PAGE_SIZE + 1):
            for offset in range(0, len(expected), size * 3):
                length = min(size, len(expected) - offset)
                assert volume.read(offset, length) == expected[offset : offset + length]

        stream = volume.open()
        assert stream.read() == expected
        assert TibxVolumeStream(volume).read(len(expected)) == expected[: len(expected)]

    @pytest.mark.parametrize("compression", CODECS)
    @pytest.mark.parametrize(("alg", "prefix", "block"), WRAPPERS)
    def test_encrypted_whole_and_sliced_reads_agree(
        self, compression: c_tibx.ComprAlg, alg: int, prefix: int, block: int
    ) -> None:
        # The encrypted path takes its own branch in read_plaintext; the volume-visible
        # bytes must still be invariant under slicing
        tibx, first, _ = _two_volume_archive(compression, password=PASSWORD, alg=alg)
        volume = _volume(tibx, 10)

        assert volume.read(0, len(first)) == first
        assert volume.read(0x200, PAGE_SIZE + 100) == first[0x200 : 0x200 + PAGE_SIZE + 100]
        for offset in (0, 1, PAGE_SIZE - 1, PAGE_SIZE, len(first) - 1):
            assert volume.read(offset, 1) == first[offset : offset + 1]
        assert volume.open().read() == first

    @pytest.mark.parametrize("compression", CODECS)
    def test_bad_continuation_yields_no_complete_volume_data(self, compression: c_tibx.ComprAlg) -> None:
        # Break: continuation relationship, seen from the volume. The first volume's last
        # continuation page is replaced by the second volume's header page. Reading the
        # first volume must fail outright, not return a full-size buffer of the
        # neighbour's bytes that a caller could take for the whole volume.
        tibx, first, second = _two_volume_archive(compression)
        segment = Segment(tibx.store.page(1), 1)
        assert segment.zlength > SEGMENT_FIRST_PAGE_PAYLOAD  # the segment spans pages

        last = segment.page_index + 1
        successor = last + 1
        archive = _damage_page(tibx.fh.getvalue(), last, tibx.store.page(successor)[ENVELOPE_SIZE:])
        damaged = TIBX(io.BytesIO(archive))

        with pytest.raises(CorruptArchiveError):
            _volume(damaged, 10).read(0, len(first))
        with pytest.raises(CorruptArchiveError):
            _volume(damaged, 10).open().read()

        # The undamaged neighbour still reads in full: the damage did not spread
        assert _volume(damaged, 11).read(0, len(second)) == second

    @pytest.mark.parametrize("compression", CODECS)
    @pytest.mark.parametrize(("alg", "prefix", "block"), WRAPPERS)
    def test_encrypted_bad_continuation_yields_no_partial_output(
        self, compression: c_tibx.ComprAlg, alg: int, prefix: int, block: int
    ) -> None:
        # Break: continuation relationship under encryption. The wrapped stream loses its
        # last page to zeros: GCM must fail its tag and CBC its padding, so neither can
        # return a plausible prefix of the volume
        tibx, first, _ = _two_volume_archive(compression, password=PASSWORD, alg=alg)
        segment = Segment(tibx.store.page(1), 1)
        assert segment.zlength > SEGMENT_FIRST_PAGE_PAYLOAD

        last = segment.page_index + 1
        archive = _damage_page(tibx.fh.getvalue(), last, bytes(PAGE_SIZE - ENVELOPE_SIZE))
        damaged = TIBX(io.BytesIO(archive))
        damaged.unlock(PASSWORD)

        with pytest.raises(CorruptArchiveError):
            _volume(damaged, 10).read(0, len(first))

    def test_locator_error_reaches_the_volume(self) -> None:
        # Break: locator, seen from the volume. The segment_map points past the header, so
        # the read must raise rather than serve zeros or the next page's bytes
        first = random.Random(24).randbytes(5000)
        archive = build_lsm_archive(
            [ExtentSpec(10, 0, first, extent_id=1)],
            compression=c_tibx.ComprAlg.NONE,
            segment_map={100: (1, 2)},
        )
        with pytest.raises(CorruptArchiveError, match="carries no segment header"):
            _volume(TIBX(io.BytesIO(archive)), 10).read(0, len(first))

    def test_declared_length_error_reaches_the_volume(self) -> None:
        # Break: decompressed content, seen from the volume. A stream short of its declared
        # length must raise, not produce data plus a zero-filled tail
        first = random.Random(25).randbytes(5000)
        archive = build_lsm_archive(
            [ExtentSpec(10, 0, first, extent_id=1)],
            compression=c_tibx.ComprAlg.ZSTD,
            segment_blobs={100: compressed(first, c_tibx.ComprAlg.ZSTD)[:-6]},
        )
        with pytest.raises(CorruptArchiveError):
            _volume(TIBX(io.BytesIO(archive)), 10).read(0, len(first))

    def test_page_count_hint_does_not_change_volume_bytes(self) -> None:
        # Break: locator (page count only). A wrong page count must not alter a single byte
        first = random.Random(26).randbytes(5000)
        good = TIBX(
            io.BytesIO(build_lsm_archive([ExtentSpec(10, 0, first, extent_id=1)], compression=c_tibx.ComprAlg.NONE))
        )
        expected = _volume(good, 10).read(0, len(first))
        for count in (0, 1, 2, 40):
            archive = build_lsm_archive(
                [ExtentSpec(10, 0, first, extent_id=1)],
                compression=c_tibx.ComprAlg.NONE,
                segment_map={100: (count, 1)},
            )
            assert _volume(TIBX(io.BytesIO(archive)), 10).read(0, len(first)) == expected

    @pytest.mark.parametrize(
        "compression",
        [pytest.param(c_tibx.ComprAlg.NONE, id="stored"), pytest.param(c_tibx.ComprAlg.ZSTD, id="zstd")],
    )
    def test_complete_segment_borrows_no_neighbour_bytes(self, compression: c_tibx.ComprAlg) -> None:
        # A complete volume read matches its source exactly: no byte of the segment that
        # follows may appear, at any offset
        tibx, first, second = _two_volume_archive(compression)
        data = _volume(tibx, 10).read(0, len(first))
        assert data == first
        assert data[-len(second) :] != second
        assert second[:16] not in data

    def test_streaming_reads_join_without_duplicates(self) -> None:
        # Reads of wildly different sizes, across page and segment boundaries, must join
        # into exactly one copy of the volume
        tibx, first, _ = _two_volume_archive(c_tibx.ComprAlg.ZSTD)
        stream = TibxVolumeStream(_volume(tibx, 10))
        pieces = [stream.read(size) for size in (3, 600, 1, 4091, 4092, 1, 17)]
        consumed = sum(len(piece) for piece in pieces)
        assert b"".join(pieces) == first[:consumed]
        assert stream.read() == first[consumed:]


class TestCountedReads:
    # The cross-page read path: a batched read for the continuations, not one per page

    def _pages(self) -> list[bytes]:
        payload = exact_payload(c_tibx.ComprAlg.ZSTD, SEGMENT_FIRST_PAGE_PAYLOAD + PAGE_BODY_SIZE)
        built = segment_pages(payload, compression=c_tibx.ComprAlg.ZSTD)
        assert len(built) == 2
        self.payload = payload
        return built

    def test_without_hint_two_reads(self) -> None:
        built = self._pages()
        fh = CountingIO(HEAD + b"".join(built))
        store = PageStore(fh)
        fh.reads = 0
        assert read_plaintext(store, 1) == self.payload
        assert fh.reads == 2

    def test_page_count_hint_one_read(self) -> None:
        built = self._pages()
        fh = CountingIO(HEAD + b"".join(built))
        store = PageStore(fh)
        fh.reads = 0
        assert read_plaintext(store, 1, page_count=2) == self.payload
        assert fh.reads == 1

    def test_short_hint_costs_a_second_read(self) -> None:
        built = self._pages()
        fh = CountingIO(HEAD + b"".join(built))
        store = PageStore(fh)
        fh.reads = 0
        assert read_plaintext(store, 1, page_count=1) == self.payload
        assert fh.reads == 2
