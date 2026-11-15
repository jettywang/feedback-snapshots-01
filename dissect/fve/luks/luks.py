from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.fve.crypto import argon2, create_cipher
from dissect.fve.crypto.dmcrypt import CryptStream, SegmentedCryptStream, SegmentStream
from dissect.fve.luks import af
from dissect.fve.luks.c_luks import (
    LUKS2_MAGIC_1ST,
    LUKS2_MAGIC_2ND,
    SECONDARY_HEADER_OFFSETS,
    c_luks,
)
from dissect.fve.luks.metadata import Metadata

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.fve.luks.metadata import Digest, Keyslot, Segment


class LUKS:
    """LUKS disk encryption.

    References:
        - https://gitlab.com/cryptsetup/cryptsetup
        - https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = None
        self.header1 = None
        self.header2 = None

        first_offset, second_offset, version = find_luks_headers(fh)
        if version is None:
            raise ValueError("Not a LUKS volume")

        if version == 1:
            header_struct = c_luks.luks_phdr
        elif version == 2:
            header_struct = c_luks.luks2_hdr_disk
        else:
            raise ValueError(f"Unsupported LUKS version: {version}")

        if first_offset is not None:
            fh.seek(first_offset)
            self.header1 = header_struct(fh)
            self.header = self.header1

        if second_offset is not None:
            fh.seek(second_offset)
            self.header2 = header_struct(fh)

        self.header = self.header2 or self.header1

        # LUKS1
        self.cipher_name = None
        self.cipher_mode = None
        self.hash_spec = None

        # LUKS2
        self.label = None
        self.checksum_algorithm = None
        self.metadata, self.metadata1, self.metadata2 = None, None, None

        self.uuid = UUID(self.header.uuid.strip(b"\x00").decode())

        if self.header.version == 1:
            # LUKS1
            self.metadata = Metadata.from_luks1_header(self.header)
        else:
            # LUKS2
            self.label = self.header.label.strip(b"\x00").decode()
            self.checksum_algorithm = self.header.checksum_alg.strip(b"\x00").decode()

            self.metadata1 = None
            if self.header is self.header1:
                json_area1 = fh.read(self.header1.hdr_size - 4096).rstrip(b"\x00").decode()
                self.metadata1 = Metadata.from_json(json_area1)
                self.header2 = c_luks.luks2_hdr_disk(fh)

            json_area2 = fh.read(self.header2.hdr_size - 4096).rstrip(b"\x00").decode()
            self.metadata2 = Metadata.from_json(json_area2)

            self.metadata = self.metadata1 or self.metadata2

        self._active_volume_key = None
        self._active_keyslot_id = None

    @property
    def unlocked(self) -> bool:
        return self._active_volume_key is not None

    @property
    def keyslots(self) -> dict[int, Keyslot]:
        return self.metadata.keyslots

    def unlock(self, key: bytes, keyslot: int) -> None:
        """Unlock the volume with the volume encryption key."""
        if not self._verify_volume_key(key, keyslot):
            raise ValueError(f"Invalid volume key for keyslot {keyslot}")
        self._active_volume_key = key
        self._active_keyslot_id = keyslot

    def unlock_with_key_file(self, path: Path, offset: int = 0, size: int = -1, keyslot: int | None = None) -> None:
        with path.open("rb") as fh:
            self.unlock_with_key_fh(fh, offset, size, keyslot)

    def unlock_with_key_fh(self, fh: BinaryIO, offset: int = 0, size: int = -1, keyslot: int | None = None) -> None:
        fh.seek(offset)
        self._unlock_passphrase(fh.read(size), keyslot)

    def unlock_with_passphrase(self, passphrase: str | bytes, keyslot: int | None = None) -> None:
        """Unlock this volume with a passphrase and optional keyslot hint."""
        if isinstance(passphrase, str):
            self._unlock_passphrase(passphrase.encode(), keyslot)
        else:
            self._unlock_passphrase(passphrase, keyslot)

    def _unlock_passphrase(self, passphrase: bytes, keyslot: int | None = None) -> None:
        """Unlock this volume with a passphrase and optional keyslot hint."""
        keyslots = (
            [(keyslot, self.metadata.keyslots[keyslot])] if keyslot is not None else self.metadata.keyslots.items()
        )

        idx = None
        vk = None
        errors = []
        for idx, keyslot in keyslots:
            try:
                key = derive_passphrase_key(passphrase, keyslot)
            except Exception as exc:
                errors.append((idx, exc))
                continue

            try:
                vk = self._unlock_volume_key(key, idx)
            except Exception as exc:
                errors.append((idx, exc))
                continue

            try:
                self.unlock(vk, idx)
                break
            except ValueError:
                continue
        else:
            if errors:
                msg = "\n".join(f"{idx}: {exc}" for idx, exc in errors)
                raise ValueError(f"No valid keyslot found, but there were errors for the following keyslots:\n{msg}")
            raise ValueError("No valid keyslot found")

    def _unlock_volume_key(self, key: bytes, keyslot: int) -> None:
        """Unlock the volume key using the given encryption key and keyslot."""
        keyslot_obj = self.metadata.keyslots[keyslot]

        self.fh.seek(keyslot_obj.area.offset)
        area = self.fh.read(keyslot_obj.key_size * keyslot_obj.af.stripes)

        cipher = create_cipher(keyslot_obj.area.encryption, key, keyslot_obj.area.key_size * 8)
        return af.merge(
            cipher.decrypt(area),
            keyslot_obj.key_size,
            keyslot_obj.af.stripes,
            keyslot_obj.af.hash,
        )

    def _verify_volume_key(self, key: bytes, keyslot: int) -> None:
        """Verify the given key for the given keyslot."""
        digest = self.find_digest(keyslot)
        if digest.type == "pbkdf2":
            result = hashlib.pbkdf2_hmac(digest.hash, key, digest.salt, digest.iterations, len(digest.digest))
        else:
            # Only the pbkdf2 type is supported in LUKS2
            raise NotImplementedError(f"Unsupported digest algorithm: {digest.type}")

        return result == digest.digest

    def find_digest(self, keyslot: int) -> Digest:
        """Find digest metadata corresponding to the given keyslot."""
        digests = [digest for digest in self.metadata.digests.values() if keyslot in (digest.keyslots or [])]
        if not digests:
            raise ValueError(f"No digest found for keyslot {keyslot}")

        return digests[0]

    def find_segment(self, keyslot: int) -> Segment:
        """Find segment metadata corresponding to the given keyslot."""
        segments = self.find_segments(keyslot)
        if len(segments) > 1:
            raise NotImplementedError(f"Keyslot {keyslot} has more than one segment")

        return segments[0]

    def find_segments(self, keyslot: int) -> list[Segment]:
        """Find all segment metadata corresponding to the given keyslot, in logical order."""
        digest = self.find_digest(keyslot)
        segments = [
            (segment_id, segment)
            for segment_id, segment in self.metadata.segments.items()
            if segment_id in (digest.segments or [])
        ]
        if not segments:
            raise ValueError(f"No segment found for keyslot {keyslot}")

        return [segment for _, segment in sorted(segments, key=lambda item: item[0])]

    def open(self) -> CryptStream | SegmentedCryptStream:
        """Open this volume and return a readable (decrypted) stream.

        For a single-segment volume this returns the traditional :class:`CryptStream` with unchanged behavior.
        For a multi-segment volume it returns the restricted, read-only segmented view from :meth:`open_segments`,
        or raises if that layout cannot be proven to use the verified volume key.
        """
        if not self.unlocked:
            raise ValueError("Volume is locked")

        segments = self.find_segments(self._active_keyslot_id)
        if len(segments) > 1:
            return self.open_segments()

        segment = segments[0]

        return CryptStream(
            self.fh,
            segment.encryption,
            self._active_volume_key,
            self.metadata.keyslots[self._active_keyslot_id].key_size * 8,
            segment.offset,
            segment.size,
            segment.iv_tweak,
            segment.sector_size,
        )

    def open_segments(self) -> SegmentedCryptStream:
        """Open a restricted, read-only view over all segments bound to the active keyslot.

        This view only supports layouts where each segment is provably encrypted with the single, already verified
        volume key and has a fully determined physical extent. A segment keeps its own cipher configuration,
        sector size and IV start, and reads crossing segment boundaries are handled by each segment in turn.

        The view is read-only; writes, truncation and similar mutation operations are not supported. Segments that
        are not part of the active keyslot's verified digest binding are never silently substituted or masked.

        Raises:
            ValueError: If the volume is locked, or the layout is ambiguous, overlapping, incomplete, unsupported,
                or cannot be proven to use the verified volume key.
        """
        if not self.unlocked:
            raise ValueError("Volume is locked")

        keyslot = self.metadata.keyslots[self._active_keyslot_id]
        key_size = keyslot.key_size * 8

        bound_segments = self._bound_segments(self._active_keyslot_id)

        segments = []
        for segment_id, segment in bound_segments:
            if segment.type != "crypt":
                raise NotImplementedError(f"Unsupported segment type for segment {segment_id}: {segment.type}")
            if segment.encryption is None:
                raise NotImplementedError(f"Segment {segment_id} has no cipher configuration")
            if segment.integrity is not None or segment.flags:
                raise NotImplementedError(f"Segment {segment_id} uses unsupported flags or integrity metadata")
            if segment.iv_tweak is None or segment.sector_size is None:
                raise ValueError(f"Segment {segment_id} is missing required crypt parameters")
            if segment.iv_tweak < 0:
                raise ValueError(f"Segment {segment_id} has a negative IV start")
            if segment.sector_size < 512 or segment.sector_size % 512:
                raise ValueError(f"Unsupported sector size for segment {segment_id}: {segment.sector_size}")
            if segment.offset < 0:
                raise ValueError(f"Segment {segment_id} has a negative physical offset")

            size = _resolve_segment_size(segment, segment_id, self.fh)

            segments.append(
                SegmentStream(
                    self.fh,
                    segment_id,
                    segment.encryption,
                    self._active_volume_key,
                    key_size,
                    segment.offset,
                    size,
                    segment.iv_tweak,
                    segment.sector_size,
                )
            )

        _validate_segment_layout(segments)

        return SegmentedCryptStream(segments)

    def _bound_segments(self, keyslot: int) -> list[tuple[int, Segment]]:
        """Return the segments bound to a keyslot through exactly one complete digest."""
        digests = [
            (digest_id, digest)
            for digest_id, digest in self.metadata.digests.items()
            if keyslot in (digest.keyslots or [])
        ]
        if not digests:
            raise ValueError(f"No digest binding found for keyslot {keyslot}")
        if len(digests) > 1:
            raise ValueError(f"Keyslot {keyslot} is bound to multiple digests, refusing an ambiguous layout")

        digest_id, digest = digests[0]
        if not digest.keyslots:
            raise ValueError(f"Digest {digest_id} has no keyslot evidence for keyslot {keyslot}")
        if not digest.segments:
            raise ValueError(f"Digest {digest_id} has no segment binding for keyslot {keyslot}")

        if len(set(digest.segments)) != len(digest.segments):
            raise ValueError(f"Digest {digest_id} binds the same segment more than once")

        missing_keyslots = sorted(set(digest.keyslots or []) - set(self.metadata.keyslots))
        if missing_keyslots:
            raise ValueError(f"Digest {digest_id} references missing keyslots: {missing_keyslots}")

        active_key_size = self.metadata.keyslots[keyslot].key_size
        for digest_keyslot in digest.keyslots or []:
            if self.metadata.keyslots[digest_keyslot].key_size != active_key_size:
                raise ValueError(
                    f"Digest {digest_id} binds keyslots with different key sizes "
                    f"({keyslot}: {active_key_size}, {digest_keyslot}: "
                    f"{self.metadata.keyslots[digest_keyslot].key_size})"
                )

        bound_ids = set(digest.segments)
        missing_ids = set(self.metadata.segments) - bound_ids
        if missing_ids:
            raise ValueError(
                f"Digest {digest_id} does not bind all volume segments, refusing to expose an unproven area: "
                f"{sorted(missing_ids)}"
            )

        result = []
        for segment_id in digest.segments:
            if segment_id not in self.metadata.segments:
                raise ValueError(f"Digest {digest_id} references missing segment {segment_id}")

            other_digests = sorted(
                other_id
                for other_id, other in self.metadata.digests.items()
                if other_id != digest_id and segment_id in (other.segments or [])
            )
            if other_digests:
                raise ValueError(
                    f"Segment {segment_id} is bound to multiple digests ({digest_id} and {other_digests}), "
                    "refusing to assume it uses the verified volume key"
                )

            result.append((segment_id, self.metadata.segments[segment_id]))

        return sorted(result, key=lambda item: item[0])


def _fh_size(fh: BinaryIO) -> int | None:
    """Return the size of a file-like object without permanently changing its position."""
    size = getattr(fh, "size", None)
    if isinstance(size, int) and not isinstance(size, bool):
        return size

    position = None
    try:
        position = fh.tell()
        fh.seek(0, io.SEEK_END)
        return fh.tell()
    except Exception:
        return None
    finally:
        if position is not None:
            fh.seek(position)


def _resolve_segment_size(segment: Segment, segment_id: int, fh: BinaryIO) -> int:
    """Resolve and validate the fully determined physical extent of a segment."""
    size = segment.size
    total_size: int | None = _fh_size(fh)

    if size in (None, "dynamic"):
        # A dynamic segment extends to the end of the backing volume. This is only determinate if the backing
        # size is known; layouts where that extent swallows another segment are rejected by the overlap check.
        if total_size is None:
            raise ValueError(f"Segment {segment_id} has a dynamic size that cannot be determined")
        size = total_size - segment.offset
    elif isinstance(size, str) and size.isdigit():
        size = int(size)

    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError(f"Segment {segment_id} has an indeterminate or unsupported size: {segment.size!r}")

    sector_size = segment.sector_size or 512
    if size % sector_size:
        raise ValueError(f"Segment {segment_id} size {size} is not aligned to its sector size {sector_size}")

    if segment.offset < 0:
        raise ValueError(f"Segment {segment_id} has a negative physical offset")

    if total_size is not None and segment.offset + size > total_size:
        raise ValueError(
            f"Segment {segment_id} extends beyond the backing volume: {segment.offset} + {size} > {total_size}"
        )

    return size


def _validate_segment_layout(segments: list[SegmentStream]) -> None:
    """Validate that a set of segments forms an unambiguous, non-overlapping physical layout."""
    if not segments:
        raise ValueError("A segmented volume requires at least one segment")

    previous = None
    for segment in sorted(segments, key=lambda item: item.offset):
        if previous is not None and segment.offset < previous.offset + previous.size:
            raise ValueError(
                f"Segments {previous.id} and {segment.id} overlap: "
                f"{previous.offset} + {previous.size} > {segment.offset}"
            )
        previous = segment


def derive_passphrase_key(passphrase: bytes, keyslot: Keyslot) -> bytes:
    """Derive a key from a passphrase with the given keyslot KDF information.

    Args:
        passphrase: The passphrase to derive a key from.
        keyslot: The keyslot to use for the derivation.
    """
    kdf = keyslot.kdf

    if kdf.type == "pbkdf2":
        return hashlib.pbkdf2_hmac(kdf.hash, passphrase, kdf.salt, kdf.iterations, keyslot.key_size)

    if kdf.type.startswith("argon2"):
        return argon2.hash_secret_raw(passphrase, kdf.salt, kdf.time, kdf.memory, kdf.cpus, keyslot.key_size, kdf.type)

    raise NotImplementedError(f"Unsupported kdf algorithm: {kdf.type}")


def find_luks_headers(fh: BinaryIO) -> tuple[int | None, int | None, int | None]:
    stored_position = fh.tell()

    fh.seek(0)
    first_header = None
    second_header = None
    version = None

    if fh.read(c_luks.LUKS2_MAGIC_L) == LUKS2_MAGIC_1ST:
        first_header = 0
        version = int.from_bytes(fh.read(2), "big")

    for offset in SECONDARY_HEADER_OFFSETS:
        fh.seek(offset)
        if fh.read(c_luks.LUKS2_MAGIC_L) == LUKS2_MAGIC_2ND:
            second_header = offset
            version = int.from_bytes(fh.read(2), "big")
            break

    fh.seek(stored_position)
    return first_header, second_header, version


def is_luks_volume(fh: BinaryIO) -> bool:
    """Return whether the file-like object is a LUKS volume."""
    _, _, version = find_luks_headers(fh)
    return version is not None
