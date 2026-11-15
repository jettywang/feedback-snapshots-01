from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.fve.crypto import argon2, create_cipher
from dissect.fve.crypto.dmcrypt import CryptStream, MultiSegmentStream, SegmentStream
from dissect.fve.exception import UnsupportedLayoutError
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
        self._active_digest_id = None

    @property
    def unlocked(self) -> bool:
        return self._active_volume_key is not None

    @property
    def keyslots(self) -> dict[int, Keyslot]:
        return self.metadata.keyslots

    def unlock(self, key: bytes, keyslot: int) -> None:
        """Unlock the volume with the volume encryption key."""
        verified = [
            (digest_id, digest) for digest_id, digest in self._find_digests(keyslot) if self._verify_digest(key, digest)
        ]

        if not verified:
            raise ValueError(f"Invalid volume key for keyslot {keyslot}")

        self._active_volume_key = key
        self._active_keyslot_id = keyslot
        self._active_digest_id = verified[0][0]

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

    def _verify_digest(self, key: bytes, digest: Digest) -> bool:
        """Verify the given volume key against a digest."""
        if digest.type == "pbkdf2":
            result = hashlib.pbkdf2_hmac(digest.hash, key, digest.salt, digest.iterations, len(digest.digest))
        else:
            # Only the pbkdf2 type is supported in LUKS2
            raise NotImplementedError(f"Unsupported digest algorithm: {digest.type}")

        return result == digest.digest

    def _find_digests(self, keyslot: int) -> list[tuple[int, Digest]]:
        """Find all digest metadata corresponding to the given keyslot."""
        digests = [
            (digest_id, digest) for digest_id, digest in self.metadata.digests.items() if keyslot in digest.keyslots
        ]
        if not digests:
            raise ValueError(f"No digest found for keyslot {keyslot}")

        return digests

    def find_digest(self, keyslot: int) -> Digest:
        """Find digest metadata corresponding to the given keyslot."""
        return self._find_digests(keyslot)[0][1]

    def find_segment(self, keyslot: int) -> Segment:
        """Find segment metadata corresponding to the given keyslot."""
        digest = self.find_digest(keyslot)
        segments = [segment for segment_id, segment in self.metadata.segments.items() if segment_id in digest.segments]
        if not segments:
            raise ValueError(f"No segment found for keyslot {keyslot}")

        if len(segments) > 1:
            raise NotImplementedError(f"Keyslot {keyslot} has more than one segment")

        return segments[0]

    def find_segments(self, keyslot: int) -> list[Segment]:
        """Find all segment metadata corresponding to the given keyslot, in logical order."""
        digest = self.find_digest(keyslot)
        segments = [segment for segment_id, segment in self.metadata.segments.items() if segment_id in digest.segments]
        if not segments:
            raise ValueError(f"No segment found for keyslot {keyslot}")

        return segments

    def open(self) -> CryptStream | MultiSegmentStream:
        """Open this volume and return a readable (decrypted) stream.

        Single-segment volumes are opened as a plain :class:`~dissect.fve.crypto.dmcrypt.CryptStream`, preserving the
        existing behaviour. Multi-segment volumes are opened as a restricted read-only
        :class:`~dissect.fve.crypto.dmcrypt.MultiSegmentStream`, but only when every segment can be proven to use the
        verified volume key and every physical range is unambiguous.

        Raises:
            UnsupportedLayoutError: If the segment layout cannot be safely presented.
        """
        if not self.unlocked:
            raise ValueError("Volume is locked")

        if len(self.metadata.segments) == 1:
            segment_id, segment = next(iter(self.metadata.segments.items()))
            digest = self.metadata.digests[self._active_digest_id]
            if segment_id in digest.segments:
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

        return self.open_multi()

    def open_multi(self) -> MultiSegmentStream:
        """Open this volume as a restricted read-only multi-segment stream.

        Unlike :meth:`open`, this never falls back to single-segment behaviour and always validates the complete
        segment layout. It can also be used to explicitly obtain the multi-segment view of a volume with one segment.

        Raises:
            UnsupportedLayoutError: If the segment layout cannot be safely presented.
            ValueError: If the volume is not unlocked.
        """
        if not self.unlocked:
            raise ValueError("Volume is locked")

        segment_ids = sorted(self.metadata.segments)
        if not segment_ids:
            raise UnsupportedLayoutError("Volume has no data segments")

        return MultiSegmentStream(self._open_multi_segment(self._active_keyslot_id, segment_ids))

    def _open_multi_segment(self, keyslot_id: int, segment_ids: list[int]) -> list[SegmentStream]:
        """Validate a multi-segment layout and return a decrypting view for every segment.

        A layout is only accepted when:

        - every data segment in the metadata has at least one digest binding it,
        - every digest binding a segment was verified with the same active volume key,
        - at least one verified digest binding the segment also binds the keyslot used to unlock,
        - no digest references a segment that is missing from the metadata,
        - every segment has a fully determinate physical range and crypto configuration,
        - segments do not overlap in the physical data area,
        - segments do not touch LUKS headers, the keyslot area or keyslot metadata.

        Args:
            keyslot_id: The keyslot that was used to unlock the volume.
            segment_ids: The IDs of all data segments in the metadata, in logical order.

        Raises:
            UnsupportedLayoutError: If the layout does not satisfy the above requirements.
        """
        if self.header.version != 2:
            raise UnsupportedLayoutError("Multi-segment volumes are only supported for LUKS2")

        if keyslot_id not in self.metadata.keyslots:
            raise UnsupportedLayoutError(f"Keyslot {keyslot_id} is not present in the metadata")

        keyslot = self.metadata.keyslots[keyslot_id]
        if keyslot.key_size * 8 != len(self._active_volume_key) * 8:
            raise UnsupportedLayoutError("Verified volume key size does not match the keyslot key size")

        # Prove which digests are backed by the same validated volume key. This is the only evidence that all data
        # segments use the key we unlocked with.
        verified_digest_ids = set()
        for digest_id, digest in self.metadata.digests.items():
            try:
                if self._verify_digest(self._active_volume_key, digest):
                    verified_digest_ids.add(digest_id)
            except NotImplementedError:
                if digest_id == self._active_digest_id:
                    raise

        known_segment_ids = set(segment_ids)
        for digest_id, digest in self.metadata.digests.items():
            unknown = sorted(set(digest.segments) - known_segment_ids)
            if unknown:
                raise UnsupportedLayoutError(
                    f"Digest {digest_id} references segments that are not present in the metadata: {unknown}"
                )

        # Map every segment to the digests that bind it, and reject segments whose binding cannot be proven.
        bindings: dict[int, list[int]] = {segment_id: [] for segment_id in segment_ids}
        for digest_id, digest in self.metadata.digests.items():
            for segment_id in digest.segments:
                bindings[segment_id].append(digest_id)

        # Any alternate layout reachable from the same keyslot is a conflict: without additional evidence there is
        # no way to tell which data segments are authoritative.
        conflicting_digests = [
            digest_id
            for digest_id, digest in self.metadata.digests.items()
            if keyslot_id in digest.keyslots and digest_id not in verified_digest_ids
        ]
        if conflicting_digests:
            raise UnsupportedLayoutError(
                f"Keyslot {keyslot_id} is also bound to digest(s) {conflicting_digests} that were not verified "
                "with the active volume key"
            )

        # Every verified digest may describe the layout, as long as they all agree on the set of segments.
        segment_sets = {
            frozenset(digest.segments)
            for digest_id, digest in self.metadata.digests.items()
            if digest_id in verified_digest_ids
        }
        if len(segment_sets) > 1:
            raise UnsupportedLayoutError(
                "Verified digests describe conflicting segment layouts: "
                + ", ".join(str(sorted(segment_set)) for segment_set in sorted(segment_sets, key=sorted))
            )

        for segment_id, digest_ids in bindings.items():
            if not digest_ids:
                raise UnsupportedLayoutError(f"Segment {segment_id} has no digest binding")

            unverified = sorted(set(digest_ids) - verified_digest_ids)
            if unverified:
                raise UnsupportedLayoutError(
                    f"Segment {segment_id} is bound to digest(s) {unverified} that were not verified with the "
                    "active volume key"
                )

            if not any(keyslot_id in self.metadata.digests[digest_id].keyslots for digest_id in digest_ids):
                raise UnsupportedLayoutError(
                    f"Segment {segment_id} has no digest binding to keyslot {keyslot_id}, "
                    "so it cannot be proven to use the verified volume key"
                )

        end_of_volume = self._volume_size()
        layout = [
            self._validate_segment(segment_id, self.metadata.segments[segment_id], end_of_volume)
            for segment_id in segment_ids
        ]

        # Check for physical overlaps independently of the logical segment order.
        by_physical_offset = sorted(layout, key=lambda item: item[1])
        previous_end = None
        previous_segment = None
        for _, physical_offset, physical_size, _, segment, _ in by_physical_offset:
            if previous_end is not None and physical_offset < previous_end:
                raise UnsupportedLayoutError(
                    f"Segment {segment} overlaps segment {previous_segment} in the physical data area"
                )
            previous_end = physical_offset + physical_size
            previous_segment = segment

        # Preserve the logical segment order from the metadata.
        layout.sort(key=lambda item: item[0])

        return [
            SegmentStream(
                self.fh,
                physical_offset,
                physical_size,
                cipher,
                segment.encryption,
                segment.iv_tweak,
                sector_size,
                segment_id,
            )
            for segment_id, physical_offset, physical_size, sector_size, segment, cipher in layout
        ]

    def _validate_segment(self, segment_id: int, segment: Segment, end_of_volume: int) -> tuple:
        """Validate the crypto configuration and physical range of a single segment."""
        if segment.type != "crypt":
            raise UnsupportedLayoutError(f"Unsupported segment {segment_id} type: {segment.type}")

        if segment.integrity is not None:
            raise UnsupportedLayoutError(f"Segment {segment_id} has integrity metadata, which is not supported")

        if segment.flags:
            raise UnsupportedLayoutError(f"Segment {segment_id} has unsupported flags: {segment.flags}")

        if not segment.encryption:
            raise UnsupportedLayoutError(f"Segment {segment_id} has no cipher specification")

        if not isinstance(segment.offset, int) or segment.offset < 0:
            raise UnsupportedLayoutError(f"Segment {segment_id} has an invalid offset: {segment.offset!r}")

        if segment.size == "dynamic":
            raise UnsupportedLayoutError(
                f"Segment {segment_id} has a dynamic size, which cannot be determined unambiguously"
            )

        if not isinstance(segment.size, int) or segment.size < 0:
            raise UnsupportedLayoutError(f"Segment {segment_id} has an invalid size: {segment.size!r}")

        sector_size = segment.sector_size
        if not isinstance(sector_size, int) or sector_size <= 0 or sector_size % 512:
            raise UnsupportedLayoutError(f"Segment {segment_id} has an unsupported sector size: {sector_size!r}")

        if segment.size % sector_size:
            raise UnsupportedLayoutError(
                f"Segment {segment_id} size {segment.size} is not aligned to its sector size {sector_size}"
            )

        if not isinstance(segment.iv_tweak, int) or segment.iv_tweak < 0:
            raise UnsupportedLayoutError(f"Segment {segment_id} has an invalid IV tweak: {segment.iv_tweak!r}")

        physical_offset = segment.offset
        physical_size = segment.size

        if physical_size == 0:
            raise UnsupportedLayoutError(f"Segment {segment_id} is empty")

        if physical_offset + physical_size > end_of_volume:
            raise UnsupportedLayoutError(
                f"Segment {segment_id} extends beyond the end of the volume "
                f"({physical_offset} + {physical_size} > {end_of_volume})"
            )

        try:
            cipher = create_cipher(segment.encryption, self._active_volume_key, sector_size=sector_size)
        except (ValueError, NotImplementedError) as exc:
            raise UnsupportedLayoutError(f"Unsupported cipher for segment {segment_id}: {exc}") from exc

        self._check_data_region(segment_id, physical_offset, physical_size)

        return segment_id, physical_offset, physical_size, sector_size, segment, cipher

    def _check_data_region(self, segment_id: int, physical_offset: int, physical_size: int) -> None:
        """Ensure a segment does not overlap the LUKS headers, JSON area or keyslot areas."""
        metadata_ranges = []
        config = self.metadata.config
        keyslots_size = config.keyslots_size if config is not None else None

        # The primary header starts at offset 0. The secondary header (if present) starts at its header size.
        primary_size = self.header1.hdr_size if self.header1 is not None else 0
        metadata_ranges.append((0, primary_size, "LUKS header"))

        keyslots_start = primary_size
        if self.header2 is not None:
            secondary_start = getattr(self.header2, "hdr_offset", primary_size)
            secondary_end = secondary_start + self.header2.hdr_size
            metadata_ranges.append((secondary_start, secondary_end, "LUKS secondary header"))
            keyslots_start = max(keyslots_start, secondary_end)

        if isinstance(keyslots_size, int) and keyslots_size > 0:
            metadata_ranges.append((keyslots_start, keyslots_start + keyslots_size, "LUKS keyslots area"))

        for keyslot_id, keyslot in self.metadata.keyslots.items():
            area = keyslot.area
            if area.type != "raw" or not isinstance(area.offset, int) or not isinstance(area.size, int):
                continue
            metadata_ranges.append((area.offset, area.offset + area.size, f"keyslot {keyslot_id}"))

        for start, end, description in metadata_ranges:
            if physical_offset < end and start < physical_offset + physical_size:
                raise UnsupportedLayoutError(
                    f"Segment {segment_id} overlaps with {description} metadata at {start:#x}-{end:#x}"
                )

    def _volume_size(self) -> int:
        """Return the size of the encrypted volume."""
        stored_position = self.fh.tell()
        try:
            return self.fh.seek(0, io.SEEK_END)
        finally:
            self.fh.seek(stored_position)


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
