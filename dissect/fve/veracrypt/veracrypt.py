from __future__ import annotations

import io
import math
import zlib
from dataclasses import dataclass, field
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.veracrypt.c_veracrypt import (
    TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET,
    TC_HIDDEN_VOLUME_HEADER_BACKUP_OFFSET,
    TC_HIDDEN_VOLUME_HEADER_OFFSET,
    TC_VOLUME_DATA_OFFSET,
    TC_VOLUME_HEADER_BACKUP_OFFSET,
    TC_VOLUME_HEADER_SALT_SIZE,
    TC_VOLUME_HEADER_SIZE,
    c_veracrypt,
)
from dissect.fve.veracrypt.crypto import CIPHERS
from dissect.fve.veracrypt.key import KEY_DERIVATIONS

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from dissect.fve.luks.luks import CryptStream


@dataclass(frozen=True)
class HeaderCandidate:
    """A caller-provided location of a VeraCrypt volume header.

    A VeraCrypt volume can contain multiple independent headers: the outer volume
    header, the hidden volume header, and backup copies of either. Each caller-provided
    location keeps its own identity and is validated on its own; no candidate is
    silently substituted for another one.

    Args:
        offset: Absolute byte offset of the 64-byte salt in the source stream.
        kind: Caller-provided identity, for example ``"outer"``, ``"hidden"`` or ``"backup"``.
    """

    offset: int
    kind: str = "primary"

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError(f"Header offset cannot be negative ({self.offset})")


@dataclass
class HeaderVerification:
    """The result of validating one caller-selected VeraCrypt header.

    The data range and key always belong to the same validated header. A failed
    verification never carries a usable key or data range.
    """

    candidate: HeaderCandidate
    valid: bool = False
    header: c_veracrypt.VolumeHeader | None = None
    kdf: str | None = None
    cipher: str | None = None
    header_key: bytes | None = None
    key: bytes | None = None
    data_offset: int | None = None
    data_size: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def offset(self) -> int:
        """The absolute byte offset of this header in the source stream."""
        return self.candidate.offset

    @property
    def kind(self) -> str:
        """The caller-provided identity of this header."""
        return self.candidate.kind

    @property
    def data_range(self) -> tuple[int, int] | None:
        """The half-open data range ``(start, end)`` declared by this header."""
        if self.data_offset is None or self.data_size is None:
            return None
        return (self.data_offset, self.data_offset + self.data_size)

    def overlaps(self, other: HeaderVerification) -> bool:
        """Return whether this header's data range overlaps another header's data range."""
        if self.data_range is None or other.data_range is None:
            return False
        return _ranges_overlap(*self.data_range, *other.data_range)

    def has_same_data_range(self, other: HeaderVerification) -> bool:
        """Return whether both headers declare the exact same data range."""
        return self.data_range is not None and self.data_range == other.data_range

    def describe(self) -> str:
        """Return a human readable description of the selection and validation result."""
        identity = f"{self.kind} header at 0x{self.offset:x}"
        if not self.valid:
            reason = "; ".join(self.errors) or "unknown validation error"
            return f"{identity}: INVALID ({reason})"

        assert self.data_offset is not None and self.data_size is not None
        description = (
            f"{identity}: VALID using {self.kdf} / {self.cipher}, "
            f"data range 0x{self.data_offset:x}-0x{self.data_offset + self.data_size:x} "
            f"({self.data_size} bytes)"
        )
        if self.warnings:
            description += f" [{' ; '.join(self.warnings)}]"
        return description

    def __str__(self) -> str:
        return self.describe()


def _coerce_candidate(candidate: HeaderCandidate | int | tuple[int, str]) -> HeaderCandidate:
    """Coerce a caller-provided header location into a :class:`HeaderCandidate`."""
    if isinstance(candidate, HeaderCandidate):
        return candidate
    if isinstance(candidate, int):
        return HeaderCandidate(candidate)
    if isinstance(candidate, tuple) and 1 <= len(candidate) <= 2:
        return HeaderCandidate(*candidate)

    raise TypeError(f"Invalid header candidate: {candidate!r}")


def verify_header(
    fh: BinaryIO,
    candidate: HeaderCandidate | int | tuple[int, str],
    *,
    passphrase: str | None = None,
    pim: int | None = None,
    header_key: bytes | None = None,
    is_system: bool = False,
    header_offsets: Iterable[int] | None = None,
) -> HeaderVerification:
    """Validate a single explicitly selected VeraCrypt header.

    Only the 64-byte salt and 512-byte encrypted header at ``candidate.offset`` are
    read. Nothing is written to ``fh``. The header must decrypt to the ``VERA`` magic
    and pass both CRC32 checks and the volume geometry checks before a key or data
    range is reported.

    Args:
        fh: The source stream containing the volume.
        candidate: The header location to validate. A plain integer is interpreted as
            a ``HeaderCandidate`` with the default ``"primary"`` identity.
        passphrase: Passphrase to derive the header key from. Mutually exclusive with
            ``header_key``.
        pim: Optional Personal Iterations Multiplier for passphrase derivation.
        header_key: A raw 32 or 64 byte header key. Mutually exclusive with ``passphrase``.
        is_system: Whether ``fh`` is a system partition.
        header_offsets: Optional additional header locations that must not be covered
            by this header's declared data range.

    Returns:
        A :class:`HeaderVerification` describing this candidate only. If validation
        fails, ``valid`` is ``False`` and no key or data range is exposed.
    """
    candidate = _coerce_candidate(candidate)
    if passphrase is None and header_key is None:
        raise ValueError("Either a passphrase or a header key is required")
    if passphrase is not None and header_key is not None:
        raise ValueError("Provide either a passphrase or a header key, not both")
    if header_key is not None and len(header_key) not in (32, 64):
        raise ValueError(f"Header key is of invalid length ({len(header_key)}), expected 32 or 64 bytes")

    result = HeaderVerification(candidate=candidate)
    raw_header_size = TC_VOLUME_HEADER_SALT_SIZE + TC_VOLUME_HEADER_SIZE

    position = fh.tell()
    try:
        fh.seek(candidate.offset)
        raw = fh.read(raw_header_size)
    except (OSError, ValueError) as exc:
        result.errors.append(f"unable to read header: {exc}")
        return result
    finally:
        fh.seek(position)

    if len(raw) != raw_header_size:
        result.errors.append(
            f"truncated header at 0x{candidate.offset:x}: expected {raw_header_size} bytes, got {len(raw)}"
        )
        return result

    salt, ciphertext = raw[:TC_VOLUME_HEADER_SALT_SIZE], raw[TC_VOLUME_HEADER_SALT_SIZE:]

    if header_key is not None:
        key_candidates = [("header-key", header_key)]
    else:
        key_candidates = [(Kdf.__name__, Kdf(passphrase, salt).derive(pim)) for Kdf in KEY_DERIVATIONS]

    protected_offsets = [candidate.offset]
    if header_offsets is not None:
        protected_offsets.extend(offset for offset in header_offsets if offset not in protected_offsets)

    magic_found = False
    for kdf_name, keys in key_candidates:
        for Cipher in CIPHERS:
            cipher = Cipher(BytesIO(ciphertext), keys, 0, TC_VOLUME_HEADER_SIZE)
            plaintext = cipher.open().read()
            header = c_veracrypt.VolumeHeader(plaintext)

            if header.magic != b"VERA":
                continue

            magic_found = True
            errors = _validate_header(header, is_system=is_system, protected_offsets=protected_offsets)
            if errors:
                result.errors.extend(f"{kdf_name}/{Cipher.__type__}: {error}" for error in errors)
                continue

            result.valid = True
            result.header = header
            result.kdf = kdf_name
            result.cipher = Cipher.__type__
            result.header_key = keys
            result.key = bytes(header.master_keys[:64])
            result.data_offset = int(header.mk_scope_offset)
            result.data_size = int(header.mk_scope_size)
            return result

    if not magic_found:
        result.errors.append("no VERA magic found; passphrase or header key is incorrect")

    # Keep the diagnostics stable and free of duplicates from the KDF/cipher loops.
    result.errors = list(dict.fromkeys(result.errors))
    return result


def _validate_header(
    header: c_veracrypt.VolumeHeader,
    *,
    is_system: bool,
    protected_offsets: Iterable[int] | None = None,
) -> list[str]:
    """Validate the decrypted header contents and declared data range."""
    errors = []

    version = int(header.version)
    if not 1 <= version <= 5:
        errors.append(f"unsupported header version {version}")

    sector_size = int(header.sector_size)
    if sector_size < 512 or sector_size > 4096 or sector_size & (sector_size - 1):
        errors.append(f"invalid sector size {sector_size}")
        return errors

    raw = bytes(header)

    if zlib.crc32(raw[192:448]) != int.from_bytes(bytes(header.crc32), "big"):
        errors.append("master key area CRC32 mismatch")
    if zlib.crc32(raw[:188]) != int.from_bytes(bytes(header.crc32_decrypted), "big"):
        errors.append("volume header CRC32 mismatch")

    data_offset = int(header.mk_scope_offset)
    data_size = int(header.mk_scope_size)
    data_end = data_offset + data_size

    if data_offset < 0:
        errors.append(f"negative data offset {data_offset}")
    if data_size <= 0:
        errors.append(f"invalid data size {data_size}")
    if data_offset % sector_size:
        errors.append(f"data offset 0x{data_offset:x} is not aligned to sector size {sector_size}")
    if data_size % sector_size:
        errors.append(f"data size 0x{data_size:x} is not aligned to sector size {sector_size}")

    # A header must not declare a data area that covers (part of) any supplied header block.
    header_size = TC_VOLUME_HEADER_SALT_SIZE + TC_VOLUME_HEADER_SIZE
    for offset in protected_offsets or ():
        if _ranges_overlap(data_offset, data_end, offset, offset + header_size):
            errors.append(f"declared data range 0x{data_offset:x}-0x{data_end:x} overlaps header at 0x{offset:x}")

    minimum_data_offset = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET + 512 if is_system else TC_VOLUME_DATA_OFFSET
    if data_offset < minimum_data_offset:
        errors.append(
            f"declared data range starts at 0x{data_offset:x}, before the minimum data offset "
            f"0x{minimum_data_offset:x}"
        )

    return errors


def _ranges_overlap(first_start: int, first_end: int, second_start: int, second_end: int) -> bool:
    """Return whether two half-open ranges overlap."""
    return first_start < second_end and second_start < first_end


def standard_header_offsets(size: int, *, is_system: bool = False) -> dict[str, int]:
    """Return the standard VeraCrypt header offsets for a volume of ``size`` bytes.

    These are convenience locations only; the caller remains responsible for deciding
    which of them to verify and select.

    Args:
        size: The size in bytes of the volume or container.
        is_system: Whether the volume is a system partition.

    Returns:
        A mapping of header identity to absolute byte offset.
    """
    offsets = {"primary": TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET if is_system else 0}
    if not is_system:
        offsets["hidden"] = TC_HIDDEN_VOLUME_HEADER_OFFSET

    backup = size - TC_VOLUME_HEADER_BACKUP_OFFSET
    if backup >= 0:
        offsets["backup"] = backup
    hidden_backup = size - TC_HIDDEN_VOLUME_HEADER_BACKUP_OFFSET
    if not is_system and hidden_backup >= 0:
        offsets["hidden_backup"] = hidden_backup

    return offsets


class VeraCrypt:
    """VeraCrypt full volume encryption implementation.

    Supports encrypted file containers and system partitions using key derivation
    algorithm PKCS5 (SHA512 or SHA256) and AES XTS cipher (SHA512 or SHA256).

    A volume may expose multiple independent headers: the outer volume header, the
    hidden volume header and backup copies. Callers performing forensic analysis must
    provide the candidate header locations explicitly, for example::

        vc = VeraCrypt(fh, header_candidates=[HeaderCandidate(0, "outer"), HeaderCandidate(0x10000, "hidden")])

    Every candidate is verified independently. Only the candidate selected with
    :meth:`select_header` provides the key and data range used by :meth:`open`.

    Non-system partition-specific behaviour and other key derivation algorithms or
    ciphers are not implemented. Key files are also not implemented. Hidden volume
    headers can be inspected and opened when the caller supplies their offset.

    References:
        - https://veracrypt.jp/en/System%20Encryption.html
        - https://github.com/veracrypt/VeraCrypt
    """

    def __init__(
        self,
        fh: BinaryIO,
        *,
        is_system: bool = False,
        header_offset: int | None = None,
        header_candidates: Iterable[HeaderCandidate | int | tuple[int, str]] | None = None,
    ) -> None:
        self.fh = fh
        self.is_system = is_system
        self.unlocked = False
        self.header = None
        self.cipher = None
        self.size = None
        self.version = None
        self.client_version = None

        self.header_keys = None
        self.key = None
        self.data_offset = None
        self.data_size = None
        self.header_salt = b""
        self.header_ciphertext = b""

        self.selected: HeaderVerification | None = None
        self.verifications: list[HeaderVerification] = []

        if header_candidates is not None and header_offset is not None:
            raise ValueError("Provide either header_offset or header_candidates, not both")

        if header_candidates is not None:
            self.header_candidates = [_coerce_candidate(candidate) for candidate in header_candidates]
        elif header_offset is not None:
            self.header_candidates = [HeaderCandidate(header_offset)]
        else:
            # Backwards compatible default: the primary header of a non-system volume or
            # the boot volume header of a system volume. No probing of other locations.
            self.header_candidates = [
                HeaderCandidate(TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET if is_system else 0, "primary")
            ]

        if len(self.header_candidates) == 1:
            self._read_header(self.header_candidates[0].offset)

    def __repr__(self) -> str:
        return (
            f"<VeraCrypt fh={self.fh} is_system={self.is_system} unlocked={self.unlocked} size={self.size} "
            f"cipher={self.cipher} version={self.version} client_version={self.client_version}>"
        )

    @property
    def header_offset(self) -> int:
        """The absolute byte offset of the currently configured (or selected) header."""
        if self.selected is not None:
            return self.selected.offset
        return self.header_candidates[0].offset

    def _read_header(self, offset: int) -> None:
        """Read the salt and encrypted header at an explicit offset, without writing to the stream."""
        self.header_salt = b""
        self.header_ciphertext = b""

        if offset < 0:
            raise ValueError(f"Header offset cannot be negative ({offset})")

        position = self.fh.tell()
        try:
            self.fh.seek(offset)
            self.header_salt = self.fh.read(TC_VOLUME_HEADER_SALT_SIZE)
            self.header_ciphertext = self.fh.read(TC_VOLUME_HEADER_SIZE)
        finally:
            self.fh.seek(position)

    def verify(
        self,
        passphrase: str | None = None,
        pim: int | None = None,
        *,
        header_key: bytes | None = None,
    ) -> list[HeaderVerification]:
        """Verify all explicitly provided header candidates, independently of each other.

        Each candidate is validated on its own. A passphrase that unlocks the outer
        volume does not imply the hidden volume does not exist, and a valid outer
        header does not cause a hidden or backup header to be skipped.

        A previously selected header is cleared so stale key material can never be
        combined with a new set of verification results.

        Args:
            passphrase: Passphrase to derive every candidate's header key from.
            pim: Optional Personal Iterations Multiplier.
            header_key: Optional raw header key used for every candidate.

        Returns:
            One :class:`HeaderVerification` per candidate, in caller-provided order.
        """
        self._clear_selection()

        header_offsets = [candidate.offset for candidate in self.header_candidates]
        self.verifications = [
            verify_header(
                self.fh,
                candidate,
                passphrase=passphrase,
                pim=pim,
                header_key=header_key,
                is_system=self.is_system,
                header_offsets=header_offsets,
            )
            for candidate in self.header_candidates
        ]

        valid = [verification for verification in self.verifications if verification.valid]
        for index, verification in enumerate(valid):
            for other in valid[index + 1 :]:
                if not verification.overlaps(other):
                    continue

                if verification.has_same_data_range(other):
                    # Primary and backup copies of the same volume commonly declare the
                    # same data range; that is expected and not a conflict.
                    detail = "declares the same data range"
                else:
                    detail = "declares a data range that partially overlaps"
                verification.warnings.append(f"{detail}: {other.kind} header at 0x{other.offset:x}")
                other.warnings.append(f"{detail}: {verification.kind} header at 0x{verification.offset:x}")

        return self.verifications

    def selection_report(self) -> str:
        """Return a multi-line report describing every candidate and the explicit selection."""
        lines = []
        for verification in self.verifications:
            selected = self.selected is not None and verification is self.selected
            lines.append(f"{'*' if selected else ' '} {verification.describe()}")
        if self.selected is None:
            lines.append("  no header explicitly selected")
        return "\n".join(lines)

    def _clear_selection(self) -> None:
        """Drop any previously selected header and its derived key and data range."""
        self.selected = None
        self.unlocked = False
        self.header = None
        self.header_keys = None
        self.key = None
        self.data_offset = None
        self.data_size = None
        self.cipher = None
        self.size = None
        self.version = None
        self.client_version = None

    def select_header(self, candidate: HeaderCandidate | int | str) -> HeaderVerification:
        """Select one verified header and bind its key and data range to this instance.

        Selection is explicit and never falls back to another candidate. The candidate
        is matched by :class:`HeaderCandidate` identity, by offset, or by ``kind``.

        Args:
            candidate: The header candidate to use. Provide the exact
                :class:`HeaderCandidate`, its offset, or its ``kind``.

        Returns:
            The :class:`HeaderVerification` that was selected.

        Raises:
            ValueError: If the candidate was not verified or did not validate.
        """
        if not self.verifications:
            raise ValueError("No header candidates have been verified yet, call verify() first")

        if isinstance(candidate, HeaderCandidate):
            matches = [verification for verification in self.verifications if verification.candidate == candidate]
        elif isinstance(candidate, int):
            matches = [verification for verification in self.verifications if verification.offset == candidate]
        else:
            matches = [verification for verification in self.verifications if verification.kind == candidate]

        if not matches:
            raise ValueError(f"No verified header candidate matches {candidate!r}")

        if len(matches) > 1:
            offsets = ", ".join(f"0x{verification.offset:x}" for verification in matches)
            raise ValueError(f"Ambiguous header selection {candidate!r}; matches offsets {offsets}")

        verification = matches[0]
        if not verification.valid:
            raise ValueError(f"Selected header is not valid: {verification.describe()}")

        self.selected = verification
        self.header = verification.header
        self.header_keys = verification.header_key
        self.key = verification.key
        self.cipher = verification.cipher
        self.size = verification.header.volume_size
        self.data_offset = verification.data_offset
        self.data_size = verification.data_size
        self.version = verification.header.version
        self.client_version = verification.header.client_version
        self._read_header(verification.offset)
        self.unlocked = True

        return verification

    def unlock_with_passphrase(self, passphrase: str, pim: int | None = None) -> None:
        """Unlock this volume with a passphrase.

        Supports the following PKCS5 header key derivation functions:
            - HMAC SHA512 (default)
            - HMAC SHA256

        Supports the following encryption modes:
            - AES XTS (default)

        KDF HMAC BLAKE2s-256, WHIRLPOOL and STREEBOG are not implemented.
        Ciphers (XTS mode) Serpent, Twofish and Camellia are not implemented.

        This is a convenience shortcut for the common single-header case. When more
        than one header candidate was provided, this method verifies every candidate
        and then refuses to guess, even if only one of them validates: use
        :meth:`verify` and :meth:`select_header` to make the choice explicit.
        """
        self.verify(passphrase, pim)

        valid = [verification for verification in self.verifications if verification.valid]
        if not valid:
            raise ValueError("Unable to decrypt using provided passphrase")

        if len(self.verifications) > 1:
            offsets = ", ".join(f"0x{verification.offset:x}" for verification in valid)
            raise ValueError(
                f"Multiple header candidates were provided ({offsets} validated); "
                "select one explicitly with select_header()"
            )

        self.select_header(valid[0].candidate)

    def unlock_with_header_key(self, keys: bytes) -> None:
        """Unlock the volume with a raw encryption key. Supports AES XTS encryption mode only.

        This is a convenience shortcut for the common single-header case. When more
        than one header candidate was provided, this method verifies every candidate
        and then refuses to guess, even if only one of them validates: use
        :meth:`verify` and :meth:`select_header` to make the choice explicit.
        """
        if len(keys) not in (32, 64):
            raise ValueError(f"Header key is of invalid length ({len(keys)}), expected 32 or 64 bytes")

        self.verify(header_key=keys)

        valid = [verification for verification in self.verifications if verification.valid]
        if not valid:
            raise ValueError("Unable to decrypt using provided header keys")

        if len(self.verifications) > 1:
            offsets = ", ".join(f"0x{verification.offset:x}" for verification in valid)
            raise ValueError(
                f"Multiple header candidates were provided ({offsets} validated); "
                "select one explicitly with select_header()"
            )

        self.select_header(valid[0].candidate)

    def unlock_with_key_file(self, path: Path) -> None:
        """Unlock the volume with a key file."""
        raise NotImplementedError

    def unlock_with_key_fh(self, fh: BinaryIO) -> None:
        """Unlock the volume with a key file handle."""
        raise NotImplementedError

    def open(self) -> CryptStream:
        """Open the explicitly selected volume and return a readable (decrypted) stream.

        The data offset, size and key all come from the same verified header. When no
        header was explicitly selected, this fails instead of falling back to another
        candidate.
        """
        if not self.unlocked:
            raise ValueError("Volume is locked")

        if self.selected is None:
            raise ValueError("No header has been explicitly selected")

        if self.data_offset is None or self.data_size is None or self.key is None:
            raise ValueError("Selected header does not provide a complete data range and key")

        if not (Cipher := next((c for c in CIPHERS if c.__type__ == self.cipher), None)):
            raise NotImplementedError(f"Unsupported Cipher {self.cipher}")

        cipher = Cipher(self.fh, self.key, self.data_offset, self.data_size)
        return cipher.open()


def entropy(data: bytes) -> float:
    """Simple Shannon entropy implementation.

    References:
        - https://en.wikipedia.org/wiki/Entropy_(information_theory)
    """
    len_data = len(data)
    prob = [float(data.count(c)) / len_data for c in dict.fromkeys(list(data))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


def is_veracrypt_volume(fh: BinaryIO) -> bool:
    """Perform a smell test to see if the provided file-like object could be a VeraCrypt volume."""
    offset = fh.tell()

    if not hasattr(fh, "size"):
        size = fh.seek(0, io.SEEK_END)
        fh.seek(offset)
    else:
        size: int = fh.size  # type: ignore

    # Division test
    if size % 512 != 0:
        return False

    # Entropy test
    chunk = fh.read(4096)
    fh.seek(offset)
    return entropy(chunk) > 7.9

    # TODO: Make sure the volume does not contain any filesystem(s) or magic headers from regular files.
