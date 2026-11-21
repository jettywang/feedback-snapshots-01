"""Read-only inventory and content-evidence collection for 7z archives.

This module supports security-investigation style workflows: first take an
inventory of an archive from its header, then optionally verify each member
by actually decompressing it in memory and hashing the content.

Every conclusion in the report is tagged with an evidence level so downstream
consumers can tell what was merely read from the archive header and what was
established by inspecting member content:

- ``header``: derived from archive header metadata only.
- ``content``: the member was decompressed in memory and its content hashed.

Nothing is written to disk: members are decompressed into in-memory hashing
writers. The report contains no wall-clock timestamps, so collecting it
twice from the same unmodified archive yields identical output.
"""

import argparse
import hashlib
import json
import lzma
import sys
import zlib
from typing import Any, BinaryIO

from py7zr.exceptions import ArchiveError, CrcError, PasswordRequired, UnsupportedCompressionMethodError
from py7zr.io import Py7zIO, WriterFactory
from py7zr.py7zr import SevenZipFile

REPORT_FORMAT = "py7zr-inventory/1"

EVIDENCE_HEADER = "header"
EVIDENCE_CONTENT = "content"

_CHUNK_SIZE = 1024 * 1024


class _HashingIO(Py7zIO):
    """In-memory writer that hashes member content instead of storing it."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self._sha256 = hashlib.sha256()
        self._crc32 = 0
        self._size = 0

    def write(self, s: bytes | bytearray) -> int:
        self._sha256.update(s)
        self._crc32 = zlib.crc32(bytes(s), self._crc32)
        self._size += len(s)
        return len(s)

    def read(self, size: int | None = None) -> bytes:
        return self._sha256.digest()

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def flush(self) -> None:
        pass

    def size(self) -> int:
        return self._size

    @property
    def sha256(self) -> str:
        return self._sha256.hexdigest()

    @property
    def crc32(self) -> int:
        return self._crc32


class _HashingFactory(WriterFactory):
    def __init__(self) -> None:
        self.products: dict[str, _HashingIO] = {}

    def create(self, filename: str) -> Py7zIO:
        product = _HashingIO(filename)
        self.products[filename] = product
        return product


def _error_kind(exc: BaseException) -> str:
    if isinstance(exc, PasswordRequired):
        return "password_required"
    if isinstance(exc, CrcError):
        return "crc_mismatch"
    if isinstance(exc, UnsupportedCompressionMethodError):
        return "unsupported_method"
    if isinstance(exc, lzma.LZMAError):
        return "decompression_error"
    if isinstance(exc, ArchiveError):
        return "archive_error"
    return "read_error"


def _fingerprint(fp: BinaryIO) -> dict[str, Any]:
    sha256 = hashlib.sha256()
    size = 0
    while True:
        chunk = fp.read(_CHUNK_SIZE)
        if not chunk:
            break
        sha256.update(chunk)
        size += len(chunk)
    return {"sha256": sha256.hexdigest(), "size": size}


def _format_crc32(crc32: int | None) -> str | None:
    return None if crc32 is None else f"{crc32:08x}"


def collect_inventory(source: str, *, password: str | None = None, verify: bool = False) -> dict[str, Any]:
    """Collect a read-only evidence report for the 7z archive at *source*.

    :param source: Path to the archive file. It is only read, never modified.
    :param password: Optional password for encrypted archives.
    :param verify: When ``True``, decompress every regular-file member in
        memory and record a content hash; members that cannot be read keep
        header-level evidence and carry an ``error`` entry instead.
    :return: A JSON-serializable report dict. Collecting it twice from the
        same unmodified archive yields equal reports.
    """
    with open(source, "rb") as fp:
        fingerprint = _fingerprint(fp)

    report: dict[str, Any] = {
        "format": REPORT_FORMAT,
        "archive": {
            "path": source,
            "fingerprint": fingerprint,
            "encrypted": None,
            "evidence": EVIDENCE_HEADER,
            "error": None,
        },
        "members": [],
    }

    try:
        with SevenZipFile(source, "r", password=password) as archive:
            report["archive"]["encrypted"] = archive.needs_password()
            infos = archive.list()
            for info in infos:
                member: dict[str, Any] = {
                    "filename": info.filename,
                    "evidence": EVIDENCE_HEADER,
                    "header": {
                        "is_directory": info.is_directory,
                        "is_file": info.is_file,
                        "is_symlink": info.is_symlink,
                        "compressed": info.compressed,
                        "uncompressed": info.uncompressed,
                        "crc32": _format_crc32(info.crc32),
                        "lastwritetime": info.creationtime.isoformat() if info.creationtime is not None else None,
                    },
                    "content": None,
                    "error": None,
                }
                report["members"].append(member)
                if not verify or info.is_directory or info.is_symlink:
                    continue
                try:
                    factory = _HashingFactory()
                    archive.extract(targets=[info.filename], factory=factory)
                    product = factory.products[info.filename]
                    crc32_verified = None if info.crc32 is None else product.crc32 == info.crc32
                    member["evidence"] = EVIDENCE_CONTENT
                    member["content"] = {
                        "sha256": product.sha256,
                        "size": product.size(),
                        "crc32": _format_crc32(product.crc32),
                        "crc32_verified": crc32_verified,
                    }
                except Exception as exc:  # noqa: BLE001 - any member failure is evidence, not a crash
                    member["error"] = {"kind": _error_kind(exc), "detail": str(exc)}
                finally:
                    archive.reset()
    except Exception as exc:  # noqa: BLE001 - an unreadable archive is still reported, with empty members
        report["archive"]["error"] = {"kind": _error_kind(exc), "detail": str(exc)}

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="py7zr.inventory",
        description="Print a read-only JSON evidence report for a 7z archive. "
        "Header-only by default; pass --verify to also hash member contents in memory.",
    )
    parser.add_argument("archive", help="path to the 7z archive (read-only)")
    parser.add_argument("--password", default=None, help="password for encrypted archives")
    parser.add_argument("--verify", action="store_true", help="decompress members in memory and hash their content")
    args = parser.parse_args(argv)

    report = collect_inventory(args.archive, password=args.password, verify=args.verify)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
