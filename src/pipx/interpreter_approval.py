from __future__ import annotations

__lazy_modules__ = [
    "datetime",
    "hashlib",
    "json",
    "pathlib",
    "pipx.paths",
]

import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypedDict

from pipx.paths import CTX
from pipx.self_install import get_environment_value
from pipx.util import PipxError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import TypeIs

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

#: Environment variable naming an admin-held approval manifest, instead of the one in the standalone cache.
APPROVAL_MANIFEST_ENV: Final[str] = "PIPX_INTERPRETER_APPROVALS"
#: Name of the approval manifest when it lives beside the cached interpreters.
APPROVAL_MANIFEST_NAME: Final[str] = "approvals.json"
#: Name of the receipt recorded next to an installed interpreter, naming the approval it satisfies.
APPROVAL_RECEIPT_NAME: Final[str] = "approval.json"
_DIGEST_PREFIX: Final[str] = "sha256:"


class _ApprovalEntry(TypedDict):
    version: str
    digest: str


class _ApprovalManifest(TypedDict):
    created: float
    releases: list[_ApprovalEntry]


class _ApprovalReceipt(TypedDict):
    version: str
    digest: str
    approved: float
    installed: float


@dataclass(frozen=True, slots=True, kw_only=True)
class Approval:
    """A standalone Python build that an administrator reviewed and approved.

    :ivar version: the full interpreter version of the build, such as ``3.13.2``.
    :ivar digest: the expected ``sha256:`` digest of the build archive.
    :ivar approved_at: the ``created`` timestamp of the manifest that approves the build.
    """

    version: str
    digest: str
    approved_at: float


def approval_manifest_path() -> Path:
    """Return the path of the admin approval manifest.

    :returns: the path named by :data:`APPROVAL_MANIFEST_ENV`, or the manifest in the standalone cache.
    """
    if value := get_environment_value(APPROVAL_MANIFEST_ENV):
        return Path(value).expanduser().absolute()
    return CTX.standalone_python_cachedir / APPROVAL_MANIFEST_NAME


def approvals_enforced() -> bool:
    """Return whether an admin approval manifest is in force.

    Enforcement is on when an administrator names a manifest with :data:`APPROVAL_MANIFEST_ENV` (even if the file is
    missing, which then fails closed), or a manifest sits in the standalone cache. Without either, standalone downloads
    keep their historical behavior.

    :returns: whether downloads must match an approval.
    """
    if get_environment_value(APPROVAL_MANIFEST_ENV):
        return True
    return approval_manifest_path().is_file()


def load_approvals() -> dict[tuple[str, str], Approval]:
    """Return the approved builds, keyed by version and digest.

    :returns: the approvals.
    :raises PipxError: when enforcement is on but the manifest is missing, unreadable or malformed.
    """
    manifest_file: Final[Path] = approval_manifest_path()
    if not manifest_file.is_file():
        msg = f"Refusing to download: no interpreter approval manifest is in force at {manifest_file}."
        raise PipxError(msg)
    try:
        loaded: Final[object] = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        msg = f"Cannot read the interpreter approval manifest at {manifest_file}."
        raise PipxError(msg) from error
    if not _is_valid_manifest(loaded):
        msg = (
            f"The interpreter approval manifest at {manifest_file} is malformed: "
            "expected {'created': number, 'releases': [{'version': str, 'digest': str}, ...]}."
        )
        raise PipxError(msg)

    approvals: Final[dict[tuple[str, str], Approval]] = {}
    for entry in loaded["releases"]:
        approval = Approval(version=entry["version"], digest=entry["digest"], approved_at=loaded["created"])
        approvals.setdefault((approval.version, approval.digest), approval)
    return approvals


def _is_valid_manifest(manifest: object) -> TypeIs[_ApprovalManifest]:
    match manifest:
        case {"created": int() | float(), "releases": list() as releases}:
            return all(
                isinstance(entry, dict)
                and isinstance(entry.get("version"), str)
                and isinstance(entry.get("digest"), str)
                for entry in releases
            )
        case _:
            return False


def approve_build(version: str, digest: str) -> Approval:
    """Return the admin approval for a build, or raise when the build is not on the approval list.

    :param version: the full interpreter version of the build.
    :param digest: the digest the index gives for the build archive.
    :returns: the matching approval.
    :raises PipxError: when enforcement is on but no approval lists this version and digest.
    """
    approvals: Final[dict[tuple[str, str], Approval]] = load_approvals()
    if (approval := approvals.get((version, digest))) is None:
        msg = (
            f"Refusing to download python {version} with digest {digest}: it is not in the interpreter approval "
            f"manifest at {approval_manifest_path()}."
        )
        raise PipxError(msg)
    return approval


def write_approval_receipt(install_dir: Path, approval: Approval) -> None:
    """Record which approval an installed interpreter satisfies, for offline verification later.

    :param install_dir: the directory the interpreter was installed into.
    :param approval: the approval the installed build satisfies.
    """
    now: Final[float] = dt.datetime.now(tz=dt.UTC).timestamp()
    receipt: Final[_ApprovalReceipt] = {
        "version": approval.version,
        "digest": approval.digest,
        "approved": approval.approved_at,
        "installed": now,
    }
    (install_dir / APPROVAL_RECEIPT_NAME).write_text(json.dumps(receipt), encoding="utf-8")


def read_approval_receipt(install_dir: Path) -> _ApprovalReceipt | None:
    """Return the receipt recorded for an installed interpreter, or None when it has none.

    :param install_dir: the directory the interpreter was installed into.
    """
    receipt_file: Final[Path] = install_dir / APPROVAL_RECEIPT_NAME
    if not receipt_file.is_file():
        return None
    try:
        loaded: Final[object] = json.loads(receipt_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return loaded if _is_valid_receipt(loaded) else None


def _is_valid_receipt(receipt: object) -> TypeIs[_ApprovalReceipt]:
    match receipt:
        case {
            "version": str(),
            "digest": str(),
            "approved": int() | float(),
            "installed": int() | float(),
        }:
            return True
        case _:
            return False


def verify_installed_build(install_dir: Path) -> Approval | None:
    """Verify an already installed interpreter against the approval list, reusing its receipt offline.

    :param install_dir: the directory the interpreter was installed into.
    :returns: the approval the installed build satisfies, or None when enforcement is off.
    :raises PipxError: when enforcement is on but the interpreter cannot be matched to an approval.
    """
    if not approvals_enforced():
        return None
    approvals: Final[dict[tuple[str, str], Approval]] = load_approvals()

    receipt: Final[_ApprovalReceipt | None] = read_approval_receipt(install_dir)
    if receipt is not None and (approval := approvals.get((receipt["version"], receipt["digest"]))) is not None:
        _LOGGER.info(
            "Using cached python %s approved at %s (manifest %s).",
            receipt["version"],
            dt.datetime.fromtimestamp(receipt["approved"], tz=dt.UTC).isoformat(),
            approval_manifest_path(),
        )
        return approval

    # without a usable receipt, hash the unpacked tree; the archive checksum cannot be reconstructed after extraction
    digest: Final[str] = f"{_DIGEST_PREFIX}{_hash_install_dir(install_dir)}"
    for (version, _entry_digest), approval in approvals.items():
        if approval.digest == digest:
            _LOGGER.info("Cached python %s matches approval %s.", version, approval_manifest_path())
            return approval

    msg = (
        f"The cached interpreter in {install_dir} is not covered by the interpreter approval manifest at "
        f"{approval_manifest_path()}. Refusing to use it."
    )
    raise PipxError(msg)


def _hash_install_dir(install_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in _ordered_files(install_dir):
        relative: Final[bytes] = path.relative_to(install_dir).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(32768), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _ordered_files(install_dir: Path) -> Iterator[Path]:
    for path in sorted(install_dir.rglob("*")):
        if path.is_file() and path.name != APPROVAL_RECEIPT_NAME:
            yield path


__all__ = [
    "APPROVAL_MANIFEST_ENV",
    "APPROVAL_MANIFEST_NAME",
    "APPROVAL_RECEIPT_NAME",
    "Approval",
    "approval_manifest_path",
    "approvals_enforced",
    "approve_build",
    "load_approvals",
    "read_approval_receipt",
    "verify_installed_build",
    "write_approval_receipt",
]
