"""Verify that a local build directory a reinstall replays is still the source that was approved."""

from __future__ import annotations

__lazy_modules__ = [
    "datetime",
    "json",
    "pathlib",
    "pipx.package_specifier",
    "pipx.paths",
    "pipx.redact",
    "pipx.util",
    "urllib.parse",
]

import json
import logging
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Self

from pipx.package_specifier import source_without_extras
from pipx.paths import CTX
from pipx.redact import redact_url_credentials
from pipx.util import PipxError

if TYPE_CHECKING:
    from collections.abc import Sequence

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

#: The recorded source still is what the install recorded; the reinstall may proceed.
UNCHANGED: Final[str] = "unchanged"
#: Another account owns the build directory; the reinstall holds for review.
BUILDER_CHANGED: Final[str] = "builder-changed"
#: The build directory's content changed since the install; the reinstall holds for review.
CONTENT_CHANGED: Final[str] = "content-changed"
#: The install predates source recording, so there is nothing to check against; the reinstall holds for review.
UNRECORDED: Final[str] = "unrecorded"
#: The build directory cannot be read, so its content cannot be checked; the reinstall holds for review.
UNREADABLE: Final[str] = "unreadable"

_REASON_TEXT: Final[dict[str, str]] = {
    UNCHANGED: "the source directory matches the fingerprint recorded at install time",
    BUILDER_CHANGED: "the source directory is owned by another account than at install time",
    CONTENT_CHANGED: "the content of the source directory changed since the install",
    UNRECORDED: "the install predates source recording, so there is no fingerprint to check against",
    UNREADABLE: "the source directory cannot be read, so its content cannot be checked",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceFingerprint:
    """Fingerprint of a local source directory: what it holds and whose build it is.

    :param content_sha256: the hash of the directory's relative paths, file contents and link targets.
    :param builder: the account that owns the directory, as ``uid:<id>``.
    """

    content_sha256: str
    builder: str

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Self:
        """Build the fingerprint from its dictionary form, as the metadata file holds it.

        :param data: the dictionary form.
        :returns: the fingerprint.
        """
        return cls(content_sha256=data["content_sha256"], builder=data["builder"])

    def to_dict(self) -> dict[str, str]:
        """Return the fingerprint as a dictionary, ready to be written as JSON.

        :returns: the dictionary form.
        """
        return {"content_sha256": self.content_sha256, "builder": self.builder}


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceCheck:
    """The outcome of checking a source directory against the recorded fingerprint.

    :param reason: one of ``UNCHANGED``, ``BUILDER_CHANGED``, ``CONTENT_CHANGED``, ``UNRECORDED`` or
        ``UNREADABLE``.
    :param current: the fingerprint of the directory now, or None when it cannot be read.
    """

    reason: str
    current: SourceFingerprint | None

    @property
    def approved(self) -> bool:
        """Return whether the reinstall may proceed."""
        return self.reason == UNCHANGED

    @property
    def summary(self) -> str:
        """Return the reason in words, for the reinstall report."""
        return _REASON_TEXT[self.reason]


def local_source_dir(package_or_url: str) -> Path | None:
    """Return the local directory a package spec names, when it names one.

    Only an absolute path or a ``file:`` URL can be checked against a record: a relative path recorded at
    install time would resolve against whatever directory a later command runs from.

    :param package_or_url: the recorded package spec.
    :returns: the source directory, or None when the spec does not name a checkable local directory.
    """
    try:
        source: Final[str] = source_without_extras(package_or_url)
    except PipxError:
        return None
    url: Final[urllib.parse.SplitResult] = urllib.parse.urlsplit(source)
    if url.scheme == "file":
        candidate = Path(urllib.parse.unquote(url.path))
    elif url.scheme:
        return None
    else:
        candidate = Path(source)
    if not candidate.is_absolute() or not candidate.is_dir():
        return None
    return candidate


def fingerprint_source(source_dir: Path) -> SourceFingerprint:
    """Fingerprint a source directory: its content and the account that owns it.

    :param source_dir: the directory to fingerprint.
    :returns: the fingerprint.
    """
    import hashlib  # ruff:ignore[import-outside-top-level]  # loads OpenSSL, slows startup

    digest: Final = hashlib.sha256()
    for path in sorted(source_dir.rglob("*")):
        relative = path.relative_to(source_dir).as_posix()
        if path.is_symlink():
            digest.update(b"link\0" + relative.encode() + b"\0" + path.readlink().as_posix().encode() + b"\0")
        elif path.is_file():
            digest.update(b"file\0" + relative.encode() + b"\0")
            with path.open("rb") as file_contents:
                for chunk in iter(lambda: file_contents.read(65536), b""):
                    digest.update(chunk)
            digest.update(b"\0")
    return SourceFingerprint(content_sha256=digest.hexdigest(), builder=_directory_owner(source_dir))


def _directory_owner(source_dir: Path) -> str:
    # on Windows st_uid is always 0, so the builder check is a no-op there and the content hash carries the check
    return f"uid:{source_dir.stat().st_uid}"


def check_source(recorded: SourceFingerprint | None, source_dir: Path) -> SourceCheck:
    """Check a source directory against the fingerprint recorded at install time.

    :param recorded: the fingerprint the install recorded, or None when it recorded none.
    :param source_dir: the directory the reinstall would install from.
    :returns: the check outcome, with the fingerprint of the directory now, or None when it cannot be read.
    """
    try:
        current = fingerprint_source(source_dir)
    except OSError:
        return SourceCheck(reason=UNREADABLE, current=None)
    if recorded is None:
        reason = UNRECORDED
    elif recorded.builder != current.builder:
        reason = BUILDER_CHANGED
    elif recorded.content_sha256 != current.content_sha256:
        reason = CONTENT_CHANGED
    else:
        reason = UNCHANGED
    return SourceCheck(reason=reason, current=current)


def write_review_report(
    *,
    environment: str,
    source_dir: Path,
    check: SourceCheck,
    recorded: SourceFingerprint | None,
    pip_args: Sequence[str],
) -> Path:
    """Write the source check as a JSON report, for review when held and for reconciliation when approved.

    :param environment: the name of the environment being reinstalled.
    :param source_dir: the source directory that was checked.
    :param check: the check outcome.
    :param recorded: the fingerprint the install recorded, or None.
    :param pip_args: the pip arguments the reinstall would replay.
    :returns: the path of the report.
    """
    reports_dir: Final[Path] = CTX.logs / "source-review"
    reports_dir.mkdir(parents=True, exist_ok=True)
    checked_at: Final[datetime] = datetime.now(UTC)
    report_path: Final[Path] = reports_dir / f"{environment}-{checked_at:%Y%m%d-%H%M%S-%f}.json"
    payload: Final = {
        "environment": environment,
        "source": str(source_dir),
        "decision": "approved" if check.approved else "review-required",
        "reason": check.reason,
        "recorded_fingerprint": recorded.to_dict() if recorded is not None else None,
        "current_fingerprint": check.current.to_dict() if check.current is not None else None,
        "pip_args": [redact_url_credentials(argument) for argument in pip_args],
        "checked_at": checked_at.isoformat(),
    }
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _LOGGER.info("%s: source check %s; report written to %s", environment, check.reason, report_path)
    return report_path
