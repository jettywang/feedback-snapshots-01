"""Generate the checked-in release-review drill archives.

The drill intentionally freezes the verification timestamp so that all three
archives share one signing-evidence record. Re-running ``pypi-attestations
review`` by hand produces the same decisions, but a fresh ``verified_at``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pypi_attestations import (
    RepositoryObservation,
    ReviewArchive,
    build_review_record,
)

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
ASSETS = ROOT / "test" / "assets"
RESULTS = HERE / "results"
RESPONSES = HERE / "responses"

ARTIFACT = ASSETS / "pypi_attestations-0.0.19.tar.gz"
PROVENANCE = ASSETS / "pypi_attestations-0.0.19.tar.gz.provenance"

VERIFIED_AT = datetime(2026, 11, 29, 9, 0, tzinfo=UTC)


def load_response(name: str) -> RepositoryObservation:
    """Load one simulated repository response."""
    return RepositoryObservation.model_validate_json((RESPONSES / name).read_bytes())


def write(name: str, archive: ReviewArchive) -> None:
    """Write an archive with stable formatting."""
    (RESULTS / name).write_text(archive.model_dump_json(indent=2) + "\n")
    print(f"{name}: {archive.outcome.decision} ({archive.record_sha256})")


def main() -> None:
    """Build success, quota-gap, and recovered archives from one base record."""
    RESULTS.mkdir(parents=True, exist_ok=True)

    base = build_review_record(
        ARTIFACT,
        PROVENANCE,
        verified_at=VERIFIED_AT,
        created_at=VERIFIED_AT,
    )

    success = base.append_observation(load_response("success-observed.json"))
    gap = base.append_observation(load_response("quota-exhausted.json"))
    recovered = gap.append_observation(load_response("recovered-renamed.json"))

    write("01-success-archived.json", ReviewArchive.from_record(success))
    write("02-quota-gap-archived.json", ReviewArchive.from_record(gap))
    write("03-recovered-after-quota-archived.json", ReviewArchive.from_record(recovered))

    # Guard the invariant that makes the drill useful: recovery never rewrites
    # the signing identity, even when the observed repository changed.
    if not (success.signing == gap.signing == recovered.signing):  # pragma: no cover - defensive
        raise SystemExit("signing evidence drifted between drill archives")


if __name__ == "__main__":
    main()
