from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from auditwheel.architecture import Architecture
from auditwheel.libc import Libc
from auditwheel.patcher import ElfPatcher, _NonePatcher
from auditwheel.policy import ExternalReference, WheelPolicies
from auditwheel.repair_cache import (
    LibraryIdentity,
    PatcherIdentity,
    PolicyIdentity,
    RepairCache,
    RepairCacheCollision,
    RepairCacheError,
    RepairInputs,
    StripIdentity,
    WheelExternal,
    capture_repair_inputs,
    wheel_contains_sbom,
)
from auditwheel.wheel_abi import WheelAbIInfo

T0 = datetime(2026, 11, 1, tzinfo=UTC)
TARGET = "manylinux_2_28_x86_64"


class RecordingPatcher(_NonePatcher):
    """Stand-in repairer: records the calls instead of running an ELF tool."""

    def __init__(self, platform: str = TARGET) -> None:
        super().__init__(platform)
        self.variant = "stand-in"
        self._tool_identity = "stand-in-v1"
        self.calls: list[tuple[str, Path, str | None]] = []

    def set_soname(self, file_name: Path, new_so_name: str) -> None:
        self.calls.append(("set_soname", file_name, new_so_name))
        super().set_soname(file_name, new_so_name)

    def replace_needed(self, file_name: Path, *pairs: tuple[str, str]) -> None:
        self.calls.append(("replace_needed", file_name, repr(pairs)))
        super().replace_needed(file_name, *pairs)

    def apply_updates(self) -> None:
        self.calls.append(("apply_updates", Path(), None))
        self._updates.clear()


def _write_wheel(path: Path, *, sbom: dict | None = None) -> Path:
    dist_info = "demo-1.0.dist-info"
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo/_demo.so", b"extension-placeholder")
        archive.writestr(f"{dist_info}/METADATA", "Metadata-Version: 2.1\nName: demo\n")
        archive.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\n")
        archive.writestr(f"{dist_info}/RECORD", "")
        if sbom is not None:
            archive.writestr(
                f"{dist_info}/sboms/auditwheel.cdx.json",
                json.dumps(sbom),
            )
    return path


def _write_library(prefix: Path, name: str, payload: str) -> Path:
    prefix.mkdir(parents=True, exist_ok=True)
    library = prefix / name
    library.write_bytes(payload.encode())
    return library


def _location(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    return root


def _abi(wheel: Path, externals: dict[str, Path]) -> WheelAbIInfo:
    policies = WheelPolicies(libc=Libc.GLIBC, arch=Architecture.x86_64)
    policy = policies.get_policy_by_name(TARGET)
    library_refs: dict[str, Path | None] = dict(externals)
    reference = ExternalReference(library_refs, {}, policy)
    return WheelAbIInfo(
        policies=policies,
        full_external_refs={Path("demo/_demo.so"): {TARGET: reference}},
        overall_policy=policy,
        external_refs={policy.name: reference},
        ref_policy=policy,
        versioned_symbols={},
        sym_policy=policy,
        ucs_policy=policy,
        pyfpe_policy=policy,
        blacklist_policy=policy,
        machine_policy=policy,
        graft_policy=policy,
    )


def _inputs(
    wheel: Path,
    externals: dict[str, Path],
    *,
    patcher: ElfPatcher | None = None,
    strip: bool = False,
    source_date_epoch: str | None = "1700000000",
) -> RepairInputs:
    return capture_repair_inputs(
        _abi(wheel, externals),
        wheel,
        abis=[TARGET, "manylinux2014_x86_64"],
        lib_sdir=".libs",
        update_tags=True,
        strip=strip,
        zip_compression_level=6,
        patcher=patcher or RecordingPatcher(),
        implementation="auditwheel-test",
        source_date_epoch=source_date_epoch,
        strip_tool="strip-test",
    )


def test_equivalent_migration_requires_a_migration_record(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library_a = _write_library(tmp_path / "a", "libfoo.so.1", "same bytes")
    library_b = _write_library(tmp_path / "b", "libfoo.so.1", "same bytes")
    cache = RepairCache(tmp_path / "cache")

    original = _inputs(wheel, {"libfoo.so.1": library_a})
    migrated = _inputs(wheel, {"libfoo.so.1": library_b})

    # Same repair semantics: only the location moved.
    assert original.cache_key() == migrated.cache_key()
    assert original.provenance_key() != migrated.provenance_key()

    output = _write_wheel(tmp_path / "out" / wheel.name)
    record = cache.record(original, output, now=T0)

    decision = cache.lookup(migrated, now=T0)
    assert decision.reusable is False
    assert decision.record is not None
    assert decision.record.record_key == record.record_key
    assert "different library provenance" in decision.reason

    invocation = tmp_path / "invocation.json"
    elf = tmp_path / "demo" / "_demo.so"
    elf.parent.mkdir(parents=True, exist_ok=True)
    elf.touch()
    patcher = RecordingPatcher()
    patcher.set_soname(elf, "libfoo-1234abcd.so.1")
    patcher.apply_updates()
    invocation.write_text(
        json.dumps(
            {
                "record_key": record.record_key,
                "cache_key": original.cache_key(),
                "new_soname": patcher.calls[0][2],
                "apply_updates": patcher.calls[-1][0],
            },
            indent=2,
        ),
    )

    migration = cache.record_migration(
        migrated,
        record,
        verified_output_sha256=record.output["sha256"],
        evidence="sbom_absent; byte-identical-output",
        now=T0,
    )
    assert migration.record_key == migrated.provenance_key()
    assert json.loads(invocation.read_text())["apply_updates"] == "apply_updates"

    migrated_decision = cache.lookup(migrated, now=T0)
    assert migrated_decision.reusable is True
    assert migrated_decision.migration == migration


def test_actual_change_creates_a_separate_record(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library_a = _write_library(tmp_path / "a", "libfoo.so.1", "old bytes")
    library_b = _write_library(tmp_path / "b", "libfoo.so.1", "new bytes")
    cache = RepairCache(tmp_path / "cache")

    old_inputs = _inputs(wheel, {"libfoo.so.1": library_a})
    new_inputs = _inputs(wheel, {"libfoo.so.1": library_b})
    assert old_inputs.cache_key() != new_inputs.cache_key()

    old_record = cache.record(old_inputs, _write_wheel(tmp_path / "old" / wheel.name), now=T0)
    newly_grafted = _write_library(tmp_path / "c", "libbar.so.2", "new dependency")
    changed_inputs = _inputs(
        wheel,
        {"libfoo.so.1": library_b, "libbar.so.2": newly_grafted},
    )
    new_record = cache.record(
        changed_inputs,
        _write_wheel(tmp_path / "new" / wheel.name),
        now=T0 + timedelta(days=1),
    )

    assert new_record.cache_key != old_record.cache_key
    assert new_record.record_key != old_record.record_key
    assert cache.lookup(old_inputs, now=T0).reusable is True
    assert cache.lookup(changed_inputs, now=T0).reusable is True

    reasons = cache.explain_mismatch(old_record, changed_inputs)
    assert [reason.kind for reason in reasons] == ["dependency_resolution"]
    assert reasons[0].changed == ("externals",)
    assert any("content SHA-256" in item for item in reasons[0].retained)
    assert any("capture_repair_inputs" in item for item in reasons[0].recheck)


def test_approval_survives_but_a_new_publish_needs_fresh_proof(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache", review_days=30)
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    record = cache.record(inputs, _write_wheel(tmp_path / "out" / wheel.name), now=T0)
    approved = cache.approve(
        record.record_key,
        platform=TARGET,
        approver="security",
        note="old-platform report",
        now=T0,
    )

    # The old platform report is still queryable after the review window.
    assert cache.lookup(inputs, platform=TARGET, now=T0).reusable is True
    late = T0 + timedelta(days=31)
    expired = cache.lookup(inputs, platform=TARGET, now=late)
    assert expired.reusable is False
    assert expired.reason == "review interval expired"
    assert {record.record_key for record in cache.query(platform=TARGET)} == {approved.record_key}

    # Republishing the same semantics with a moved, still-identical library
    # needs a new record and a new approval.
    moved = _write_library(tmp_path / "moved", "libfoo.so.1", "bytes")
    moved_inputs = _inputs(wheel, {"libfoo.so.1": moved})
    moved_decision = cache.lookup(moved_inputs, platform=TARGET, now=late)
    assert moved_decision.reusable is False
    assert moved_decision.record is not None
    assert moved_decision.record.record_key == approved.record_key

    # A new release can query the old approval but must produce its own.
    assert (
        cache.lookup(
            inputs,
            platform=TARGET,
            release="2027.02",
            now=T0,
        ).reusable
        is False
    )
    cache.approve(
        approved.record_key,
        platform=TARGET,
        approver="security",
        release="2027.02",
        now=T0,
    )
    assert (
        cache.lookup(
            inputs,
            platform=TARGET,
            release="2027.02",
            now=T0,
        ).reusable
        is True
    )
    assert (
        cache.lookup(
            inputs,
            platform=TARGET,
            release="2027.02",
            approved_after=T0 + timedelta(days=1),
            now=T0,
        ).reusable
        is False
    )


@pytest.mark.parametrize("kind", ["dependency_resolution", "target_policy", "patcher_tool"])
def test_three_invalidations_keep_evidence_and_name_rechecks(tmp_path: Path, kind: str) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    record = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}),
        _write_wheel(tmp_path / "out" / wheel.name),
        now=T0,
    )

    if kind == "dependency_resolution":
        changed = _inputs(
            wheel,
            {"libfoo.so.1": _write_library(tmp_path / "b", "libfoo.so.1", "other")},
        )
    elif kind == "target_policy":
        changed = _inputs(
            wheel,
            {"libfoo.so.1": library},
            strip=False,
        )
        changed = RepairInputs(
            **{
                **changed.__dict__,
                "target_abis": ("manylinux_2_17_x86_64",),
            },
        )
    else:
        other_patcher = RecordingPatcher()
        other_patcher._tool_identity = "other-tool"
        changed = _inputs(wheel, {"libfoo.so.1": library}, patcher=other_patcher)

    reasons = cache.explain_mismatch(record, changed)
    assert [reason.kind for reason in reasons] == [kind]
    assert reasons[0].changed
    assert reasons[0].retained
    assert reasons[0].recheck


def test_source_paths_do_not_change_semantics_but_do_change_provenance(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library_a = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    library_b = _write_library(tmp_path / "b/nested", "libfoo.so.1", "bytes")

    first = _inputs(wheel, {"libfoo.so.1": library_a})
    second = _inputs(wheel, {"libfoo.so.1": library_b})
    assert first.cache_key() == second.cache_key()
    assert first.provenance_key() != second.provenance_key()
    assert first.externals[0].libraries[0].source_path == str(library_a)
    assert second.to_dict()["externals"][0]["libraries"][0]["source_path"] == str(library_b)


def test_renamed_library_changes_the_grafted_soname_key(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    renamed = library.with_name("libfoo.so.2")
    renamed.write_bytes(library.read_bytes())

    first = _inputs(wheel, {"libfoo.so.1": library})
    second = _inputs(wheel, {"libfoo.so.1": renamed})
    assert first.cache_key() != second.cache_key()


def test_policy_catalogue_change_invalidates_results(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    current = _inputs(wheel, {"libfoo.so.1": library})
    cache.record(current, _write_wheel(tmp_path / "out" / wheel.name), now=T0)

    old_policies = WheelPolicies(libc=Libc.GLIBC, arch=Architecture.x86_64)
    old_policies._policies = old_policies._policies[:-1]
    old_abi = _abi(wheel, {"libfoo.so.1": library})
    object.__setattr__(old_abi, "policies", old_policies)
    previous = capture_repair_inputs(
        old_abi,
        wheel,
        abis=[TARGET],
        lib_sdir=".libs",
        update_tags=True,
        strip=False,
        zip_compression_level=6,
        patcher=RecordingPatcher(),
        implementation="auditwheel-test",
        source_date_epoch="1700000000",
        strip_tool="strip-test",
    )
    reasons = cache.explain_mismatch(previous, current)
    assert {reason.kind for reason in reasons} == {"target_policy"}
    assert cache.lookup(previous, now=T0).reusable is False
    assert current.cache_key() != previous.cache_key()


def test_patcher_identity_is_part_of_the_key(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    first = RecordingPatcher()
    second = RecordingPatcher()
    second._tool_identity = "other-tool"
    assert (
        _inputs(wheel, {"libfoo.so.1": library}, patcher=first).cache_key()
        != _inputs(
            wheel,
            {"libfoo.so.1": library},
            patcher=second,
        ).cache_key()
    )


def test_strip_tool_only_matters_when_stripping(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    unstripped = _inputs(wheel, {"libfoo.so.1": library}, strip=False)
    assert unstripped.strip_tool.tool == "unused"
    stripped = _inputs(wheel, {"libfoo.so.1": library}, strip=True)
    assert stripped.strip_tool.tool == "strip-test"
    assert stripped.cache_key() != unstripped.cache_key()


def test_reproducible_collision_is_rejected(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    cache.record(inputs, _write_wheel(tmp_path / "out1" / wheel.name), now=T0)

    other = _write_wheel(tmp_path / "out2" / wheel.name)
    with zipfile.ZipFile(other, "a") as archive:
        archive.writestr("extra.txt", "different output")
    with pytest.raises(RepairCacheCollision):
        cache.record(inputs, other, now=T0)


def test_non_reproducible_output_is_not_a_collision(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    inputs = _inputs(wheel, {"libfoo.so.1": library}, source_date_epoch=None)
    first = cache.record(inputs, _write_wheel(tmp_path / "out1" / wheel.name), now=T0)
    second = cache.record(inputs, _write_wheel(tmp_path / "out2" / wheel.name), now=T0)
    assert first.record_key == second.record_key


def test_supersede_keeps_old_approval_queryable(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "old")
    moved = _write_library(tmp_path / "b", "libfoo.so.1", "new")
    cache = RepairCache(tmp_path / "cache")
    old = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}), _write_wheel(tmp_path / "o" / wheel.name), now=T0
    )
    new = cache.record(
        _inputs(wheel, {"libfoo.so.1": moved}),
        _write_wheel(tmp_path / "n" / wheel.name),
        now=T0 + timedelta(days=1),
    )
    cache.approve(old.record_key, platform=TARGET, approver="security", now=T0)
    cache.supersede(old.record_key, new.record_key)

    assert [item.status for item in cache.query(platform=TARGET)] == [
        "superseded",
        "verified",
    ]
    assert cache.get_by_record_key(old.record_key).superseded_by == new.record_key
    assert cache.get_by_record_key(new.record_key).supersedes == old.record_key
    assert (
        cache.lookup(_inputs(wheel, {"libfoo.so.1": library}), platform=TARGET, now=T0).reusable
        is False
    )


def test_artifact_round_trip(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache", store_artifacts=True)
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    output = _write_wheel(tmp_path / "out" / wheel.name)
    record = cache.record(inputs, output, now=T0)
    decision = cache.lookup(inputs, now=T0, require_artifact=True)
    assert decision.reusable is True
    assert decision.artifact_path is not None
    assert decision.artifact_path.read_bytes() == output.read_bytes()
    assert record.artifact_path is not None


def test_wheel_contains_sbom(tmp_path: Path) -> None:
    plain = _write_wheel(tmp_path / "plain.whl")
    with_sbom = _write_wheel(tmp_path / "sbom.whl", sbom={"bomFormat": "CycloneDX"})
    assert wheel_contains_sbom(plain) is False
    assert wheel_contains_sbom(with_sbom) is True


def test_capture_rejects_a_missing_policy(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    abi = _abi(wheel, {"libfoo.so.1": library})
    with pytest.raises(ValueError, match="no external reference information"):
        capture_repair_inputs(
            abi,
            wheel,
            abis=["manylinux_2_17_x86_64"],
            lib_sdir=".libs",
            update_tags=True,
            strip=False,
            zip_compression_level=6,
            patcher=RecordingPatcher(),
            implementation="auditwheel-test",
            source_date_epoch=None,
        )


def test_capture_allows_libpython_without_a_file(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    inputs = _inputs(
        wheel,
        {"libfoo.so.1": library, "libpython3.12.so.1.0": None},
    )
    libpython = next(
        item for item in inputs.externals[0].libraries if item.soname == "libpython3.12.so.1.0"
    )
    assert libpython.content_sha256 is None
    assert libpython.source_name is None


def test_capture_rejects_an_unresolvable_library(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    with pytest.raises(ValueError, match="unresolvable library"):
        _inputs(wheel, {"libfoo.so.1": library, "libmissing.so.1": None})


def test_migration_must_match_the_canonical_semantics(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    canonical = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}), _write_wheel(tmp_path / "o" / wheel.name), now=T0
    )
    different = _inputs(
        wheel, {"libfoo.so.1": _write_library(tmp_path / "c", "libfoo.so.1", "other")}
    )
    with pytest.raises(ValueError, match="same repair semantics"):
        cache.record_migration(
            different,
            canonical,
            verified_output_sha256=canonical.output["sha256"],
            evidence="byte-identical-output",
            now=T0,
        )


def test_expired_record_remains_queryable_and_invalid(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache", review_days=1)
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    record = cache.record(inputs, _write_wheel(tmp_path / "o" / wheel.name), now=T0)
    late = T0 + timedelta(days=2)
    assert cache.lookup(inputs, now=late).reusable is False
    cache.expire_due(now=late)
    assert cache.query(status="expired")[0].record_key == record.record_key
    # The old record is still readable, but no longer authorises reuse.
    assert cache.get_by_record_key(record.record_key) is not None
    assert cache.lookup(inputs, now=T0).reusable is False


# --- checked-in stand-in records -----------------------------------------

RECORDS = Path(__file__).parent / "repair_cache_records"
FIXED_WHEEL_NAME = "demo-1.0-cp312-cp312-linux_x86_64.whl"
FIXED_WHEEL_SHA = "0" * 64
FIXED_POLICY = PolicyIdentity(
    libc="glibc",
    architecture="x86_64",
    fingerprint="policy-fingerprint-stand-in",
    policies=("linux_x86_64", "manylinux_2_28_x86_64"),
)
FIXED_PATCHER = PatcherIdentity(
    variant="stand-in",
    tool="stand-in-v1",
    platform=TARGET,
)


def _manual_inputs(
    *,
    wheel_sha256: str = FIXED_WHEEL_SHA,
    libraries: tuple[tuple[str, str, str], ...],
    source_path: str | None = None,
) -> RepairInputs:
    return RepairInputs(
        wheel_filename=FIXED_WHEEL_NAME,
        wheel_sha256=wheel_sha256,
        externals=(
            WheelExternal(
                wheel_path="demo/_demo.so",
                libraries=tuple(
                    LibraryIdentity(soname, name, digest, source_path)
                    for soname, name, digest in libraries
                ),
            ),
        ),
        target_abis=(TARGET, "manylinux2014_x86_64"),
        policy=FIXED_POLICY,
        patcher=FIXED_PATCHER,
        lib_sdir=".libs",
        update_tags=True,
        strip=False,
        strip_tool=StripIdentity("unused"),
        zip_compression_level=6,
        implementation="auditwheel-stand-in",
        source_date_epoch="1700000000",
        zlib_version="stand-in-zlib",
        sbom_environment="stand-in-packages",
    )


def _fixed_wheel(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in (
            ("demo/_demo.so", b"extension-placeholder"),
            ("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.1\nName: demo\n"),
            ("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("demo-1.0.dist-info/RECORD", b""),
            ("demo-1.0.dist-info/marker.txt", payload),
        ):
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=6)
    return path


def _stand_in_records(
    tmp_path: Path,
) -> tuple[RepairCache, RepairInputs, RepairInputs, RepairInputs]:
    canonical_output = _fixed_wheel(tmp_path / "out" / FIXED_WHEEL_NAME, b"canonical")
    changed_output = _fixed_wheel(tmp_path / "changed" / FIXED_WHEEL_NAME, b"changed")
    cache = RepairCache(tmp_path / "cache")
    canonical_inputs = _manual_inputs(
        libraries=(("libfoo.so.1", "libfoo.so.1", "a" * 64),),
    )
    # Same soname, same basename, same bytes: only the mirror moved.
    migrated_inputs = _manual_inputs(
        libraries=(("libfoo.so.1", "libfoo.so.1", "a" * 64),),
        source_path="/srv/mirror/libfoo.so.1",
    )
    # The advisory fix replaced the library bytes.
    changed_inputs = _manual_inputs(
        libraries=(("libfoo.so.1", "libfoo.so.1", "b" * 64),),
    )
    canonical = cache.record(canonical_inputs, canonical_output, now=T0)
    cache.record_migration(
        migrated_inputs,
        canonical,
        verified_output_sha256=canonical.output["sha256"],
        evidence="sbom_absent; byte-identical-output",
        now=T0,
    )
    cache.record(
        changed_inputs,
        changed_output,
        now=T0 + timedelta(hours=1),
    )
    return cache, canonical_inputs, migrated_inputs, changed_inputs


def test_checked_in_stand_in_records_are_current(tmp_path: Path) -> None:
    cache, canonical_inputs, migrated_inputs, changed_inputs = _stand_in_records(tmp_path)

    expected_canonical = cache.get_by_record_key(canonical_inputs.provenance_key())
    expected_migration = cache.get_migration(migrated_inputs.provenance_key())
    expected_changed = cache.get_by_record_key(changed_inputs.provenance_key())
    assert expected_canonical is not None
    assert expected_migration is not None
    assert expected_changed is not None
    assert cache.lookup(migrated_inputs, now=T0).reusable is True
    assert cache.lookup(changed_inputs, now=T0).reusable is True
    assert [item.kind for item in cache.explain_mismatch(expected_canonical, changed_inputs)] == [
        "dependency_resolution"
    ]

    assert json.loads((RECORDS / "canonical.json").read_text()) == expected_canonical.to_dict()
    assert json.loads((RECORDS / "migration.json").read_text()) == expected_migration.to_dict()
    assert json.loads((RECORDS / "actual-change.json").read_text()) == expected_changed.to_dict()


def test_sbom_output_blocks_migration(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    output = _write_wheel(
        tmp_path / "out" / wheel.name,
        sbom={"bomFormat": "CycloneDX", "version": 1},
    )
    record = cache.record(inputs, output, now=T0)
    assert record.sbom_emitted is True

    moved = _write_library(tmp_path / "b", "libfoo.so.1", "bytes")
    moved_inputs = _inputs(wheel, {"libfoo.so.1": moved})
    with pytest.raises(ValueError, match="contains an SBOM"):
        cache.record_migration(
            moved_inputs,
            record,
            verified_output_sha256=record.output["sha256"],
            evidence="sbom_absent; byte-identical-output",
            now=T0,
        )


def test_sbom_environment_is_part_of_the_key(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    before = _inputs(wheel, {"libfoo.so.1": library})
    after = RepairInputs(
        **{
            **before.__dict__,
            "sbom_environment": "sha256:distribution-upgrade",
        },
    )
    assert before.cache_key() != after.cache_key()
    reasons = RepairCache(tmp_path / "cache").explain_mismatch(before, after)
    assert [reason.kind for reason in reasons] == ["sbom_environment"]
    assert any("identify_sbom_environment" in item for item in reasons[0].recheck)


def test_migration_requires_matching_output_digest(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    moved = _write_library(tmp_path / "b", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    canonical = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}),
        _write_wheel(tmp_path / "o" / wheel.name),
        now=T0,
    )
    with pytest.raises(ValueError, match="must match the canonical output digest"):
        cache.record_migration(
            _inputs(wheel, {"libfoo.so.1": moved}),
            canonical,
            verified_output_sha256="f" * 64,
            evidence="byte-identical-output",
            now=T0,
        )


def test_migration_requires_reproducible_timestamps(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    moved = _write_library(tmp_path / "b", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    canonical = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}, source_date_epoch=None),
        _write_wheel(tmp_path / "o" / wheel.name),
        now=T0,
    )
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        cache.record_migration(
            _inputs(wheel, {"libfoo.so.1": moved}, source_date_epoch=None),
            canonical,
            verified_output_sha256=canonical.output["sha256"],
            evidence="byte-identical-output",
            now=T0,
        )


def test_revoked_record_can_be_renewed_but_stays_queryable(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    first = cache.record(inputs, _write_wheel(tmp_path / "o" / wheel.name), now=T0)
    cache.revoke(first.record_key, reason="withdrawn advisory")

    renewed = cache.record(
        inputs,
        _write_wheel(tmp_path / "again" / wheel.name),
        now=T0 + timedelta(days=1),
    )
    assert renewed.record_key == first.record_key
    assert renewed.created_at != first.created_at
    history = cache.history(first.record_key)
    assert [item.status for item in history] == ["revoked", "verified"]
    assert history[0].notes == "withdrawn advisory"
    assert cache.lookup(inputs, now=T0 + timedelta(days=1)).reusable is True


def test_superseded_record_is_not_recreated_silently(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "old")
    changed_library = _write_library(tmp_path / "b", "libfoo.so.1", "new")
    cache = RepairCache(tmp_path / "cache")
    old = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}),
        _write_wheel(tmp_path / "o" / wheel.name),
        now=T0,
    )
    new = cache.record(
        _inputs(wheel, {"libfoo.so.1": changed_library}),
        _write_wheel(tmp_path / "n" / wheel.name),
        now=T0 + timedelta(days=1),
    )
    cache.supersede(old.record_key, new.record_key)
    with pytest.raises(RepairCacheError, match="superseded"):
        cache.record(
            _inputs(wheel, {"libfoo.so.1": library}),
            _write_wheel(tmp_path / "again" / wheel.name),
            now=T0 + timedelta(days=2),
        )


def test_pure_relocation_shows_no_proof_change(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    moved = _write_library(tmp_path / "b", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    record = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}),
        _write_wheel(tmp_path / "o" / wheel.name),
        now=T0,
    )
    moved_inputs = _inputs(wheel, {"libfoo.so.1": moved})
    # The proof deliberately excludes source paths, so a pure relocation is a
    # lookup-level decision, not a mismatch in any output-affecting family.
    assert cache.explain_mismatch(record, moved_inputs) == ()
    assert cache.lookup(moved_inputs, now=T0).reusable is False


def test_migration_stops_working_when_canonical_is_revoked(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    moved = _write_library(tmp_path / "b", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    canonical = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}),
        _write_wheel(tmp_path / "o" / wheel.name),
        now=T0,
    )
    moved_inputs = _inputs(wheel, {"libfoo.so.1": moved})
    cache.record_migration(
        moved_inputs,
        canonical,
        verified_output_sha256=canonical.output["sha256"],
        evidence="sbom_absent; byte-identical-output",
        now=T0,
    )
    assert cache.lookup(moved_inputs, now=T0).reusable is True

    cache.revoke(canonical.record_key, reason="advisory withdrawn")
    decision = cache.lookup(moved_inputs, now=T0)
    assert decision.reusable is False
    # The migration evidence itself is retained for audit.
    assert cache.get_migration(moved_inputs.provenance_key()) is not None


def test_migration_alias_cannot_be_repointed(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    moved = _write_library(tmp_path / "b", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    canonical = cache.record(
        _inputs(wheel, {"libfoo.so.1": library}),
        _write_wheel(tmp_path / "o" / wheel.name),
        now=T0,
    )
    migrated_inputs = _inputs(wheel, {"libfoo.so.1": moved})
    cache.record_migration(
        migrated_inputs,
        canonical,
        verified_output_sha256=canonical.output["sha256"],
        evidence="byte-identical-output",
        now=T0,
    )

    # A second semantics key must not silently take over an existing alias.
    other_library = _write_library(tmp_path / "c", "libfoo.so.1", "rev")
    other_inputs = _inputs(wheel, {"libfoo.so.1": other_library})
    other = cache.record(
        other_inputs,
        _write_wheel(tmp_path / "r" / wheel.name),
        now=T0,
    )
    # Simulate an alias left by an older tool which pointed at other.
    alias_path = cache.aliases_dir / f"{other_inputs.provenance_key()}.json"
    alias_path.parent.mkdir(parents=True, exist_ok=True)
    alias_path.write_text(
        json.dumps(
            {
                "record_key": other_inputs.provenance_key(),
                "canonical_key": "stale-semantics-key",
                "verified_at": T0.isoformat(),
                "verified_output_sha256": other.output["sha256"],
                "evidence": "legacy",
                "source_paths": [],
            },
        ),
    )
    with pytest.raises(RepairCacheError, match="already linked"):
        cache.record_migration(
            other_inputs,
            other,
            verified_output_sha256=other.output["sha256"],
            evidence="byte-identical-output",
            now=T0,
        )


def test_query_returns_only_the_newest_version(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl")
    library = _write_library(tmp_path / "a", "libfoo.so.1", "bytes")
    cache = RepairCache(tmp_path / "cache")
    inputs = _inputs(wheel, {"libfoo.so.1": library})
    first = cache.record(inputs, _write_wheel(tmp_path / "o" / wheel.name), now=T0)
    cache.revoke(first.record_key, reason="withdrawn")
    renewed = cache.record(
        inputs,
        _write_wheel(tmp_path / "again" / wheel.name),
        now=T0 + timedelta(days=1),
    )
    assert renewed.revision == 2
    assert [item.revision for item in cache.history(first.record_key)] == [1, 2]
    visible = cache.query()
    assert len(visible) == 1
    assert visible[0].revision == 2
