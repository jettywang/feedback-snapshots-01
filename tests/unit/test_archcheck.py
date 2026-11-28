from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from auditwheel.archcheck import (
    ArchDecision,
    check_dependency_architectures,
    decide_architecture,
    enforce_dependency_architectures,
)
from auditwheel.architecture import Architecture
from auditwheel.policy import ExternalReference, Policy

if TYPE_CHECKING:
    from auditwheel.patcher import ElfPatcher
    from auditwheel.wheel_abi import WheelAbIInfo

# Minimal ELF fixtures: only the ELF header is needed for the admission
# check to determine the architecture of a candidate dependency.
_ELF_MACHINES = {
    Architecture.x86_64: (62, 64, True),
    Architecture.i686: (3, 32, True),
    Architecture.aarch64: (183, 64, True),
    Architecture.armv7l: (40, 32, True),
    Architecture.ppc64: (21, 64, False),
    Architecture.ppc64le: (21, 64, True),
    Architecture.s390x: (22, 64, False),
    Architecture.riscv64: (243, 64, True),
    Architecture.loongarch64: (258, 64, True),
}

# EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_HARD, required for armv7l
_ARMV7L_FLAGS = 0x05000400


def _elf_bytes(arch: Architecture) -> bytes:
    machine, bits, little_endian = _ELF_MACHINES[arch]
    e_ident = bytearray(16)
    e_ident[0:4] = b"\x7fELF"
    e_ident[4] = 2 if bits == 64 else 1
    e_ident[5] = 1 if little_endian else 2
    e_ident[6] = 1  # EI_VERSION
    endian = "<" if little_endian else ">"
    flags = _ARMV7L_FLAGS if arch is Architecture.armv7l else 0
    if bits == 64:
        header = struct.pack(
            endian + "HHIQQQIHHHHHH", 3, machine, 1, 0, 0, 0, flags, 64, 0, 0, 0, 0, 0
        )
    else:
        header = struct.pack(
            endian + "HHIIIIIHHHHHH", 3, machine, 1, 0, 0, 0, flags, 52, 0, 0, 0, 0, 0
        )
    return bytes(e_ident) + header


def _write_elf(directory: Path, name: str, arch: Architecture) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(_elf_bytes(arch))
    return path


def _foreign_architecture() -> Architecture:
    """An architecture that is guaranteed to differ from the host's."""
    host = Architecture.detect().baseline
    for arch in (
        Architecture.s390x,
        Architecture.ppc64,
        Architecture.riscv64,
        Architecture.i686,
    ):
        if arch != host:
            return arch
    msg = "no foreign architecture available"
    raise AssertionError(msg)


def _external_refs(
    libs: dict[str, Path | None], abi: str
) -> dict[Path, dict[str, ExternalReference]]:
    policy = Policy(
        name=abi,
        aliases=(),
        priority=0,
        symbol_versions={},
        whitelist=frozenset(),
        blacklist={},
    )
    return {Path("pkg/module.so"): {abi: ExternalReference(libs, {}, policy)}}


@pytest.fixture
def accept_fixture(tmp_path: Path) -> tuple[dict[str, Path | None], Architecture]:
    """Fixture set where every candidate dependency matches the target.

    The target architecture deliberately differs from the host's: the
    admission check must rely on the ELF headers, not on the host.
    """
    target = _foreign_architecture()
    directory = tmp_path / "accept"
    libs: dict[str, Path | None] = {
        "libfoo.so.1": _write_elf(directory, "libfoo.so.1", target),
        "libbar.so.2": _write_elf(directory, "libbar.so.2", target),
    }
    return libs, target


@pytest.fixture
def reject_fixture(tmp_path: Path) -> tuple[dict[str, Path | None], Architecture]:
    """Fixture set mixing a matching dependency with a foreign one."""
    target = _foreign_architecture()
    other = Architecture.x86_64 if target != Architecture.x86_64 else Architecture.aarch64
    directory = tmp_path / "reject"
    libs: dict[str, Path | None] = {
        "libok.so.1": _write_elf(directory, "libok.so.1", target),
        "libwrong.so.1": _write_elf(directory, "libwrong.so.1", other),
    }
    return libs, target


class TestCheckDependencyArchitectures:
    def test_accept_records_cross_host(
        self, accept_fixture: tuple[dict[str, Path | None], Architecture]
    ) -> None:
        libs, target = accept_fixture
        abi = f"manylinux_2_28_{target.value}"
        assert target != Architecture.detect().baseline
        records = check_dependency_architectures(
            _external_refs(libs, abi),
            abi,
            wheel_tag_arch=target,
            target_arch=target,
        )
        assert len(records) == 2
        for record in records:
            assert record.decision is ArchDecision.ACCEPT
            # the three architecture sources are recorded separately
            assert record.wheel_tag_arch == target
            assert record.elf_arch == target
            assert record.target_arch == target
        enforce_dependency_architectures(records)

    def test_reject_records_cross_host(
        self, reject_fixture: tuple[dict[str, Path | None], Architecture]
    ) -> None:
        libs, target = reject_fixture
        abi = f"manylinux_2_28_{target.value}"
        assert target != Architecture.detect().baseline
        records = check_dependency_architectures(
            _external_refs(libs, abi),
            abi,
            wheel_tag_arch=target,
            target_arch=target,
        )
        by_soname = {record.soname: record for record in records}
        assert by_soname["libok.so.1"].decision is ArchDecision.ACCEPT
        rejected = by_soname["libwrong.so.1"]
        assert rejected.decision is ArchDecision.REJECT
        assert rejected.elf_arch != rejected.target_arch
        with pytest.raises(ValueError, match="libwrong.so.1"):
            enforce_dependency_architectures(records)

    def test_alias_accepted_only_when_approved(self, tmp_path: Path) -> None:
        target = _foreign_architecture()
        other = Architecture.x86_64 if target != Architecture.x86_64 else Architecture.aarch64
        lib = _write_elf(tmp_path, "libalias.so.1", other)
        abi = f"manylinux_2_28_{target.value}"
        refs = _external_refs({"libalias.so.1": lib}, abi)

        records = check_dependency_architectures(
            refs, abi, wheel_tag_arch=target, target_arch=target
        )
        assert records[0].decision is ArchDecision.REJECT

        records = check_dependency_architectures(
            refs,
            abi,
            wheel_tag_arch=target,
            target_arch=target,
            allowed_aliases=frozenset({(other, target)}),
        )
        assert records[0].decision is ArchDecision.ALIAS
        enforce_dependency_architectures(records)

    def test_unreadable_elf_is_rejected(self, tmp_path: Path) -> None:
        target = _foreign_architecture()
        lib = tmp_path / "libnotelf.so.1"
        lib.write_bytes(b"not an ELF file")
        abi = f"manylinux_2_28_{target.value}"
        records = check_dependency_architectures(
            _external_refs({"libnotelf.so.1": lib}, abi),
            abi,
            wheel_tag_arch=target,
            target_arch=target,
        )
        assert records[0].decision is ArchDecision.REJECT
        assert records[0].elf_arch is None

    def test_libpython_and_unresolved_dependencies_are_skipped(
        self, accept_fixture: tuple[dict[str, Path | None], Architecture]
    ) -> None:
        libs, target = accept_fixture
        libs["libpython3.11.so.1.0"] = None
        libs["libmissing.so.1"] = None
        abi = f"manylinux_2_28_{target.value}"
        records = check_dependency_architectures(
            _external_refs(libs, abi),
            abi,
            wheel_tag_arch=target,
            target_arch=target,
        )
        assert {record.soname for record in records} == {"libfoo.so.1", "libbar.so.2"}


class TestDecideArchitecture:
    def test_exact_match(self) -> None:
        decision, _ = decide_architecture(Architecture.aarch64, Architecture.aarch64, frozenset())
        assert decision is ArchDecision.ACCEPT

    def test_compatible_subset(self) -> None:
        # a baseline x86_64 library is fine for an x86_64_v2 target
        decision, _ = decide_architecture(Architecture.x86_64, Architecture.x86_64_v2, frozenset())
        assert decision is ArchDecision.ACCEPT

    def test_micro_architecture_upgrade_needs_alias(self) -> None:
        # an x86_64_v2 library grafted into a plain x86_64 wheel is only
        # acceptable when the alias is explicitly approved
        decision, _ = decide_architecture(Architecture.x86_64_v2, Architecture.x86_64, frozenset())
        assert decision is ArchDecision.REJECT
        decision, _ = decide_architecture(
            Architecture.x86_64_v2,
            Architecture.x86_64,
            frozenset({(Architecture.x86_64_v2, Architecture.x86_64)}),
        )
        assert decision is ArchDecision.ALIAS

    def test_unknown_elf_architecture(self) -> None:
        decision, _ = decide_architecture(None, Architecture.aarch64, frozenset())
        assert decision is ArchDecision.REJECT


class TestRepairWheelGate:
    def test_rejection_happens_before_any_file_is_moved(
        self, tmp_path: Path, reject_fixture: tuple[dict[str, Path | None], Architecture]
    ) -> None:
        from types import SimpleNamespace

        from auditwheel.repair import repair_wheel

        libs, target = reject_fixture
        abi = f"manylinux_2_28_{target.value}"
        wheel_abi = cast(
            "WheelAbIInfo", SimpleNamespace(full_external_refs=_external_refs(libs, abi))
        )
        out_dir = tmp_path / "wheelhouse"
        out_dir.mkdir()

        with pytest.raises(ValueError, match="do not match the target architecture"):
            repair_wheel(
                wheel_abi,
                tmp_path / f"pkg-1.0-cp311-cp311-{abi}.whl",
                abis=[abi],
                lib_sdir=".libs",
                out_dir=out_dir,
                update_tags=False,
                patcher=cast("ElfPatcher", SimpleNamespace()),
                strip=False,
                zip_compression_level=6,
                verify_dep_arch=True,
                target_arch=target,
                wheel_tag_arch=target,
            )

        # the candidate sources were not moved or copied anywhere
        for src_path in libs.values():
            assert src_path is not None and src_path.is_file()
        assert list(out_dir.iterdir()) == []

    def test_gate_disabled_by_default(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from auditwheel.repair import repair_wheel

        wheel_abi = cast("WheelAbIInfo", SimpleNamespace(full_external_refs={}))
        result = repair_wheel(
            wheel_abi,
            tmp_path / "pkg-1.0-py3-none-any.whl",
            abis=["manylinux_2_28_x86_64"],
            lib_sdir=".libs",
            out_dir=tmp_path,
            update_tags=False,
            patcher=cast("ElfPatcher", SimpleNamespace()),
            strip=False,
            zip_compression_level=6,
        )
        assert result is None
