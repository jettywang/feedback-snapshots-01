from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.regf import (
    InvalidLinkError,
    LinkLoopError,
    LinkTargetNotFoundError,
    MountNotFoundError,
    RegistryHive,
    RegistryMounts,
)
from dissect.regf.c_regf import REG_BINARY, REG_LINK, REG_SZ
from tests.hive_builder import KeySpec, ValueSpec, build_hive, link_value, string_value

MACHINE = r"\REGISTRY\MACHINE"
SOFTWARE = r"\REGISTRY\MACHINE\SOFTWARE"
USERS = r"\REGISTRY\USER"


def make_machine_hive() -> BinaryIO:
    spec = KeySpec(
        "ROOT",
        root=True,
        subkeys=[
            KeySpec(
                "Software",
                subkeys=[
                    KeySpec("Target", values=[string_value("Name", "target-value")]),
                    KeySpec(
                        "GoodLink",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\Target")],
                    ),
                    KeySpec(
                        "StringValue",
                        values=[string_value("SymbolicLinkValue", r"\REGISTRY\MACHINE\Software\Target")],
                    ),
                    KeySpec(
                        "BinaryLinkName",
                        values=[ValueSpec("SymbolicLinkValue", REG_BINARY, b"\x01\x02\x03")],
                    ),
                    KeySpec(
                        "BadEncoding",
                        link=True,
                        values=[ValueSpec("SymbolicLinkValue", REG_LINK, b"\x00\xd8\xff")],
                    ),
                    KeySpec(
                        "WrongType",
                        link=True,
                        values=[string_value("SymbolicLinkValue", r"\REGISTRY\MACHINE\Software\Target")],
                    ),
                    KeySpec("EmptyLink", link=True),
                    KeySpec(
                        "LinkTypeNoFlag",
                        values=[link_value(r"\REGISTRY\MACHINE\Software\Target")],
                    ),
                    KeySpec(
                        "Missing",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\DoesNotExist")],
                    ),
                    KeySpec(
                        "External",
                        link=True,
                        values=[link_value(r"\REGISTRY\USER\Profile\Place")],
                    ),
                    KeySpec(
                        "ChainA",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\ChainB")],
                    ),
                    KeySpec(
                        "ChainB",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\Target")],
                    ),
                    KeySpec(
                        "SelfLoop",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\SelfLoop")],
                    ),
                    KeySpec(
                        "LoopA",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\LoopB")],
                    ),
                    KeySpec(
                        "LoopB",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\LoopA")],
                    ),
                ],
            )
        ],
    )
    return build_hive(spec, "MACHINE")


def make_users_hive() -> BinaryIO:
    spec = KeySpec(
        "ROOT",
        root=True,
        subkeys=[
            KeySpec(
                "Profile",
                subkeys=[
                    KeySpec("Place", values=[string_value("Who", "user-value")]),
                    KeySpec(
                        "BackToMachine",
                        link=True,
                        values=[link_value(r"\REGISTRY\MACHINE\Software\Target")],
                    ),
                ],
            )
        ],
    )
    return build_hive(spec, "USERS")


@pytest.fixture
def machine_hive() -> RegistryHive:
    return RegistryHive(make_machine_hive())


@pytest.fixture
def users_hive() -> RegistryHive:
    return RegistryHive(make_users_hive())


@pytest.fixture
def mounts(machine_hive: RegistryHive, users_hive: RegistryHive) -> RegistryMounts:
    return RegistryMounts({MACHINE: machine_hive, USERS: users_hive})


def test_valid_link_is_detected(machine_hive: RegistryHive) -> None:
    link_key = machine_hive.open(r"Software\GoodLink")

    assert link_key.is_link
    evidence = link_key.inspect_link()
    assert evidence is not None
    assert evidence.target == r"\REGISTRY\MACHINE\Software\Target"
    assert evidence.source is link_key
    assert evidence.value.type == REG_LINK
    assert evidence.value_offset == evidence.value.offset
    assert evidence.value_offset >= 0
    assert evidence.raw_target == evidence.value.data


def test_resolve_normal_link(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    link_key = machine_hive.open(r"Software\GoodLink")
    result = link_key.resolve_link(mounts)

    assert result.target is machine_hive.open(r"Software\Target")
    assert result.target_hive is machine_hive
    assert result.target_path == r"\REGISTRY\MACHINE\Software\Target"
    assert result.followed_link
    assert len(result.hops) == 1

    hop = result.hops[0]
    assert hop.source_hive is machine_hive
    assert hop.target_hive is machine_hive
    assert hop.source_cell == link_key.offset
    assert hop.link is link_key.link
    assert hop.target == link_key.link.target


def test_every_hop_traces_to_source_cell(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    chain_a = machine_hive.open(r"Software\ChainA")
    chain_b = machine_hive.open(r"Software\ChainB")
    target = machine_hive.open(r"Software\Target")

    result = chain_a.resolve_link(mounts)

    assert result.target is target
    assert [hop.source_cell for hop in result.hops] == [chain_a.offset, chain_b.offset]
    assert [hop.link.target for hop in result.hops] == [
        r"\REGISTRY\MACHINE\Software\ChainB",
        r"\REGISTRY\MACHINE\Software\Target",
    ]
    for hop in result.hops:
        assert hop.source_hive.cell(hop.source_cell) is hop.link.source


def test_plain_string_value_is_not_a_link(machine_hive: RegistryHive) -> None:
    string_key = machine_hive.open(r"Software\StringValue")
    value = string_key.value("SymbolicLinkValue")

    assert value.type == REG_SZ
    assert not string_key.is_link
    assert string_key.inspect_link() is None


def test_binary_value_with_link_name_is_not_a_link(machine_hive: RegistryHive) -> None:
    binary_key = machine_hive.open(r"Software\BinaryLinkName")

    assert not binary_key.is_link
    assert binary_key.inspect_link() is None


def test_open_does_not_follow_links(machine_hive: RegistryHive) -> None:
    link_key = machine_hive.open(r"Software\GoodLink")

    assert machine_hive.open(r"Software\GoodLink") is link_key
    assert link_key.name == "GoodLink"
    assert list(link_key.values())  # link evidence stays readable as values


def test_resolve_ordinary_key_returns_itself(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    target = machine_hive.open(r"Software\Target")
    result = target.resolve_link(mounts)

    assert result.target is target
    assert result.target_hive is machine_hive
    assert result.hops == ()
    assert not result.followed_link


def test_cross_hive_link(machine_hive: RegistryHive, users_hive: RegistryHive, mounts: RegistryMounts) -> None:
    external = machine_hive.open(r"Software\External")
    result = external.resolve_link(mounts)

    assert result.target_hive is users_hive
    assert result.target is users_hive.open(r"Profile\Place")
    assert result.target.value("Who").value == "user-value"
    assert result.target_path == r"\REGISTRY\USER\Profile\Place"
    assert len(result.hops) == 1
    assert result.hops[0].source_hive is machine_hive
    assert result.hops[0].target_hive is users_hive
    assert result.hops[0].source_cell == external.offset


def test_cross_hive_link_returns_back(
    machine_hive: RegistryHive, users_hive: RegistryHive, mounts: RegistryMounts
) -> None:
    back = users_hive.open(r"Profile\BackToMachine")
    result = back.resolve_link(mounts)

    assert result.target_hive is machine_hive
    assert result.target is machine_hive.open(r"Software\Target")
    assert len(result.hops) == 1
    assert result.hops[0].source_hive is users_hive
    assert result.hops[0].target_hive is machine_hive


def test_missing_mount_keeps_link_evidence(machine_hive: RegistryHive, users_hive: RegistryHive) -> None:
    external = machine_hive.open(r"Software\External")
    partial_mounts = RegistryMounts({MACHINE: machine_hive})

    with pytest.raises(MountNotFoundError) as exc_info:
        external.resolve_link(partial_mounts)

    error = exc_info.value
    assert error.link is external.link
    assert len(error.hops) == 1
    assert error.hops[0].source_cell == external.offset
    # The link itself is still fully inspectable.
    assert external.inspect_link().target == r"\REGISTRY\USER\Profile\Place"


def test_missing_target_key_keeps_evidence(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    missing = machine_hive.open(r"Software\Missing")

    with pytest.raises(LinkTargetNotFoundError) as exc_info:
        missing.resolve_link(mounts)

    error = exc_info.value
    assert error.link is missing.link
    assert len(error.hops) == 1
    assert error.hops[0].target == r"\REGISTRY\MACHINE\Software\DoesNotExist"
    assert missing.is_link


def test_self_loop_is_detected(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    self_loop = machine_hive.open(r"Software\SelfLoop")

    with pytest.raises(LinkLoopError) as exc_info:
        self_loop.resolve_link(mounts)

    error = exc_info.value
    assert error.link is self_loop.link
    assert len(error.hops) == 1
    assert error.hops[0].source_cell == self_loop.offset
    # Evidence retained, not reported as an empty key.
    assert self_loop.inspect_link().target == r"\REGISTRY\MACHINE\Software\SelfLoop"


def test_two_node_loop_is_detected(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    loop_a = machine_hive.open(r"Software\LoopA")
    loop_b = machine_hive.open(r"Software\LoopB")

    with pytest.raises(LinkLoopError) as exc_info:
        loop_a.resolve_link(mounts)

    error = exc_info.value
    assert [hop.source_cell for hop in error.hops] == [loop_a.offset, loop_b.offset]
    assert error.link is loop_b.link


def test_malformed_link_wrong_encoding(machine_hive: RegistryHive) -> None:
    bad = machine_hive.open(r"Software\BadEncoding")
    assert not bad.is_link

    with pytest.raises(InvalidLinkError):
        bad.inspect_link()


def test_malformed_link_wrong_value_type(machine_hive: RegistryHive) -> None:
    wrong = machine_hive.open(r"Software\WrongType")
    assert not wrong.is_link

    with pytest.raises(InvalidLinkError):
        wrong.inspect_link()
    # The ordinary string value remains accessible and is not a jump.
    assert wrong.value("SymbolicLinkValue").type == REG_SZ


def test_symlink_flag_without_values_is_invalid(machine_hive: RegistryHive) -> None:
    empty = machine_hive.open(r"Software\EmptyLink")
    assert not empty.is_link

    with pytest.raises(InvalidLinkError):
        empty.inspect_link()


def test_reg_link_value_without_flag_is_not_a_link(machine_hive: RegistryHive) -> None:
    no_flag = machine_hive.open(r"Software\LinkTypeNoFlag")
    value = no_flag.value("SymbolicLinkValue")

    assert value.type == REG_LINK
    assert not no_flag.is_link
    assert no_flag.inspect_link() is None


def test_mounts_longest_prefix_and_case_insensitive(machine_hive: RegistryHive, users_hive: RegistryHive) -> None:
    mounts = RegistryMounts()
    mounts.mount(r"\registry\machine", machine_hive)
    mounts.mount(r"\REGISTRY\MACHINE\SOFTWARE", machine_hive)
    mounts.mount(USERS, users_hive)

    hive, remaining = mounts.lookup(r"\REGISTRY\Machine\Software\Target")
    assert hive is machine_hive
    assert remaining == ("Target",)

    assert r"\REGISTRY\MACHINE" in mounts
    assert len(mounts) == 3


def test_mounts_reject_non_virtual_target(machine_hive: RegistryHive) -> None:
    mounts = RegistryMounts({MACHINE: machine_hive})

    with pytest.raises(MountNotFoundError):
        mounts.lookup(r"\Device\HarddiskVolume1\foo")


def test_resolver_never_consults_host_registry(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    # Resolution only traverses the caller-supplied hives; the package must not
    # depend on the host registry bridge (winreg) at any layer.
    import dissect.regf as package
    import dissect.regf.regf as regf_module

    assert not hasattr(regf_module, "winreg")
    assert not hasattr(package, "winreg")

    # With no mounts at all, an ordinary key still resolves purely from its own
    # hive, while a link would fail rather than reaching out to the host.
    target = machine_hive.open(r"Software\Target")
    assert target.resolve_link(RegistryMounts()).target is target

    result = machine_hive.open(r"Software\GoodLink").resolve_link(mounts)
    assert result.target.name == "Target"


def test_hive_level_inspect_and_resolve(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    evidence = machine_hive.inspect_link(r"Software\GoodLink")
    assert evidence is not None
    assert evidence.target == r"\REGISTRY\MACHINE\Software\Target"

    result = machine_hive.resolve_link(r"Software\GoodLink", mounts)
    assert result.target is machine_hive.open(r"Software\Target")


def test_repeated_resolution_is_stable(machine_hive: RegistryHive, mounts: RegistryMounts) -> None:
    link_key = machine_hive.open(r"Software\GoodLink")
    first = link_key.resolve_link(mounts)
    second = link_key.resolve_link(mounts)

    assert first.target is second.target
    assert first.hops[0].source_cell == second.hops[0].source_cell
    assert link_key.is_link


def test_walk_reports_link_cell_offsets(machine_hive: RegistryHive) -> None:
    link_key = machine_hive.open(r"Software\GoodLink")
    seen = {cell.offset for _, _, cell in machine_hive.walk() if hasattr(cell, "offset") and cell.offset >= 0}

    assert link_key.offset in seen
