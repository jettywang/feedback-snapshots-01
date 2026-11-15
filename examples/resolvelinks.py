"""Offline registry link inspection and resolution demo.

Builds two small in-memory hives that contain normal links, an ordinary key
with a same-named string value, a cross-hive link and a loop, then shows the
two ways of dealing with a link key:

* ``inspect_link`` keeps the on-disk link evidence without following anything;
* ``resolve_link`` follows links strictly through a caller-supplied mount map.

Nothing here opens the host registry; every jump is traced back to its source
cell and unresolvable links keep their evidence instead of looking empty.
"""

from __future__ import annotations

from dissect.regf import (
    InvalidLinkError,
    LinkLoopError,
    MountNotFoundError,
    RegistryHive,
    RegistryMounts,
)

from tests.hive_builder import KeySpec, build_hive, link_value, string_value

MACHINE = r"\REGISTRY\MACHINE"
USERS = r"\REGISTRY\USER"


def build_machine() -> RegistryHive:
    spec = KeySpec(
        "ROOT",
        root=True,
        subkeys=[
            KeySpec(
                "Software",
                subkeys=[
                    KeySpec("Target", values=[string_value("Name", "real-target")]),
                    KeySpec("GoodLink", link=True, values=[link_value(rf"{MACHINE}\Software\Target")]),
                    KeySpec("NotALink", values=[string_value("SymbolicLinkValue", rf"{MACHINE}\Software\Target")]),
                    KeySpec("CrossHive", link=True, values=[link_value(rf"{USERS}\Profile\Place")]),
                    KeySpec("Loop", link=True, values=[link_value(rf"{MACHINE}\Software\Loop")]),
                ],
            )
        ],
    )
    return RegistryHive(build_hive(spec, "MACHINE"))


def build_users() -> RegistryHive:
    spec = KeySpec(
        "ROOT",
        root=True,
        subkeys=[
            KeySpec("Profile", subkeys=[KeySpec("Place", values=[string_value("Who", "user-hive")])]),
        ],
    )
    return RegistryHive(build_hive(spec, "USERS"))


def main() -> None:
    machine = build_machine()
    users = build_users()
    mounts = RegistryMounts({MACHINE: machine, USERS: users})

    print("== inspect only (never follows, never mounts) ==")
    for name in ("GoodLink", "NotALink", "CrossHive", "Loop"):
        key = machine.open(rf"Software\{name}")
        evidence = key.inspect_link()
        if evidence is None:
            print(f"{name}: ordinary key, value type = {key.value('SymbolicLinkValue').type} (not REG_LINK)")
        else:
            print(f"{name}: link at cell 0x{key.offset:x} -> {evidence.target}")

    print("\n== resolve through the offline mount map ==")
    for name in ("GoodLink", "CrossHive", "Loop", "NotALink"):
        key = machine.open(rf"Software\{name}")
        try:
            result = key.resolve_link(mounts)
        except LinkLoopError as exc:
            print(f"{name}: {type(exc).__name__}; {len(exc.hops)} hop(s) recorded, evidence kept")
            continue
        except InvalidLinkError:
            print(f"{name}: not a link, nothing to resolve")
            continue
        except MountNotFoundError as exc:
            print(f"{name}: missing mount for {exc.link.target}")
            continue

        for hop in result.hops:
            print(
                f"  hop: cell 0x{hop.source_cell:x} in {hop.source_hive.filename!r} "
                f"-> {hop.target} ({hop.target_hive.filename!r})"
            )
        print(f"{name}: resolved to {result.target_path} = {result.target.name!r}")


if __name__ == "__main__":
    main()
