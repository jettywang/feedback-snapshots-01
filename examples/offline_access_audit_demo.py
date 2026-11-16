"""Offline DACL access-decision walk-through.

This script never touches the host user database: every token is an explicit
list of SID strings supplied on the command line / in the constants below, and
every security descriptor is synthesised offline or parsed from an NTFS
``$SDS`` stream. Run it with::

    python examples/offline_access_audit_demo.py

It prints, for each scenario, the small descriptor under review and the full
re-computable decision path produced by :mod:`dissect.ntfs.access`.
"""

from __future__ import annotations

from dissect.ntfs.access import (
    AceSpec,
    Decision,
    build_descriptor,
    build_empty_dacl_descriptor,
    build_null_dacl_descriptor,
    evaluate_descriptor_bytes,
    mask_names,
)

USER = "S-1-5-21-10-20-30-1000"
GUEST_GROUP = "S-1-5-32-546"
TOKEN = [USER, "S-1-5-32-545", "S-1-5-11"]

FILE_ALL = 0x1F01FF
GENERIC_READ = 0x80000000


def describe(blob: bytes) -> str:
    """Render a compact, human-readable summary of a descriptor's DACL."""
    decision_descriptor = evaluate_descriptor_bytes(blob, [], 0)
    if decision_descriptor.dacl_state == "null":
        return "DACL = NULL (no DACL present)"
    if decision_descriptor.dacl_state == "empty":
        return "DACL = present but EMPTY (0 ACEs)"
    lines = []
    import io

    from dissect.ntfs.secure import SecurityDescriptor

    sd = SecurityDescriptor(io.BytesIO(blob))
    for index, ace in enumerate(sd.dacl.ace):
        flags = int(ace.header.AceFlags)
        inherit = f" flags=0x{flags:x}" if flags else ""
        lines.append(f"  ACE[{index}] {ace.type.name:<28} mask=0x{(ace.mask or 0):08x} " f"sid={ace.sid}{inherit}")
    return "DACL:\n" + "\n".join(lines)


def run(title: str, blob: bytes, requested: int, token: list[str] | None = None) -> None:
    print("=" * 100)
    print(title)
    print("-" * 100)
    print(describe(blob))
    print(f"token SIDs = {token or TOKEN}")
    print(f"requested  = 0x{requested:08x} {mask_names(requested)}")
    print("-" * 100)
    result = evaluate_descriptor_bytes(blob, token or TOKEN, requested)
    print(result.render_path())
    print(f">>> VERDICT: {result.decision.value.upper()}")
    print()


def main() -> None:
    # Scenario 1: the stored ACE order drives the sequential walk. The final
    # granted/denied bit set is identical for plain allow/deny ACEs (Windows
    # unions the grants and denials), but the recorded decision path - which
    # ACE fires first and the accumulated mask at each step - changes, which
    # is exactly what an auditor needs to reproduce.
    deny_first = build_descriptor(
        [
            AceSpec("ACCESS_DENIED", USER, 0x00000002),
            AceSpec("ACCESS_ALLOWED", USER, FILE_ALL),
        ]
    )
    allow_first = build_descriptor(
        [
            AceSpec("ACCESS_ALLOWED", USER, FILE_ALL),
            AceSpec("ACCESS_DENIED", USER, 0x00000002),
        ]
    )
    run("Scenario 1a - deny ACE before allow ACE (canonical ordering)", deny_first, FILE_ALL)
    run("Scenario 1b - same ACEs, allow before deny (reordered)", allow_first, FILE_ALL)

    # Where ordering *can* change a conclusion is a misordered conditional ACE:
    # a naive tool that silently skips the unevaluable callback would let the
    # later state of the walk decide. This evaluator instead returns UNDECIDED
    # whenever the conditional ACE is applicable, in both orders, and only a
    # matching explicit deny can still force a hard DENY.
    conditional_first = build_descriptor(
        [
            AceSpec("ACCESS_ALLOWED_CALLBACK", USER, 0x3, application_data=b"\x00\x00\x00\x00"),
            AceSpec("ACCESS_DENIED", USER, 0x1),
        ]
    )
    run("Scenario 1c - conditional allow before deny: never silently allowed", conditional_first, 0x3)

    # Scenario 2: the same SID against NULL vs empty DACL.
    run("Scenario 2a - NULL DACL", build_null_dacl_descriptor(owner=USER), FILE_ALL, [USER])
    run("Scenario 2b - empty DACL", build_empty_dacl_descriptor(owner=USER), FILE_ALL, [USER])

    # Scenario 3: generic right mapping and partial grants.
    generic_read_only = build_descriptor(
        [
            AceSpec("ACCESS_ALLOWED", USER, GENERIC_READ),
        ]
    )
    run("Scenario 3a - GENERIC_READ requested and granted", generic_read_only, GENERIC_READ)
    run("Scenario 3b - FILE_ALL requested but only GENERIC_READ granted", generic_read_only, FILE_ALL)

    # Scenario 4: inherit-only vs effective inherited ACE.
    inherit_only = build_descriptor(
        [
            AceSpec("ACCESS_ALLOWED", USER, FILE_ALL, ace_flags=0x08),
        ]
    )
    inherited = build_descriptor(
        [
            AceSpec("ACCESS_ALLOWED", USER, 0x00000001, ace_flags=0x10),
        ]
    )
    run("Scenario 4a - INHERIT_ONLY ACE does not protect this object", inherit_only, 0x1)
    run("Scenario 4b - INHERITED ACE still applies to this object", inherited, 0x1)

    # Scenario 5: conditional/callback ACE cannot be evaluated offline.
    conditional = build_descriptor(
        [
            AceSpec("ACCESS_ALLOWED_CALLBACK", USER, FILE_ALL, application_data=b"\x00\x00\x00\x00"),
        ]
    )
    run("Scenario 5 - conditional ACE without token claims -> UNDECIDED", conditional, 0x1)

    # Scenario 6: a hard deny still wins when other ACEs are unevaluable.
    hard_deny_with_condition = build_descriptor(
        [
            AceSpec("ACCESS_DENIED", GUEST_GROUP, 0x00000001),
            AceSpec("ACCESS_ALLOWED_CALLBACK", USER, FILE_ALL, application_data=b"\x00\x00\x00\x00"),
        ]
    )
    run(
        "Scenario 6 - explicit deny plus an unevaluable conditional allow",
        hard_deny_with_condition,
        0x1,
        [USER, GUEST_GROUP],
    )

    verdicts = {
        "1a": evaluate_descriptor_bytes(deny_first, TOKEN, FILE_ALL).decision,
        "1c": evaluate_descriptor_bytes(conditional_first, TOKEN, 0x3).decision,
        "2a": evaluate_descriptor_bytes(build_null_dacl_descriptor(owner=USER), [USER], FILE_ALL).decision,
        "2b": evaluate_descriptor_bytes(build_empty_dacl_descriptor(owner=USER), [USER], FILE_ALL).decision,
        "5": evaluate_descriptor_bytes(conditional, TOKEN, 0x1).decision,
    }
    assert verdicts["1a"] == Decision.DENY
    assert verdicts["1c"] == Decision.DENY
    assert verdicts["2a"] == Decision.ALLOW
    assert verdicts["2b"] == Decision.DENY
    assert verdicts["5"] == Decision.UNDECIDED
    print("All demo assertions passed.")


if __name__ == "__main__":
    main()
