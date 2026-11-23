# SPDX-License-Identifier: MIT

"""
Cross-platform digest policy demonstration.

The password service runs on two kinds of workers with different
capabilities.  Both are driven by the *same* application-declared target and
the *same* versioned policy:

* a regular server (up to 4 parallel threads), and
* a single-threaded WebAssembly edge worker (parallelism must be 1).

The parameters below are deliberately synthetic and cheap so the demo runs
in milliseconds; the policy logic itself is identical for production values.

Run with:

    python examples/cross_platform_policy_demo.py
"""

from __future__ import annotations

from dataclasses import replace

from argon2 import (
    DigestDecision,
    DigestPolicy,
    Parameters,
    PasswordHasher,
    PlatformCapabilities,
    PolicyPasswordHasher,
    Type,
    extract_parameters,
)


POLICY_VERSION = "2026.1"

# The target declared by the *application*.  It does not change just because
# the process happens to run on a different platform.
TARGET = Parameters(
    type=Type.ID,
    version=19,
    salt_len=16,
    hash_len=32,
    time_cost=2,
    memory_cost=1024,  # 1 MiB -- synthetic value for a fast demo
    parallelism=4,
)

# Two platform capability stand-ins: no sys.platform monkey-patching needed.
SERVER = PlatformCapabilities(name="server", max_parallelism=4)
WASM = PlatformCapabilities(name="wasm", max_parallelism=1)

# Fixed salts keep the printed digests reproducible.  Real services rely on
# the random salts generated inside PasswordHasher.hash().
SALT_COMPLIANT = b"salt-compliant-0"  # 16 bytes
SALT_LEGACY = b"salt-legacy-rec0"  # 16 bytes
SALT_FRESH = b"salt-fresh-wasm0"  # 16 bytes


def banner(title: str) -> None:
    print(f"\n=== {title} ===")


def show_decision(label: str, decision) -> None:
    print(
        f"  {label}: {decision.action.value.upper()} "
        f"(policy {decision.policy_version}) -- {decision.reason}"
    )


def main() -> None:
    server_policy = DigestPolicy(TARGET, SERVER, version=POLICY_VERSION)
    wasm_policy = DigestPolicy(TARGET, WASM, version=POLICY_VERSION)
    server = PolicyPasswordHasher(server_policy)
    wasm = PolicyPasswordHasher(wasm_policy)

    # The process-level PasswordHasher default may differ from the application
    # target; the policy keeps both concepts explicitly separate.
    banner("Application target vs. process default")
    print(f"  application target : {TARGET}")
    print(f"  process default    : {PasswordHasher()._parameters}")
    print(f"  server effective   : {server_policy.effective_parameters()}")
    print(f"  wasm effective     : {wasm_policy.effective_parameters()}")

    # Record A: already at the target (produced earlier on a server).  A
    # fixed salt makes the printed digest reproducible.
    record_a = server.policy_platform_hash("hunter2", salt=SALT_COMPLIANT)
    # Record B: a weaker legacy record that pre-dates the target.
    legacy_params = replace(
        TARGET, time_cost=1, memory_cost=512, parallelism=1
    )
    record_b = PasswordHasher.from_parameters(legacy_params).hash(
        "correct horse battery staple", salt=SALT_LEGACY
    )

    banner("Record A -- already compliant, must never be rewritten")
    print(f"  stored digest: {record_a}")
    for label, worker in (("server", server), ("wasm", wasm)):
        ok, decision = worker.verify_and_plan(record_a, "hunter2")
        assert ok
        show_decision(label, decision)
        assert decision.action is DigestDecision.KEEP
        assert worker.rehash_if_allowed(record_a, "hunter2") is None
    # The WASM worker can verify parallelism=4 even though it cannot
    # produce it.
    assert wasm.verify(record_a, "hunter2") is True

    banner("Record B -- below target: upgrade on server, defer on WASM")
    print(f"  stored digest: {record_b}")
    print(f"  stored params: {extract_parameters(record_b)}")

    ok, server_decision = server.verify_and_plan(
        record_b, "correct horse battery staple"
    )
    assert ok
    show_decision("server", server_decision)
    assert server_decision.action is DigestDecision.UPGRADE
    upgraded = server.rehash_if_allowed(
        record_b, "correct horse battery staple"
    )
    assert upgraded is not None
    assert extract_parameters(upgraded) == TARGET
    print(f"  upgraded digest: {upgraded}")

    ok, wasm_decision = wasm.verify_and_plan(
        record_b, "correct horse battery staple"
    )
    assert ok
    show_decision("wasm", wasm_decision)
    assert wasm_decision.action is DigestDecision.DEFER
    # The record stays byte-identical on the incapable platform.
    assert (
        wasm.rehash_if_allowed(
            record_b, "correct horse battery staple"
        )
        is None
    )

    banner("New hashes created on each platform")
    fresh_server = server.hash("edge password", salt=SALT_FRESH)
    fresh_wasm = wasm.hash("edge password", salt=SALT_FRESH)
    print(f"  server: {fresh_server}")
    print(f"  wasm  : {fresh_wasm}")
    # Same salt and password, different parallelism => different digests, but
    # each is verifiable on the *other* platform.
    assert server.verify(fresh_wasm, "edge password") is True
    assert wasm.verify(fresh_server, "edge password") is True

    banner("Local audit of every final digest against the policy version")
    finals = [
        ("A (kept, target)", record_a, server_policy),
        ("B (upgraded on server)", upgraded, server_policy),
        ("B (untouched on wasm)", record_b, wasm_policy),
        ("fresh server hash", fresh_server, server_policy),
        ("fresh wasm hash", fresh_wasm, wasm_policy),
    ]
    for label, digest, policy in finals:
        decision = policy.evaluate(digest)
        print(
            f"  {label:24} policy={policy.version} "
            f"decision={decision.action.value:7} params="
            f"t={decision.current.time_cost} "
            f"m={decision.current.memory_cost} "
            f"p={decision.current.parallelism}"
        )

    banner("Summary")
    print("  - verification succeeds on both platforms for every digest")
    print("  - compliant records are kept, never rewritten back and forth")
    print("  - weaker records upgrade only where the target is producible")
    print("  - the WASM worker defers instead of silently downgrading")
    print(f"  - every decision carries policy version {POLICY_VERSION}")


if __name__ == "__main__":
    main()
