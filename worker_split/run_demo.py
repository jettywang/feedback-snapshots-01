# SPDX-License-Identifier: MIT
"""
Builds a 3-record local sample from the legacy store and runs the three
stages (online verify / offline audit / upgrade admission) with two
different worker default profiles:

  - audit worker reference profile : PRE_21_2   (legacy fleet baseline)
  - online + upgrade issuer profile: RFC_9106_LOW_MEMORY (current default)

Outputs worker_split/stage_records.jsonl and worker_split/call_log.jsonl.
"""

from __future__ import annotations

import json
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret
from argon2.profiles import CHEAPEST, PRE_21_2

from workers import (
    CallLog,
    DigestOnlyAuditGateway,
    InstrumentedHasher,
    Policy,
    offline_audit_worker,
    online_verify_worker,
    upgrade_admission_worker,
)

PASSWORD = "correct horse"

POLICY = Policy(
    min_version=19,
    allowed_types=("argon2id",),
    min_memory_cost=65536,   # 64 MiB (RFC 9106 second recommendation)
    min_time_cost=2,
    min_parallelism=1,
    min_hash_len=16,
)


def build_sample_records() -> dict[str, str]:
    # R1: historical Argon v1.2 encoding (no `v=` field), argon2i, weak params.
    modern = hash_secret(PASSWORD.encode(), b"12345678", 2, 1024, 1, 16,
                         Type.I).decode("ascii")
    parts = modern.split("$")
    r1 = "$".join([parts[0], parts[1], *parts[3:]])  # strip "v=19" segment

    # R2: pre-21.2 default profile (differs from current default, still strong).
    r2 = PasswordHasher.from_parameters(PRE_21_2).hash(PASSWORD)

    # R3: below-policy cheap hash.
    r3 = PasswordHasher.from_parameters(CHEAPEST).hash(PASSWORD)

    return {"R1-legacy-v1.2": r1, "R2-pre-21.2-profile": r2,
            "R3-below-policy": r3}


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    log = CallLog()

    online = InstrumentedHasher(PasswordHasher(), "online-verify", log,
                                "RFC_9106_LOW_MEMORY")
    audit = DigestOnlyAuditGateway(
        InstrumentedHasher(PasswordHasher.from_parameters(PRE_21_2),
                           "offline-audit", log, "PRE_21_2"),
        "offline-audit", log)
    issuer = InstrumentedHasher(PasswordHasher(), "upgrade-job", log,
                                "RFC_9106_LOW_MEMORY")

    records = build_sample_records()
    stage_records = []

    for record_id, stored_hash in records.items():
        online_out = online_verify_worker(online, record_id, stored_hash,
                                          PASSWORD)
        audit_out = offline_audit_worker(audit, record_id, stored_hash, POLICY)

        # Naive gate: what check_needs_rehash alone would say, per profile.
        naive = {
            "audit_profile_PRE_21_2": audit.check_needs_rehash(stored_hash),
            "issuer_profile_default": issuer._hasher.check_needs_rehash(stored_hash),
        }

        # Cleartext is only present if this record's login just succeeded.
        cleartext = PASSWORD if online_out["result"] == "match" else None
        admission = upgrade_admission_worker(issuer, record_id, audit_out,
                                             online_out, cleartext)

        stage_records.append({
            "record_id": record_id,
            "stored_hash": stored_hash,
            "stages": {
                "online_verify": online_out,
                "offline_audit": audit_out,
                "upgrade_admission": admission,
            },
            "naive_check_needs_rehash": naive,
        })

    (out_dir / "stage_records.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in stage_records) + "\n")
    (out_dir / "call_log.jsonl").write_text(log.to_jsonl() + "\n")

    for r in stage_records:
        s = r["stages"]
        print(f"{r['record_id']}:")
        print(f"  online_verify     -> {s['online_verify']['result']}"
              f" ({s['online_verify']['exception']})")
        print(f"  offline_audit     -> {s['offline_audit']['conclusion']}"
              f" {s['offline_audit']['policy_violations']}")
        adm = s["upgrade_admission"]
        print(f"  upgrade_admission -> admitted={adm['admitted']} route={adm['route']}")
        print(f"  naive check_needs_rehash -> {r['naive_check_needs_rehash']}")

    secret_calls = [e for e in log.entries
                    if e["worker"] == "offline-audit" and e["touches_secret"]]
    print(f"\noffline-audit calls touching secrets: {len(secret_calls)} "
          f"(verifiable in call_log.jsonl)")


if __name__ == "__main__":
    main()
