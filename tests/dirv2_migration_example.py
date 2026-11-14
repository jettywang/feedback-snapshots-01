#!/usr/bin/env python3
# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Old-to-new directory digest migration example.

This runnable example demonstrates how to move a directory artifact from the
legacy ``dir:`` scheme to the versioned ``dirv2:`` scheme without losing the
ability to verify historical evidence:

1. A directory is recorded *twice*, once per scheme. The two records carry
   different artifact names (``dir:`` vs ``dirv2:``) and different digest
   values, so they are never treated as equivalent.
2. The legacy record is re-verified with the legacy
   :class:`~in_toto.resolver.DirectoryResolver`, proving historical proofs
   still validate under their original scheme.
3. The new record is re-verified independently, both with
   :class:`~in_toto.resolver.DirV2Resolver` and with the stdlib-only reference
   script ``tests/dirv2_recompute.py``.

Run it with::

    python tests/dirv2_migration_example.py
"""

import hashlib
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from in_toto.resolver import DirectoryResolver, DirV2Resolver  # noqa: E402

RECOMPUTE_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "dirv2_recompute.py"
)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        project = os.path.join(tmp, "project")
        os.makedirs(os.path.join(project, "src"))
        with open(
            os.path.join(project, "README with newline\nand ä.txt"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("readme")
        with open(os.path.join(project, "src", "main.py"), "w") as handle:
            handle.write("print('hi')\n")

        # --- Step 1: dual-record migration entry -------------------------
        # Keep the legacy "dir:" record for backward compatibility and add
        # the new "dirv2:" record alongside it.
        legacy_record = DirectoryResolver().hash_artifacts(
            [f"dir:{project}"]
        )
        new_record = DirV2Resolver().hash_artifacts([f"dirv2:{project}"])

        print("legacy record:", legacy_record)
        print("new record   :", new_record)

        legacy_name = next(iter(legacy_record))
        new_name = next(iter(new_record))
        assert legacy_name.startswith("dir:")
        assert new_name.startswith("dirv2:")
        assert legacy_name != new_name
        assert legacy_record[legacy_name] != new_record[new_name], (
            "the two schemes must not produce interchangeable digests"
        )

        # --- Step 2: historical proof still verifies under the old rule --
        legacy_recheck = DirectoryResolver().hash_artifacts(
            [f"dir:{project}"]
        )
        assert legacy_recheck == legacy_record
        print("historical dir: record re-verified with DirectoryResolver")

        # --- Step 3: new record verifies with the new resolver -----------
        new_recheck = DirV2Resolver().hash_artifacts([f"dirv2:{project}"])
        assert new_recheck == new_record
        print("dirv2: record re-verified with DirV2Resolver")

        # --- Step 4: independent stdlib-only recomputation ---------------
        output = subprocess.check_output(
            [sys.executable, RECOMPUTE_SCRIPT, project], text=True
        ).strip()
        standalone_digest = output.split("sha256:", 1)[1]
        assert (
            standalone_digest == new_record[new_name]["sha256"]
        ), (standalone_digest, new_record)
        print("dirv2: record re-verified with independent recompute script")

        # Sanity: the empty-input sha256 is only ever used by the legacy
        # empty-directory case; the versioned scheme always has a preamble.
        assert new_record[new_name]["sha256"] != hashlib.sha256(
            b""
        ).hexdigest()

    print("\nmigration example OK")


if __name__ == "__main__":
    main()
