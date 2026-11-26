"""Create the edge-state specimen C.

C contains an installable archived script (``*.data/scripts/ghost-cmd``)
that is deliberately NOT listed in RECORD.  It demonstrates the
"present in the archive but no usable digest evidence" state on a command
candidate, distinct from the spec-mandated empty hash of RECORD itself.

Stdlib only; this intentionally non-compliant wheel is an edge fixture,
not a Poetry build.
"""

from __future__ import annotations

import base64
import hashlib
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence_lab" / "dist" / "edge"
DIST = "evidence_edge-0.1.0.dist-info"
DATA_SCRIPT = "evidence_edge-0.1.0.data/scripts/ghost-cmd"

INIT = b"__version__ = '0.1.0'\n"
METADATA = b"Metadata-Version: 2.1\nName: evidence-edge\nVersion: 0.1.0\n"
WHEEL = b"Wheel-Version: 1.0\nGenerator: edge-fixture\nRoot-Is-Purelib: true\n"
SCRIPT = b"#!/usr/bin/env python3\nprint('ghost command')\n"


def digest(data: bytes) -> str:
    d = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(d).decode().rstrip("=")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "evidence_edge-0.1.0-py3-none-any.whl"

    recorded = {
        "evidence_edge/__init__.py": INIT,
        f"{DIST}/METADATA": METADATA,
        f"{DIST}/WHEEL": WHEEL,
        # DATA_SCRIPT is intentionally absent from RECORD.
    }
    lines = [f"{name},{digest(data)},{len(data)}" for name, data in recorded.items()]
    lines.append(f"{DIST}/RECORD,,")
    record = ("\n".join(lines) + "\n").encode()

    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in recorded.items():
            zf.writestr(name, data)
        info = zipfile.ZipInfo(DATA_SCRIPT)
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        zf.writestr(info, SCRIPT)
        zf.writestr(f"{DIST}/RECORD", record)

    print(target.relative_to(ROOT))


if __name__ == "__main__":
    main()
