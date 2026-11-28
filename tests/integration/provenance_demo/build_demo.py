"""Build an offline demo wheel used by the provenance integration test.

The wheel contains one native extension and two legitimate test members
(``native_a`` and ``native_b``).  All three are ELF shared objects that
``DT_NEEDED`` the same system library, ``libffi.so.5``.  The bundled copy in
``tests/integration/libffi.so.5`` is placed on the library search path so the
whole scenario can run without a Linux host.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import zipfile
from pathlib import Path

HERE = Path(__file__).parent.resolve()
REPO_ROOT = HERE.parent.parent.parent
BUNDLED_CFFI = REPO_ROOT / "tests" / "bundled-wheels" / "cffi-1.5.0-cp27-none-linux_x86_64.whl"
BUNDLED_LIBFFI = REPO_ROOT / "tests" / "integration" / "libffi.so.5"

WHEEL_NAME = "provenance_demo-0.0.1-cp27-none-linux_x86_64.whl"
DIST_INFO = "provenance_demo-0.0.1.dist-info"


def _record(data: dict[str, bytes], names: list[str]) -> str:
    rows = []
    for name in names:
        if name.endswith("RECORD"):
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(data[name]).digest()).rstrip(b"=")
        rows.append(f"{name},sha256={digest.decode()},{len(data[name])}")
    rows.append(f"{DIST_INFO}/RECORD,,")
    return "\n".join(rows) + "\n"


def build_demo_wheel(dest_dir: Path) -> Path:
    """Create the demo wheel in ``dest_dir`` and return its path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(BUNDLED_CFFI) as archive:
        extension = archive.read("_cffi_backend.so")

    data: dict[str, bytes] = {
        "provenance_demo/__init__.py": b"",
        # The native extension.  Its filename matches the init symbol in the
        # bundled cffi ELF, so auditwheel recognizes it as a Python extension.
        "provenance_demo/_cffi_backend.so": extension,
        # Two additional legitimate wheel members that both DT_NEEDED the
        # same external library (libffi.so.5).  Each gets a distinct digest so
        # per-referrer evidence cannot be satisfied by another member's row.
        "provenance_demo/tests/member_a.so": extension + b"\0",
        "provenance_demo/tests/member_b.so": extension + b"\0\0",
        f"{DIST_INFO}/METADATA": (
            b"Metadata-Version: 2.1\nName: provenance-demo\nVersion: 0.0.1\n"
        ),
        f"{DIST_INFO}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: auditwheel-demo\n"
            b"Root-Is-Purelib: false\nTag: cp27-none-linux_x86_64\n"
        ),
        f"{DIST_INFO}/top_level.txt": b"provenance_demo\n",
    }
    wheel_path = dest_dir / WHEEL_NAME
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in data.items():
            archive.writestr(name, payload)
        archive.writestr(f"{DIST_INFO}/RECORD", _record(data, list(data)))
    return wheel_path


def stage_library(dest_dir: Path) -> Path:
    """Copy the bundled shared library into a search directory."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / BUNDLED_LIBFFI.name
    shutil.copy2(BUNDLED_LIBFFI, target)
    return target
