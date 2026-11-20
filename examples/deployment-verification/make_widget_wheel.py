"""Build a tiny `internal-widget` wheel embedding the given build marker.

The marker simulates an internal dependency tool rebuilding a wheel under
an identical name and version: same `internal-widget==1.0.0`, different
artifact contents.
"""

import base64
import hashlib
import sys
import zipfile
from pathlib import Path

PACKAGE = "internal_widget"
DIST = "internal-widget"
VERSION = "1.0.0"


def main() -> None:
    marker = sys.argv[1]
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    dist_info = f"{PACKAGE}-{VERSION}.dist-info"
    members = {
        f"{PACKAGE}/__init__.py": (
            f'"""Example internal package (build {marker})."""\n\n'
            f'__version__ = "{VERSION}"\n'
            f'BUILD_MARKER = "{marker}"\n'
        ),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {DIST}\n"
            f"Version: {VERSION}\n"
            f"Summary: example internal package, build {marker}\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: pip-audit-deployment-example\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }

    record_lines = []
    for path, content in members.items():
        data = content.encode()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record_lines.append(f"{path},sha256={digest},{len(data)}")
    record_lines.append(f"{dist_info}/RECORD,,")
    members[f"{dist_info}/RECORD"] = "\n".join(record_lines) + "\n"

    wheel = out_dir / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in members.items():
            zf.writestr(path, content)
    print(wheel)


if __name__ == "__main__":
    main()
