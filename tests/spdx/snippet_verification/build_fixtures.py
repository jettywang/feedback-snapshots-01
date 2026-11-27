# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Deterministically build the snippet-verification fixtures.

Run from the repository root:

    .venv/bin/python tests/spdx/snippet_verification/build_fixtures.py

The script writes multi-byte source files in LF and CRLF flavours, a "control"
copy whose content diverges, and SPDX-2.3 JSON documents whose byte/line
ranges and file checksums are computed from the actual bytes, so the fixtures
can be regenerated and audited at any time.
"""
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple

DATA_DIR = Path(__file__).parent / "data"

# Each line is written without a terminator here; the build adds LF or CRLF.
ORIGINAL_LINES: List[str] = [
    "# 可疑依赖取证样本 / suspicious dependency evidence sample",
    "def grant_access(user):",
    "    # 后门标记：免校验直接放行 (backdoor marker: bypass all checks)",
    "    if user == 'root':",
    "        return True  # 未授权提权 / unauthorized privilege escalation",
    "    return user.is_authenticated",
    "",
    "def audit(entry):",
    '    log.write("审计条目 / audit entry: " + entry)',
    "    return len(entry)",
]

# The control copy keeps the same overall shape and length profile but changes
# the content of the snippet region, so ranges still fit while content differs.
CONTROL_LINES: List[str] = [
    "# 对照样本（已修复） / hardened control sample",
    "def grant_access(user):",
    "    # 校验已恢复：必须通过权限检查 (check restored: require permission)",
    "    if user == 'root':",
    "        return user.is_superuser  # 强制鉴权 / enforced authorization",
    "    return user.is_authenticated",
    "",
    "def audit(entry):",
    '    log.write("审计条目 / audit entry: " + entry)',
    "    return len(entry)",
]

SNIPPET_LINE_RANGE: Tuple[int, int] = (2, 6)


def build_source(lines: List[str], newline: str) -> bytes:
    return (newline.join(lines) + newline).encode("utf-8")


def line_start_offsets(raw: bytes) -> List[int]:
    offsets = [0]
    index = 0
    while index < len(raw):
        if raw[index] == 0x0A:
            offsets.append(index + 1)
        index += 1
    # A trailing offset past the final newline is not a real line; drop it.
    if offsets and offsets[-1] == len(raw):
        offsets.pop()
    return offsets


def byte_range_for_lines(raw: bytes, line_begin: int, line_end: int) -> Tuple[int, int]:
    starts = line_start_offsets(raw)
    begin_byte = starts[line_begin - 1] + 1  # SPDX byte offsets are 1-based inclusive
    if line_end < len(starts):
        end_byte = starts[line_end]  # start of the next line, already 1-based offset of prior byte
    else:
        end_byte = len(raw)
    return begin_byte, end_byte


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def make_document(
    document_name: str,
    source_file_name: str,
    source_raw: bytes,
    byte_range: Tuple[int, int],
    line_range: Tuple[int, int],
    snippet_id: str = "SPDXRef-Snippet-Evidence",
) -> Dict:
    file_spdx_id = "SPDXRef-SuspiciousSource"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": f"https://example.com/spdxdocs/{document_name}",
        "creationInfo": {
            "created": "2026-11-28T00:00:00Z",
            "creators": ["Tool: pyspdxtools-snippet-fixture-builder"],
        },
        "files": [
            {
                "SPDXID": file_spdx_id,
                "fileName": source_file_name,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": sha256_hex(source_raw)},
                    {"algorithm": "SHA1", "checksumValue": hashlib.sha1(source_raw).hexdigest()},
                ],
            }
        ],
        "snippets": [
            {
                "SPDXID": snippet_id,
                "snippetFromFile": file_spdx_id,
                "name": "backdoor evidence",
                "ranges": [
                    {
                        "startPointer": {"offset": byte_range[0], "reference": file_spdx_id},
                        "endPointer": {"offset": byte_range[1], "reference": file_spdx_id},
                    },
                    {
                        "startPointer": {"lineNumber": line_range[0], "reference": file_spdx_id},
                        "endPointer": {"lineNumber": line_range[1], "reference": file_spdx_id},
                    },
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": file_spdx_id,
            }
        ],
    }


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    original_lf = build_source(ORIGINAL_LINES, "\n")
    original_crlf = build_source(ORIGINAL_LINES, "\r\n")
    control_lf = build_source(CONTROL_LINES, "\n")

    (DATA_DIR / "suspicious_lf.py").write_bytes(original_lf)
    (DATA_DIR / "suspicious_crlf.py").write_bytes(original_crlf)
    (DATA_DIR / "control_lf.py").write_bytes(control_lf)

    byte_range = byte_range_for_lines(original_lf, *SNIPPET_LINE_RANGE)
    document = make_document(
        "snippet-evidence-lf", "suspicious_lf.py", original_lf, byte_range, SNIPPET_LINE_RANGE
    )
    (DATA_DIR / "snippet-evidence-lf.spdx.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    crlf_byte_range = byte_range_for_lines(original_crlf, *SNIPPET_LINE_RANGE)
    crlf_document = make_document(
        "snippet-evidence-crlf",
        "suspicious_crlf.py",
        original_crlf,
        crlf_byte_range,
        SNIPPET_LINE_RANGE,
    )
    (DATA_DIR / "snippet-evidence-crlf.spdx.json").write_text(
        json.dumps(crlf_document, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    manifest = {
        "suspicious_lf.py": {
            "sha256": sha256_hex(original_lf),
            "bytes": len(original_lf),
            "newline": "LF",
            "line_range": list(SNIPPET_LINE_RANGE),
            "byte_range": list(byte_range),
        },
        "suspicious_crlf.py": {
            "sha256": sha256_hex(original_crlf),
            "bytes": len(original_crlf),
            "newline": "CRLF",
            "line_range": list(SNIPPET_LINE_RANGE),
            "byte_range": list(crlf_byte_range),
        },
        "control_lf.py": {
            "sha256": sha256_hex(control_lf),
            "bytes": len(control_lf),
            "newline": "LF",
            "note": "same line layout as suspicious_lf.py, different content",
        },
    }
    (DATA_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
