from __future__ import annotations

import base64
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

from auditwheel.main import main
from auditwheel.sboms import create_sbom_for_wheel
from auditwheel.verify import verify_wheel

HERE = Path(__file__).parent.resolve()
BUNDLED = HERE.parent / "bundled-wheels"
EXTENSION_WHEEL = BUNDLED / "glibc" / "testsimple-0.0.1-cp313-cp313-linux_x86_64.whl"
EXTENSION_MEMBER = "testsimple.cpython-313-x86_64-linux-gnu.so"
LIBRARY_FIXTURE = HERE.parent / "integration" / "libffi.so.5"

DIST_INFO = "demo-0.0.1.dist-info"
ALPHA = "demo.libs/libalpha-11111111.so"
BETA = "demo.libs/libbeta-22222222.so"


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _record_row(path: str, data: bytes) -> str:
    return f"{path},sha256={_record_hash(data)},{len(data)}"


def _extension_bytes() -> bytes:
    with zipfile.ZipFile(EXTENSION_WHEEL) as zf:
        return zf.read(EXTENSION_MEMBER)


def _library_bytes(marker: int) -> bytes:
    """Return a distinct, still-parseable ELF library for each marker.

    The mutation only changes one byte in the ``.comment`` section.  The
    verifier must never run the library; it only hashes and parses metadata.
    """
    data = bytearray(LIBRARY_FIXTURE.read_bytes())
    # Last byte of the GCC comment string, located through the section table.
    comment = data.find(b"GCC: (GNU) 4.8.5 20150623")
    assert comment >= 0
    data[comment + 24] = ord("A") + marker
    return bytes(data)


def _new_style_sbom(components: list[dict[str, object]]) -> bytes:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": "pkg:pypi/demo@0.0.1",
                "name": "demo",
                "version": "0.0.1",
            }
        },
        "components": components,
        "dependencies": [],
    }
    return json.dumps(document).encode()


def _component(
    *,
    name: str,
    purl: str,
    path: str,
    data: bytes,
    digest: bytes | None = None,
    size: int | None = None,
) -> dict[str, object]:
    return {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": "1.0",
        "purl": purl,
        "hashes": [
            {"alg": "SHA-256", "content": hashlib.sha256(digest or data).hexdigest()},
        ],
        "properties": [
            {"name": "auditwheel:archive_path", "value": path},
            {"name": "auditwheel:member_size", "value": str(len(data) if size is None else size)},
        ],
    }


def _write_wheel(
    path: Path,
    *,
    alpha: bytes,
    beta: bytes,
    sbom_components: list[dict[str, object]] | None,
    sbom_document: bytes | None = None,
    last_write: bytes | None = None,
) -> Path:
    files = [
        (EXTENSION_MEMBER, _extension_bytes()),
        (ALPHA, alpha),
        (BETA, beta),
        (
            f"{DIST_INFO}/METADATA",
            b"Metadata-Version: 2.1\nName: demo\nVersion: 0.0.1\n",
        ),
        (
            f"{DIST_INFO}/WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp313-cp313-linux_x86_64\n",
        ),
    ]
    if sbom_document is None and sbom_components is not None:
        sbom_document = _new_style_sbom(sbom_components)
    if sbom_document is not None:
        files.append((f"{DIST_INFO}/sboms/auditwheel.cdx.json", sbom_document))

    rows = [_record_row(member, data) for member, data in files]
    rows.append(f"{DIST_INFO}/RECORD,,")
    record = "\n".join(rows) + "\n"

    with zipfile.ZipFile(path, "w") as zf:
        for member, data in files:
            zf.writestr(member, data)
        if last_write is not None:
            # Same archive path, written after RECORD was computed.  This is the
            # "manifest complete but the last-written member differs" sample.
            zf.writestr(ALPHA, last_write)
        zf.writestr(f"{DIST_INFO}/RECORD", record)
    return path


def _normal_components(alpha: bytes, beta: bytes) -> list[dict[str, object]]:
    return [
        _component(
            name="supplier-alpha",
            purl="pkg:rpm/almalinux/libalpha@1.0-1",
            path=ALPHA,
            data=alpha,
        ),
        _component(
            name="supplier-beta",
            purl="pkg:rpm/almalinux/libbeta@1.0-1",
            path=BETA,
            data=beta,
        ),
    ]


def test_normal_wheel_is_verified(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
    )

    report = verify_wheel(wheel)

    assert report["status"] == "verified"
    assert report["gaps"] == []
    assert report["archive"]["sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert report["archive"]["sha256"] != _record_hash(wheel.read_bytes())
    assert report["checks"]["record_self_consistent"] is True
    assert report["checks"]["all_local_libraries_verified"] is True
    assert report["summary"]["evidence_coverage"] == "complete"
    assert report["summary"]["record_entries_verified"] == 6

    libraries = {library["path"]: library for library in report["local_libraries"]}
    assert libraries[ALPHA]["sha256"] == hashlib.sha256(alpha).hexdigest()
    assert libraries[BETA]["sha256"] == hashlib.sha256(beta).hexdigest()
    assert libraries[ALPHA]["provenance"] == "verified"
    assert libraries[BETA]["provenance"] == "verified"

    proofs = report["proofs"]
    member_proofs = {
        proof["member"]: proof for proof in proofs if proof["kind"] == "member-record-sbom"
    }
    assert member_proofs[ALPHA]["member_sha256"] == hashlib.sha256(alpha).hexdigest()
    assert member_proofs[BETA]["component_name"] == "supplier-beta"
    assert "path + SHA-256 + size" in member_proofs[BETA]["basis"]


def test_record_consistent_but_sbom_omits_a_library(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta)[:1],
    )

    report = verify_wheel(wheel)
    gaps = {(gap["code"], gap.get("path")): gap for gap in report["gaps"]}

    assert report["status"] == "incomplete"
    assert report["checks"]["record_self_consistent"] is True
    assert (report["summary"]["record_entries_verified"]) == 6
    assert report["summary"]["evidence_coverage"] == "partial"

    beta_gap = gaps[("local-library-not-in-sbom", BETA)]
    assert beta_gap["sha256"] == hashlib.sha256(beta).hexdigest()
    assert "no member-level SBOM component maps to it" in beta_gap["detail"]

    libraries = {library["path"]: library for library in report["local_libraries"]}
    assert libraries[ALPHA]["provenance"] == "verified"
    assert libraries[BETA]["record_verified"] is True
    assert libraries[BETA]["provenance"] == "missing"
    assert libraries[BETA]["sbom_components"] == []

    # The SBOM has one component with the right supplier name, but no
    # component maps to BETA.  Name equality alone cannot hide the gap.
    assert [component["archive_path"] for component in report["components"]] == [ALPHA]


def test_manifest_complete_but_last_written_member_differs(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    shadowed = _library_bytes(2)
    beta = _library_bytes(1)
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
        last_write=shadowed,
    )

    report = verify_wheel(wheel)
    gaps = {(gap["code"], gap.get("path")): gap for gap in report["gaps"]}

    assert report["status"] == "failed"
    assert report["archive"]["duplicate_member_count"] == 1

    duplicate_gap = gaps[("archive-duplicate-member", ALPHA)]
    assert duplicate_gap["occurrences"] == 2
    assert duplicate_gap["archive_indexes"] == [1, 6]
    assert duplicate_gap["sha256s"] == [
        hashlib.sha256(alpha).hexdigest(),
        hashlib.sha256(shadowed).hexdigest(),
    ]
    assert duplicate_gap["effective_archive_index"] == 6

    record_gap = gaps[("record-hash-mismatch", ALPHA)]
    assert record_gap["detail"] == (
        "bytes read from the effective archive member do not match RECORD"
    )

    sbom_gap = next(
        gap for gap in report["gaps"] if gap["code"] == "sbom-component-digest-mismatch"
    )
    assert sbom_gap["component"] == "pkg:rpm/almalinux/libalpha@1.0-1"
    assert sbom_gap["archive_path"] == ALPHA
    assert sbom_gap["matches_shadowed_occurrence"] is True

    alpha_members = [member for member in report["members"] if member["path"] == ALPHA]
    assert [(member["archive_index"], member["effective"]) for member in alpha_members] == [
        (1, False),
        (6, True),
    ]
    assert alpha_members[0]["record_status"] == "shadowed"
    assert alpha_members[0]["sha256"] == hashlib.sha256(alpha).hexdigest()
    assert alpha_members[1]["record_status"] == "hash-mismatch"
    assert alpha_members[1]["sha256"] == hashlib.sha256(shadowed).hexdigest()

    libraries = {library["path"]: library for library in report["local_libraries"]}
    assert libraries[ALPHA]["sha256"] == hashlib.sha256(shadowed).hexdigest()
    assert libraries[ALPHA]["provenance"] == "failed"
    assert libraries[BETA]["provenance"] == "verified"
    assert report["checks"]["record_self_consistent"] is False


def test_legacy_sbom_without_member_evidence_is_an_evidence_gap(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    legacy = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:rpm/almalinux/libalpha@1.0-1",
                    "name": "supplier-alpha",
                    "version": "1.0",
                    "purl": "pkg:rpm/almalinux/libalpha@1.0-1",
                }
            ],
        }
    ).encode()
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=None,
        sbom_document=legacy,
    )

    report = verify_wheel(wheel)
    gaps = {(gap["code"], gap.get("path")): gap for gap in report["gaps"]}

    assert report["status"] == "incomplete"
    assert report["checks"]["record_self_consistent"] is True
    assert report["sbom_manifests"][0]["new_style"] is False
    assert ("legacy-sbom-no-member-evidence", None) in gaps
    assert ("local-library-name-only-sbom", ALPHA) in gaps
    assert ("local-library-name-only-sbom", BETA) in gaps
    assert report["summary"]["evidence_coverage"] == "partial"
    assert all(component["basis"] == "name-only" for component in report["components"])


def test_component_name_and_path_alone_do_not_pass(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    wrong = _library_bytes(3)
    components = _normal_components(alpha, beta)
    # Same member path, supplier name and purl, but the digest is for other bytes.
    components[0] = _component(
        name="supplier-alpha",
        purl="pkg:rpm/almalinux/libalpha@1.0-1",
        path=ALPHA,
        data=alpha,
        digest=wrong,
    )
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=components,
    )

    report = verify_wheel(wheel)
    gaps = {(gap["code"], gap.get("path")): gap for gap in report["gaps"]}

    assert report["status"] == "failed"
    sbom_gap = next(
        gap for gap in report["gaps"] if gap["code"] == "sbom-component-digest-mismatch"
    )
    assert sbom_gap["component"] == "pkg:rpm/almalinux/libalpha@1.0-1"
    assert sbom_gap["archive_path"] == ALPHA
    assert gaps[("local-library-sbom-mismatch", ALPHA)]["sha256"] == (
        hashlib.sha256(alpha).hexdigest()
    )


def test_verify_is_read_only(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
    )
    before = (wheel.read_bytes(), wheel.stat().st_mtime_ns)
    first = verify_wheel(wheel)
    second = verify_wheel(wheel)
    after = (wheel.read_bytes(), wheel.stat().st_mtime_ns)

    assert before == after
    assert first == second
    assert first["archive"]["sha256"] == hashlib.sha256(before[0]).hexdigest()


def test_cli_verify(tmp_path: Path, monkeypatch, capsys) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    good = _write_wheel(
        tmp_path / "good-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
    )
    incomplete = _write_wheel(
        tmp_path / "incomplete-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta)[:1],
    )
    bad = _write_wheel(
        tmp_path / "bad-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
        last_write=_library_bytes(2),
    )

    monkeypatch.setattr(sys, "argv", ["auditwheel", "verify", str(good), "--json"])
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "verified"

    monkeypatch.setattr(sys, "argv", ["auditwheel", "verify", str(incomplete), "--json"])
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "incomplete"

    monkeypatch.setattr(
        sys,
        "argv",
        ["auditwheel", "verify", str(incomplete), "--json", "--fail-on-gaps"],
    )
    assert main() == 1
    assert json.loads(capsys.readouterr().out)["status"] == "incomplete"

    monkeypatch.setattr(sys, "argv", ["auditwheel", "verify", str(bad), "--json"])
    assert main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "failed"


def test_cli_verify_missing_file(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.setattr(sys, "argv", ["auditwheel", "verify", str(tmp_path / "missing.whl")])
    with pytest.raises(SystemExit):
        main()
    assert "No such file" in capsys.readouterr().err


def test_generated_sbom_binds_component_to_member(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    from auditwheel._vendor.whichprovides import ProvidedBy

    member = tmp_path / "demo.libs" / "libalpha-11111111.so"
    member.parent.mkdir()
    data = _library_bytes(0)
    member.write_bytes(data)
    source = tmp_path / "libalpha.so.1"
    source.write_bytes(data)

    provided = ProvidedBy(
        package_type="rpm",
        package_name="supplier-alpha",
        package_version="1.0-1",
        distro="almalinux",
    )
    with patch("auditwheel.sboms.whichprovides", return_value={str(source): provided}):
        sbom = create_sbom_for_wheel(
            "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
            [source],
            sbom_members={str(source): member.as_posix()},
        )

    assert sbom is not None
    component = sbom["components"][0]
    # Supplier naming is preserved; identity now carries member bytes too.
    assert component["name"] == "supplier-alpha"
    assert component["purl"] == "pkg:rpm/almalinux/supplier-alpha@1.0-1"
    assert component["hashes"] == [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}]
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties["auditwheel:archive_path"] == member.as_posix()
    assert properties["auditwheel:member_size"] == str(len(data))


def test_repair_sbom_member_evidence_verifies_end_to_end(tmp_path) -> None:
    """Repair a real wheel and prove the generated SBOM against packed bytes.

    The fixture is a prebuilt cffi wheel whose extension links against
    ``libffi.so.5``.  The test supplies that library from the repository's
    integration fixture, runs the normal repair path, then verifies the
    resulting archive read-only.
    """
    from argparse import Namespace
    from unittest.mock import Mock, patch

    from auditwheel import main_repair
    from auditwheel._vendor.whichprovides import ProvidedBy
    from auditwheel.patcher import ElfPatcher

    class _RecordingPatcher(ElfPatcher):
        def get_rpath_direct(self, file_name):
            return ""

        def apply_updates(self):
            self._updates.clear()

    wheel = BUNDLED / "cffi-1.5.0-cp27-none-linux_x86_64.whl"
    out_dir = tmp_path / "wheelhouse"
    args = Namespace(
        LIB_SDIR=".libs",
        ONLY_PLAT=False,
        PLAT="auto",
        STRIP=False,
        UPDATE_TAGS=True,
        WHEEL_DIR=out_dir,
        WHEEL_FILE=[wheel],
        EXCLUDE=[],
        LDPATHS=str(LIBRARY_FIXTURE.parent),
        DISABLE_ISA_EXT_CHECK=False,
        ZIP_COMPRESSION_LEVEL=6,
        PATCHER="none",
        cmd="repair",
        func=Mock(),
        prog="auditwheel",
        verbose=0,
        ALLOW_PURE_PY_WHEEL=False,
    )

    provided = ProvidedBy(
        package_type="rpm",
        package_name="libffi",
        package_version="3.0.13-1",
        distro="almalinux",
    )
    with (
        patch(
            "auditwheel.main_repair.ElfPatcher.get_patcher",
            return_value=_RecordingPatcher(platform=""),
        ),
        patch("auditwheel.sboms.whichprovides", return_value={str(LIBRARY_FIXTURE): provided}),
    ):
        main_repair.execute(args, Mock())
    repaired, *_ = list(out_dir.glob("*.whl"))
    report = verify_wheel(repaired)

    libraries = report["local_libraries"]
    assert len(libraries) == 1
    assert libraries[0]["path"].startswith("cffi.libs/libffi-")
    assert libraries[0]["path"].endswith(".so.5")
    assert libraries[0]["provenance"] == "verified", report["gaps"]

    assert len(report["sbom_manifests"]) == 1
    manifest = report["sbom_manifests"][0]
    assert manifest["new_style"] is True
    assert manifest["record_status"] == "verified"
    component = report["components"][0]
    assert component["status"] == "verified"
    assert component["archive_path"] == libraries[0]["path"]
    assert component["declared_sha256"] == libraries[0]["sha256"]
    assert component["declared_size"] == libraries[0]["size"]
    # The supplier naming is preserved from whichprovides, not rewritten.
    assert component["name"] == "libffi"
    assert component["purl"] == "pkg:rpm/almalinux/libffi@3.0.13-1"
    assert report["status"] == "verified"


def _write_minimal_wheel(path: Path, record: str | None, extra: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for member, data in extra:
            zf.writestr(member, data)
        if record is not None:
            zf.writestr(f"{DIST_INFO}/RECORD", record)
    return path


def test_missing_record_fails(tmp_path: Path) -> None:
    wheel = _write_minimal_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        None,
        [(f"{DIST_INFO}/METADATA", b"Metadata-Version: 2.1\nName: demo\nVersion: 0.0.1\n")],
    )

    report = verify_wheel(wheel)
    codes = {gap["code"] for gap in report["gaps"]}

    assert report["status"] == "failed"
    assert "record-missing" in codes
    assert "archive-member-unrecorded" in codes
    assert report["record"]["path"] is None


def test_record_lists_a_missing_member(tmp_path: Path) -> None:
    present = f"{DIST_INFO}/METADATA"
    data = b"Metadata-Version: 2.1\nName: demo\nVersion: 0.0.1\n"
    missing = "demo.libs/libgone-00000000.so"
    record = "\n".join(
        [
            _record_row(present, data),
            f"{missing},sha256={_record_hash(b'gone')},4",
            f"{DIST_INFO}/RECORD,,",
        ]
    )
    wheel = _write_minimal_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        record,
        [(present, data)],
    )

    report = verify_wheel(wheel)
    gaps = {(gap["code"], gap.get("path")): gap for gap in report["gaps"]}

    assert report["status"] == "failed"
    assert report["record"]["missing_members"] == [missing]
    assert gaps[("record-member-missing", missing)]["detail"].startswith("RECORD lists")


def test_legacy_sha1_record_is_accepted(tmp_path: Path) -> None:
    present = f"{DIST_INFO}/METADATA"
    data = b"Metadata-Version: 2.1\nName: demo\nVersion: 0.0.1\n"
    digest = base64.urlsafe_b64encode(hashlib.sha1(data).digest()).rstrip(b"=").decode()
    record = "\n".join(
        [
            f"{present},sha1={digest},{len(data)}",
            f"{DIST_INFO}/RECORD,,",
        ]
    )
    wheel = _write_minimal_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        record,
        [(present, data)],
    )

    report = verify_wheel(wheel)

    assert report["status"] == "verified"
    entry = next(item for item in report["record"]["entries"] if item["path"] == present)
    assert entry["verified"] is True


def test_report_schema(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).parents[2] / "src/auditwheel/verify-schema.json").read_text()
    )
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
    )
    jsonschema.validate(instance=verify_wheel(wheel), schema=schema)


def test_spdx_is_recorded_but_not_used_as_member_evidence(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    spdx = json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "demo",
            "packages": [{"name": "supplier-alpha"}],
        }
    ).encode()
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=None,
        sbom_document=spdx,
    )

    report = verify_wheel(wheel)
    codes = {gap["code"] for gap in report["gaps"]}

    assert report["sbom_manifests"][0]["format"] == "SPDX"
    assert report["status"] == "incomplete"
    assert "sbom-format-unsupported" in codes
    assert "local-library-name-only-sbom" in codes


def test_three_samples_have_independent_evidence(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    beta = _library_bytes(1)
    shadowed = _library_bytes(2)
    normal = _write_wheel(
        tmp_path / "normal-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
    )
    missing = _write_wheel(
        tmp_path / "missing-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta)[:1],
    )
    rewritten = _write_wheel(
        tmp_path / "rewritten-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=beta,
        sbom_components=_normal_components(alpha, beta),
        last_write=shadowed,
    )

    reports = [verify_wheel(wheel) for wheel in (normal, missing, rewritten)]

    assert [report["status"] for report in reports] == ["verified", "incomplete", "failed"]
    assert len({report["archive"]["sha256"] for report in reports}) == 3
    for report, wheel in zip(reports, (normal, missing, rewritten), strict=True):
        assert report["archive"]["sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
        # Every report can be rechecked member by member without trusting names.
        for member in report["members"]:
            assert len(member["sha256"]) == 64
            assert member["record_status"] is not None

    missing_gap = next(
        gap for gap in reports[1]["gaps"] if gap["code"] == "local-library-not-in-sbom"
    )
    rewritten_gap = next(
        gap for gap in reports[2]["gaps"] if gap["code"] == "archive-duplicate-member"
    )
    assert missing_gap["path"] == BETA
    assert missing_gap["sha256"] == hashlib.sha256(beta).hexdigest()
    assert rewritten_gap["path"] == ALPHA
    assert rewritten_gap["sha256s"][1] == hashlib.sha256(shadowed).hexdigest()


def test_old_wheel_without_sbom_is_incomplete_not_failed(tmp_path: Path) -> None:
    alpha = _library_bytes(0)
    wheel = _write_wheel(
        tmp_path / "old-0.0.1-cp313-cp313-linux_x86_64.whl",
        alpha=alpha,
        beta=_library_bytes(1),
        sbom_components=None,
    )

    report = verify_wheel(wheel)
    codes = {gap["code"] for gap in report["gaps"]}

    assert report["status"] == "incomplete"
    assert report["checks"]["record_self_consistent"] is True
    assert report["checks"]["sbom_present"] is False
    assert "local-library-without-sbom" in codes
    assert report["summary"]["evidence_coverage"] == "partial"
