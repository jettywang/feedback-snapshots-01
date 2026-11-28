from __future__ import annotations

import json

import pytest
from auditwheel.main import main

from tests.unit.test_candidates import _wheel, _write_candidate


def _run(monkeypatch, capsys, wheel, manifest):
    monkeypatch.setattr(
        "sys.argv",
        ["auditwheel", "compare", str(wheel), "--candidates", str(manifest)],
    )
    retval = main()
    return retval, capsys.readouterr()


def test_compare_reports_retained_tags(tmp_path, monkeypatch, capsys):
    wheel = _wheel(tmp_path)
    candidate = _write_candidate(tmp_path, "libm-boundary.so")
    manifest_path = tmp_path / "candidates.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "candidates": [
                    {
                        "soname": "libm.so.6",
                        "path": candidate.name,
                        "patch_evidence": [
                            {
                                "policy": "manylinux_2_17_x86_64",
                                "reference": "SEC-1234/evidence.json",
                            }
                        ],
                    }
                ],
            }
        )
    )

    retval, captured = _run(monkeypatch, capsys, wheel, manifest_path)

    assert retval == 0
    assert "Publication tags that can be kept" in captured.out
    assert "manylinux_2_17_x86_64" in captured.out
    assert "pow@GLIBC_2.29" in captured.out


def test_compare_names_missing_symbol_and_policy(tmp_path, monkeypatch, capsys):
    wheel = _wheel(tmp_path)
    candidate = _write_candidate(tmp_path, "libm-broken.so", provide_pow=False)
    manifest_path = tmp_path / "candidates.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "candidates": [
                    {
                        "soname": "libm.so.6",
                        "path": candidate.name,
                        "patch_evidence": [
                            {
                                "policy": "manylinux_2_17_x86_64",
                                "reference": "SEC-5678/evidence.json",
                            }
                        ],
                    }
                ],
            }
        )
    )

    retval, captured = _run(monkeypatch, capsys, wheel, manifest_path)

    assert retval == 0
    output = " ".join(captured.out.split())
    assert "no candidate provides the required symbols" in output
    assert "pow@GLIBC_2.29" in output
    assert "manylinux_2_31_x86_64" in output


def test_compare_json_output(tmp_path, monkeypatch, capsys):
    wheel = _wheel(tmp_path)
    candidate = _write_candidate(tmp_path, "libm-broken.so", provide_pow=False)
    manifest_path = tmp_path / "candidates.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "candidates": [
                    {
                        "soname": "libm.so.6",
                        "path": candidate.name,
                        "patch_evidence": [
                            {
                                "policy": "manylinux_2_17_x86_64",
                                "reference": "SEC-5678/evidence.json",
                            }
                        ],
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(
        "sys.argv",
        ["auditwheel", "compare", str(wheel), "--candidates", str(manifest_path), "--json"],
    )

    retval = main()

    assert retval == 0
    output = json.loads(capsys.readouterr().out)
    assert output["wheel"] == wheel.name
    assert output["baseline_covered"] is False
    # The wheel is already compatible with manylinux_2_31 and newer, so each of
    # those tags is an originally supported tag that no candidate can keep.
    assert "manylinux_2_31_x86_64" in output["dropped_tags"]
    assert "manylinux_2_42_x86_64" in output["dropped_tags"]
    # Tags older than the wheel itself were never supported by it.
    assert "manylinux_2_5_x86_64" in output["unreachable_tags"]
    assert "manylinux_2_5_x86_64" not in output["dropped_tags"]
    verdict = next(p for p in output["policies"] if p["policy"] == "manylinux_2_31_x86_64")
    assert verdict["missing_symbols"] == [
        {"soname": "libm.so.6", "symbol": "pow", "version": "GLIBC_2.29"}
    ]


def test_compare_rejects_bad_manifest(tmp_path, monkeypatch, capsys):
    wheel = _wheel(tmp_path)
    manifest_path = tmp_path / "candidates.json"
    manifest_path.write_text(json.dumps({"version": 1, "candidates": []}))
    monkeypatch.setattr(
        "sys.argv",
        ["auditwheel", "compare", str(wheel), "--candidates", str(manifest_path)],
    )
    with pytest.raises(SystemExit):
        main()
    assert "does not list any candidates" in capsys.readouterr().err


def test_compare_json_matches_schema(tmp_path, monkeypatch, capsys):
    jsonschema = pytest.importorskip("jsonschema")
    from importlib.resources import files

    schema = json.loads(files("auditwheel").joinpath("compare-schema.json").read_text())

    wheel = _wheel(tmp_path)
    candidate = _write_candidate(tmp_path, "libm-boundary.so")
    manifest_path = tmp_path / "candidates.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "candidates": [
                    {
                        "soname": "libm.so.6",
                        "path": candidate.name,
                        "patch_evidence": [
                            {
                                "policy": "manylinux_2_17_x86_64",
                                "reference": "SEC-1234/evidence.json",
                            }
                        ],
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(
        "sys.argv",
        ["auditwheel", "compare", str(wheel), "--candidates", str(manifest_path), "--json"],
    )

    assert main() == 0
    output = json.loads(capsys.readouterr().out)
    jsonschema.validate(instance=output, schema=schema)
