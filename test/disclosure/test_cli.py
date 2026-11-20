import json

import pretend
import pytest
from packaging.version import Version

import pip_audit._cli
from pip_audit._service import ResolvedDependency, SkippedDependency, VulnerabilityResult
from pip_audit._service.interface import ConnectionError as ServiceConnectionError


PUBLIC = ResolvedDependency(name="public-lib", version=Version("1.0.0"))
PRIVATE = ResolvedDependency(name="internal-payments-lib", version=Version("1.2.3"))
BROKEN = SkippedDependency(
    name="internal-broken-lib", skip_reason="invalid version at /srv/private/broken"
)

RESULTS = [
    (
        PUBLIC,
        [
            VulnerabilityResult(
                id="PYSEC-2099-0001",
                description="ADVISORY-DESCRIPTION-MARKER mentions internal-payments-lib",
                fix_versions=[Version("1.0.1")],
                aliases={"CVE-2099-0001"},
            )
        ],
    ),
    (
        PRIVATE,
        [
            VulnerabilityResult(
                id="PYSEC-2099-0002",
                description="PRIVATE-ADVISORY-MARKER",
                fix_versions=[Version("1.2.4")],
                aliases=set(),
            )
        ],
    ),
    (BROKEN, []),
]


def _run(monkeypatch, tmp_path, args, audit_impl):
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("# public packages\npublic-lib\n")

    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    auditor = pretend.stub(audit=audit_impl)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    parser = pip_audit._cli._parser()
    argv = [
        "--public-report",
        str(tmp_path / "public.json"),
        "--internal-report",
        str(tmp_path / "internal.json"),
        "--public-allowlist",
        str(allowlist),
        "--progress-spinner",
        "off",
        *args,
    ]
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(argv))

    with pytest.raises(SystemExit) as excinfo:
        pip_audit._cli.audit()
    return excinfo.value.code


def test_success_writes_orthogonal_reports(monkeypatch, tmp_path, capsys):
    code = _run(monkeypatch, tmp_path, [], lambda source: iter(RESULTS))

    assert code == 1
    public_text = (tmp_path / "public.json").read_text()
    public = json.loads(public_text)
    internal = json.loads((tmp_path / "internal.json").read_text())

    assert [d["name"] for d in public["public_dependencies"]] == ["public-lib"]
    assert "description" not in public_text
    assert "internal-payments-lib" not in public_text
    assert "/srv/private" not in public_text

    internal_names = [d["name"] for d in internal["dependencies"]]
    assert internal_names == ["internal-broken-lib", "internal-payments-lib", "public-lib"]
    assert internal["dependencies"][0]["skip_reason"].endswith("/srv/private/broken")
    assert internal["dependencies"][1]["vulnerabilities"][0]["description"] == (
        "PRIVATE-ADVISORY-MARKER"
    )
    assert internal["audit"]["status"] == "complete"

    assert "Found 2 known vulnerabilities in 2 packages" in capsys.readouterr().err


def test_failure_withholds_public_report_but_writes_internal(monkeypatch, tmp_path, caplog):
    stale = tmp_path / "public.json"
    stale.write_text("yesterday's summary")

    def boom(source):
        raise ServiceConnectionError("Could not connect to OSV's vulnerability feed")

    code = _run(monkeypatch, tmp_path, [], boom)

    assert code == 1
    assert not stale.exists()

    internal = json.loads((tmp_path / "internal.json").read_text())
    assert internal["audit"]["status"] == "failed"
    assert internal["audit"]["exit_code"] == 1
    assert internal["error"]["type"] == "ConnectionError"
    assert internal["error"]["message"] == "Could not connect to OSV's vulnerability feed"
    assert "Traceback" in internal["error"]["traceback"]

    assert "Could not connect to OSV's vulnerability feed" in caplog.text
    assert "Tip: your network may be blocking this service" in caplog.text


def test_public_report_requires_allowlist(monkeypatch, tmp_path):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)
    monkeypatch.setattr(
        pip_audit._cli, "Auditor", lambda *a, **kw: pretend.stub(audit=lambda s: iter(RESULTS))
    )

    parser = pip_audit._cli._parser()
    argv = ["--public-report", str(tmp_path / "public.json"), "--progress-spinner", "off"]
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(argv))

    with pytest.raises(SystemExit) as excinfo:
        pip_audit._cli.audit()
    assert excinfo.value.code == 2


def test_public_report_refuses_dry_run(monkeypatch, tmp_path):
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("public-lib\n")
    parser = pip_audit._cli._parser()
    argv = [
        "--public-report",
        str(tmp_path / "public.json"),
        "--public-allowlist",
        str(allowlist),
        "--dry-run",
        "--progress-spinner",
        "off",
    ]
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(argv))

    with pytest.raises(SystemExit) as excinfo:
        pip_audit._cli.audit()
    assert excinfo.value.code == 2
    assert not (tmp_path / "public.json").exists()
