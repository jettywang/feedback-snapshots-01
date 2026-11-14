"""报告脱敏、JSON 结构与 CLI 测试。"""

import json
import os
import subprocess
import sys

from nonce_audit.analyzer import analyze
from nonce_audit.models import parse_records
from nonce_audit.reporting import render_text, report_to_dict
from nonce_audit.sampler import build_demo_sample


def _report():
    payload, _ = build_demo_sample()
    return analyze(parse_records(payload)), payload


def test_secrets_redacted_by_default():
    report, _ = _report()
    data = report_to_dict(report)
    confirmed = data["confirmed"][0]
    assert confirmed["secrets"] == {
        "redacted": True,
        "private_key_d": None,
        "canonical_nonce_k": None,
    }


def test_reveal_secrets_includes_hex():
    report, _ = _report()
    data = report_to_dict(report, reveal_secrets=True)
    secrets = data["confirmed"][0]["secrets"]
    assert secrets["redacted"] is False
    assert int(secrets["private_key_d"], 16) > 0
    assert int(secrets["canonical_nonce_k"], 16) > 0


def test_text_report_mentions_evidence_and_reasons():
    report, _ = _report()
    text = render_text(report)
    assert "已确认 nonce 重用" in text
    assert "A1-reused-k" in text
    assert "cross_key_r_collision" in text
    assert "已隐藏" in text


def test_summary_counts_match_groups():
    report, _ = _report()
    data = report_to_dict(report)
    summary = data["summary"]
    assert summary["confirmed_nonce_reuse_groups"] == 1
    assert summary["invalid_signature_records"] == 2
    assert (
        summary["r_groups"]
        == len(data["confirmed"]) + len(data["unconfirmed_clues"])
    )


def test_cli_analyze_exit_codes(tmp_path):
    payload, _ = build_demo_sample()
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps(payload), encoding="utf-8")

    env = dict(os.environ)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = os.path.join(root, "src") + os.pathsep + root

    ok = subprocess.run(
        [sys.executable, "-m", "nonce_audit", "analyze", str(sample)],
        capture_output=True, text=True, env=env, cwd=root,
    )
    assert ok.returncode == 0
    assert "已确认 nonce 重用" in ok.stdout

    fail = subprocess.run(
        [sys.executable, "-m", "nonce_audit", "analyze", str(sample),
         "--fail-on-confirmed", "--format", "json"],
        capture_output=True, text=True, env=env, cwd=root,
    )
    assert fail.returncode == 2
    body = json.loads(fail.stdout)
    assert body["summary"]["confirmed_nonce_reuse_groups"] == 1


def test_cli_generate_demo_and_private_file(tmp_path):
    env = dict(os.environ)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = os.path.join(root, "src") + os.pathsep + root
    out = tmp_path / "demo.json"

    result = subprocess.run(
        [sys.executable, "-m", "nonce_audit", "generate-demo", str(out),
         "--emit-private"],
        capture_output=True, text=True, env=env, cwd=root,
    )
    assert result.returncode == 0
    assert out.exists()
    priv = tmp_path / "demo.json.priv.json"
    assert priv.exists()
    assert "private_scalars" in json.loads(priv.read_text())


def test_cli_bad_input_returns_usage_error(tmp_path):
    env = dict(os.environ)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = os.path.join(root, "src") + os.pathsep + root
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "nonce_audit", "analyze", str(bad)],
        capture_output=True, text=True, env=env, cwd=root,
    )
    assert result.returncode == 64
    assert "输入错误" in result.stderr


def test_cli_reads_stdin(tmp_path):
    import json as _json

    payload, _ = build_demo_sample()
    env = dict(os.environ)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = os.path.join(root, "src") + os.pathsep + root
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "nonce_audit",
            "analyze",
            "-",
            "--format",
            "json",
            "--fail-on-confirmed",
        ],
        input=_json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        cwd=root,
    )
    assert result.returncode == 2
    body = _json.loads(result.stdout)
    assert body["summary"]["total_records"] == len(payload["records"])


def test_mixed_curves_keep_r_groups_separate():
    from nonce_audit.curves import get_curve
    from tests.helpers import fresh_key, make_record

    p256 = get_curve("NIST256p")
    p384 = get_curve("NIST384p")
    sk256 = fresh_key(p256, 301)
    sk384 = fresh_key(p384, 302)
    recs = [
        make_record("c256-1", p256, sk256, b"a", k=424242),
        make_record("c256-2", p256, sk256, b"b", k=424242),
        make_record("c384-1", p384, sk384, b"c", k=424242),
        make_record("c384-2", p384, sk384, b"d", k=424242),
    ]
    report = analyze(recs)
    curves = {g.curve for g in report.confirmed_groups}
    assert curves == {"NIST256p", "NIST384p"}
    assert len(report.confirmed_groups) == 2
