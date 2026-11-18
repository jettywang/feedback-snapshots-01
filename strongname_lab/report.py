"""Build the machine-readable report and the human-readable summary."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from . import external, fixtures, verify


def _covered_blob(image: bytes, ranges: list[dict]) -> bytes:
    return b"".join(image[item["start"]:item["end"]] for item in ranges)


def analyse(path: Path, anchors: list[dict] | None = None) -> dict:
    image = path.read_bytes()
    record = {
        "file": str(path),
        "sha256": hashlib.sha256(image).hexdigest(),
        "size": len(image),
        "executed": False,
    }
    try:
        sn = verify.strong_name_check(image)
    except Exception as exc:  # noqa: BLE001 - report parse failures instead of aborting
        record["strong_name"] = {"error": f"{type(exc).__name__}: {exc}"}
    else:
        covered = _covered_blob(image, sn["covered_ranges"])
        hash_name = sn["identity"].get("hash_algorithm") or "sha1"
        if sn["checks"].get("signature_nonzero"):
            signature = image[sn["cli"]["signature_file_offset"]:sn["cli"]["signature_file_offset"] + sn["cli"]["strong_name_size"]]
            from . import crypto

            parsed = crypto.parse_public_key_blob(_public_key_blob(image, sn))
            external_result = external.openssl_rsa_verify(
                parsed["modulus"], parsed["exponent"], signature[::-1], covered, hash_name,
            )
        else:
            external_result = {"available": external.available(), "ok": None, "detail": "no signature to verify"}
        sn["external"] = {
            "covered_bytes": len(covered),
            "hash_algorithm": hash_name,
            "python_digest": hashlib.new(hash_name, covered).hexdigest(),
            "openssl_digest": external.openssl_digest(covered, hash_name)["hex"],
            "openssl_signature": external_result,
        }
        record["strong_name"] = sn
    try:
        au = verify.authenticode_check(image, anchors=anchors or [])
    except Exception as exc:  # noqa: BLE001
        record["authenticode"] = {"error": f"{type(exc).__name__}: {exc}"}
    else:
        if au.get("covered_ranges") and au.get("signed_content_digest"):
            covered = _covered_blob(image, au["covered_ranges"])
            au["external"] = {
                "covered_bytes": len(covered),
                "covered_sha256": hashlib.sha256(covered).hexdigest(),
                "openssl_digest": external.openssl_digest(covered, "sha256")["hex"],
            }
            try:
                entries = verify.parse_win_certificates(image)
                pkcs7 = verify.parse_pkcs7(entries[0]["data"])
                signer = pkcs7["signer_infos"][0]
                leaf = next(cert for cert in pkcs7["certificates"] if cert["serial"] == signer["serial"])
                au["external"]["openssl_signed_attrs"] = external.openssl_rsa_verify(
                    leaf["modulus"], leaf["exponent"], signer["signature"],
                    signer["signed_attributes_raw"], "sha256",
                )
                if len(pkcs7["certificates"]) > 1:
                    root = pkcs7["certificates"][-1]
                    au["external"]["openssl_chain"] = external.openssl_certificate_chain(leaf["raw"], root["raw"])
            except Exception as exc:  # noqa: BLE001
                au["external"]["error"] = f"{type(exc).__name__}: {exc}"
        record["authenticode"] = au
    return record


def _public_key_blob(image: bytes, sn: dict) -> bytes:
    info = verify.parse_managed(image)
    return info["public_key"]


def _summary_sn(sn: dict) -> str:
    if "error" in sn:
        return f"解析失败: {sn['error']}"
    checks = sn["checks"]
    pieces = [
        f"token={sn['identity']['public_key_token'] or '-'}",
        f"name={sn['identity']['name']} {sn['identity']['version']}",
        f"flag={sn['cli']['strong_name_signed_flag']}",
        f"slot={sn['cli']['strong_name_size']}B@{sn['cli']['signature_file_offset']}",
        f"rsa={'valid' if checks.get('rsa_signature_valid') else 'invalid'}",
    ]
    if checks.get("rsa_verification_detail"):
        pieces.append(f"detail={checks['rsa_verification_detail']}")
    return " | ".join(pieces)


def _summary_auth(au: dict) -> str:
    if "error" in au:
        return f"解析失败: {au['error']}"
    if not au.get("certificate_entries"):
        return "无 WIN_CERTIFICATE"
    return " | ".join([
        f"digest_match={au.get('digest_matches')}",
        f"signer_ok={au.get('signer_signature_valid')}",
        f"attrs_digest={au.get('message_digest_attribute_matches')}",
        f"chain={(au.get('certificate_chain') or {}).get('trusted')}",
        f"verdict={au.get('verdict', {}).get('signature')}/{au.get('verdict', {}).get('trust')}",
    ])


def build(fixture_dir: Path, output_dir: Path) -> dict:
    fixture_dir = Path(fixture_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
    roots = fixtures._root_and_leaf("signer")
    anchor = verify.parse_certificate(roots[0])
    report = {
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "fixture_dir": str(fixture_dir),
        "trust_anchor": {
            "subject": verify._name_to_text(anchor["subject_raw"]),
            "serial": anchor["serial"],
            "sha256": hashlib.sha256(anchor["raw"]).hexdigest(),
            "note": "Anchor supplied explicitly to the checker; not the host trust store.",
        },
        "cases": {},
    }
    for name, item in manifest.items():
        path = fixture_dir / item["path"]
        record = analyse(path, anchors=[anchor])
        record["notes"] = item["notes"]
        report["cases"][name] = record
        print(f"{name:22} {_summary_sn(record.get('strong_name', {}))}")
        print(f"{'':22} {_summary_auth(record.get('authenticode', {}))}")
    (output_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    return report
