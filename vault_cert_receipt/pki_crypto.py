"""基于 OpenSSL 命令行的本地 PKI 工具。

仅依赖 Python 标准库与系统 openssl，不引入 cryptography 等第三方包。
所有私钥只在本模块内部按需读写，不进入回执与证据对象。
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class OpenSslError(RuntimeError):
    """openssl 子进程执行失败。"""


def _run(args: list[str], stdin: str | None = None) -> str:
    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    proc = subprocess.run(
        [openssl, *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise OpenSslError(
            f"openssl {' '.join(args)} 失败 (rc={proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout


def _run_bytes(args: list[str], stdin: str | None = None) -> bytes:
    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    proc = subprocess.run(
        [openssl, *args],
        input=stdin.encode("utf-8") if stdin is not None else None,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise OpenSslError(
            f"openssl {' '.join(args)} 失败 (rc={proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


def gen_ec_key(key_path: Path) -> None:
    """生成 P-256 EC 私钥，文件权限 600。"""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    _run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_path)])
    key_path.chmod(0o600)


def self_signed_root(
    key_path: Path,
    cert_path: Path,
    subject_cn: str,
    *,
    days: int = 3650,
) -> None:
    """生成自签名根 CA 证书。"""
    ext = (
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    _run(
        [
            "req", "-new", "-x509", "-sha256", "-key", str(key_path),
            "-out", str(cert_path), "-days", str(days),
            "-subj", f"/CN={subject_cn}",
            "-extensions", "v3_ca",
            "-config", "-",
        ],
        stdin=f"[req]\ndistinguished_name=dn\nprompt=no\n[v3_ca]\n{ext}\n[dn]\n",
    )


def sign_intermediate(
    issuer_key: Path,
    issuer_cert: Path,
    subject_key: Path,
    out_cert: Path,
    subject_cn: str,
    *,
    days: int = 1825,
    pathlen: int = 0,
) -> None:
    """用根 CA 签发中间 CA（Vault 签发方）证书。"""
    csr_path = out_cert.with_suffix(".csr")
    _run(
        ["req", "-new", "-sha256", "-key", str(subject_key),
         "-out", str(csr_path), "-subj", f"/CN={subject_cn}"],
    )
    ext = (
        "basicConstraints=critical,CA:TRUE,pathlen:" + str(pathlen) + "\n"
        "keyUsage=critical,digitalSignature,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
    )
    ext_path = out_cert.with_suffix(".ext")
    ext_path.write_text(ext, encoding="utf-8")
    _run(
        [
            "x509", "-req", "-sha256", "-in", str(csr_path),
            "-CA", str(issuer_cert), "-CAkey", str(issuer_key),
            "-CAcreateserial", "-out", str(out_cert), "-days", str(days),
            "-extfile", str(ext_path),
        ]
    )
    csr_path.unlink(missing_ok=True)
    ext_path.unlink(missing_ok=True)


def _leaf_extfile(ext_path: Path, sans: list[str]) -> None:
    san_line = ",".join(f"DNS:{name}" for name in sans)
    ext_path.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
        f"subjectAltName={san_line}\n",
        encoding="utf-8",
    )


def issue_leaf(
    issuer_key: Path,
    issuer_cert: Path,
    leaf_key: Path,
    out_cert: Path,
    common_name: str,
    sans: list[str],
    *,
    days: int,
) -> None:
    """模拟 Vault PKI /issue：由中间 CA 签发终端服务证书。"""
    csr_path = out_cert.with_suffix(".csr")
    _run(
        ["req", "-new", "-sha256", "-key", str(leaf_key),
         "-out", str(csr_path), "-subj", f"/CN={common_name}"],
    )
    ext_path = out_cert.with_suffix(".ext")
    _leaf_extfile(ext_path, sans)
    _run(
        [
            "x509", "-req", "-sha256", "-in", str(csr_path),
            "-CA", str(issuer_cert), "-CAkey", str(issuer_key),
            "-CAcreateserial", "-out", str(out_cert), "-days", str(days),
            "-extfile", str(ext_path),
        ]
    )
    csr_path.unlink(missing_ok=True)
    ext_path.unlink(missing_ok=True)


def parse_cert(cert_pem: str) -> dict:
    """解析证书，返回用于核对的识别信息（不含私钥、不含 PEM 原文）。"""
    text = _run(["x509", "-noout", "-text", "-nameopt", "RFC2253"], stdin=cert_pem)
    subject = _run(["x509", "-noout", "-subject", "-nameopt", "RFC2253"],
                   stdin=cert_pem).strip()
    issuer = _run(["x509", "-noout", "-issuer", "-nameopt", "RFC2253"],
                  stdin=cert_pem).strip()
    serial = _run(["x509", "-noout", "-serial"], stdin=cert_pem).strip()
    dates = _run(["x509", "-noout", "-startdate", "-enddate"], stdin=cert_pem)
    fingerprint = _run(
        ["x509", "-noout", "-fingerprint", "-sha256"], stdin=cert_pem
    ).strip()
    sans = _extract_sans(text)
    not_before, not_after = _parse_dates(dates)
    return {
        "subject_dn": _strip_name_prefix(subject),
        "issuer_dn": _strip_name_prefix(issuer),
        "common_name": _extract_cn(subject),
        "sans": sans,
        "serial_number": serial.split("=", 1)[1].strip().lower(),
        "sha256_fingerprint": fingerprint.split("=", 1)[1].replace(":", "").lower(),
        "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lifetime_seconds": int((not_after - not_before).total_seconds()),
        "is_ca": "CA:TRUE" in text.replace(" ", ""),
    }


def _strip_name_prefix(name_line: str) -> str:
    line = name_line.strip()
    for prefix in ("subject=", "issuer="):
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return line


def _extract_cn(subject_line: str) -> str:
    line = subject_line
    for prefix in ("subject=", "issuer="):
        if line.startswith(prefix):
            line = line[len(prefix):]
    for part in line.split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "CN":
            return value
    raise OpenSslError(f"主题中缺少 CN: {subject_line}")


def _extract_sans(text: str) -> list[str]:
    sans: list[str] = []
    in_san = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("X509v3 Subject Alternative Name"):
            in_san = True
            continue
        if in_san:
            for item in line.split(","):
                item = item.strip()
                if item.startswith("DNS:"):
                    sans.append(item[4:])
            break
    return sorted(sans)


def _parse_openssl_date(value: str) -> datetime:
    value = value.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise OpenSslError(f"无法解析证书时间: {value}")


def _parse_dates(dates: str) -> tuple[datetime, datetime]:
    mapping: dict[str, datetime] = {}
    for line in dates.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        mapping[key.strip()] = _parse_openssl_date(value)
    return mapping["notBefore"], mapping["notAfter"]


def sha256_fingerprint(cert_pem: str) -> str:
    return parse_cert(cert_pem)["sha256_fingerprint"]


def public_key_sha256(cert_pem: str) -> str:
    """证书内嵌公钥的 SHA-256 指纹，作为公钥识别项。"""
    pub_pem = _run(["x509", "-pubkey", "-noout"], stdin=cert_pem)
    der = _run_bytes(["pkey", "-pubin", "-outform", "DER"], stdin=pub_pem)
    return hashlib.sha256(der).hexdigest()


def verify_chain(leaf_pem: str, untrusted_pem: str, root_pem: str) -> dict:
    """用 openssl verify 校验叶子->中间->根链，返回结构化结果。"""
    tmp_dir = Path(_mktemp_dir())
    try:
        leaf = tmp_dir / "leaf.pem"
        untrusted = tmp_dir / "chain.pem"
        root = tmp_dir / "root.pem"
        leaf.write_text(leaf_pem, encoding="utf-8")
        untrusted.write_text(untrusted_pem, encoding="utf-8")
        root.write_text(root_pem, encoding="utf-8")
        proc = subprocess.run(
            [
                shutil.which("openssl") or "/usr/bin/openssl", "verify",
                "-CAfile", str(root),
                "-untrusted", str(untrusted),
                str(leaf),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        output = (proc.stdout + proc.stderr).strip()
        return {
            "ok": proc.returncode == 0 and output.endswith(": OK"),
            "detail": output,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _mktemp_dir() -> str:
    import tempfile

    return tempfile.mkdtemp(prefix="vcr-verify-")


def _write_temp(content: bytes | str, suffix: str) -> Path:
    import tempfile

    mode = "wb" if isinstance(content, bytes) else "w"
    with tempfile.NamedTemporaryFile(mode=mode, suffix=suffix, delete=False) as fh:
        fh.write(content)
        return Path(fh.name)


def sign_bytes(key_path: Path, payload: bytes) -> str:
    """用 EC 私钥对字节做 ECDSA-with-SHA256 签名，返回 base64(DER)。"""
    import base64

    payload_path = _write_temp(payload, ".bin")
    try:
        sig_der = _run_bytes(
            ["dgst", "-sha256", "-binary", "-sign", str(key_path),
             str(payload_path)]
        )
        return base64.b64encode(sig_der).decode("ascii")
    finally:
        payload_path.unlink(missing_ok=True)


def verify_bytes(public_key_pem: str, payload: bytes,
                 signature_b64: str) -> bool:
    """用公钥 PEM 验证 ECDSA-SHA256 签名。"""
    import base64
    import tempfile

    key_path = _write_temp(public_key_pem, ".pem")
    payload_path = _write_temp(payload, ".bin")
    sig_path = Path(tempfile.mkstemp(suffix=".sig")[1])
    sig_path.write_bytes(base64.b64decode(signature_b64))
    try:
        proc = subprocess.run(
            [
                shutil.which("openssl") or "/usr/bin/openssl", "dgst",
                "-sha256", "-verify", str(key_path),
                "-signature", str(sig_path), str(payload_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0 and "OK" in proc.stdout
    finally:
        for path in (key_path, payload_path, sig_path):
            path.unlink(missing_ok=True)
