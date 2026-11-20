"""本地模拟的 hvac PKI 客户端。

真实环境用法（hvac 源码在本仓库内）：

    client = hvac.Client(url=vault_addr, token=vault_token)
    resp = client.secrets.pki.generate_certificate(
        name=role, common_name=cn,
        extra_params={"alt_names": ..., "ttl": "48h"},
        mount_point=mount,
    )
    data = resp["data"]

本模块提供同名方法 ``generate_certificate`` 与一致的响应结构，使申请/回执
代码无需区分真实 Vault 与本地模拟。响应中的 private_key 仅在内存中返回一次，
调用方落盘证据前必须剥离（见 issue_cert.py）。
"""
from __future__ import annotations

import re
from pathlib import Path

from . import pki_crypto

# Vault /issue 响应字段；private_key 仅内存传递，禁止写入证据目录
SENSITIVE_FIELDS = ("private_key", "private_key_type")

TTL_UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


def parse_ttl(ttl: str) -> int:
    """把 Vault 风格 TTL（如 48h、30m、7200s）换算为秒。"""
    match = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", ttl)
    if not match:
        raise ValueError(f"无法解析 TTL: {ttl!r}")
    value, unit = match.groups()
    return int(value) * TTL_UNIT_SECONDS[unit]


class MockPki:
    """对齐 hvac PKI 引擎的最小本地实现。"""

    def __init__(self, ca_dir: Path, key_dir: Path):
        self.ca_dir = ca_dir
        self.key_dir = key_dir
        self._serial_index: dict[str, Path] = {}

    def generate_certificate(
        self,
        name: str,
        common_name: str,
        extra_params: dict | None = None,
        mount_point: str = "pki",
        wrap_ttl: str | None = None,
    ) -> dict:
        params = dict(extra_params or {})
        ttl = params.get("ttl", "720h")
        ttl_seconds = parse_ttl(ttl)
        alt_names = [
            item.strip()
            for item in params.get("alt_names", "").split(",")
            if item.strip()
        ]
        sans = sorted(set([common_name, *alt_names]))

        issuer_key = self.ca_dir / "private" / "intermediate.key"
        issuer_cert = self.ca_dir / "certs" / "intermediate.crt"
        safe_cn = re.sub(r"[^A-Za-z0-9_.-]", "_", common_name)
        leaf_key = self.key_dir / f"{safe_cn}.key"
        leaf_cert = self.key_dir / f"{safe_cn}.crt"

        pki_crypto.gen_ec_key(leaf_key)
        # openssl -days 取整为天；TTL 核对以证书实际 notBefore/notAfter 为准
        days = max(1, round(ttl_seconds / 86400))
        pki_crypto.issue_leaf(
            issuer_key=issuer_key,
            issuer_cert=issuer_cert,
            leaf_key=leaf_key,
            out_cert=leaf_cert,
            common_name=common_name,
            sans=sans,
            days=days,
        )

        cert_pem = leaf_cert.read_text(encoding="utf-8")
        chain_pem = (self.ca_dir / "certs" / "intermediate.crt").read_text(
            encoding="utf-8"
        )
        root_pem = (self.ca_dir / "certs" / "root.crt").read_text(
            encoding="utf-8"
        )
        serial = pki_crypto.parse_cert(cert_pem)["serial_number"]
        self._serial_index[serial] = leaf_cert

        return {
            "request_id": f"mock-{mount_point}-{name}-{serial[:8]}",
            "lease_id": "",
            "renewable": False,
            "data": {
                "certificate": cert_pem,
                "issuing_ca": chain_pem,
                "ca_chain": [chain_pem, root_pem],
                "private_key": leaf_key.read_text(encoding="utf-8"),
                "private_key_type": "ec",
                "serial_number": serial,
            },
        }

    def read_certificate(self, serial: str,
                         mount_point: str = "pki") -> dict:
        cert_path = self._serial_index.get(serial.lower())
        if cert_path is None or not cert_path.exists():
            return {"data": {"certificate": None}}
        return {"data": {"certificate": cert_path.read_text(encoding="utf-8")}}


class MockHvacClient:
    """对齐 hvac.Client 的最小外壳，仅暴露 secrets.pki。"""

    def __init__(self, ca_dir: Path, key_dir: Path):
        self.secrets = _Secrets(MockPki(ca_dir, key_dir))


class _Secrets:
    def __init__(self, pki: MockPki):
        self.pki = pki
