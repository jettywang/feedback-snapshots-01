"""Cross-checks that do not use the lab's own RSA verifier.

OpenSSL is used as an independent implementation for:
  * RSA signature verification over the exact bytes the lab claims are covered;
  * X.509 chain verification against a supplied trust anchor;
  * digest recomputation over assembled coverage bytes.

If OpenSSL is unavailable every function returns ``available: False`` rather
than silently passing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from Crypto.PublicKey import RSA

OPENSSL = shutil.which("openssl")


def available() -> bool:
    return OPENSSL is not None


def _run(args: list[str], cwd: str) -> dict:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30, check=False)
    return {
        "command": " ".join(Path(args[0]).name if index == 0 else arg for index, arg in enumerate(args)),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def openssl_rsa_verify(modulus: int, exponent: int, signature: bytes, data: bytes, hash_name: str) -> dict:
    if not available():
        return {"available": False, "ok": None}
    key = RSA.construct((modulus, exponent))
    with tempfile.TemporaryDirectory() as tmp:
        public_path = os.path.join(tmp, "public.pem")
        signature_path = os.path.join(tmp, "signature.bin")
        data_path = os.path.join(tmp, "covered.bin")
        Path(public_path).write_text(key.export_key().decode("ascii"), encoding="ascii")
        Path(signature_path).write_bytes(signature)
        Path(data_path).write_bytes(data)
        result = _run(
            [OPENSSL, "dgst", f"-{hash_name}", "-verify", public_path, "-signature", signature_path, data_path],
            tmp,
        )
        return {
            "available": True,
            "ok": result["returncode"] == 0 and "Verified OK" in result["stdout"],
            "detail": result["stdout"] or result["stderr"],
        }


def openssl_digest(data: bytes, hash_name: str) -> dict:
    if not available():
        return {"available": False, "hex": None}
    with tempfile.TemporaryDirectory() as tmp:
        data_path = os.path.join(tmp, "covered.bin")
        Path(data_path).write_bytes(data)
        result = _run([OPENSSL, "dgst", f"-{hash_name}", data_path], tmp)
        hex_value = result["stdout"].split("=")[-1].strip()
        return {"available": True, "hex": hex_value, "error": None if result["returncode"] == 0 else result["stderr"]}


def openssl_certificate_chain(leaf_der: bytes, root_der: bytes) -> dict:
    if not available():
        return {"available": False, "ok": None}
    with tempfile.TemporaryDirectory() as tmp:
        leaf_der_path = os.path.join(tmp, "leaf.der")
        root_der_path = os.path.join(tmp, "root.der")
        leaf_pem_path = os.path.join(tmp, "leaf.pem")
        root_pem_path = os.path.join(tmp, "root.pem")
        Path(leaf_der_path).write_bytes(leaf_der)
        Path(root_der_path).write_bytes(root_der)
        for der_path, pem_path in ((leaf_der_path, leaf_pem_path), (root_der_path, root_pem_path)):
            conversion = _run([OPENSSL, "x509", "-inform", "DER", "-in", der_path, "-out", pem_path], tmp)
            if conversion["returncode"] != 0:
                return {"available": True, "ok": False, "error": conversion["stderr"]}
        result = _run([OPENSSL, "verify", "-CAfile", root_pem_path, leaf_pem_path], tmp)
        return {
            "available": True,
            "ok": result["returncode"] == 0,
            "detail": (result["stdout"] + "\n" + result["stderr"]).strip(),
        }
