#!/usr/bin/env python3
"""Interleaved two-transaction CMP round trip over raw DER.

This is the executable evidence requested for the offline transaction
validator.  It:

1. asks the local OpenSSL CLI to mint a real CA plus four end-entity
   certificates (cryptographically valid, verifiable with ``openssl verify``);
2. runs two independent initialization transactions for two different clients
   on one validator, interleaving their messages;
3. injects a cryptologically valid certificate that legitimately belongs to
   transaction B into an ``ip`` addressed to transaction A;
4. proves the injection is rejected, no certificate from B is installed in A,
   and transaction A still completes normally afterwards;
5. writes every PKIMessage as a raw DER file and independently re-decodes each
   one from disk before validation (a true DER round trip).

Only the Python standard library, pyasn1/pyasn1-modules and the ``openssl``
command line are required.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

from pyasn1_modules import rfc4210

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cmp_transaction import CMPTransactionValidator, RejectReason, CertReqState
from cmp_transaction import builders


def run_openssl(args):
    subprocess.run(["openssl"] + args, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def mint_certificates(workdir):
    """Return (ca_cert_der, {label: ee_cert_der}) via the OpenSSL CLI."""
    ca_key = os.path.join(workdir, "ca.key")
    ca_cert_pem = os.path.join(workdir, "ca.pem")
    run_openssl(["genpkey", "-algorithm", "RSA", "-out", ca_key])
    run_openssl(["req", "-new", "-x509", "-key", ca_key, "-sha256",
                 "-days", "3650", "-subj", "/CN=CMP Demo CA",
                 "-out", ca_cert_pem])
    with open(ca_cert_pem, "rb") as handle:
        ca_pem = handle.read()
    ca_der = subprocess.run(
        ["openssl", "x509", "-in", ca_cert_pem, "-outform", "DER"],
        check=True, capture_output=True).stdout

    labels = ("ee-a1", "ee-a2", "ee-b1", "ee-b2")
    certs = {}
    for label in labels:
        key = os.path.join(workdir, label + ".key")
        csr = os.path.join(workdir, label + ".csr")
        pem = os.path.join(workdir, label + ".pem")
        run_openssl(["genpkey", "-algorithm", "RSA", "-out", key])
        run_openssl(["req", "-new", "-key", key, "-subj",
                     "/CN=" + label, "-out", csr])
        run_openssl(["x509", "-req", "-in", csr, "-CA", ca_cert_pem,
                     "-CAkey", ca_key, "-CAcreateserial", "-sha256",
                     "-days", "365", "-out", pem])
        der = subprocess.run(
            ["openssl", "x509", "-in", pem, "-outform", "DER"],
            check=True, capture_output=True).stdout
        # Independently prove the certificate is cryptographically valid.
        verify = subprocess.run(
            ["openssl", "verify", "-CAfile", ca_cert_pem, pem],
            capture_output=True, text=True)
        if verify.returncode != 0:
            raise RuntimeError("openssl verify failed for %s: %s"
                               % (label, verify.stderr))
        certs[label] = der
    return ca_der, ca_cert_pem, certs


def load_certificate(cert_der):
    cert, rest = der_decoder.decode(cert_der, asn1Spec=rfc4210.CMPCertificate())
    if rest:
        raise ValueError("trailing bytes in certificate DER")
    return cert


def sha256_der(cert_der):
    return hashlib.sha256(cert_der).digest()


class Transcript:
    def __init__(self, outdir):
        self.outdir = outdir
        self.lines = []
        self.counter = 0

    def emit(self, message_der, name, result, note=""):
        self.counter += 1
        path = os.path.join(self.outdir, "%02d-%s.der" % (self.counter, name))
        with open(path, "wb") as handle:
            handle.write(message_der)
        # Independent DER round trip: re-decode exactly what was written.
        with open(path, "rb") as handle:
            disk_der = handle.read()
        decoded, rest = der_decoder.decode(
            disk_der, asn1Spec=rfc4210.PKIMessage())
        if rest or der_encoder.encode(decoded) != disk_der:
            raise AssertionError("DER round trip mismatch on %s" % path)
        verdict = "ACCEPT" if result.accepted else (
            "REJECT " + result.reason.value)
        line = "%02d %-28s %-7d %-24s %s" % (
            self.counter, name, len(disk_der), verdict, note)
        self.lines.append(line)
        print(line)


def main():
    outdir = os.environ.get("CMP_DEMO_DIR")
    created_tmp = outdir is None
    if created_tmp:
        outdir = tempfile.mkdtemp(prefix="cmp-demo-")
    os.makedirs(outdir, exist_ok=True)
    print("Writing DER artifacts to", outdir)

    ca_der, ca_cert_pem, raw_certs = mint_certificates(outdir)
    certs = {label: load_certificate(der) for label, der in raw_certs.items()}
    print("Minted CA + 4 EE certificates; all pass `openssl verify`\n")

    t0 = datetime(2026, 11, 15, 9, 0, tzinfo=timezone.utc)
    clock = [t0]

    def now():
        return clock[0]

    validator = CMPTransactionValidator(clock=now)
    transcript = Transcript(outdir)

    ca = builders.rfc822_name("ca@demo.test")
    ee_a = builders.rfc822_name("alice@demo.test")
    ee_b = builders.rfc822_name("bob@demo.test")
    txn_a, txn_b = b"transaction-alice", b"transaction-bob"

    def feed(message_der, name, note=""):
        result = validator.validate(message_der)
        transcript.emit(message_der, name, result, note)
        return result

    # --- both clients open a two-certificate initialization transaction ---
    # Each ir binds certReqId -> requested subject Name and public key so an
    # issued certificate can be tied back to the request that asked for it.
    a_specs = [
        (0, builders.cert_subject(certs["ee-a1"]),
         builders.cert_spki(certs["ee-a1"])),
        (1, builders.cert_subject(certs["ee-a2"]),
         builders.cert_spki(certs["ee-a2"])),
    ]
    b_specs = [
        (0, builders.cert_subject(certs["ee-b1"]),
         builders.cert_spki(certs["ee-b1"])),
        (1, builders.cert_subject(certs["ee-b2"]),
         builders.cert_spki(certs["ee-b2"])),
    ]
    feed(builders.ir(a_specs, ee_a, ca, txn_a, b"a1", t0), "A-ir")
    feed(builders.ir(b_specs, ee_b, ca, txn_b, b"b1", t0), "B-ir")

    # --- B gets its first response while A is still open (interleaving) ----
    feed(builders.ip(
        [(0, 0, certs["ee-b1"]), (1, 3, None)],
        ca, ee_b, txn_b, b"b2", b"b1", t0), "B-ip-waiting")

    # ATTACK: a cryptographically valid certificate from B (ee-b1), wrapped in
    # an otherwise well-formed ip addressed to A.  Outer protection would
    # verify (same CA key), but the message does not belong to transaction A.
    attack = builders.ip(
        [(0, 0, certs["ee-b1"]), (1, 3, None)],
        ca, ee_a, txn_a, b"a2", b"a1", t0)
    attack_result = feed(
        attack, "A-ip-FOREIGN-cert",
        "valid cert ee-b1 injected into Alice's transaction")
    assert not attack_result.accepted
    assert attack_result.reason is RejectReason.CERT_DOES_NOT_MATCH_REQUEST

    record_a = validator.get_transaction(
        der_encoder.encode(ee_a), txn_a)
    record_b = validator.get_transaction(
        der_encoder.encode(ee_b), txn_b)
    assert record_a.installed_certs == {}, "foreign cert must not install"
    assert all(cert.state is CertReqState.REQUESTED
               for cert in record_a.certs.values()), \
        "rejected ip must leave A's certReqIds untouched"
    print("\n[+] foreign response rejected (%s); A unchanged, no cert installed\n"
          % attack_result.reason.value)

    # --- A still completes normally: real A certificates, polling, etc. ---
    feed(builders.ip(
        [(0, 0, certs["ee-a1"]), (1, 3, None)],
        ca, ee_a, txn_a, b"a2", b"a1", t0), "A-ip-waiting")

    clock[0] += timedelta(seconds=30)
    feed(builders.poll_req(
        [1], ee_a, ca, txn_a, b"a3", b"a2", clock[0]), "A-pollReq")
    feed(builders.poll_rep(
        [(1, 60)], ca, ee_a, txn_a, b"a4", b"a3", clock[0]), "A-pollRep")

    clock[0] += timedelta(seconds=60)
    feed(builders.poll_req(
        [1], ee_a, ca, txn_a, b"a5", b"a4", clock[0]), "A-pollReq-2")
    feed(builders.ip(
        [(1, 0, certs["ee-a2"])], ca, ee_a, txn_a,
        b"a6", b"a5", clock[0]), "A-ip-granted")

    feed(builders.cert_conf(
        [(0, sha256_der(raw_certs["ee-a1"])),
         (1, sha256_der(raw_certs["ee-a2"]))],
        ee_a, ca, txn_a, b"a7", b"a6", clock[0]), "A-certConf")
    feed(builders.pki_conf(
        ca, ee_a, txn_a, b"a8", b"a7", clock[0]), "A-pkiConf")

    # --- B also finishes, proving the two transactions stay independent ---
    clock[0] += timedelta(seconds=10)
    feed(builders.poll_req(
        [1], ee_b, ca, txn_b, b"b3", b"b2", clock[0]), "B-pollReq")
    feed(builders.ip(
        [(1, 0, certs["ee-b2"])], ca, ee_b, txn_b,
        b"b4", b"b3", clock[0]), "B-ip-granted")
    feed(builders.cert_conf(
        [(0, sha256_der(raw_certs["ee-b1"])),
         (1, sha256_der(raw_certs["ee-b2"]))],
        ee_b, ca, txn_b, b"b5", b"b4", clock[0]), "B-certConf")
    feed(builders.pki_conf(
        ca, ee_b, txn_b, b"b6", b"b5", clock[0]), "B-pkiConf")

    record_a = validator.get_transaction(
        der_encoder.encode(ee_a), txn_a)
    record_b = validator.get_transaction(
        der_encoder.encode(ee_b), txn_b)

    print("\n=== Final state ===")
    print("A phase:", record_a.phase.value,
          "installed certReqIds:", sorted(record_a.installed_certs))
    print("B phase:", record_b.phase.value,
          "installed certReqIds:", sorted(record_b.installed_certs))

    # Hard assertions for the security property.
    assert record_a.phase.value == "completed"
    assert record_b.phase.value == "completed"
    assert set(record_a.installed_certs) == {0, 1}
    assert set(record_b.installed_certs) == {0, 1}
    foreign_der = raw_certs["ee-b1"]
    assert foreign_der not in record_a.installed_certs.values()
    assert raw_certs["ee-a1"] in record_a.installed_certs.values()
    assert raw_certs["ee-b1"] in record_b.installed_certs.values()

    # The installed A certificates still verify against the real CA.
    for cert_req_id, cert_der in sorted(record_a.installed_certs.items()):
        pem_path = os.path.join(outdir, "A-installed-%d.pem" % cert_req_id)
        pem = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
            input=cert_der, check=True, capture_output=True).stdout
        with open(pem_path, "wb") as handle:
            handle.write(pem)
        verify = subprocess.run(
            ["openssl", "verify", "-CAfile", ca_cert_pem, pem_path],
            capture_output=True, text=True)
        assert verify.returncode == 0, verify.stderr
        print("openssl verify A certReqId %d: %s"
              % (cert_req_id, verify.stdout.strip()))

    print("\n[+] SECURITY PROPERTY HELD: a valid certificate belonging to "
          "transaction B")
    print("    was never installed in A, and A and B both completed.")
    if created_tmp:
        print("\nDER transcript directory:", outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
