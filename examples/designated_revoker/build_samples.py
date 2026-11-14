#!/usr/bin/env python3
"""Build local, offline OpenPGP designated-revoker revocation samples.

Everything here is generated in this process and written under ``samples/``.
No key or certificate is ever fetched from a network: the only revoker public
keys the verifier sees are the ones produced locally and passed explicitly.

Three families are produced, all evaluated at one *fixed verification moment*
(the frozen timestamp ``AT``) so that the exact authorization relied upon is
deterministic:

  1. primary-key self-revocation,
  2. legitimate designated-revoker revocation,
  3. over-reaching revocations (unhashed-only claim, foreign-key claim,
     wrong target, unknown signer, tampered signature).

Run with the repository's virtualenv::

    .venv/bin/python examples/designated_revoker/build_samples.py
"""
import copy
import json
import os
from datetime import timedelta

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import EllipticCurveOID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationKeyClass
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.packet.fields import MPI

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "samples")

# A single frozen verification moment shared by every sample. It is anchored
# to the primary key's creation time so the run is independent of wall clock.
AT_OFFSET = timedelta(days=30)


def make_key(name):
    key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    uid = PGPUID.new(name, email=name.lower().replace(" ", ".") + "@example.invalid")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    return key


def write(name, armored):
    path = os.path.join(OUT, name)
    with open(path, "w") as handle:
        handle.write(str(armored))
    return path


def move_revocation_key_to_unhashed(signature, revoker):
    """Return ``signature`` with its Revocation Key only in the unhashed area.

    The signed (hashed) region is left otherwise intact, so the signature stays
    cryptographically valid; only the authorization claim is downgraded to a
    region that is not covered by the signature.
    """
    subpackets = signature._signature.subpackets
    for key in [k for k in list(subpackets._hashed_sp.keys()) if k[0] == "RevocationKey"]:
        del subpackets._hashed_sp[key]
    subpackets.addnew(
        "RevocationKey",
        hashed=False,
        algorithm=revoker.key_algorithm,
        fingerprint=revoker.fingerprint,
        keyclass=RevocationKeyClass.Normal,
    )
    return signature


def tamper(signature):
    """Flip a few bits of a signature MPI, breaking cryptographic validity."""
    damaged = copy.deepcopy(signature)
    mpi = damaged._signature.signature
    mpi.r = MPI(int(mpi.r) ^ (1 << 3))
    damaged._signature.update_hlen()
    return damaged


def main():
    os.makedirs(OUT, exist_ok=True)
    report = {"fixed_verification_moment": None, "samples": []}

    primary = make_key("Primary Key")
    designated = make_key("Designated Revoker")
    intruder = make_key("Intruder Revoker")
    foreign_primary = make_key("Foreign Primary")
    victim = make_key("Victim Key")

    at = primary.created + AT_OFFSET
    report["fixed_verification_moment"] = at.isoformat()

    # The primary designates the revoker with a *hashed* Revocation Key.
    designation = primary.revoker(designated)
    primary |= designation
    write("primary.pub.asc", primary.pubkey)
    write("designated_revoker.pub.asc", designated.pubkey)
    write("intruder_revoker.pub.asc", intruder.pubkey)
    write("foreign_primary.pub.asc", foreign_primary.pubkey)
    write("victim.pub.asc", victim.pubkey)

    def record(label, target, signature, candidates, note, authorization_basis):
        result = target.pubkey.verify_revocation(signature, [c.pubkey for c in candidates], at=at)
        sig_name = label.lower().replace(" ", "_").replace("/", "_") + ".sig.asc"
        write(sig_name, signature)
        entry = {
            "label": label,
            "signature_file": sig_name,
            "status": result.status.name,
            "is_revoked": result.is_revoked,
            "missing_authorization": result.missing_authorization,
            "authorization_relied_upon": authorization_basis,
            "note": note,
        }
        report["samples"].append(entry)
        print("{:<34} {:<26} revoked={!s:<5} missing_auth={!s}".format(
            label, result.status.name, result.is_revoked, result.missing_authorization))
        return result

    # 1. primary key self-revocation ----------------------------------------
    record(
        "self revocation",
        primary,
        primary.revoke(primary),
        [primary],
        "The primary key signs its own 0x20 revocation; no Revocation Key subpacket is needed.",
        "target's own primary key (self-signature)",
    )

    # 2. legitimate designated-revoker revocation ---------------------------
    record(
        "designated revoker revocation",
        primary,
        designated.revoke(primary),
        [designated],
        "Hashed Revocation Key on the primary's direct-key self-signature matches "
        "the revoker fingerprint and algorithm.",
        "hashed Revocation Key subpacket on primary self-signature",
    )

    # 3a. authorization only in the unhashed area ---------------------------
    unhashed_primary = make_key("Unhashed Target")
    unhashed_revoker = make_key("Unhashed Revoker")
    weak = unhashed_primary.revoker(unhashed_revoker)
    move_revocation_key_to_unhashed(weak, unhashed_revoker)
    unhashed_primary |= weak
    write("unhashed_target.pub.asc", unhashed_primary.pubkey)
    write("unhashed_revoker.pub.asc", unhashed_revoker.pubkey)
    record(
        "unhashed-only authorization",
        unhashed_primary,
        unhashed_revoker.revoke(unhashed_primary),
        [unhashed_revoker],
        "The Revocation Key claim sits in the unhashed region, so it is not bound "
        "by the self-signature and cannot authorize the revoker.",
        "none (unhashed claim ignored)",
    )

    # 3b. authorization granted by a different primary key ------------------
    # A clean target that carries ONLY a Revocation Key signed by a different
    # primary. Its own self-signatures never designate the revoker.
    foreign_target = make_key("Foreign Auth Target")
    foreign_target |= foreign_primary.revoker(designated)
    write("foreign_target.pub.asc", foreign_target.pubkey)
    record(
        "foreign-key authorization",
        foreign_target,
        designated.revoke(foreign_target),
        [designated, foreign_primary],
        "The matching Revocation Key is carried by a self-signature of another primary "
        "key, not by the target primary, so it cannot revoke this target.",
        "none (authorization belongs to foreign primary)",
    )

    # 3c. signature valid but for a different target ------------------------
    record(
        "wrong target",
        primary,
        designated.revoke(victim),
        [designated, victim],
        "The revoker is authorized on the primary, but this signature is computed over "
        "a different key; plain signature validity does not make this target revoked.",
        "hashed Revocation Key present, but signature target mismatch",
    )

    # 3d. signer not supplied offline ---------------------------------------
    record(
        "unknown signer",
        primary,
        designated.revoke(primary),
        [intruder],
        "No supplied candidate matches the signature issuer, so the path cannot be "
        "completed offline; distinct from a bad signature.",
        "not evaluable (issuer key absent)",
    )

    # 3e. cryptographically invalid signature -------------------------------
    record(
        "tampered signature",
        primary,
        tamper(designated.revoke(primary)),
        [designated],
        "Authorization is present, but the signature MPI was corrupted and no longer "
        "verifies over the target.",
        "hashed Revocation Key present, signature invalid",
    )

    with open(os.path.join(OUT, "report.json"), "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("\nwrote report and armored blocks to", OUT)


if __name__ == "__main__":
    main()
