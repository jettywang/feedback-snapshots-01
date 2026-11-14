"""
Tests for restricted OpenSSH user certificate issuance.
"""

from base64 import decodebytes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from pytest import raises

from paramiko import (
    CertificateAuthority,
    CertificateError,
    CertificatePolicy,
    CertificateRequest,
    Ed25519Key,
    Message,
    PublicBlob,
    RSAKey,
    SignedCertificate,
    issue_user_certificate,
)
from paramiko.cert import CERT_TYPE_USER, USER_CERT_TYPE

from ._util import _support

CA_FIXTURE = _support("ed25519-ca.key")
USER_FIXTURE = _support("ed25519.key")

FIXED_NOW = 1_800_000_000
# Comma-separated source networks, exactly as they appear in the wire format.
SOURCE_ADDRESS = "192.0.2.0/24,2001:db8::/32"


def _fixed_ca():
    return Ed25519Key.from_private_key_file(CA_FIXTURE)


def _fixed_user():
    return Ed25519Key.from_private_key_file(USER_FIXTURE)


def _policy(**overrides):
    kwargs = dict(
        principals=("alice", "bob"),
        max_validity=3600,
        extensions=(
            "permit-pty",
            "permit-user-rc",
            "permit-agent-forwarding",
        ),
        force_command="echo approved",
        source_addresses=("192.0.2.0/24", "2001:db8::/32"),
    )
    kwargs.update(overrides)
    return CertificatePolicy(**kwargs)


def _authority(pol=None, now=FIXED_NOW):
    return CertificateAuthority(
        _fixed_ca(), pol or _policy(), clock=lambda: now
    )


class _ParsedCertificate:
    """
    Independent parser for the OpenSSH user certificate wire format.

    Uses only the base64 line plus plain byte/int handling: it does not import
    any issuance-side helper, and it rebuilds the signed byte range itself so
    the tests can prove the signature covers exactly the fields that matter.
    """

    def __init__(self, line):
        fields = line.split()
        assert fields[0] == USER_CERT_TYPE
        self.blob = decodebytes(fields[1].encode())
        self._offset = 0

        self.key_type = self._text()
        self.nonce = self._binary()
        self.user_public = self._binary()
        self.serial = self._int64()
        self.cert_type = self._int32()
        self.key_id = self._text()
        self.principals = self._principals()
        self.valid_after = self._int64()
        self.valid_before = self._int64()
        self.critical_options = self._options()
        self.extensions = self._options()
        self.reserved = self._binary()
        self.signature_key = self._binary()
        self._signature_offset = self._offset
        self.signature = self._binary()
        assert self._offset == len(self.blob)

        # The signature covers the initial key type field through the
        # signature key field, inclusive.
        self.signed_bytes = self.blob[: self._signature_offset]

    def _take(self, count):
        chunk = self.blob[self._offset : self._offset + count]
        assert len(chunk) == count
        self._offset += count
        return chunk

    def _int32(self):
        return int.from_bytes(self._take(4), "big")

    def _int64(self):
        return int.from_bytes(self._take(8), "big")

    def _binary(self):
        return self._take(self._int32())

    def _text(self):
        return self._binary().decode()

    def _principals(self):
        blob = self._binary()
        result = []
        offset = 0
        while offset < len(blob):
            length = int.from_bytes(blob[offset : offset + 4], "big")
            offset += 4
            result.append(blob[offset : offset + length].decode())
            offset += length
        return tuple(result)

    def _options(self):
        blob = self._binary()
        result = []
        offset = 0
        while offset < len(blob):
            name_length = int.from_bytes(blob[offset : offset + 4], "big")
            offset += 4
            name = blob[offset : offset + name_length].decode()
            offset += name_length
            data_length = int.from_bytes(blob[offset : offset + 4], "big")
            offset += 4
            data = blob[offset : offset + data_length]
            offset += data_length
            result.append((name, data))
        return tuple(result)

    def critical_option(self, name):
        for option_name, data in self.critical_options:
            if option_name == name:
                # Double-check the inner encoding independently.
                length = int.from_bytes(data[:4], "big")
                assert length == len(data) - 4
                return data[4:]
        raise KeyError(name)

    def extension_names(self):
        # Extensions carry an empty data field; the name alone enables them.
        assert all(data == b"" for _, data in self.extensions)
        return tuple(name for name, _ in self.extensions)


def _verify_with_cryptography(parsed, ca_key=None):
    ca_key = ca_key or _fixed_ca()
    sig = Message(parsed.signature)
    algorithm = sig.get_text()
    signature = sig.get_binary()
    assert algorithm == "ssh-ed25519"
    ca_msg = Message(ca_key.asbytes())
    ca_msg.get_text()
    public = Ed25519PublicKey.from_public_bytes(ca_msg.get_binary())
    public.verify(signature, parsed.signed_bytes)


class CertificateAuthority_:
    class issuance:
        def issues_a_normal_user_certificate(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_after=FIXED_NOW + 60,
                valid_before=FIXED_NOW + 600,
                extensions=("permit-pty",),
                source_addresses=("192.0.2.0/25",),
                key_id="alice@example",
                serial=42,
            )
            assert isinstance(cert, SignedCertificate)

            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.key_type == USER_CERT_TYPE
            assert len(parsed.nonce) == 32
            user_msg = Message(_fixed_user().asbytes())
            user_msg.get_text()
            assert parsed.user_public == user_msg.get_binary()
            assert parsed.serial == 42
            assert parsed.cert_type == CERT_TYPE_USER
            assert parsed.key_id == "alice@example"
            assert parsed.principals == ("alice",)
            assert parsed.valid_after == FIXED_NOW + 60
            assert parsed.valid_before == FIXED_NOW + 600

            # critical options carry the correctly nested inner strings
            assert parsed.critical_option("force-command") == b"echo approved"
            assert parsed.critical_option("source-address") == b"192.0.2.0/25"
            assert [name for name, _ in parsed.critical_options] == [
                "force-command",
                "source-address",
            ]
            assert parsed.extension_names() == ("permit-pty",)

        def default_validity_is_policy_maximum(self):
            cert = _authority().issue(_fixed_user(), principals=("alice",))
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.valid_after == FIXED_NOW
            assert parsed.valid_before == FIXED_NOW + 3600
            assert parsed.serial == 0
            assert parsed.key_id == ""
            # policy restrictions apply even when the request omits them
            assert parsed.critical_option("force-command") == b"echo approved"
            assert parsed.critical_option("source-address") == (
                SOURCE_ADDRESS.encode()
            )
            # ...but unrequested extensions are not granted
            assert parsed.extension_names() == ()

        def accepts_a_CertificateRequest_object(self):
            request = CertificateRequest(
                principals=("bob",),
                valid_before=FIXED_NOW + 30,
                key_id="bob-key",
            )
            cert = _authority().issue(_fixed_user(), request)
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.principals == ("bob",)
            assert parsed.valid_before == FIXED_NOW + 30

        def accepts_explicit_critical_options_mapping(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_after=FIXED_NOW,
                valid_before=FIXED_NOW + 10,
                critical_options={"force-command": "echo approved"},
            )
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.critical_option("force-command") == b"echo approved"
            # Policy-wide source restriction still applied.
            assert parsed.critical_option("source-address") == (
                SOURCE_ADDRESS.encode()
            )

        def accepts_pairs_as_lists(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                critical_options=[["force-command", "echo approved"]],
            )
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.critical_option("force-command") == b"echo approved"

        def module_level_helper_issues_the_same_shape(self):
            cert = issue_user_certificate(
                _fixed_ca(),
                _fixed_user(),
                _policy(),
                principals=("alice",),
                valid_before=FIXED_NOW + 60,
                clock=lambda: FIXED_NOW,
            )
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.principals == ("alice",)
            _verify_with_cryptography(parsed)

    class independent_verification:
        def force_command_uses_nested_string_encoding(self):
            # PROTOCOL.certkeys says the critical-option data field itself
            # contains an SSH string; a bare command here would be misread.
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                critical_options={"force-command": "echo approved"},
            )
            parsed = _ParsedCertificate(cert.certificate)
            raw = dict(parsed.critical_options)["force-command"]
            assert raw == len(b"echo approved").to_bytes(4, "big") + (
                b"echo approved"
            )
            assert Message(raw).get_string() == b"echo approved"

        def source_address_uses_nested_string_encoding(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                source_addresses=("192.0.2.0/25", "2001:db8::/64"),
            )
            parsed = _ParsedCertificate(cert.certificate)
            raw = dict(parsed.critical_options)["source-address"]
            expected = b"192.0.2.0/25,2001:db8::/64"
            assert raw == len(expected).to_bytes(4, "big") + expected
            assert Message(raw).get_string() == expected

        def signature_covers_parsed_fields(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_after=FIXED_NOW,
                valid_before=FIXED_NOW + 300,
                extensions=("permit-pty", "permit-agent-forwarding"),
                source_addresses=("192.0.2.128/25",),
                key_id="independent",
                serial=7,
            )
            parsed = _ParsedCertificate(cert.certificate)
            _verify_with_cryptography(parsed)

            # The signature key field is the Ed25519 CA public key, not a
            # certificate.
            assert parsed.signature_key == _fixed_ca().asbytes()
            assert Message(parsed.signature_key).get_text() == "ssh-ed25519"

        def mutated_signed_field_breaks_the_signature(self):
            cert = _authority().issue(_fixed_user(), principals=("alice",))
            parsed = _ParsedCertificate(cert.certificate)
            _verify_with_cryptography(parsed)

            # Flip one byte within the principals portion of the signed range.
            tampered = bytearray(parsed.signed_bytes)
            needle = b"\x00\x00\x00\x05alice"
            offset = bytes(tampered).index(needle)
            tampered[offset + 5] = ord("b")
            ca_msg = Message(_fixed_ca().asbytes())
            ca_msg.get_text()
            public = Ed25519PublicKey.from_public_bytes(ca_msg.get_binary())
            sig = Message(parsed.signature).get_binary()
            with raises(InvalidSignature):
                public.verify(sig, bytes(tampered))

        def ssh_keygen_can_verify_the_signature(self, tmp_path):
            # Interop check: a real OpenSSH implementation must accept the
            # certificate and its signature, not just our own parser.
            from shutil import which
            from subprocess import run

            if which("ssh-keygen") is None:
                from pytest import skip

                skip("ssh-keygen not available")

            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_after=FIXED_NOW,
                valid_before=FIXED_NOW + 300,
                extensions=("permit-pty",),
                source_addresses=("192.0.2.0/24",),
                key_id="interop",
                serial=11,
            )
            path = tmp_path / "interop-cert.pub"
            path.write_text(cert.certificate + "\n")
            result = run(
                ["ssh-keygen", "-L", "-f", str(path)],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr
            output = result.stdout
            assert "Type: ssh-ed25519-cert-v01@openssh.com user" in output
            assert "Key ID: \"interop\"" in output
            assert "Serial: 11" in output
            assert "force-command echo approved" in output
            assert "source-address 192.0.2.0/24" in output
            assert "permit-pty" in output

        def loads_via_existing_load_certificate(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_before=FIXED_NOW + 120,
                extensions=("permit-pty",),
            )
            key = _fixed_user()
            assert key.public_blob is None
            key.load_certificate(cert.to_string())
            assert key.public_blob is not None
            assert key.public_blob.key_type == USER_CERT_TYPE
            assert key.public_blob.key_blob == cert.blob
            # Round-tripping via the generic parser also works.
            assert PublicBlob.from_string(cert.certificate).key_blob == (
                cert.blob
            )
            # And the cert can be re-parsed as a generic PublicBlob, which is
            # how the client auth path obtains the public blob.
            blob = PublicBlob.from_message(Message(cert.blob))
            assert blob.key_type == USER_CERT_TYPE
            assert blob.key_blob == cert.blob
            # The key remains usable for signing after the cert is attached.
            signature = key.sign_ssh_data(b"challenge")
            signature.rewind()
            assert signature.get_text() == "ssh-ed25519"

        def can_be_loaded_directly_from_certificate_blob(self):
            cert = _authority().issue(_fixed_user(), principals=("alice",))
            key = Ed25519Key(data=cert.blob)
            assert key.public_blob.key_blob == cert.blob
            assert key.public_blob.key_type == USER_CERT_TYPE

        def parsed_loading_is_not_authorisation(self):
            # A syntactically valid, correctly signed certificate still
            # produces public_blob only; loading must not flag authentication.
            cert = _authority().issue(_fixed_user(), principals=("alice",))
            key = _fixed_user()
            key.load_certificate(cert.certificate)
            assert key.public_blob is not None
            assert not hasattr(key, "authenticated")
            audit = cert.audit
            assert "authorized" not in audit
            assert "authenticated" not in audit

    class narrowed_requests:
        def request_principals_must_be_a_subset(self):
            with raises(CertificateError):
                _authority().issue(_fixed_user(), principals=("mallory",))

        def empty_request_principals_are_rejected(self):
            # Crucially, empty must never become "all principals".
            with raises(CertificateError):
                _authority().issue(_fixed_user(), principals=())
            with raises(CertificateError):
                _authority().issue(_fixed_user(), principals=None)
            with raises(CertificateError):
                _authority().issue(_fixed_user())

        def empty_policy_principals_are_rejected(self):
            with raises(CertificateError):
                CertificatePolicy(principals=(), max_validity=60)

        def validity_cannot_exceed_the_policy_window(self):
            ca = _authority()
            user = _fixed_user()
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    valid_before=FIXED_NOW + 3601,
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    valid_after=FIXED_NOW - 1,
                    valid_before=FIXED_NOW + 60,
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    valid_after=FIXED_NOW + 60,
                    valid_before=FIXED_NOW + 60,
                )

        def extensions_cannot_exceed_the_policy_set(self):
            with raises(CertificateError):
                _authority().issue(
                    _fixed_user(),
                    principals=("alice",),
                    extensions=("permit-X11-forwarding",),
                )

        def unknown_or_unapproved_critical_options_are_rejected(self):
            ca = _authority()
            user = _fixed_user()
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    critical_options={"unknown-option": "x"},
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    force_command="rm -rf /",
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    source_addresses=("198.51.100.0/24",),
                )
            # No policy-wide force command means callers cannot add one.
            no_command = _authority(_policy(force_command=None))
            with raises(CertificateError):
                no_command.issue(
                    user,
                    principals=("alice",),
                    force_command="echo sneaky",
                )

        def explicitly_empty_critical_values_are_rejected(self):
            ca = _authority()
            user = _fixed_user()
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    critical_options={"force-command": ""},
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    critical_options={"source-address": ""},
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    critical_options={"force-command": None},
                )

        def duplicate_conflicting_options_are_rejected(self):
            ca = _authority()
            user = _fixed_user()
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    force_command="echo approved",
                    critical_options={"force-command": "echo approved"},
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    source_addresses=("192.0.2.0/25",),
                    critical_options={"source-address": "192.0.2.0/25"},
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice",),
                    critical_options=[
                        ("force-command", "echo approved"),
                        ("force-command", "echo approved"),
                    ],
                )
            with raises(CertificateError):
                ca.issue(
                    user,
                    principals=("alice", "alice"),
                )

    class role_separation:
        def issued_certificate_is_a_user_certificate(self):
            cert = _authority().issue(_fixed_user(), principals=("alice",))
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.cert_type == CERT_TYPE_USER
            assert parsed.key_type == USER_CERT_TYPE
            assert parsed.key_type != "ssh-ed25519"

        def ca_key_must_be_a_plain_ed25519_key(self):
            rsa = RSAKey.generate(1024)
            with raises(CertificateError):
                CertificateAuthority(rsa, _policy())

            # A cert-bearing CA is a chained CA, which OpenSSH does not allow.
            ca_with_cert = _fixed_ca()
            ca_with_cert.load_certificate(_support("ed25519.key-cert.pub"))
            with raises(CertificateError):
                CertificateAuthority(ca_with_cert, _policy())

        def user_key_must_be_a_plain_ed25519_key(self):
            ca = _authority()
            with raises(CertificateError):
                ca.issue(RSAKey.generate(1024), principals=("alice",))

            cert_user = _fixed_user()
            cert_user.load_certificate(_support("ed25519.key-cert.pub"))
            with raises(CertificateError):
                ca.issue(cert_user, principals=("alice",))

        def ca_and_user_must_be_distinct_keys(self):
            ca = _fixed_ca()
            with raises(CertificateError):
                _authority().issue(ca, principals=("alice",))

    class audit_output:
        def contains_only_public_fields(self):
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_before=FIXED_NOW + 120,
                extensions=("permit-pty",),
                key_id="audit",
                serial=9,
            )
            audit = cert.audit
            assert audit.certificate_type == "user"
            assert audit.certificate_type_id == CERT_TYPE_USER
            assert audit.key_id == "audit"
            assert audit.serial == 9
            assert audit.principals == ("alice",)
            assert audit.valid_after == FIXED_NOW
            assert audit.valid_before == FIXED_NOW + 120
            assert audit.validity_seconds == 120
            assert audit.extensions == ("permit-pty",)
            assert audit.critical_options == (
                "force-command",
                "source-address",
            )
            assert audit.force_command == "echo approved"
            assert audit.source_addresses == (
                "192.0.2.0/24",
                "2001:db8::/32",
            )
            assert audit.signature_algorithm == "ssh-ed25519"
            assert audit.ca_fingerprint == _fixed_ca().fingerprint

            # No CA private material anywhere in the output.
            serialised = repr(audit) + repr(cert) + cert.certificate
            assert "PRIVATE KEY" not in serialised
            assert "private" not in audit
            # The raw Ed25519 private seed is not recoverable from the public
            # certificate or its audit fields either.
            seed = bytes(_fixed_ca()._signing_key._signing_key)
            assert seed not in cert.blob
            assert seed not in cert.certificate.encode()
            assert seed not in repr(audit).encode()

        def mapping_output_has_only_certificate_and_audit(self):
            cert = _authority().issue(
                _fixed_user(), principals=("alice",), key_id="mapping"
            )
            output = cert.to_dict()
            assert set(output) == {"certificate", "audit"}
            assert output["certificate"] == cert.certificate
            assert output["audit"]["key_id"] == "mapping"
            assert "private" not in repr(output).lower()

        def output_is_reproducible_for_a_fixed_nonce(self, monkeypatch):
            fixed_nonce = b"\x01" * 32
            monkeypatch.setattr(
                "paramiko.cert.os.urandom", lambda _n: fixed_nonce
            )
            cert = _authority().issue(
                _fixed_user(),
                principals=("alice",),
                valid_before=FIXED_NOW + 60,
                key_id="stable",
                serial=1,
            )
            parsed = _ParsedCertificate(cert.certificate)
            assert parsed.nonce == fixed_nonce
            _verify_with_cryptography(parsed)
