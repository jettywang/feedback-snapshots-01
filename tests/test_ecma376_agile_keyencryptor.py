"""Agile keyEncryptor selection: password vs. certificate credentials.

Builds local Agile-encrypted files whose EncryptionInfo carries both a
password and a certificate keyEncryptor, and checks that the caller can
explicitly select the credential class (and certificate identity) instead of
relying on the first encryptedKey in the XML.
"""

import base64
import datetime
import io
import unittest
import zipfile
from hashlib import sha1

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.container.ecma376_encrypted import ECMA376Encrypted
from msoffcrypto.method.ecma376_agile import ECMA376Agile

PASSWORD = "Password1234_"

#: keep the password hash derivation cheap in tests
SPIN_COUNT = 100

_PASSWORD_URI = "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
_CERTIFICATE_URI = (
    "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate"
)


def _make_plaintext():
    buf = io.BytesIO()
    # NOTE: the payload must stay above the 4096-byte mini-stream cutoff of
    # the OLE container writer (ECMA376Encrypted).
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<document>{}</document>".format("x" * 6000))
    return buf.getvalue()


PLAINTEXT = _make_plaintext()


def _make_certificate(common_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_id = base64.b64encode(
        sha1(cert.public_bytes(serialization.Encoding.DER)).digest()
    ).decode("ascii")
    return key, cert, cert_id


def _enc64(b):
    return base64.b64encode(b).decode("ascii")


def _password_key_encryptor_xml(info, salt_value=None, cipher_algorithm="AES"):
    ek = info.encryptedKey
    salt = ek.saltValue if salt_value is None else salt_value
    return (
        '<keyEncryptor uri="{}">'
        '<p:encryptedKey spinCount="{spin}" saltSize="{ek.saltSize}" blockSize="{ek.blockSize}"'
        ' keyBits="{ek.keyBits}" hashSize="{ek.hashSize}" cipherAlgorithm="{cipher}"'
        ' cipherChaining="ChainingModeCBC" hashAlgorithm="{ek.hashName}"'
        ' saltValue="{salt}" encryptedVerifierHashInput="{vhi}"'
        ' encryptedVerifierHashValue="{vhv}" encryptedKeyValue="{kv}" />'
        "</keyEncryptor>"
    ).format(
        _PASSWORD_URI,
        spin=info.spinCount,
        ek=ek,
        cipher=cipher_algorithm,
        salt=_enc64(salt),
        vhi=_enc64(info.encryptedVerifierHashInput),
        vhv=_enc64(info.encryptedVerifierHashValue),
        kv=_enc64(info.encryptedKeyValue),
    )


def _certificate_key_encryptor_xml(cert, cert_id, secret_key):
    encrypted_key_value = cert.public_key().encrypt(secret_key, padding.PKCS1v15())
    return (
        '<keyEncryptor uri="{}">'
        '<c:encryptedKey certId="{}" encryptedKeyValue="{}" />'
        "</keyEncryptor>"
    ).format(_CERTIFICATE_URI, cert_id, _enc64(encrypted_key_value))


def _descriptor_xml(info, key_encryptors_xml):
    kd = info.keyData
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption"
            xmlns:p="{p_uri}" xmlns:c="{c_uri}">
  <keyData saltSize="{kd.saltSize}" blockSize="{kd.blockSize}" keyBits="{kd.keyBits}" hashSize="{kd.hashSize}"
           cipherAlgorithm="{kd.cipherName}" cipherChaining="ChainingModeCBC" hashAlgorithm="{kd.hashName}"
           saltValue="{kd_salt}" />
  <dataIntegrity encryptedHmacKey="{hmac_key}" encryptedHmacValue="{hmac_value}" />
  <keyEncryptors>
    {key_encryptors}
  </keyEncryptors>
</encryption>
""".format(
        p_uri=_PASSWORD_URI,
        c_uri=_CERTIFICATE_URI,
        kd=kd,
        kd_salt=_enc64(kd.saltValue),
        hmac_key=_enc64(info.encryptedHmacKey),
        hmac_value=_enc64(info.encryptedHmacValue),
        key_encryptors="\n    ".join(key_encryptors_xml),
    )


def _build_encrypted_file(password, extra_key_encryptors=(), certificate_first=False):
    """Return (file_like, secret_key, certs) for a fresh Agile-encrypted file.

    ``extra_key_encryptors`` is a list of (key, cert, cert_id) tuples whose
    certificate keyEncryptors are added alongside the password one.
    """
    info, secret_key = ECMA376Agile.generate_encryption_parameters(
        password, spin_count=SPIN_COUNT
    )
    encrypted_data = ECMA376Agile.encrypt_payload(
        io.BytesIO(PLAINTEXT), info.encryptedKey, secret_key, info.keyData.saltValue
    )
    info.encryptedHmacKey, info.encryptedHmacValue = (
        ECMA376Agile.generate_integrity_parameter(
            encrypted_data, info.keyData, secret_key, info.keyData.saltValue
        )
    )

    password_xml = _password_key_encryptor_xml(info)
    cert_xmls = [
        _certificate_key_encryptor_xml(cert, cert_id, secret_key)
        for _, cert, cert_id in extra_key_encryptors
    ]
    if certificate_first:
        key_encryptors = cert_xmls + [password_xml]
    else:
        key_encryptors = [password_xml] + cert_xmls

    xml = _descriptor_xml(info, key_encryptors)
    encryption_info = info.getEncryptionDescriptorHeader() + xml.encode("UTF-8")

    obuf = io.BytesIO()
    ECMA376Encrypted(encrypted_data, encryption_info).write_to(obuf)
    obuf.seek(0)
    return obuf, secret_key


def _pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _decrypt_with(buf, **load_key_kwargs):
    buf.seek(0)
    office_file = OfficeFile(buf)
    office_file.load_key(**load_key_kwargs)
    out = io.BytesIO()
    office_file.decrypt(out, verify_integrity=True)
    return out.getvalue()


def _assert_credentials_rejected(test_case, buf, **load_key_kwargs):
    """Assert the given credentials cannot produce a success conclusion.

    Depending on the cryptography version, a mismatched private key either
    fails the RSA unwrap (InvalidKeyError at load_key) or yields a garbage
    key (implicit rejection) that fails payload decryption.
    """
    buf.seek(0)
    office_file = OfficeFile(buf)
    try:
        office_file.load_key(**load_key_kwargs)
    except exceptions.InvalidKeyError:
        return
    with test_case.assertRaises(exceptions.InvalidKeyError):
        office_file.decrypt(io.BytesIO(), verify_integrity=True)


class AgileKeyEncryptorSelectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_key, cls.cert, cls.cert_id = _make_certificate("escrow-one")
        cls.other_key, cls.other_cert, cls.other_cert_id = _make_certificate(
            "escrow-two"
        )

    def _dual_file(self, certificate_first=False):
        return _build_encrypted_file(
            PASSWORD,
            extra_key_encryptors=[(self.cert_key, self.cert, self.cert_id)],
            certificate_first=certificate_first,
        )

    def test_both_credentials_open_same_file(self):
        buf, _ = self._dual_file()
        self.assertEqual(
            _decrypt_with(buf, password=PASSWORD, verify_password=True), PLAINTEXT
        )
        self.assertEqual(
            _decrypt_with(buf, private_key=io.BytesIO(_pem(self.cert_key))),
            PLAINTEXT,
        )

    def test_xml_order_does_not_matter(self):
        password_first, _ = self._dual_file(certificate_first=False)
        certificate_first, _ = self._dual_file(certificate_first=True)
        for buf in (password_first, certificate_first):
            self.assertEqual(
                _decrypt_with(buf, password=PASSWORD, verify_password=True),
                PLAINTEXT,
            )
            self.assertEqual(
                _decrypt_with(buf, private_key=io.BytesIO(_pem(self.cert_key))),
                PLAINTEXT,
            )

    def test_explicit_key_encryptor_selection(self):
        buf, _ = self._dual_file()
        self.assertEqual(
            _decrypt_with(buf, password=PASSWORD, key_encryptor="password"),
            PLAINTEXT,
        )
        self.assertEqual(
            _decrypt_with(
                buf,
                private_key=io.BytesIO(_pem(self.cert_key)),
                key_encryptor="certificate",
            ),
            PLAINTEXT,
        )

    def test_key_encryptor_must_match_credential(self):
        buf, _ = self._dual_file()
        buf.seek(0)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(password=PASSWORD, key_encryptor="certificate")
        buf.seek(0)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(
                private_key=io.BytesIO(_pem(self.cert_key)),
                key_encryptor="password",
            )
        buf.seek(0)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(password=PASSWORD, key_encryptor="unknown")

    def test_certificate_id_selects_identity(self):
        buf, _ = _build_encrypted_file(
            PASSWORD,
            extra_key_encryptors=[
                (self.cert_key, self.cert, self.cert_id),
                (self.other_key, self.other_cert, self.other_cert_id),
            ],
        )
        self.assertEqual(
            _decrypt_with(
                buf,
                private_key=io.BytesIO(_pem(self.other_key)),
                certificate_id=self.other_cert_id,
            ),
            PLAINTEXT,
        )
        # The matching private key for the other identity fails there.
        _assert_credentials_rejected(
            self,
            buf,
            private_key=io.BytesIO(_pem(self.cert_key)),
            certificate_id=self.other_cert_id,
        )

    def test_unknown_certificate_id(self):
        buf, _ = self._dual_file()
        buf.seek(0)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(
                private_key=io.BytesIO(_pem(self.cert_key)),
                certificate_id="not-a-known-cert",
            )

    def test_certificate_id_requires_private_key(self):
        buf, _ = self._dual_file()
        buf.seek(0)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(password=PASSWORD, certificate_id=self.cert_id)

    def test_wrong_password_not_rescued_by_certificate_path(self):
        buf, _ = self._dual_file()
        buf.seek(0)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.InvalidKeyError):
            office_file.load_key(password="wrong-password", verify_password=True)

    def test_wrong_private_key_not_rescued_by_password_path(self):
        buf, _ = self._dual_file()
        unrelated_key, _, _ = _make_certificate("unrelated")
        _assert_credentials_rejected(
            self, buf, private_key=io.BytesIO(_pem(unrelated_key))
        )

    def test_missing_selected_entry(self):
        # Certificate-only file: the password path must report a missing entry.
        info_file, _ = _build_encrypted_file(
            PASSWORD,
            extra_key_encryptors=[(self.cert_key, self.cert, self.cert_id)],
        )
        # Rebuild without the password keyEncryptor by patching the XML.
        buf = _rebuild_without_password_entry(info_file)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(password=PASSWORD)
        # The certificate path still works on the same file.
        office_file = OfficeFile(_rebuild_without_password_entry(info_file))
        office_file.load_key(private_key=io.BytesIO(_pem(self.cert_key)))
        out = io.BytesIO()
        office_file.decrypt(out)
        self.assertEqual(out.getvalue(), PLAINTEXT)

        # Password-only file: the certificate path must report a missing entry.
        buf, _ = _build_encrypted_file(PASSWORD)
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(private_key=io.BytesIO(_pem(self.cert_key)))

    def test_conflicting_password_entries(self):
        buf, _ = _build_encrypted_file(
            PASSWORD,
            extra_key_encryptors=[(self.cert_key, self.cert, self.cert_id)],
        )
        buf = _rewrite_encryption_info(buf, lambda xml: _add_conflicting_password(xml))
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(password=PASSWORD)

    def test_conflicting_certificate_entries(self):
        buf, _ = _build_encrypted_file(
            PASSWORD,
            extra_key_encryptors=[
                (self.cert_key, self.cert, self.cert_id),
                (self.other_key, self.other_cert, self.other_cert_id),
            ],
        )
        # Two different certificate identities and no explicit selection.
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(private_key=io.BytesIO(_pem(self.cert_key)))

    def test_unsupported_wrap_params(self):
        buf, _ = _build_encrypted_file(PASSWORD)
        buf = _rewrite_encryption_info(
            buf, lambda xml: _set_password_cipher(xml, "DES")
        )
        office_file = OfficeFile(buf)
        with self.assertRaises(exceptions.DecryptionError):
            office_file.load_key(password=PASSWORD)

    def test_unknown_namespace_reported_not_supported(self):
        buf, _ = _build_encrypted_file(PASSWORD)
        unknown = (
            '<keyEncryptor uri="http://example.com/unknown/keyEncryptor">'
            "<x:encryptedKey xmlns:x='http://example.com/unknown/keyEncryptor'"
            " encryptedKeyValue='AAAA' />"
            "</keyEncryptor>"
        )
        buf = _rewrite_encryption_info(
            buf, lambda xml: xml.replace("</keyEncryptors>", unknown + "</keyEncryptors>")
        )
        office_file = OfficeFile(buf)
        self.assertEqual(
            office_file.info["keyEncryptors"]["unsupported"],
            ["http://example.com/unknown/keyEncryptor"],
        )
        # Supported credentials keep working; the unknown entry is ignored.
        office_file.load_key(password=PASSWORD, verify_password=True)
        out = io.BytesIO()
        office_file.decrypt(out)
        self.assertEqual(out.getvalue(), PLAINTEXT)


def _rewrite_encryption_info(buf, transform):
    """Rewrite the EncryptionInfo XML of an encrypted file via transform()."""
    import olefile

    buf.seek(0)
    ole = olefile.OleFileIO(buf)
    with ole.openstream("EncryptionInfo") as stream:
        info_data = stream.read()
    with ole.openstream("EncryptedPackage") as stream:
        package = stream.read()
    ole.close()

    header, xml = info_data[:8], info_data[8:].decode("UTF-8")
    new_info = header + transform(xml).encode("UTF-8")

    out = io.BytesIO()
    ECMA376Encrypted(package, new_info).write_to(out)
    out.seek(0)
    return out


def _rebuild_without_password_entry(buf):
    def drop_password(xml):
        start = xml.index('<keyEncryptor uri="{}'.format(_PASSWORD_URI))
        end = xml.index("</keyEncryptor>", start) + len("</keyEncryptor>")
        return xml[:start] + xml[end:]

    return _rewrite_encryption_info(buf, drop_password)


def _add_conflicting_password(xml):
    """Duplicate the password encryptedKey with a different saltValue."""
    start = xml.index('<keyEncryptor uri="{}'.format(_PASSWORD_URI))
    end = xml.index("</keyEncryptor>", start) + len("</keyEncryptor>")
    original = xml[start:end]
    conflicting = original.replace(
        'saltValue="', 'saltValue="{}'.format(_enc64(b"\x00" * 16)), 1
    )
    return xml[:end] + conflicting + xml[end:]


def _set_password_cipher(xml, cipher):
    start = xml.index('<keyEncryptor uri="{}'.format(_PASSWORD_URI))
    end = xml.index("</keyEncryptor>", start)
    segment = xml[start:end].replace(
        'cipherAlgorithm="AES"', 'cipherAlgorithm="{}"'.format(cipher)
    )
    return xml[:start] + segment + xml[end:]


if __name__ == "__main__":
    unittest.main()
