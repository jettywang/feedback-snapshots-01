import base64
import io
import logging
import zipfile
from struct import unpack
from xml.dom.minidom import parseString

import olefile

from msoffcrypto import exceptions
from msoffcrypto.format import base
from msoffcrypto.format.common import _parse_encryptionheader, _parse_encryptionverifier
from msoffcrypto.method.ecma376_agile import ALGORITHM_HASH, ECMA376Agile
from msoffcrypto.method.ecma376_standard import ECMA376Standard

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

#: keyEncryptor URIs defined by [MS-OFFCRYPTO] 2.3.4.8
_KEY_ENCRYPTOR_URI_PASSWORD = (
    "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
)
_KEY_ENCRYPTOR_URI_CERTIFICATE = (
    "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate"
)

#: keyEncryptor kinds a caller can explicitly request in ``load_key``
KEY_ENCRYPTOR_KINDS = ("password", "certificate")


def _is_ooxml(file):
    if not zipfile.is_zipfile(file):
        return False
    try:
        zfile = zipfile.ZipFile(file)
        with zfile.open("[Content_Types].xml") as stream:
            xml = parseString(stream.read())
            # Heuristic
            if (
                xml.documentElement.tagName == "Types"
                and xml.documentElement.namespaceURI
                == "http://schemas.openxmlformats.org/package/2006/content-types"
            ):
                return True
            else:
                return False
    except Exception:
        return False


def _parseinfo_standard(ole):
    (headerFlags,) = unpack("<I", ole.read(4))
    (encryptionHeaderSize,) = unpack("<I", ole.read(4))
    block = ole.read(encryptionHeaderSize)
    blob = io.BytesIO(block)
    header = _parse_encryptionheader(blob)
    block = ole.read()
    blob = io.BytesIO(block)
    algIdMap = {
        0x0000660E: "AES-128",
        0x0000660F: "AES-192",
        0x00006610: "AES-256",
    }
    verifier = _parse_encryptionverifier(
        blob, "AES" if header["algId"] & 0xFF00 == 0x6600 else "RC4"
    )  # TODO: Fix
    info = {
        "header": header,
        "verifier": verifier,
    }
    return info


def _parse_password_encrypted_key(node):
    spinValue = int(node.getAttribute("spinCount"))
    # [MS-OFFCRYPTO] 2.3.4.10 SpinCount: An unsigned integer that specifies the number of times to iterate on a hash of a password. It MUST NOT be greater than 10,000,000.
    # https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/87020a34-e73f-4139-99bc-bbdf6cf6fa55
    if not 0 <= spinValue <= 10_000_000:
        raise exceptions.DecryptionError("Agile spinCount must be between 0 and 10000000")
    return {
        "spinCount": spinValue,
        "saltSize": int(node.getAttribute("saltSize")),
        "blockSize": int(node.getAttribute("blockSize")),
        "keyBits": int(node.getAttribute("keyBits")),
        "hashSize": int(node.getAttribute("hashSize")),
        "cipherAlgorithm": node.getAttribute("cipherAlgorithm"),
        "cipherChaining": node.getAttribute("cipherChaining"),
        "hashAlgorithm": node.getAttribute("hashAlgorithm"),
        "saltValue": base64.b64decode(node.getAttribute("saltValue")),
        "encryptedVerifierHashInput": base64.b64decode(
            node.getAttribute("encryptedVerifierHashInput")
        ),
        "encryptedVerifierHashValue": base64.b64decode(
            node.getAttribute("encryptedVerifierHashValue")
        ),
        "encryptedKeyValue": base64.b64decode(node.getAttribute("encryptedKeyValue")),
    }


def _parse_certificate_encrypted_key(node):
    entry = {
        "certId": node.getAttribute("certId"),
        "encryptedKeyValue": base64.b64decode(node.getAttribute("encryptedKeyValue")),
    }
    # [MS-OFFCRYPTO] 2.3.4.5 defines only certId and encryptedKeyValue, but
    # some producers add wrapping parameters; keep them for validation.
    for attr in ("cipherAlgorithm", "cipherChaining", "hashAlgorithm", "keyBits"):
        if node.hasAttribute(attr):
            value = node.getAttribute(attr)
            entry[attr] = int(value) if attr == "keyBits" else value
    return entry


def _parse_key_encryptors(xml):
    """Group every keyEncryptor entry by credential kind.

    Entries in unknown namespaces are reported but never treated as supported.
    """
    key_encryptors = {"password": [], "certificate": [], "unsupported": []}
    for keyEncryptor in xml.getElementsByTagName("keyEncryptor"):
        uri = keyEncryptor.getAttribute("uri")
        if uri == _KEY_ENCRYPTOR_URI_PASSWORD:
            kind, parse = "password", _parse_password_encrypted_key
        elif uri == _KEY_ENCRYPTOR_URI_CERTIFICATE:
            kind, parse = "certificate", _parse_certificate_encrypted_key
        else:
            key_encryptors["unsupported"].append(uri)
            logger.warning("Ignoring keyEncryptor with unsupported uri: %r", uri)
            continue
        for node in keyEncryptor.getElementsByTagNameNS(uri, "encryptedKey"):
            key_encryptors[kind].append(parse(node))
    return key_encryptors


def _select_key_encryptor(entries, kind, certificate_id=None):
    """Pick the single keyEncryptor entry bound to the requested credential.

    Raises a clear error if the selected entry is missing or if several
    entries of the same kind contradict each other.
    """
    if certificate_id is not None:
        entries = [e for e in entries if e.get("certId") == certificate_id]
        if not entries:
            raise exceptions.DecryptionError(
                "No certificate keyEncryptor matches certId {!r}".format(certificate_id)
            )
    if not entries:
        raise exceptions.DecryptionError(
            "No {} keyEncryptor entry found in EncryptionInfo".format(kind)
        )
    first = entries[0]
    for other in entries[1:]:
        if other != first:
            raise exceptions.DecryptionError(
                "Conflicting {} keyEncryptor entries; cannot select one unambiguously".format(
                    kind
                )
            )
    return first


def _validate_wrap_params(entry, kind):
    """Reject key wrapping parameters this implementation cannot handle."""
    if "cipherAlgorithm" in entry and entry["cipherAlgorithm"] != "AES":
        raise exceptions.DecryptionError(
            "Unsupported {} keyEncryptor cipherAlgorithm: {!r}".format(
                kind, entry["cipherAlgorithm"]
            )
        )
    if "cipherChaining" in entry and entry["cipherChaining"] != "ChainingModeCBC":
        raise exceptions.DecryptionError(
            "Unsupported {} keyEncryptor cipherChaining: {!r}".format(
                kind, entry["cipherChaining"]
            )
        )
    if "hashAlgorithm" in entry and entry["hashAlgorithm"] not in ALGORITHM_HASH:
        raise exceptions.DecryptionError(
            "Unsupported {} keyEncryptor hashAlgorithm: {!r}".format(
                kind, entry["hashAlgorithm"]
            )
        )
    if "keyBits" in entry and entry["keyBits"] not in (128, 192, 256):
        raise exceptions.DecryptionError(
            "Unsupported {} keyEncryptor keyBits: {!r}".format(kind, entry["keyBits"])
        )


def _parseinfo_agile(ole):
    ole.seek(8)
    xml = parseString(ole.read())
    keyDataSalt = base64.b64decode(
        xml.getElementsByTagName("keyData")[0].getAttribute("saltValue")
    )
    keyDataHashAlgorithm = xml.getElementsByTagName("keyData")[0].getAttribute(
        "hashAlgorithm"
    )
    keyDataBlockSize = int(
        xml.getElementsByTagName("keyData")[0].getAttribute("blockSize")
    )
    keyDataKeyBits = int(
        xml.getElementsByTagName("keyData")[0].getAttribute("keyBits")
    )
    encryptedHmacKey = base64.b64decode(
        xml.getElementsByTagName("dataIntegrity")[0].getAttribute("encryptedHmacKey")
    )
    encryptedHmacValue = base64.b64decode(
        xml.getElementsByTagName("dataIntegrity")[0].getAttribute("encryptedHmacValue")
    )
    keyEncryptors = _parse_key_encryptors(xml)
    info = {
        "keyDataSalt": keyDataSalt,
        "keyDataHashAlgorithm": keyDataHashAlgorithm,
        "keyDataBlockSize": keyDataBlockSize,
        "keyDataKeyBits": keyDataKeyBits,
        "encryptedHmacKey": encryptedHmacKey,
        "encryptedHmacValue": encryptedHmacValue,
        "keyEncryptors": keyEncryptors,
    }
    # Legacy top-level aliases for the (first) password entry; credential
    # handling in load_key always goes through the selected entry instead.
    if keyEncryptors["password"]:
        password_entry = keyEncryptors["password"][0]
        info.update(
            {
                "encryptedVerifierHashInput": password_entry[
                    "encryptedVerifierHashInput"
                ],
                "encryptedVerifierHashValue": password_entry[
                    "encryptedVerifierHashValue"
                ],
                "encryptedKeyValue": password_entry["encryptedKeyValue"],
                "spinValue": password_entry["spinCount"],
                "passwordSalt": password_entry["saltValue"],
                "passwordHashAlgorithm": password_entry["hashAlgorithm"],
                "passwordKeyBits": password_entry["keyBits"],
            }
        )
    return info


def _parseinfo(ole):
    versionMajor, versionMinor = unpack("<HH", ole.read(4))
    if versionMajor == 4 and versionMinor == 4:  # Agile
        return "agile", _parseinfo_agile(ole)
    elif versionMajor in [2, 3, 4] and versionMinor == 2:  # Standard
        return "standard", _parseinfo_standard(ole)
    elif versionMajor in [3, 4] and versionMinor == 3:  # Extensible
        raise exceptions.DecryptionError(
            "Unsupported EncryptionInfo version (Extensible Encryption)"
        )
    raise exceptions.DecryptionError(
        "Unsupported EncryptionInfo version ({}:{})".format(versionMajor, versionMinor)
    )


class OOXMLFile(base.BaseOfficeFile):
    """Return an OOXML file object.

    Examples:
        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key(password="Password1234_", verify_password=True)

        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key(password="0000", verify_password=True)
        Traceback (most recent call last):
            ...
        msoffcrypto.exceptions.InvalidKeyError: ...
    """

    def __init__(self, file):
        self.format = "ooxml"

        file.seek(0)  # TODO: Investigate the effect (required for olefile.isOleFile)

        # olefile cannot process non password protected ooxml files.
        # TODO: this code is duplicate of OfficeFile(). Merge?
        if olefile.isOleFile(file):
            ole = olefile.OleFileIO(file)
            self.file = ole

            try:
                with self.file.openstream("EncryptionInfo") as stream:
                    self.type, self.info = _parseinfo(stream)
            except IOError:
                raise exceptions.FileFormatError(
                    "Supposed to be an encrypted OOXML file, but no EncryptionInfo stream found"
                )

            logger.debug("OOXMLFile.type: {}".format(self.type))

            self.secret_key = None

            if self.type == "agile":
                # TODO: Support aliases?
                self.keyTypes = ("password", "private_key", "secret_key")
            elif self.type == "standard":
                self.keyTypes = ("password", "secret_key")
            elif self.type == "extensible":
                pass
        elif _is_ooxml(file):
            self.type = "plain"
            self.file = file
        else:
            raise exceptions.FileFormatError("Unsupported file format")

    def load_key(
        self,
        password=None,
        private_key=None,
        secret_key=None,
        verify_password=False,
        key_encryptor=None,
        certificate_id=None,
    ):
        """
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key("1234")

        For ECMA-376 Agile files, ``key_encryptor`` may explicitly name the
        credential class to unwrap with (``"password"`` or ``"certificate"``)
        and ``certificate_id`` may select a certificate keyEncryptor entry by
        its ``certId`` attribute. The selected entry alone provides the salt,
        verifier and keyBits used for the operation.
        """
        if key_encryptor is not None:
            if key_encryptor not in KEY_ENCRYPTOR_KINDS:
                raise exceptions.DecryptionError(
                    "Unsupported key_encryptor {!r}; expected one of {}".format(
                        key_encryptor, KEY_ENCRYPTOR_KINDS
                    )
                )
            if self.type != "agile":
                raise exceptions.DecryptionError(
                    "key_encryptor selection is only supported for Agile encryption"
                )
        if certificate_id is not None and private_key is None:
            raise exceptions.DecryptionError(
                "certificate_id can only be used together with a private_key"
            )
        if password:
            if key_encryptor not in (None, "password"):
                raise exceptions.DecryptionError(
                    "A password cannot be used with key_encryptor={!r}".format(
                        key_encryptor
                    )
                )
            if self.type == "agile":
                entry = _select_key_encryptor(
                    self.info["keyEncryptors"]["password"], "password"
                )
                _validate_wrap_params(entry, "password")
                self.secret_key = ECMA376Agile.makekey_from_password(
                    password,
                    entry["saltValue"],
                    entry["hashAlgorithm"],
                    entry["encryptedKeyValue"],
                    entry["spinCount"],
                    entry["keyBits"],
                )
                if verify_password:
                    verified = ECMA376Agile.verify_password(
                        password,
                        entry["saltValue"],
                        entry["hashAlgorithm"],
                        entry["encryptedVerifierHashInput"],
                        entry["encryptedVerifierHashValue"],
                        entry["spinCount"],
                        entry["keyBits"],
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError("Key verification failed")
            elif self.type == "standard":
                self.secret_key = ECMA376Standard.makekey_from_password(
                    password,
                    self.info["header"]["algId"],
                    self.info["header"]["algIdHash"],
                    self.info["header"]["providerType"],
                    self.info["header"]["keySize"],
                    self.info["verifier"]["saltSize"],
                    self.info["verifier"]["salt"],
                )
                if verify_password:
                    verified = ECMA376Standard.verifykey(
                        self.secret_key,
                        self.info["verifier"]["encryptedVerifier"],
                        self.info["verifier"]["encryptedVerifierHash"],
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError("Key verification failed")
            elif self.type == "extensible":
                pass
            elif self.type == "plain":
                pass
        elif private_key:
            if key_encryptor not in (None, "certificate"):
                raise exceptions.DecryptionError(
                    "A private key cannot be used with key_encryptor={!r}".format(
                        key_encryptor
                    )
                )
            if self.type == "agile":
                entry = _select_key_encryptor(
                    self.info["keyEncryptors"]["certificate"],
                    "certificate",
                    certificate_id=certificate_id,
                )
                _validate_wrap_params(entry, "certificate")
                try:
                    self.secret_key = ECMA376Agile.makekey_from_privkey(
                        private_key, entry["encryptedKeyValue"]
                    )
                except ValueError as e:
                    raise exceptions.InvalidKeyError(
                        "The private key does not match the certificate keyEncryptor"
                    ) from e
                # NOTE: Recent cryptography versions apply implicit rejection
                # to RSA PKCS1v15 and return a garbage key instead of raising;
                # reject it here if its size cannot wrap the payload key.
                if len(self.secret_key) != self.info["keyDataKeyBits"] // 8:
                    raise exceptions.InvalidKeyError(
                        "The private key does not match the certificate keyEncryptor"
                    )
            else:
                raise exceptions.DecryptionError(
                    "Unsupported key type for the encryption method"
                )
        elif secret_key:
            if key_encryptor is not None:
                raise exceptions.DecryptionError(
                    "key_encryptor selection does not apply to a raw secret_key"
                )
            self.secret_key = secret_key
        else:
            raise exceptions.DecryptionError("No key specified")

    def decrypt(self, outfile, verify_integrity=False):
        """
        >>> from msoffcrypto import exceptions
        >>> from io import BytesIO; outfile = BytesIO()
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key("1234")
        ...     officefile.decrypt(outfile)
        Traceback (most recent call last):
        msoffcrypto.exceptions.DecryptionError: Document is not encrypted
        """
        if self.type == "agile":
            with self.file.openstream("EncryptedPackage") as stream:
                if verify_integrity:
                    verified = ECMA376Agile.verify_integrity(
                        self.secret_key,
                        self.info["keyDataSalt"],
                        self.info["keyDataHashAlgorithm"],
                        self.info["keyDataBlockSize"],
                        self.info["encryptedHmacKey"],
                        self.info["encryptedHmacValue"],
                        stream,
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError(
                            "Payload integrity verification failed"
                        )

                obuf = ECMA376Agile.decrypt(
                    self.secret_key,
                    self.info["keyDataSalt"],
                    self.info["keyDataHashAlgorithm"],
                    stream,
                )
            outfile.write(obuf)
        elif self.type == "standard":
            with self.file.openstream("EncryptedPackage") as stream:
                obuf = ECMA376Standard.decrypt(self.secret_key, stream)
            outfile.write(obuf)
        elif self.type == "plain":
            raise exceptions.DecryptionError("Document is not encrypted")
        else:
            raise exceptions.DecryptionError("Unsupported encryption method")

        # If the file is successfully decrypted, there must be a valid OOXML file, i.e. a valid zip file
        if not zipfile.is_zipfile(io.BytesIO(obuf)):
            raise exceptions.InvalidKeyError(
                "The file could not be decrypted with this password"
            )

    def encrypt(self, password, outfile):
        """
        >>> from msoffcrypto.format.ooxml import OOXMLFile
        >>> from io import BytesIO; outfile = BytesIO()
        >>> with open("tests/outputs/example.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.encrypt("1234", outfile)
        """
        if self.is_encrypted():
            raise exceptions.EncryptionError("File is already encrypted")

        self.file.seek(0)

        buf = ECMA376Agile.encrypt(password, self.file)

        if not olefile.isOleFile(buf):
            raise exceptions.EncryptionError("Unable to encrypt this file")

        outfile.write(buf)

    def is_encrypted(self):
        """
        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.is_encrypted()
        True
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.is_encrypted()
        False
        """
        # Heuristic
        if self.type == "plain":
            return False
        elif isinstance(self.file, olefile.OleFileIO):
            return True
        else:
            return False
