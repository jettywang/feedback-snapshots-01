#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from pysnmp.proto import error


class AbstractEncryptionService:
    """Abstract encryption service."""

    SERVICE_ID = None
    KEY_SIZE = 0

    # Maximum number of padding octets the cipher may legitimately
    # append to the plaintext scopedPDU. Stream ciphers (AES CFB)
    # never pad; block ciphers (DES/3DES) pad up to one block.
    PADDING_BLOCK_SIZE = 0

    def hash_passphrase(self, authProtocol, privKey):
        """Hash authentication key."""
        raise error.ProtocolError("no encryption")

    def localize_key(self, authProtocol, privKey, snmpEngineID):
        """Localize privacy key."""
        raise error.ProtocolError("no encryption")

    def encrypt_data(self, encryptKey, privParameters, dataToEncrypt):
        """Encrypt data."""
        raise error.ProtocolError("no encryption")

    def decrypt_data(self, decryptKey, privParameters, encryptedData):
        """Decrypt data."""
        raise error.ProtocolError("no encryption")
