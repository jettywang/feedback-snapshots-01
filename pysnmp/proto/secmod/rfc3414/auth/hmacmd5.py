#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
import hmac as hmac_module
from hashlib import md5

from pyasn1.type import univ
from pysnmp.proto import errind, error
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto.secmod.rfc3414.auth import base

TWELVE_ZEROS = univ.OctetString((0,) * 12).asOctets()
FORTY_EIGHT_ZEROS = (0,) * 48
DIGEST_LENGTH = 12


# rfc3414: 6.2.4


class HmacMd5(base.AbstractAuthenticationService):
    """The HMAC-MD5-96 authentication protocol.

    https://tools.ietf.org/html/rfc3414#section-6.2.4
    """

    SERVICE_ID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 2)  # usmHMACMD5AuthProtocol
    IPAD = [0x36] * 64
    OPAD = [0x5C] * 64

    def hash_passphrase(self, authKey):
        """Hash a passphrase."""
        return localkey.hash_passphrase_md5(authKey)

    def localize_key(self, authKey, snmpEngineID):
        """Localize a key."""
        return localkey.localize_key_md5(authKey, snmpEngineID)

    @property
    def digest_length(self):
        """Return digest length."""
        return DIGEST_LENGTH

    def _resolve_location(self, wholeMsg, authParametersLocation):
        """Return the (offset, length) of the auth parameter value octets."""
        if authParametersLocation is None:
            # Legacy entry point: recover the location from the BER structure
            # rather than scanning the substrate for matching bytes.
            authParametersLocation = base.locate_authentication_parameters(wholeMsg)
        offset, length = authParametersLocation
        if length != DIGEST_LENGTH or offset + length > len(wholeMsg):
            raise error.ProtocolError("Invalid digest placeholder location")
        return offset, length

    @staticmethod
    def _compute_mac(authKey, message):
        """Compute the 12-byte HMAC-MD5-96 MAC over *message* (RFC 3414 6.3)."""
        # 6.3.1.2a
        extendedAuthKey = authKey.asNumbers() + FORTY_EIGHT_ZEROS

        # 6.3.1.2c
        k1 = univ.OctetString(map(lambda x, y: x ^ y, extendedAuthKey, HmacMd5.IPAD))

        # 6.3.1.2e
        k2 = univ.OctetString(map(lambda x, y: x ^ y, extendedAuthKey, HmacMd5.OPAD))

        # 6.3.1.3
        d1 = md5(k1.asOctets() + message).digest()

        # 6.3.1.4
        d2 = md5(k2.asOctets() + d1).digest()
        return d2[:DIGEST_LENGTH]

    # 6.3.1
    def authenticate_outgoing_message(
        self, authKey, wholeMsg, authParametersLocation=None
    ):
        """Authenticate outgoing message."""
        offset, length = self._resolve_location(wholeMsg, authParametersLocation)

        # The caller is required to zero the whole msgAuthenticationParameters
        # value before hashing; verify rather than assume that the located
        # octets are that placeholder, keeping every other wire byte intact.
        if wholeMsg[offset : offset + length] != TWELVE_ZEROS:
            raise error.ProtocolError("Digest placeholder is not zeroed")

        mac = self._compute_mac(authKey, wholeMsg)

        # 6.3.1.5 & 6 -- splice the MAC into the located value only
        return wholeMsg[:offset] + mac + wholeMsg[offset + length :]

    # 6.3.2
    def authenticate_incoming_message(
        self, authKey, authParameters, wholeMsg, authParametersLocation=None
    ):
        """Authenticate incoming message."""
        # 6.3.2.1 & 2
        if len(authParameters) != DIGEST_LENGTH:
            raise error.StatusInformation(errorIndication=errind.authenticationError)

        offset, length = self._resolve_location(wholeMsg, authParametersLocation)

        # The structural location must delimit exactly the received digest;
        # a mismatch means the decoded parameters do not match the wire layout.
        if wholeMsg[offset : offset + length] != authParameters.asOctets():
            raise error.StatusInformation(
                errorIndication=errind.authenticationFailure
            )

        # 6.3.2.3 -- zero the located value, preserving all other wire bytes
        authenticatedWholeMsg = (
            wholeMsg[:offset] + TWELVE_ZEROS + wholeMsg[offset + length :]
        )

        mac = self._compute_mac(authKey, authenticatedWholeMsg)

        # 6.3.2.6
        if not hmac_module.compare_digest(mac, authParameters.asOctets()):
            raise error.StatusInformation(errorIndication=errind.authenticationFailure)

        return authenticatedWholeMsg
