#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
import hmac as hmac_module
from hashlib import sha1

from pyasn1.type import univ
from pysnmp.proto import errind, error
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto.secmod.rfc3414.auth import base

TWELVE_ZEROS = univ.OctetString((0,) * 12).asOctets()
FORTY_FOUR_ZEROS = (0,) * 44
DIGEST_LENGTH = 12


# 7.2.4


class HmacSha(base.AbstractAuthenticationService):
    """The HMAC-SHA-1-96 authentication protocol.

    https://tools.ietf.org/html/rfc3414#section-7.2.4
    """

    SERVICE_ID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 3)  # usmHMACSHAAuthProtocol
    IPAD = [0x36] * 64
    OPAD = [0x5C] * 64

    def hash_passphrase(self, authKey) -> univ.OctetString:
        """Hash a passphrase."""
        return localkey.hash_passphrase_sha(authKey)

    def localize_key(self, authKey, snmpEngineID) -> univ.OctetString:
        """Localize a key."""
        return localkey.localize_key_sha(authKey, snmpEngineID)

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
        """Compute the 12-byte HMAC-SHA-1-96 MAC over *message* (RFC 3414 7.3)."""
        # 7.3.1.2a
        extendedAuthKey = authKey.asNumbers() + FORTY_FOUR_ZEROS

        # 7.3.1.2c
        k1 = univ.OctetString(map(lambda x, y: x ^ y, extendedAuthKey, HmacSha.IPAD))

        # 7.3.1.2e
        k2 = univ.OctetString(map(lambda x, y: x ^ y, extendedAuthKey, HmacSha.OPAD))

        # 7.3.1.3
        d1 = sha1(k1.asOctets() + message).digest()

        # 7.3.1.4
        d2 = sha1(k2.asOctets() + d1).digest()
        return d2[:DIGEST_LENGTH]

    # 7.3.1
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

        # 7.3.1.5 & 6 -- splice the MAC into the located value only
        return wholeMsg[:offset] + mac + wholeMsg[offset + length :]

    # 7.3.2
    def authenticate_incoming_message(
        self, authKey, authParameters, wholeMsg, authParametersLocation=None
    ):
        """Authenticate incoming message."""
        # 7.3.2.1 & 2
        if len(authParameters) != DIGEST_LENGTH:
            raise error.StatusInformation(errorIndication=errind.authenticationError)

        offset, length = self._resolve_location(wholeMsg, authParametersLocation)

        # The structural location must delimit exactly the received digest;
        # a mismatch means the decoded parameters do not match the wire layout.
        if wholeMsg[offset : offset + length] != authParameters.asOctets():
            raise error.StatusInformation(
                errorIndication=errind.authenticationFailure
            )

        # 7.3.2.3 -- zero the located value, preserving all other wire bytes
        authenticatedWholeMsg = (
            wholeMsg[:offset] + TWELVE_ZEROS + wholeMsg[offset + length :]
        )

        mac = self._compute_mac(authKey, authenticatedWholeMsg)

        # 7.3.2.6
        if not hmac_module.compare_digest(mac, authParameters.asOctets()):
            raise error.StatusInformation(errorIndication=errind.authenticationFailure)

        return authenticatedWholeMsg
