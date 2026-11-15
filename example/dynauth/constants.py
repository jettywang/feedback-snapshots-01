"""RADIUS Dynamic Authorization constants (RFC 5176).

Only the attribute codes, packet codes and Error-Cause values used by the
policy adapter are listed here. Packet codes are also available from
:mod:`pyrad.packet`.
"""

from pyrad.packet import (  # noqa: F401
    CoAACK,
    CoANAK,
    CoARequest,
    DisconnectACK,
    DisconnectNAK,
    DisconnectRequest,
)

# Short aliases used throughout the adapter.
COA_REQUEST = CoARequest
COA_ACK = CoAACK
COA_NAK = CoANAK
DISCONNECT_REQUEST = DisconnectRequest
DISCONNECT_ACK = DisconnectACK
DISCONNECT_NAK = DisconnectNAK

# Standard RADIUS attribute codes used as session locators / targets.
USER_NAME = 1
NAS_IP_ADDRESS = 4
FILTER_ID = 11
SESSION_TIMEOUT = 27
CALLED_STATION_ID = 30
CALLING_STATION_ID = 31
NAS_IDENTIFIER = 32
ACCT_SESSION_ID = 44
FRAMED_IP_ADDRESS = 8
MESSAGE_AUTHENTICATOR = 80
ERROR_CAUSE = 101

# RFC 5176 section 3.2 Error-Cause values.
MISSING_ATTRIBUTE = 402
UNSUPPORTED_EXTENSION = 401
INVALID_ATTRIBUTE_VALUE = 407
ADMINISTRATIVELY_PROHIBITED = 501
SESSION_CONTEXT_NOT_FOUND = 503
SESSION_CONTEXT_NOT_REMOVABLE = 505

# Attributes that identify a session; everything else in a CoA-Request is a
# requested authorization change.
LOCATOR_CODES = frozenset((
    NAS_IP_ADDRESS,
    NAS_IDENTIFIER,
    ACCT_SESSION_ID,
    FRAMED_IP_ADDRESS,
    CALLING_STATION_ID,
    CALLED_STATION_ID,
    USER_NAME,
))

# CoA attribute changes the demo policy knows how to apply.
SUPPORTED_CHANGE_CODES = frozenset((FILTER_ID, SESSION_TIMEOUT))
