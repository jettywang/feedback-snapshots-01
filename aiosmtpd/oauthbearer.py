# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
RFC 7628 OAUTHBEARER SASL mechanism support.

This module implements the strict, token-agnostic parts of the OAUTHBEARER
mechanism: parsing and validating the wire format of the initial client
response (the GS2 header and the key/value pairs), and enforcing the local
security policy (audience, scope, host/port and authzid).

It deliberately does NOT perform any network access and does NOT know how to
introspect or validate a bearer token against an identity service.  That
decision is delegated to a caller-supplied :data:`OAuthTokenValidatorType`
callback, which is invoked locally with the parsed request.
"""

import re
from typing import Callable, NamedTuple, Optional, Sequence, Tuple

from public import public


# region #### Constants ##############################################################

#: The field separator (``%x01``) used between the GS2 header and every
#: key/value pair, and the single byte that makes up the dummy client
#: response used to finish a failed exchange.
KVSEP = b"\x01"

#: OAUTHBEARER does not use a channel binding, so the GS2 channel-binding
#: flag MUST be "n" (RFC 5801).
GS2_NO_CHANNEL_BINDING = "n"

#: OAuth 2.0 error code for syntactically malformed client responses.
ERR_INVALID_REQUEST = "invalid_request"

#: OAuth 2.0 error code for tokens (or policies) that cannot be accepted.
ERR_INVALID_TOKEN = "invalid_token"

# Keys defined by RFC 7628 for the initial client response.
KEY_AUTH = "auth"
KEY_HOST = "host"
KEY_PORT = "port"

# A key is 1*(ALPHA); a decimal positive integer without leading zeros.
_RE_KEY = re.compile(r"[A-Za-z]+\Z")
_RE_PORT = re.compile(r"[1-9][0-9]*\Z")

# endregion


@public
class OAuthBearerError(Exception):
    """
    Raised when an OAUTHBEARER exchange cannot succeed.

    :param error_status: The OAuth 2.0 error code (from the IANA "OAuth
        Extensions Error Registry") to place in the JSON error result.
    """

    def __init__(self, error_status: str, message: str):
        super().__init__(message)
        self.error_status = error_status


@public
class OAuthBearerRequest(NamedTuple):
    """
    The strictly parsed contents of an OAUTHBEARER initial client response.

    The bearer token is intentionally excluded from ``__repr__``/``__str__``
    so that logging these objects can never leak the credential.
    """

    authzid: Optional[str]
    host: Optional[str]
    port: Optional[int]
    token: str

    def __repr__(self) -> str:
        return (
            "OAuthBearerRequest(authzid=%r, host=%r, port=%r, token=...)"
            % (self.authzid, self.host, self.port)
        )

    def __str__(self) -> str:
        return self.__repr__()


@public
class OAuthIdentity(NamedTuple):
    """
    The identity securely established for the client by the validated OAuth
    credential.  Returned by the token validator on success.

    ``subject`` is the canonical identity reported by the SASL mechanism; it
    is what later mail authorization (e.g. MAIL FROM) is based on.  The
    contents of ``audiences`` and ``scopes`` are compared against the local
    service configuration.
    """

    subject: str
    audiences: Tuple[str, ...]
    scopes: Tuple[str, ...]

    @property
    def login(self) -> str:
        """The authenticated identity, exposed for ``session.login_data``."""
        return self.subject


#: A locally-invoked callback that validates the bearer token.
#:
#: It receives the parsed request and MUST return the :class:`OAuthIdentity`
#: established by the credential, or raise :class:`OAuthBearerError` (or any
#: other exception, which is treated as a validation failure).  It MUST NOT
#: mutate the session or the envelope.  Implementations perform their token
#: validation locally (for example by verifying a JWT or consulting a local
#: cache); this library never performs that work itself.
OAuthTokenValidatorType = Callable[[OAuthBearerRequest], OAuthIdentity]


def _parse_gs2_header(header: bytes) -> Optional[str]:
    """
    Parse and strictly validate the GS2 header (RFC 5801) of an OAUTHBEARER
    initial client response.

    Accepts only the non-channel-binding form ``n,`` or ``n,a=<authzid>,``.
    Returns the decoded authzid (or ``None`` when absent).  Raises
    :class:`OAuthBearerError` for any other form.
    """
    try:
        text = header.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "GS2 header is not valid UTF-8"
        ) from error
    parts = text.split(",")
    if len(parts) not in (2, 3):
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "malformed GS2 header"
        )
    cb_flag = parts[0]
    if cb_flag != GS2_NO_CHANNEL_BINDING:
        # OAUTHBEARER offers no channel binding; "y" and "p=" are prohibited.
        raise OAuthBearerError(
            ERR_INVALID_REQUEST,
            "OAUTHBEARER does not support channel binding",
        )
    if len(parts) == 2:
        # Canonical non-authzid form: "n,"
        if parts[1] != "":
            raise OAuthBearerError(
                ERR_INVALID_REQUEST, "malformed GS2 header"
            )
        return None
    # Authzid form: "n,a=<authzid>," -- the trailing element must be empty.
    authzid_field, trailer = parts[1], parts[2]
    if trailer != "":
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "malformed GS2 header"
        )
    prefix = "a="
    if not authzid_field.startswith(prefix):
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "malformed GS2 authzid"
        )
    authzid = authzid_field[len(prefix):]
    if not authzid:
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "empty GS2 authzid"
        )
    return authzid


@public
def parse_oauthbearer_request(raw: bytes) -> OAuthBearerRequest:
    """
    Strictly parse the (already base64-decoded) initial client response.

    The grammar from RFC 7628 is::

        kvsep       = %x01
        key         = 1*(ALPHA)
        kvpair      = key "=" value kvsep
        client-resp = (gs2-header kvsep *kvpair kvsep) / kvsep

    A response consisting of a single separator (the dummy response) is only
    valid to finish a failed exchange, so it is rejected here.  Duplicate or
    otherwise conflicting fields are rejected, as is a missing or malformed
    ``auth`` field.
    """
    if raw == KVSEP:
        raise OAuthBearerError(
            ERR_INVALID_REQUEST,
            "empty client response is only valid to finish an error exchange",
        )
    # ABNF: gs2-header kvsep *kvpair kvsep.  Each kvpair (including the last
    # one) carries its own trailing kvsep, and the whole response ends with
    # another kvsep.  Splitting therefore yields two trailing empty elements;
    # anything else indicates misplaced or missing separators.
    elements = raw.split(KVSEP)
    if len(elements) < 4 or elements[-1] != b"" or elements[-2] != b"":
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "malformed field separation"
        )
    header, kv_elements = elements[0], elements[1:-2]
    if any(element == b"" for element in kv_elements):
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "malformed field separation"
        )
    authzid = _parse_gs2_header(header)

    fields: dict[str, str] = {}
    for element in kv_elements:
        key, sep, value = element.partition(b"=")
        key_text = key.decode("ascii", errors="strict") if key else ""
        if not sep or not _RE_KEY.fullmatch(key_text):
            raise OAuthBearerError(
                ERR_INVALID_REQUEST, "malformed key/value pair"
            )
        if key_text in fields:
            # Reject repeated (and therefore conflicting) fields outright.
            raise OAuthBearerError(
                ERR_INVALID_REQUEST, f"duplicate field: {key_text}"
            )
        try:
            fields[key_text] = value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise OAuthBearerError(
                ERR_INVALID_REQUEST, f"value of {key_text} is not valid UTF-8"
            ) from error

    auth_value = fields.get(KEY_AUTH)
    if auth_value is None:
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "missing required 'auth' field"
        )
    scheme, sep, token = auth_value.partition(" ")
    if not sep or scheme.lower() != "bearer" or not token:
        raise OAuthBearerError(
            ERR_INVALID_REQUEST, "malformed 'auth' field"
        )

    host = fields.get(KEY_HOST) or None

    port: Optional[int] = None
    port_text = fields.get(KEY_PORT)
    if port_text is not None:
        if not _RE_PORT.fullmatch(port_text):
            raise OAuthBearerError(
                ERR_INVALID_REQUEST, "malformed 'port' field"
            )
        port = int(port_text)

    return OAuthBearerRequest(
        authzid=authzid, host=host, port=port, token=token
    )


@public
def evaluate_oauthbearer(
    request: OAuthBearerRequest,
    validator: Optional[OAuthTokenValidatorType],
    *,
    expected_audience: Optional[str],
    required_scopes: Sequence[str],
    expected_host: Optional[str] = None,
    expected_port: Optional[int] = None,
) -> OAuthIdentity:
    """
    Apply the local security policy and invoke the token validator.

    The order of checks is chosen so that cheap, local invariants are
    verified before the (potentially more expensive) validator runs:

    1. A validator must be configured.
    2. ``host``/``port`` from the response must match the service the client
       is connected to (only checked when the value was actually provided and
       the server knows the expected value).
    3. The validator establishes the :class:`OAuthIdentity` from the token.
    4. The identity must carry a non-empty subject, the expected audience and
       every required scope for this mail service.
    5. An asserted ``authzid`` must be identical to the validated subject; it
       can never be used to assume another user.

    Any failure raises :class:`OAuthBearerError`; the caller must keep the
    session unauthenticated and complete the RFC 7628 error exchange.
    """
    if validator is None:
        raise OAuthBearerError(
            ERR_INVALID_TOKEN, "no token validator configured"
        )

    if expected_host is not None and request.host is not None:
        if request.host.lower() != expected_host.lower():
            raise OAuthBearerError(
                ERR_INVALID_TOKEN, "'host' does not match this service"
            )
    if expected_port is not None and request.port is not None:
        if request.port != expected_port:
            raise OAuthBearerError(
                ERR_INVALID_TOKEN, "'port' does not match this service"
            )

    try:
        identity = validator(request)
    except OAuthBearerError:
        raise
    except Exception as error:
        # A validator raising any other exception is a failed validation, not
        # a reason to authenticate the session.
        raise OAuthBearerError(
            ERR_INVALID_TOKEN, "token validator raised an exception"
        ) from error
    if not isinstance(identity, OAuthIdentity):
        raise OAuthBearerError(
            ERR_INVALID_TOKEN, "token validator returned an invalid identity"
        )

    if not identity.subject:
        raise OAuthBearerError(
            ERR_INVALID_TOKEN, "token is missing a subject"
        )
    if (
        expected_audience is not None
        and expected_audience not in identity.audiences
    ):
        raise OAuthBearerError(
            ERR_INVALID_TOKEN,
            "token audience does not grant access to this service",
        )
    missing = [
        scope for scope in required_scopes if scope not in identity.scopes
    ]
    if missing:
        raise OAuthBearerError(
            ERR_INVALID_TOKEN,
            "token is missing required scope(s): " + " ".join(missing),
        )
    if request.authzid is not None and request.authzid != identity.subject:
        # The authzid cannot be used to replace the validated identity.
        raise OAuthBearerError(
            ERR_INVALID_TOKEN,
            "authzid does not match the authenticated identity",
        )

    return identity
