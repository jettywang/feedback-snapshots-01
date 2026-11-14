# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RFC 7628 OAUTHBEARER SASL mechanism."""

import asyncio
import contextlib
import json
import logging
from base64 import b64decode, b64encode
from typing import Callable, List, Optional
from unittest import mock

import pytest

from aiosmtpd.handlers import Sink
from aiosmtpd.oauthbearer import (
    ERR_INVALID_REQUEST,
    ERR_INVALID_TOKEN,
    KVSEP,
    OAuthBearerError,
    OAuthBearerRequest,
    OAuthIdentity,
    evaluate_oauthbearer,
    parse_oauthbearer_request,
)
from aiosmtpd.smtp import SMTP as Server

MAIL_AUDIENCE = "smtp://mail.example.com"
MAIL_SCOPE = "https://mail.example.com/SMTP.send"
OTHER_AUDIENCE = "smtp://calendar.example.net"

# A fixed, non-secret test token used to demonstrate the exchanges.
GOOD_TOKEN = "test-access-token-0123456789"
BAD_TOKEN = "test-access-token-BAD"

SUBJECT = "user@example.com"
ATTACKER = "attacker@example.com"


def bearer_response(
    token: str,
    *,
    authzid: Optional[str] = SUBJECT,
    host: Optional[str] = "mail.example.com",
    port: Optional[int] = 587,
) -> bytes:
    gs2 = (
        b"n,"
        if authzid is None
        else b"n,a=" + authzid.encode("ascii") + b","
    )
    parts = [gs2]
    if host is not None:
        parts.append(("host=" + host).encode("ascii"))
    if port is not None:
        parts.append(("port=" + str(port)).encode("ascii"))
    parts.append(("auth=Bearer " + token).encode("ascii"))
    return KVSEP.join(parts) + KVSEP + KVSEP


# region #### Pure parser tests ######################################################


class TestParseOAuthBearerRequest:
    def test_rfc7628_example(self):
        # Section 4.1 of RFC 7628 (SMTP, port 587).
        wire = (
            "bixhPXVzZXJAZXhhbXBsZS5jb20sAWhvc3Q9c2VydmVyLmV4YW1wbGUuY29t"
            "AXBvcnQ9NTg3AWF1dGg9QmVhcmVyIHZGOWRmdDRxbVRjMk52YjNSbGNrQmhi"
            "SFJoZG1semRHRXVZMjl0Q2c9PQEB"
        )
        request = parse_oauthbearer_request(b64decode(wire))
        assert request.authzid == "user@example.com"
        assert request.host == "server.example.com"
        assert request.port == 587
        assert request.token == "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg=="

    def test_no_authzid(self):
        request = parse_oauthbearer_request(
            b"n,\x01auth=Bearer " + GOOD_TOKEN.encode() + b"\x01\x01"
        )
        assert request.authzid is None
        assert request.token == GOOD_TOKEN

    @pytest.mark.parametrize(
        "raw",
        [
            # Dummy response is only valid to finish an error exchange.
            KVSEP,
            # Missing terminating separator.
            b"n,\x01auth=Bearer x\x01",
            # Empty kvpair (stray separator).
            b"n,\x01\x01auth=Bearer x\x01\x01",
            # No GS2 header at all.
            b"host=a\x01auth=Bearer x\x01\x01",
        ],
    )
    def test_malformed_separation(self, raw):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(raw)
        assert exc.value.error_status == ERR_INVALID_REQUEST

    @pytest.mark.parametrize("flag", [b"y,", b"p=tls-server-end-point,"])
    def test_rejects_channel_binding(self, flag):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(
                flag + b"\x01auth=Bearer x\x01\x01"
            )
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_rejects_empty_authzid(self):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(
                b"n,a=,\x01auth=Bearer x\x01\x01"
            )
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_rejects_non_utf8_gs2_header(self):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(
                b"n,a=\xff,\x01auth=Bearer x\x01\x01"
            )
        assert exc.value.error_status == ERR_INVALID_REQUEST

    @pytest.mark.parametrize(
        "header",
        [
            b"n,x",  # two elements with a non-empty trailing field
            b"n,a=user,x",  # three elements with a non-empty trailer
        ],
    )
    def test_rejects_malformed_gs2_structure(self, header):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(
                header + b"\x01auth=Bearer x\x01\x01"
            )
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_accepts_authzid_gs2_form(self):
        request = parse_oauthbearer_request(
            b"n,a=user,\x01auth=Bearer x\x01\x01"
        )
        assert request.authzid == "user"

    def test_rejects_authzid_field_without_prefix(self):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(
                b"n,user,\x01auth=Bearer x\x01\x01"
            )
        assert exc.value.error_status == ERR_INVALID_REQUEST

    @pytest.mark.parametrize(
        "raw",
        [
            # No '=' separator in a kvpair.
            b"n,\x01hostonly\x01auth=Bearer x\x01\x01",
            # Empty key.
            b"n,\x01=value\x01auth=Bearer x\x01\x01",
            # Non-alpha key.
            b"n,\x01hos1=a\x01auth=Bearer x\x01\x01",
        ],
    )
    def test_rejects_malformed_kvpair(self, raw):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(raw)
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_rejects_non_utf8_value(self):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(
                b"n,\x01host=\xff\x01auth=Bearer x\x01\x01"
            )
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_rejects_duplicate_field(self):
        raw = (
            b"n,\x01host=a\x01host=b\x01auth=Bearer "
            + GOOD_TOKEN.encode()
            + b"\x01\x01"
        )
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(raw)
        assert exc.value.error_status == ERR_INVALID_REQUEST
        assert "duplicate" in str(exc.value)

    @pytest.mark.parametrize("port", ["0", "0587", "-587", "58a", "abc"])
    def test_rejects_bad_port(self, port):
        raw = (
            b"n,\x01port=" + port.encode()
            + b"\x01auth=Bearer x\x01\x01"
        )
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(raw)
        assert exc.value.error_status == ERR_INVALID_REQUEST

    @pytest.mark.parametrize(
        "auth",
        [
            "",  # missing auth value
            "Basic x",  # wrong scheme
            "Bearer",  # no token
            "Bearer ",  # empty token
        ],
    )
    def test_rejects_bad_auth_field(self, auth):
        raw = b"n,\x01auth=" + auth.encode() + b"\x01\x01"
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(raw)
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_missing_auth_field(self):
        with pytest.raises(OAuthBearerError) as exc:
            parse_oauthbearer_request(b"n,\x01host=a\x01\x01")
        assert exc.value.error_status == ERR_INVALID_REQUEST

    def test_scheme_name_case_insensitive(self):
        request = parse_oauthbearer_request(
            b"n,\x01auth=bearer " + GOOD_TOKEN.encode() + b"\x01\x01"
        )
        assert request.token == GOOD_TOKEN

    def test_unknown_keys_ignored_but_duplicates_rejected(self):
        request = parse_oauthbearer_request(
            b"n,\x01foo=bar\x01auth=Bearer " + GOOD_TOKEN.encode() + b"\x01\x01"
        )
        assert request.token == GOOD_TOKEN
        with pytest.raises(OAuthBearerError):
            parse_oauthbearer_request(
                b"n,\x01foo=a\x01foo=b\x01auth=Bearer x\x01\x01"
            )

    def test_repr_never_contains_token(self):
        request = parse_oauthbearer_request(
            b"n,\x01auth=Bearer " + GOOD_TOKEN.encode() + b"\x01\x01"
        )
        assert GOOD_TOKEN not in repr(request)
        assert GOOD_TOKEN not in str(request)


# endregion


# region #### Pure policy tests ######################################################


def accepting_validator(request: OAuthBearerRequest) -> OAuthIdentity:
    return OAuthIdentity(
        subject=SUBJECT,
        audiences=(MAIL_AUDIENCE,),
        scopes=(MAIL_SCOPE,),
    )


def cross_audience_validator(request: OAuthBearerRequest) -> OAuthIdentity:
    return OAuthIdentity(
        subject=SUBJECT,
        audiences=(OTHER_AUDIENCE,),
        scopes=(MAIL_SCOPE,),
    )


class TestEvaluateOAuthBearer:
    @pytest.fixture
    def oauth_request(self) -> OAuthBearerRequest:
        return parse_oauthbearer_request(
            bearer_response(GOOD_TOKEN, host="mail.example.com", port=587)
        )

    def test_success(self, oauth_request):
        identity = evaluate_oauthbearer(
            oauth_request,
            accepting_validator,
            expected_audience=MAIL_AUDIENCE,
            required_scopes=[MAIL_SCOPE],
            expected_host="mail.example.com",
            expected_port=587,
        )
        assert identity.subject == SUBJECT
        assert identity.login == SUBJECT

    def test_cross_service_audience_rejected(self, oauth_request):
        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                cross_audience_validator,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[MAIL_SCOPE],
                expected_host="mail.example.com",
                expected_port=587,
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_missing_scope_rejected(self, oauth_request):
        def no_scopes(req):
            return OAuthIdentity(SUBJECT, (MAIL_AUDIENCE,), ())

        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                no_scopes,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[MAIL_SCOPE],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_authzid_impersonation_rejected(self):
        request = parse_oauthbearer_request(
            bearer_response(GOOD_TOKEN, authzid=ATTACKER)
        )
        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                request,
                accepting_validator,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[MAIL_SCOPE],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_same_authzid_as_subject_allowed(self, oauth_request):
        identity = evaluate_oauthbearer(
            oauth_request,
            accepting_validator,
            expected_audience=MAIL_AUDIENCE,
            required_scopes=[MAIL_SCOPE],
        )
        assert identity.subject == SUBJECT

    @pytest.mark.parametrize(
        "host,port",
        [("evil.example.com", 587), ("mail.example.com", 25)],
    )
    def test_host_port_must_match_service(self, oauth_request, host, port):
        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                accepting_validator,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[],
                expected_host=host,
                expected_port=port,
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_validator_exception_does_not_authenticate(self, oauth_request):
        def boom(req):
            raise RuntimeError("identity service unavailable")

        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                boom,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_missing_validator_rejected(self, oauth_request):
        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                None,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_empty_subject_rejected(self, oauth_request):
        def empty_subject(req):
            return OAuthIdentity("", (MAIL_AUDIENCE,), ())

        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                empty_subject,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_oauth_error_from_validator_propagates(self, oauth_request):
        def rejects(req):
            raise OAuthBearerError(ERR_INVALID_TOKEN, "revoked")

        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                rejects,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN
        assert str(exc.value) == "revoked"

    def test_wrong_validator_return_type_rejected(self, oauth_request):
        def wrong_type(req):
            return "not-an-identity"

        with pytest.raises(OAuthBearerError) as exc:
            evaluate_oauthbearer(
                oauth_request,
                wrong_type,
                expected_audience=MAIL_AUDIENCE,
                required_scopes=[],
            )
        assert exc.value.error_status == ERR_INVALID_TOKEN

    def test_host_match_is_case_insensitive(self, oauth_request):
        identity = evaluate_oauthbearer(
            oauth_request,
            accepting_validator,
            expected_audience=MAIL_AUDIENCE,
            required_scopes=[],
            expected_host="MAIL.Example.COM",
            expected_port=587,
        )
        assert identity.subject == SUBJECT

    def test_omitted_host_port_not_checked(self):
        request = parse_oauthbearer_request(
            bearer_response(GOOD_TOKEN, host=None, port=None)
        )
        identity = evaluate_oauthbearer(
            request,
            accepting_validator,
            expected_audience=MAIL_AUDIENCE,
            required_scopes=[],
            expected_host="mail.example.com",
            expected_port=587,
        )
        assert identity.subject == SUBJECT


# endregion


# region #### SMTP-level (mock transport, no sockets) tests ##########################


class _Harness:
    """Drive an SMTP protocol over a mock transport, without real sockets."""

    def __init__(self, validator: Optional[Callable], **server_kwargs):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.transport = mock.Mock()
        self.responses: List[bytes] = []
        self.transport.write = self.responses.append
        defaults = dict(
            auth_require_tls=True,
            oauth_token_validator=validator,
            oauth_service_audience=MAIL_AUDIENCE,
            oauth_required_scopes=[MAIL_SCOPE],
        )
        defaults.update(server_kwargs)
        self.server = Server(Sink(), loop=self.loop, **defaults)
        self.server.connection_made(self.transport)

    def enable_tls(self) -> None:
        self.server._tls_protocol = mock.Mock()

    def pump(self, data: Optional[bytes]) -> None:
        if data:
            self.server.data_received(data)

        async def _tick():
            await asyncio.sleep(0.01)

        self.loop.run_until_complete(_tick())

    def close(self) -> None:
        handler = self.server._handler_coroutine
        if handler is not None and not handler.done():
            handler.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                self.loop.run_until_complete(handler)
        self.loop.close()

    def codes(self) -> List[int]:
        raw = b"".join(self.responses).split(b"\r\n")
        return [int(line[:3]) for line in raw if line]


class TestSMTPOAuthBearer:
    @pytest.fixture
    def harness(self):
        def validator(request: OAuthBearerRequest) -> OAuthIdentity:
            if request.token != GOOD_TOKEN:
                raise OAuthBearerError(ERR_INVALID_TOKEN, "unknown token")
            return OAuthIdentity(SUBJECT, (MAIL_AUDIENCE,), (MAIL_SCOPE,))

        h = _Harness(validator)
        h.enable_tls()
        h.pump(b"EHLO example.com\r\n")
        yield h
        h.close()

    def _auth(self, harness: _Harness, raw: bytes):
        harness.pump(b"AUTH OAUTHBEARER " + b64encode(raw) + b"\r\n")

    def test_mechanism_advertised_over_tls(self, harness):
        advertised = [
            line
            for line in b"".join(harness.responses).split(b"\r\n")
            if line.startswith(b"250-AUTH")
        ]
        assert advertised == [b"250-AUTH LOGIN OAUTHBEARER PLAIN"]

    def test_successful_login_uses_validated_identity(self, harness):
        self._auth(harness, bearer_response(GOOD_TOKEN))
        assert harness.codes()[-1] == 235
        session = harness.server.session
        assert session.authenticated is True
        assert isinstance(session.auth_data, OAuthIdentity)
        assert session.auth_data.subject == SUBJECT
        # Later MAIL authorization relies on the validated identity.
        harness.pump(b"MAIL FROM: <" + SUBJECT.encode() + b">\r\nQUIT\r\n")
        assert harness.codes()[-2:] == [250, 221]

    def test_cross_service_audience_fails(self):
        def validator(request):
            return OAuthIdentity(SUBJECT, (OTHER_AUDIENCE,), (MAIL_SCOPE,))

        h = _Harness(validator)
        h.enable_tls()
        h.pump(b"EHLO example.com\r\n")
        h.pump(
            b"AUTH OAUTHBEARER "
            + b64encode(bearer_response(GOOD_TOKEN))
            + b"\r\n"
        )
        # Preserve the RFC 7628 error interaction: 334 JSON, then dummy, 535.
        assert h.codes()[-1] == 334
        h.pump(b64encode(KVSEP) + b"\r\n")
        assert h.codes()[-1] == 535
        assert h.server.session.authenticated is not True
        h.close()

    def test_authzid_impersonation_fails(self, harness):
        raw = bearer_response(GOOD_TOKEN, authzid=ATTACKER)
        self._auth(harness, raw)
        assert harness.codes()[-1] == 334
        harness.pump(b64encode(KVSEP) + b"\r\n")
        assert harness.codes()[-1] == 535
        assert harness.server.session.authenticated is not True

    def test_bad_token_preserves_error_exchange(self, harness):
        raw = bearer_response(BAD_TOKEN)
        self._auth(harness, raw)
        # The JSON error is delivered in a normal 334 message.
        challenge_lines = [
            line
            for line in b"".join(harness.responses).split(b"\r\n")
            if line.startswith(b"334 ")
        ]
        assert len(challenge_lines) == 1
        payload = challenge_lines[0][4:]
        error = json.loads(b64decode(payload))
        assert error["status"] == ERR_INVALID_TOKEN
        assert error["scope"] == MAIL_SCOPE
        # Dummy client response completes the exchange; then auth fails.
        harness.pump(b64encode(KVSEP) + b"\r\n")
        assert harness.codes()[-1] == 535
        assert harness.server.session.authenticated is not True

    def test_error_exchange_abort(self, harness):
        self._auth(harness, bearer_response(BAD_TOKEN))
        assert harness.codes()[-1] == 334
        harness.pump(b"*\r\n")
        assert harness.codes()[-1] == 501
        assert harness.server.session.authenticated is not True

    def test_malformed_response_still_runs_error_exchange(self, harness):
        # A bare %x01 as the *initial* response is invalid (RFC 7628 3.1).
        harness.pump(
            b"AUTH OAUTHBEARER " + b64encode(KVSEP) + b"\r\n"
        )
        assert harness.codes()[-1] == 334
        challenge_lines = [
            line
            for line in b"".join(harness.responses).split(b"\r\n")
            if line.startswith(b"334 ")
        ]
        error = json.loads(b64decode(challenge_lines[0][4:]))
        assert error["status"] == ERR_INVALID_REQUEST
        harness.pump(b64encode(KVSEP) + b"\r\n")
        assert harness.codes()[-1] == 535
        assert harness.server.session.authenticated is not True

    def test_wrong_dummy_response_rejected(self, harness):
        self._auth(harness, bearer_response(BAD_TOKEN))
        assert harness.codes()[-1] == 334
        harness.pump(b64encode(b"not-the-dummy") + b"\r\n")
        assert harness.codes()[-1] == 501
        assert harness.server.session.authenticated is not True

    def test_bad_base64_rejected(self, harness):
        harness.pump(b"AUTH OAUTHBEARER not-base64!!\r\n")
        assert harness.codes()[-1] == 501
        assert harness.server.session.authenticated is not True

    def test_two_step_initial_response_success(self, harness):
        # "AUTH OAUTHBEARER" with no payload yields an empty 334 challenge.
        harness.pump(b"AUTH OAUTHBEARER\r\n")
        assert harness.codes()[-1] == 334
        harness.pump(
            b64encode(bearer_response(GOOD_TOKEN)) + b"\r\n"
        )
        assert harness.codes()[-1] == 235
        assert harness.server.session.authenticated is True

    def test_two_step_abort_leaves_session_unauthenticated(self, harness):
        harness.pump(b"AUTH OAUTHBEARER\r\n")
        assert harness.codes()[-1] == 334
        harness.pump(b"*\r\n")
        assert harness.codes()[-1] == 501
        assert harness.server.session.authenticated is not True

    def test_two_step_bad_base64_rejected(self, harness):
        harness.pump(b"AUTH OAUTHBEARER\r\n")
        assert harness.codes()[-1] == 334
        harness.pump(b"not-base64!!\r\n")
        assert harness.codes()[-1] == 501
        assert harness.server.session.authenticated is not True

    def test_error_body_omits_scope_when_none_required(self):
        def validator(request):
            raise OAuthBearerError(ERR_INVALID_TOKEN, "unknown token")

        h = _Harness(validator, oauth_required_scopes=[])
        h.enable_tls()
        h.pump(b"EHLO example.com\r\n")
        h.pump(
            b"AUTH OAUTHBEARER "
            + b64encode(bearer_response(BAD_TOKEN))
            + b"\r\n"
        )
        challenge_lines = [
            line
            for line in b"".join(h.responses).split(b"\r\n")
            if line.startswith(b"334 ")
        ]
        error = json.loads(b64decode(challenge_lines[0][4:]))
        assert error == {"status": ERR_INVALID_TOKEN}
        h.pump(b64encode(KVSEP) + b"\r\nQUIT\r\n")
        assert h.server.session.authenticated is not True
        h.close()

    def test_local_endpoint_uses_transport_sockname(self, harness):
        harness.transport.get_extra_info = mock.Mock(
            return_value=("127.0.0.1", 587)
        )
        host, port = harness.server._local_service_endpoint()
        assert host == harness.server.hostname
        assert port == 587

    def test_host_port_enforced_against_local_endpoint(self, harness):
        # The transport reports port 587 and the service hostname, matching the
        # response, so the local endpoint policy accepts it and the token is
        # validated successfully.
        harness.transport.get_extra_info = mock.Mock(
            return_value=("127.0.0.1", 587)
        )
        raw = bearer_response(
            GOOD_TOKEN,
            host=harness.server.hostname,
            port=587,
        )
        self._auth(harness, raw)
        assert harness.codes()[-1] == 235
        assert harness.server.session.authenticated is True

    def test_port_mismatch_against_local_endpoint_fails(self, harness):
        harness.transport.get_extra_info = mock.Mock(
            return_value=("127.0.0.1", 25)
        )
        self._auth(harness, bearer_response(GOOD_TOKEN, port=587))
        assert harness.codes()[-1] == 334
        harness.pump(b64encode(KVSEP) + b"\r\n")
        assert harness.codes()[-1] == 535
        assert harness.server.session.authenticated is not True

    def test_tls_required(self):
        def validator(request):
            return OAuthIdentity(SUBJECT, (MAIL_AUDIENCE,), (MAIL_SCOPE,))

        h = _Harness(validator)  # TLS deliberately NOT enabled
        h.pump(b"EHLO example.com\r\n")
        h.pump(
            b"AUTH OAUTHBEARER "
            + b64encode(bearer_response(GOOD_TOKEN))
            + b"\r\n"
        )
        assert h.codes()[-1] == 538
        assert h.server.session.authenticated is not True
        h.close()

    def test_no_token_in_logs(self, caplog):
        def validator(request):
            if request.token != GOOD_TOKEN:
                raise OAuthBearerError(ERR_INVALID_TOKEN, "unknown token")
            return OAuthIdentity(SUBJECT, (MAIL_AUDIENCE,), (MAIL_SCOPE,))

        h = _Harness(validator)
        h.enable_tls()
        with caplog.at_level(logging.DEBUG, logger="mail.log"):
            h.pump(b"EHLO example.com\r\n")
            h.pump(
                b"AUTH OAUTHBEARER "
                + b64encode(bearer_response(BAD_TOKEN))
                + b"\r\n"
            )
            h.pump(b64encode(KVSEP) + b"\r\n")
            h.pump(b"QUIT\r\n")
        blob = b64encode(bearer_response(BAD_TOKEN)).decode()
        for record in caplog.records:
            assert GOOD_TOKEN not in record.getMessage()
            assert BAD_TOKEN not in record.getMessage()
            assert blob not in record.getMessage()
        h.close()


# endregion
