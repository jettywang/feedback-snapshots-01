# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
In-memory transport tests for the trusted-proxy admission policy.

These tests never bind a socket. A mocked transport reports a configurable
*real* peer so we can prove that:

* only peers admitted by a TrustedProxies policy may drive the PROXY protocol;
* an untrusted, directly reachable client cannot masquerade as an internal
  source by sending a PROXY preamble;
* a self-reported SSL TLV is treated purely as data and can neither make the
  process consider itself TLS-secured nor relax the AUTH TLS requirement;
* STARTTLS / RSET never change the trust source of the connection metadata.
"""

import asyncio
import struct
from contextlib import suppress
from typing import Callable, List, Optional

import pytest
from pytest_mock import MockFixture

from aiosmtpd.handlers import Sink
from aiosmtpd.proxy_protocol import (
    V2_CMD,
    V2_SIGNATURE,
    AF,
    PROTO,
    ProxyData,
    TrustedProxies,
    is_proxy_signature,
)
from aiosmtpd.smtp import SMTP as SMTPServer
from aiosmtpd.smtp import Session as SMTPSession
from aiosmtpd.smtp import Envelope as SMTPEnvelope

TRUSTED_PEER = ("10.0.0.7", 51000)
UNTRUSTED_PEER = ("203.0.113.9", 51001)
TRUSTED_NET = "10.0.0.0/8"

V1_HANDSHAKE = b"PROXY TCP4 198.51.100.20 10.0.0.7 40000 25\r\n"
V1_CLAIMED_SRC = "198.51.100.20"


def build_v2_ssl_handshake(
    *,
    command: V2_CMD = V2_CMD.PROXY,
    src: str = "198.51.100.20",
    dst: str = "10.0.0.7",
    src_port: int = 40000,
    dst_port: int = 25,
) -> bytes:
    """Build a PROXYv2 INET/STREAM header carrying a forged SSL TLV."""
    import socket as _socket

    src_b = _socket.inet_aton(src)
    dst_b = _socket.inet_aton(dst)
    addr = src_b + dst_b + struct.pack("!HH", src_port, dst_port)
    # PP2_TYPE_SSL (0x20): client=0x01, verify=0, no sub-TLVs => parser sets
    # SSL=True, i.e. the proxy *claims* the client<->proxy leg is TLS.
    ssl_tlv = b"\x20" + struct.pack("!H", 5) + b"\x01" + struct.pack("!I", 0)
    payload = addr + ssl_tlv
    ver_cmd = 0x20 | int(command)
    fam_proto = (AF.INET << 4) | PROTO.STREAM
    return (
        V2_SIGNATURE
        + bytes([ver_cmd, fam_proto])
        + struct.pack("!H", len(payload))
        + payload
    )


class RecordingHandler(Sink):
    def __init__(self, accept: bool = True):
        self.proxy_datas: List[ProxyData] = []
        self.sessions: List[SMTPSession] = []
        self.accept = accept

    async def handle_PROXY(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        proxy_data: ProxyData,
    ) -> bool:
        self.proxy_datas.append(proxy_data)
        self.sessions.append(session)
        return self.accept


@pytest.fixture
def make_protocol(mocker: MockFixture, temp_event_loop: asyncio.AbstractEventLoop):
    transport = mocker.Mock()
    responses: List[bytes] = []
    transport.write = responses.append

    def factory(
        peername,
        *,
        trusted: Optional[TrustedProxies] = None,
        handler: Optional[RecordingHandler] = None,
        require_starttls: bool = False,
        tls_context=None,
        auth_required: bool = False,
        auth_require_tls: bool = True,
        proxy_timeout: float = 1.0,
        enable_proxy: bool = True,
    ):
        handler = handler or RecordingHandler()
        kwargs = dict(
            loop=temp_event_loop,
            handler=handler,
            auth_required=auth_required,
            auth_require_tls=auth_require_tls,
        )
        if tls_context is not None:
            kwargs["tls_context"] = tls_context
            kwargs["require_starttls"] = require_starttls
        if enable_proxy:
            kwargs["proxy_protocol_timeout"] = proxy_timeout
            if trusted is not None:
                kwargs["proxy_protocol_trusted_proxies"] = trusted
        protocol = SMTPServer(**kwargs)
        transport.get_extra_info = lambda name, default=None, _pn=peername: (
            _pn if name == "peername" else default
        )
        protocol.connection_made(transport)
        return protocol

    def run(protocol: SMTPServer, stop_after: float = 0.2):
        loop = temp_event_loop
        loop.call_later(stop_after, protocol._handler_coroutine.cancel)
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(protocol._handler_coroutine)

    return factory, transport, responses, run


def joined_response(responses: List[bytes]) -> bytes:
    return b"".join(responses)


def greeting_sent(responses: List[bytes]) -> bool:
    """A 220 greeting proves the connection was admitted past PROXY handling."""
    return joined_response(responses).startswith(b"220 ")


class TestTrustedProxiesPolicy:
    def test_address_and_cidr_and_unix(self):
        policy = TrustedProxies(
            [TRUSTED_NET, "192.168.1.5", "2001:db8::/32", "/run/lb.sock"]
        )
        assert policy.is_trusted(("10.255.0.1", 9))
        assert policy.is_trusted(("192.168.1.5", 9))
        assert policy.is_trusted(("2001:db8::abcd", 9, 0, 0))
        assert policy.is_trusted("/run/lb.sock")
        assert not policy.is_trusted(("11.0.0.1", 9))
        assert not policy.is_trusted(("2002::1", 9, 0, 0))
        assert not policy.is_trusted("/run/other.sock")

    def test_empty_policy_trusts_nobody(self):
        assert not TrustedProxies().is_trusted(("10.0.0.7", 9))
        assert not TrustedProxies().is_trusted(None)
        assert not TrustedProxies()

    def test_none_peername_rejected(self):
        assert not TrustedProxies([TRUSTED_NET]).is_trusted(None)

    def test_signature_detection(self):
        assert is_proxy_signature(b"PROXY TCP4 ...")
        assert is_proxy_signature(V2_SIGNATURE)
        assert not is_proxy_signature(b"HELO example.org\r\n")
        assert not is_proxy_signature(b"EHLO mail\r\n")


class TestProxyAdmission:
    def test_trusted_proxy_v1_accepted_and_origin_kept_separate(
        self, make_protocol
    ):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(TRUSTED_PEER, trusted=policy)
        protocol.data_received(V1_HANDSHAKE + b"EHLO example.org\r\n")
        run(protocol)

        handler = protocol.event_handler
        assert len(handler.proxy_datas) == 1
        session = protocol.session
        # Real peer is the adjacent proxy, never overwritten by the header.
        assert session.actual_peer == TRUSTED_PEER
        assert session.peer == TRUSTED_PEER
        # Claimed origin is available separately.
        assert str(session.proxied_peer[0]) == V1_CLAIMED_SRC
        assert greeting_sent(responses)
        assert joined_response(responses).startswith(b"220 ")
        assert b"250" in joined_response(responses)

    def test_trusted_proxy_v2_local_accepted(self, make_protocol):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(TRUSTED_PEER, trusted=policy)
        local_header = (
            V2_SIGNATURE
            + bytes([0x20, 0x00])
            + struct.pack("!H", 0)
        )
        protocol.data_received(local_header + b"EHLO example.org\r\n")
        run(protocol)
        assert len(protocol.event_handler.proxy_datas) == 1
        assert protocol.session.proxy_data.command == V2_CMD.LOCAL
        # LOCAL carries no addresses -> no claimed origin.
        assert protocol.session.proxied_peer is None
        assert protocol.session.actual_peer == TRUSTED_PEER
        assert greeting_sent(responses)

    def test_untrusted_direct_proxy_preamble_rejected(self, make_protocol):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(UNTRUSTED_PEER, trusted=policy)
        protocol.data_received(V1_HANDSHAKE + b"EHLO example.org\r\n")
        run(protocol)

        # Header must never be parsed or handed to the hook.
        assert protocol.event_handler.proxy_datas == []
        assert protocol.session.proxy_data is None
        assert not greeting_sent(responses)
        # No SMTP greeting is leaked to a spoofing client.
        assert joined_response(responses) == b""

    def test_untrusted_direct_v2_preamble_rejected(self, make_protocol):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(UNTRUSTED_PEER, trusted=policy)
        protocol.data_received(build_v2_ssl_handshake() + b"EHLO x\r\n")
        run(protocol)
        assert protocol.event_handler.proxy_datas == []
        assert not greeting_sent(responses)
        assert joined_response(responses) == b""

    def test_untrusted_direct_plain_smtp_served_without_proxy_data(
        self, make_protocol
    ):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(UNTRUSTED_PEER, trusted=policy)
        protocol.data_received(b"EHLO example.org\r\n")
        run(protocol)

        # A non-PROXY client is still served (mixed LB/direct deployment), but
        # no proxy metadata is ever associated with the session.
        assert greeting_sent(responses)
        assert protocol.session.proxy_data is None
        assert protocol.session.proxied_peer is None
        assert protocol.session.actual_peer == UNTRUSTED_PEER
        out = joined_response(responses)
        assert out.startswith(b"220 ")
        assert b"250" in out

    def test_invalid_handshake_from_trusted_peer_rejected(self, make_protocol):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(TRUSTED_PEER, trusted=policy)
        protocol.data_received(b"PROXY GARBAGE not a real header\r\n")
        run(protocol)
        assert not greeting_sent(responses)
        assert protocol.session.proxy_data is not None
        assert not protocol.session.proxy_data.valid

    def test_hook_rejection_still_closes(self, make_protocol):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        handler = RecordingHandler(accept=False)
        protocol = factory(TRUSTED_PEER, trusted=policy, handler=handler)
        protocol.data_received(V1_HANDSHAKE)
        run(protocol)
        assert len(handler.proxy_datas) == 1
        assert not greeting_sent(responses)


class TestProxyFailures:
    def _drive_custom_reader(self, make_protocol, reader, peername=TRUSTED_PEER):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(peername, trusted=policy, proxy_timeout=0.3)
        protocol._reader = reader
        try:
            run(protocol, stop_after=1.0)
        except asyncio.IncompleteReadError:  # pragma: no cover - defensive
            pass
        return protocol, transport, responses

    def test_disconnect_during_v1_signature_closes(self, make_protocol):
        class PartialV1:
            async def readexactly(self, n):
                raise asyncio.IncompleteReadError(partial=b"PR", expected=n)

            async def read(self, n=-1):
                return b""

        protocol, transport, responses = self._drive_custom_reader(
            make_protocol, PartialV1()
        )
        assert not greeting_sent(responses)
        assert transport.close.called

    def test_disconnect_during_v2_signature_closes(self, make_protocol):
        class PartialV2:
            def __init__(self):
                self.stage = 0

            async def readexactly(self, n):
                self.stage += 1
                if self.stage == 1:
                    return V2_SIGNATURE[:5]
                raise asyncio.IncompleteReadError(
                    partial=V2_SIGNATURE[5:9], expected=n
                )

            async def read(self, n=-1):
                return b""

        protocol, transport, responses = self._drive_custom_reader(
            make_protocol, PartialV2()
        )
        assert not greeting_sent(responses)
        assert transport.close.called

    def test_timeout_before_signature_closes(self, make_protocol):
        class StallingReader:
            async def readexactly(self, n):
                await asyncio.sleep(100)

            async def read(self, n=-1):
                await asyncio.sleep(100)

        protocol, transport, responses = self._drive_custom_reader(
            make_protocol, StallingReader()
        )
        # The proxy timeout fires and closes the transport; no greeting leaks.
        assert not greeting_sent(responses)
        assert transport.close.called


class TestForgedSslTLV:
    def _server_with_forged_ssl(self, make_protocol, peername, policy):
        factory, transport, responses, run = make_protocol
        protocol = factory(peername, trusted=policy)
        protocol.data_received(build_v2_ssl_handshake() + b"EHLO example.org\r\n")
        run(protocol)
        return protocol, transport, responses

    def test_ssl_tlv_is_only_a_report(self, make_protocol):
        policy = TrustedProxies([TRUSTED_NET])
        protocol, transport, responses = self._server_with_forged_ssl(
            make_protocol, TRUSTED_PEER, policy
        )
        assert greeting_sent(responses)
        proxy_data = protocol.session.proxy_data
        assert proxy_data is not None and proxy_data.valid
        # The proxy *claims* SSL via TLV ...
        assert proxy_data.tlv is not None
        assert proxy_data.tlv.SSL is True
        # ... but this process never established TLS itself.
        assert protocol._tls_protocol is None
        assert protocol.session.ssl is None

    def test_forged_ssl_tlv_cannot_enable_auth_without_tls(
        self, make_protocol
    ):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        # AUTH advertised only when TLS is up (auth_require_tls defaults True).
        protocol = factory(
            TRUSTED_PEER, trusted=policy, auth_required=True
        )
        protocol.data_received(
            build_v2_ssl_handshake()
            + b"EHLO example.org\r\n"
            + b"AUTH PLAIN AHRlc3QAcGFzcw==\r\n"
        )
        run(protocol)
        out = joined_response(responses)
        # No AUTH extension advertised because there is no real TLS.
        assert b"AUTH" not in out
        # And an explicit AUTH attempt is refused by the real-TLS gate.
        assert b"538" in out
        assert protocol.session.authenticated is not True
        # Still no local TLS, regardless of the claimed TLV.
        assert protocol._tls_protocol is None

    def test_untrusted_peer_forged_ssl_tlv_rejected(self, make_protocol):
        policy = TrustedProxies([TRUSTED_NET])
        protocol, transport, responses = self._server_with_forged_ssl(
            make_protocol, UNTRUSTED_PEER, policy
        )
        # Spoofed SSL does not buy admission for an untrusted direct peer.
        assert not greeting_sent(responses)
        assert protocol.session.proxy_data is None
        assert joined_response(responses) == b""


class TestMetadataStability:
    def test_rset_does_not_change_trust_metadata(self, make_protocol):
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(TRUSTED_PEER, trusted=policy)
        protocol.data_received(
            V1_HANDSHAKE + b"EHLO example.org\r\nRSET\r\n"
        )
        run(protocol)
        session = protocol.session
        assert session.actual_peer == TRUSTED_PEER
        assert str(session.proxied_peer[0]) == V1_CLAIMED_SRC
        assert session.proxy_data is not None and session.proxy_data.valid
        # RSET only resets the envelope, never the trust source.
        assert b"250 OK" in joined_response(responses)

    def test_starttls_does_not_change_trust_metadata(
        self, make_protocol, mocker: MockFixture
    ):
        # Real STARTTLS (smtp_STARTTLS) swaps the transport and re-enters
        # connection_made(), which resets RFC 3207 transaction state. The trust
        # boundary, however, does not move: the real peer stays the same and the
        # proxy metadata must be carried over from the same admitted PROXY header.
        factory, transport, responses, run = make_protocol
        policy = TrustedProxies([TRUSTED_NET])
        protocol = factory(TRUSTED_PEER, trusted=policy)
        protocol.data_received(V1_HANDSHAKE)
        run(protocol)

        before_peer = protocol.session.actual_peer
        before_claimed = protocol.session.proxied_peer
        before_proxy = protocol.session.proxy_data

        # Model the SSL transport upgrade exactly as smtp_STARTTLS does.
        tls_extra = {"ssl_object": object()}
        protocol._original_transport = transport
        protocol._tls_protocol = mocker.Mock(_extra=tls_extra)
        protocol.connection_made(transport)

        # Transaction state was reset, but trust metadata was preserved.
        assert protocol.session.actual_peer == before_peer == TRUSTED_PEER
        assert protocol.session.proxied_peer == before_claimed
        assert protocol.session.proxy_data is before_proxy
        # Real local TLS state is what marks the session secure, not any TLV.
        assert protocol.session.ssl == tls_extra


class TestLegacyNoProxy:
    def test_proxy_disabled_serves_plain_smtp(self, make_protocol):
        factory, transport, responses, run = make_protocol
        # No proxy_protocol_timeout -> PROXY support stays off entirely.
        protocol = factory(UNTRUSTED_PEER, enable_proxy=False)
        protocol.data_received(b"EHLO example.org\r\n")
        run(protocol)
        assert greeting_sent(responses)
        assert protocol.session.proxy_data is None
        assert protocol.session.actual_peer == UNTRUSTED_PEER
        assert joined_response(responses).startswith(b"220 ")

    def test_proxy_disabled_ignores_proxy_like_bytes_as_smtp(
        self, make_protocol
    ):
        factory, transport, responses, run = make_protocol
        protocol = factory(UNTRUSTED_PEER, enable_proxy=False)
        # With PROXY disabled the bytes are just an unknown SMTP command.
        protocol.data_received(b"PROXY TCP4 1.2.3.4 5.6.7.8 9 10\r\n")
        run(protocol)
        out = joined_response(responses)
        assert out.startswith(b"220 ")
        assert b"500" in out
        assert protocol.session.proxy_data is None

    def test_default_no_policy_preserves_legacy_trust_any_peer(
        self, make_protocol
    ):
        factory, transport, responses, run = make_protocol
        # No explicit policy: any adjacent peer's valid header is honoured.
        protocol = factory(UNTRUSTED_PEER, trusted=None)
        protocol.data_received(V1_HANDSHAKE + b"EHLO example.org\r\n")
        run(protocol)
        assert len(protocol.event_handler.proxy_datas) == 1
        assert greeting_sent(responses)
