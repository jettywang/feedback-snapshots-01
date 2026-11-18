"""Offline regression tests for establishing TLS connections via an HTTP proxy (HTTP CONNECT).

No network access is performed: a metered fake socket scripts the proxy's responses chunk by chunk and a
handshake stand-in replaces the nassl SSL client, so the tests can observe the exact bytes the TLS client
receives once the CONNECT response has been fully consumed, as well as the socket's lifecycle.
"""

import socket
from base64 import b64encode
from collections import deque
from traceback import TracebackException
from typing import Deque, List, Optional, Tuple, Union

import pytest

from sslyze.connection_helpers import tls_connection
from sslyze.connection_helpers.tls_connection import SslConnection
from sslyze.errors import (
    ConnectionToHttpProxyFailed,
    ConnectionToHttpProxyTimedOut,
    HttpProxyRejectedConnection,
)
from sslyze.server_connectivity import TlsVersionEnum
from sslyze.server_setting import HttpProxySettings, ServerNetworkConfiguration, ServerNetworkLocation

PROXY_HOSTNAME = "proxy.example.com"
PROXY_PORT = 3128
TARGET_HOSTNAME = "target.example.com"
TARGET_PORT = 443

PROXY_USER = "proxy_user"
PROXY_PASSWORD = "proxy_password"
PROXY_AUTH_TOKEN = b64encode(f"{PROXY_USER}:{PROXY_PASSWORD}".encode("utf-8")).decode("utf-8")

SUCCESS_RESPONSE = b"HTTP/1.1 200 Connection established\r\n\r\n"
# Bytes sent by the TLS server right after the tunnel is established (e.g. a ServerHello)
TLS_SERVER_BYTES = b"\x16\x03\x03\x00\x7f\x02\x00\x00\x7b\x03\x03" + b"\xaa" * 120


class MeteredSocket:
    """A fake socket that returns scripted chunks on recv() and records every interaction."""

    def __init__(self, script: List[Union[bytes, Exception]]) -> None:
        self._script: Deque[Union[bytes, Exception]] = deque(script)
        self.recv_call_sizes: List[int] = []
        self.sent_data = b""
        self.close_call_count = 0
        self._consecutive_eof_count = 0

    def sendall(self, data: bytes) -> None:
        self.sent_data += bytes(data)

    def send(self, data: bytes) -> int:
        self.sent_data += bytes(data)
        return len(data)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        self.recv_call_sizes.append(bufsize)
        if not self._script:
            self._consecutive_eof_count += 1
            if self._consecutive_eof_count > 3:
                raise RuntimeError("recv() was called repeatedly after EOF: the response parser is stuck in a loop")
            return b""
        self._consecutive_eof_count = 0
        next_item = self._script[0]
        if isinstance(next_item, Exception):
            self._script.popleft()
            raise next_item
        # A real socket returns at most bufsize bytes per recv() call
        data, remaining = next_item[:bufsize], next_item[bufsize:]
        if remaining:
            self._script[0] = remaining
        else:
            self._script.popleft()
        return data

    @property
    def unconsumed_data(self) -> bytes:
        """Scripted data that was never consumed via recv()."""
        return b"".join(item for item in self._script if isinstance(item, bytes))

    def settimeout(self, timeout: Optional[float]) -> None:
        pass

    def gettimeout(self) -> Optional[float]:
        return None

    def setblocking(self, flag: bool) -> None:
        pass

    def close(self) -> None:
        self.close_call_count += 1


class TlsHandshakeStandIn:
    """A drop-in replacement for the nassl SSL client to observe the TLS layer without doing real TLS."""

    def __init__(self) -> None:
        self.server_name_indication: Optional[str] = None
        self.cipher_list: Optional[str] = None
        self.underlying_socket = None
        self.expected_server_bytes_count = 0
        self.received_tls_bytes = b""
        self.sent_tls_bytes = b""
        self.handshake_call_count = 0
        self.shutdown_call_count = 0

    def set_cipher_list(self, cipher_list: str) -> None:
        self.cipher_list = cipher_list

    def set_tlsext_host_name(self, server_name_indication: str) -> None:
        self.server_name_indication = server_name_indication

    def set_underlying_socket(self, sock) -> None:
        self.underlying_socket = sock

    def do_handshake(self) -> None:
        self.handshake_call_count += 1
        # Pretend to send a ClientHello and read the server's flight; use small, odd-sized reads to ensure
        # leftover data from the CONNECT exchange is correctly sliced regardless of the requested size
        self.sent_tls_bytes = b"<CLIENT_HELLO>"
        self.underlying_socket.sendall(self.sent_tls_bytes)
        while len(self.received_tls_bytes) < self.expected_server_bytes_count:
            chunk = self.underlying_socket.recv(7)
            if not chunk:
                break
            self.received_tls_bytes += chunk

    def shutdown(self) -> None:
        self.shutdown_call_count += 1


def _server_location(with_proxy_auth: bool = False) -> ServerNetworkLocation:
    proxy_settings = HttpProxySettings(
        hostname=PROXY_HOSTNAME,
        port=PROXY_PORT,
        basic_auth_user=PROXY_USER if with_proxy_auth else None,
        basic_auth_password=PROXY_PASSWORD if with_proxy_auth else None,
    )
    return ServerNetworkLocation(hostname=TARGET_HOSTNAME, port=TARGET_PORT, http_proxy_settings=proxy_settings)


def _make_connection(
    monkeypatch,
    proxy_script: List[Union[bytes, Exception]],
    server_location: Optional[ServerNetworkLocation] = None,
    network_configuration: Optional[ServerNetworkConfiguration] = None,
) -> Tuple[SslConnection, MeteredSocket, TlsHandshakeStandIn, List]:
    metered_socket = MeteredSocket(proxy_script)
    create_connection_calls: List = []

    def fake_create_connection(*args, **kwargs):
        create_connection_calls.append((args, kwargs))
        return metered_socket

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    stand_in = TlsHandshakeStandIn()
    monkeypatch.setattr(tls_connection, "SslClient", lambda **kwargs: stand_in)

    if server_location is None:
        server_location = _server_location()
    if network_configuration is None:
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication=server_location.hostname,
            network_timeout=3,
            network_max_retries=1,
        )

    ssl_connection = SslConnection(
        server_location=server_location,
        network_configuration=network_configuration,
        tls_version=TlsVersionEnum.TLS_1_2,
        should_ignore_client_auth=False,
    )
    return ssl_connection, metered_socket, stand_in, create_connection_calls


class TestConnectRequestCommand:
    def test_connect_request_is_sent_to_proxy_and_targets_server_hostname(self, monkeypatch):
        ssl_conn, metered_socket, stand_in, create_connection_calls = _make_connection(
            monkeypatch, [SUCCESS_RESPONSE]
        )

        ssl_conn.connect(should_retry_connection=False)

        # The TCP connection was opened to the proxy, not to the target server
        assert create_connection_calls == [(((PROXY_HOSTNAME, PROXY_PORT),), {"timeout": 3})]
        # The CONNECT command targets the server's hostname and port, and nothing else was sent before the TLS data
        expected_connect_request = b"CONNECT target.example.com:443 HTTP/1.1\r\n\r\n"
        assert metered_socket.sent_data == expected_connect_request + stand_in.sent_tls_bytes
        assert b"Proxy-Authorization" not in metered_socket.sent_data

    def test_proxy_credentials_are_only_sent_within_the_connect_request(self, monkeypatch):
        ssl_conn, metered_socket, stand_in, _ = _make_connection(
            monkeypatch,
            [SUCCESS_RESPONSE + TLS_SERVER_BYTES],
            server_location=_server_location(with_proxy_auth=True),
        )
        stand_in.expected_server_bytes_count = len(TLS_SERVER_BYTES)

        ssl_conn.connect(should_retry_connection=False)

        # The credentials appear exactly once overall: within the CONNECT request sent to the proxy
        assert metered_socket.sent_data.count(PROXY_AUTH_TOKEN.encode("utf-8")) == 1
        expected_connect_request = (
            b"CONNECT target.example.com:443 HTTP/1.1\r\n"
            b"Proxy-Authorization: Basic " + PROXY_AUTH_TOKEN.encode("utf-8") + b"\r\n\r\n"
        )
        assert metered_socket.sent_data.startswith(expected_connect_request)
        # The bytes sent into the tunnel after the CONNECT exchange never contain the proxy credentials
        sent_within_tunnel = metered_socket.sent_data[len(expected_connect_request):]
        assert PROXY_AUTH_TOKEN.encode("utf-8") not in sent_within_tunnel
        assert PROXY_PASSWORD.encode("utf-8") not in sent_within_tunnel


class TestConnectResponseParsing:
    def test_fragmented_status_line_and_headers(self, monkeypatch):
        fragmented_response = [
            b"HT",
            b"TP/1.1 2",
            b"00 Connection estab",
            b"lished\r\nX-Proxy-Header: abc\r\n",
            b"\r\n",
        ]
        ssl_conn, metered_socket, stand_in, _ = _make_connection(monkeypatch, fragmented_response)

        ssl_conn.connect(should_retry_connection=False)

        assert stand_in.handshake_call_count == 1
        # The parser kept reading until the end of the headers
        assert len(metered_socket.recv_call_sizes) >= len(fragmented_response)

    def test_intermittent_1xx_responses_are_skipped(self, monkeypatch):
        script = [
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\nX-Proxy-Header: abc\r\n\r\n",
            SUCCESS_RESPONSE,
        ]
        ssl_conn, _, stand_in, _ = _make_connection(monkeypatch, script)

        ssl_conn.connect(should_retry_connection=False)

        assert stand_in.handshake_call_count == 1

    def test_intermittent_and_final_responses_arriving_in_the_same_segment(self, monkeypatch):
        script = [b"HTTP/1.1 100 Continue\r\n\r\n" + SUCCESS_RESPONSE]
        ssl_conn, _, stand_in, _ = _make_connection(monkeypatch, script)

        ssl_conn.connect(should_retry_connection=False)

        assert stand_in.handshake_call_count == 1

    def test_tls_data_arriving_with_the_headers_end_is_handed_to_the_tls_client(self, monkeypatch):
        # The proxy's response and the beginning of the TLS stream are received in a single read
        ssl_conn, metered_socket, stand_in, _ = _make_connection(
            monkeypatch, [SUCCESS_RESPONSE + TLS_SERVER_BYTES]
        )
        stand_in.expected_server_bytes_count = len(TLS_SERVER_BYTES)

        ssl_conn.connect(should_retry_connection=False)

        # The TLS client received exactly the bytes that followed the CONNECT response, in order
        assert stand_in.received_tls_bytes == TLS_SERVER_BYTES
        assert metered_socket.unconsumed_data == b""

    def test_tls_data_arriving_in_a_later_segment_is_not_consumed_by_the_response_parser(self, monkeypatch):
        ssl_conn, metered_socket, stand_in, _ = _make_connection(
            monkeypatch, [SUCCESS_RESPONSE, TLS_SERVER_BYTES]
        )
        stand_in.expected_server_bytes_count = len(TLS_SERVER_BYTES)

        ssl_conn.connect(should_retry_connection=False)

        assert stand_in.received_tls_bytes == TLS_SERVER_BYTES
        assert metered_socket.unconsumed_data == b""

    def test_non_200_status_is_rejected(self, monkeypatch):
        script = [b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"]
        ssl_conn, metered_socket, stand_in, _ = _make_connection(monkeypatch, script)

        with pytest.raises(HttpProxyRejectedConnection):
            ssl_conn.connect(should_retry_connection=False)

        # The failed socket was closed exactly once and no TLS handshake was attempted on it
        assert metered_socket.close_call_count == 1
        assert stand_in.handshake_call_count == 0

    def test_407_proxy_authentication_required_is_rejected(self, monkeypatch):
        script = [b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"]
        ssl_conn, metered_socket, stand_in, _ = _make_connection(
            monkeypatch, script, server_location=_server_location(with_proxy_auth=True)
        )

        with pytest.raises(HttpProxyRejectedConnection):
            ssl_conn.connect(should_retry_connection=False)

        assert metered_socket.close_call_count == 1
        assert stand_in.handshake_call_count == 0

    def test_truncated_response(self, monkeypatch):
        # The proxy closes the connection in the middle of the response headers
        script = [b"HTTP/1.1 200 Connection established\r\n"]
        ssl_conn, metered_socket, stand_in, _ = _make_connection(monkeypatch, script)

        with pytest.raises(ConnectionToHttpProxyFailed):
            ssl_conn.connect(should_retry_connection=False)

        assert metered_socket.close_call_count == 1
        assert stand_in.handshake_call_count == 0

    def test_proxy_closing_connection_before_any_response(self, monkeypatch):
        ssl_conn, metered_socket, stand_in, _ = _make_connection(monkeypatch, [])

        with pytest.raises(ConnectionToHttpProxyFailed):
            ssl_conn.connect(should_retry_connection=False)

        assert metered_socket.close_call_count == 1
        assert stand_in.handshake_call_count == 0

    def test_response_that_is_not_http(self, monkeypatch):
        script = [b"<html><body>not an HTTP response</body></html>"]
        ssl_conn, metered_socket, _, _ = _make_connection(monkeypatch, script)

        with pytest.raises(ConnectionToHttpProxyFailed):
            ssl_conn.connect(should_retry_connection=False)

        assert metered_socket.close_call_count == 1

    def test_timeout_while_waiting_for_response(self, monkeypatch):
        script = [socket.timeout("timed out")]
        ssl_conn, metered_socket, _, _ = _make_connection(monkeypatch, script)

        with pytest.raises(ConnectionToHttpProxyTimedOut):
            ssl_conn.connect(should_retry_connection=False)

        assert metered_socket.close_call_count == 1


class TestTunnelLifecycle:
    def test_socket_is_not_closed_on_success_and_tls_shutdown_happens_once(self, monkeypatch):
        ssl_conn, metered_socket, stand_in, _ = _make_connection(monkeypatch, [SUCCESS_RESPONSE])

        ssl_conn.connect(should_retry_connection=False)

        # Ownership of the socket was transferred to the TLS layer: the tunneling code did not close it
        assert metered_socket.close_call_count == 0

        ssl_conn.close()
        assert stand_in.shutdown_call_count == 1


class TestHostnameAndSniSemantics:
    def test_sni_uses_tls_server_name_indication_while_connect_uses_server_hostname(self, monkeypatch):
        server_location = _server_location()
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication="sni.example.com",
            network_timeout=3,
            network_max_retries=1,
        )
        ssl_conn, metered_socket, stand_in, _ = _make_connection(
            monkeypatch, [SUCCESS_RESPONSE], server_location, network_configuration
        )

        ssl_conn.connect(should_retry_connection=False)

        # The CONNECT command still targets the server's hostname...
        assert metered_socket.sent_data.startswith(b"CONNECT target.example.com:443 HTTP/1.1\r\n")
        # ...while the TLS ClientHello uses the configured Server Name Indication
        assert stand_in.server_name_indication == "sni.example.com"

    def test_sni_defaults_to_server_hostname(self, monkeypatch):
        server_location = _server_location()
        network_configuration = ServerNetworkConfiguration.default_for_server_location(server_location)
        ssl_conn, _, stand_in, _ = _make_connection(
            monkeypatch, [SUCCESS_RESPONSE], server_location, network_configuration
        )

        ssl_conn.connect(should_retry_connection=False)

        assert stand_in.server_name_indication == TARGET_HOSTNAME


class TestErrorReportsDoNotLeakProxyCredentials:
    @pytest.mark.parametrize(
        "script",
        [
            [b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"],
            [b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"],
            [b"HTTP/1.1 200 Connection established\r\n"],
        ],
    )
    def test_error_report_contains_no_proxy_credentials(self, monkeypatch, script):
        ssl_conn, _, _, _ = _make_connection(
            monkeypatch, script, server_location=_server_location(with_proxy_auth=True)
        )

        with pytest.raises(Exception) as exc_info:
            ssl_conn.connect(should_retry_connection=False)

        error_report = str(exc_info.value)
        error_report += exc_info.value.error_message
        error_report += "".join(TracebackException.from_exception(exc_info.value).format(chain=False))
        assert PROXY_AUTH_TOKEN not in error_report
        assert PROXY_PASSWORD not in error_report
