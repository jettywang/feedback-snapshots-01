from io import BytesIO
from socket import socket
from typing import Callable, Optional, Tuple
from http.client import HTTPResponse
from nassl.ssl_client import BaseSslClient


class _FakeSocket(BytesIO):
    def makefile(self, *args, **kw):  # type: ignore
        return self


class NotAValidHttpResponseError(Exception):
    pass


def _parse_status_code(headers_block: bytes) -> Optional[int]:
    """Best-effort parsing of the status code; invalid status lines are handled by HTTPResponse later."""
    status_line = headers_block.split(b"\r\n", 1)[0]
    parts = status_line.split(None, 2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


class HttpResponseParser:
    """Utility to parse HTTP responses - http://pythonwise.blogspot.com/2010/02/parse-http-response.html."""

    @classmethod
    def parse_from_socket(cls, sock: socket) -> HTTPResponse:
        http_response, _ = cls._parse(sock.recv)
        return http_response

    @classmethod
    def parse_from_socket_and_return_leftover(
        cls, sock: socket, already_received: bytes = b""
    ) -> Tuple[HTTPResponse, bytes]:
        """Parse an HTTP response and also return any extra bytes received after the response's headers.

        When tunneling (e.g. via HTTP CONNECT), the bytes that follow the response's headers belong to the
        tunneled stream and must not be discarded.
        """
        return cls._parse(sock.recv, already_received)

    @classmethod
    def parse_from_ssl_connection(cls, ssl_conn: BaseSslClient) -> HTTPResponse:
        http_response, _ = cls._parse(ssl_conn.read)
        return http_response

    @staticmethod
    def _parse(read_method: Callable, already_received: bytes = b"") -> Tuple[HTTPResponse, bytes]:
        """Trick to standardize the API between sockets and SSLConnection objects."""
        response = already_received
        while True:
            while b"HTTP/" not in response or b"\r\n\r\n" not in response:
                # Parse until the end of the headers
                next_chunk = read_method(4096)
                if not next_chunk:
                    # The peer closed the connection before the full response was received
                    raise NotAValidHttpResponseError("Connection was closed before the HTTP response was received")
                response += next_chunk

            # Bytes past the end of the headers do not belong to this HTTP response
            headers, _, leftover = response.partition(b"\r\n\r\n")
            status_code = _parse_status_code(headers)
            if status_code is not None and 100 <= status_code < 200:
                # Interim 1xx response; the final response is yet to be received
                response = leftover
                continue

            fake_sock = _FakeSocket(headers + b"\r\n\r\n")
            http_response = HTTPResponse(fake_sock)  # type: ignore
            http_response.begin()

            if http_response.version == 9:
                # HTTP 0.9 => Probably not an HTTP response
                raise NotAValidHttpResponseError()

            return http_response, leftover
