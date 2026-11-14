# Copyright 2024 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Tests for the opt-in CHUNKING / BDAT support (RFC 3030)."""

import asyncio
import hashlib
import socket
from contextlib import suppress
from typing import Any, List, Optional

import pytest

from aiosmtpd.smtp import SMTP, Envelope, Session


class RecordingHandler:
    """Counts delivery calls and records every delivered envelope."""

    def __init__(self) -> None:
        self.box: List[Envelope] = []
        self.calls = 0

    async def handle_DATA(
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        self.calls += 1
        self.box.append(envelope)
        return "250 OK"


class CommandProbeHandler(RecordingHandler):
    """
    Records every non-DATA command hook invoked.  A test fails if any hook
    other than the explicitly sent commands gets triggered, which would mean
    body bytes leaked into the command parser.
    """

    def __init__(self) -> None:
        super().__init__()
        self.leaked_commands: List[str] = []

    async def handle_NOOP(self, server, session, envelope, arg):
        self.leaked_commands.append("NOOP")
        return "250 OK"

    async def handle_RSET(self, server, session, envelope):
        self.leaked_commands.append("RSET")
        return "250 OK"

    async def handle_QUIT(self, server, session, envelope):
        self.leaked_commands.append("QUIT")
        return "221 Bye"


class BdatServer:
    """
    Drives an SMTP protocol instance over a socketpair so the tests do not
    need to bind a TCP port.
    """

    def __init__(
        self,
        handler: Any,
        loop: asyncio.AbstractEventLoop,
        **smtp_kwargs: Any,
    ) -> None:
        self.loop = loop
        self.handler = handler
        self.csock, self.ssock = socket.socketpair()
        self.protocol = SMTP(handler, loop=loop, **smtp_kwargs)
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def start(self) -> None:
        await self.loop.create_connection(
            lambda: self.protocol, sock=self.ssock
        )
        self.reader, self.writer = await asyncio.open_connection(
            sock=self.csock
        )

    async def read_reply(self) -> bytes:
        assert self.reader is not None
        lines: List[bytes] = []
        while True:
            line = await self.reader.readline()
            if not line:
                break
            lines.append(line)
            if len(line) >= 4 and line[3:4] == b" ":
                break
        return b"".join(lines)

    def send_raw(self, data: bytes) -> None:
        assert self.writer is not None
        self.writer.write(data)

    async def command(self, line: bytes) -> bytes:
        """Send a single command line (CRLF appended) and read its reply."""
        self.send_raw(line if line.endswith(b"\r\n") else line + b"\r\n")
        return await self.read_reply()

    async def bdat(self, body: bytes, last: bool = False) -> bytes:
        """Send one BDAT chunk: header line plus exactly len(body) octets."""
        header = b"BDAT " + str(len(body)).encode()
        if last:
            header += b" LAST"
        self.send_raw(header + b"\r\n" + body)
        return await self.read_reply()

    async def close(self) -> None:
        # Cancel the server-side handler task first so closing the loop does
        # not leave a dangling task behind.
        handler_task = self.protocol._handler_coroutine
        if handler_task is not None:
            handler_task.cancel()
            with suppress(asyncio.CancelledError):
                await handler_task
        if self.writer is not None:
            self.writer.close()
            with suppress(ConnectionResetError, BrokenPipeError, OSError):
                await self.writer.wait_closed()
        self.csock.close()
        self.ssock.close()


@pytest.fixture
def event_loop_factory():
    loops: List[asyncio.AbstractEventLoop] = []

    def make_loop() -> asyncio.AbstractEventLoop:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loops.append(loop)
        return loop

    yield make_loop
    for loop in loops:
        # Drain any lingering transports/tasks before closing the loop.
        pending = [
            task for task in asyncio.all_tasks(loop) if not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        loop.close()


def run(loop: asyncio.AbstractEventLoop, coro):
    return loop.run_until_complete(coro)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Body containing NUL, bare CR/LF, dot-stuffing shapes and lines that look
# exactly like SMTP commands.  None of this may ever reach the command parser.
SMUGGLE_BODY = (
    b"From: anne@example.com\r\n"
    b"\x00\x00binary\x00data\r\n"
    b"bare-cr\rbare-lf\ncrlf\r\n"
    b".\r\n"
    b"RSET\r\n"
    b"MAIL FROM:<attacker@example.com>\r\n"
    b"RCPT TO:<victim@example.com>\r\n"
    b"DATA\r\n"
    b"BDAT 12 LAST\r\n"
    b"QUIT\r\n"
    b"\xff\xfe trailing binary"
)

NORMAL_BODY = (
    b"From: bart@example.com\r\n"
    b"Subject: ordinary mail\r\n\r\n"
    b"Nothing special here, just a normal message.\r\n"
)


def chunked(data: bytes, sizes: List[int]) -> List[bytes]:
    pieces = []
    offset = 0
    for size in sizes:
        pieces.append(data[offset:offset + size])
        offset += size
    assert offset == len(data)
    return pieces


def prepare_transaction(server: BdatServer) -> None:
    loop = server.loop
    run(loop, server.command(b"EHLO example.com"))
    run(loop, server.command(b"MAIL FROM:<anne@example.com>"))
    run(loop, server.command(b"RCPT TO:<bart@example.com>"))


class TestChunkingAdvertisement:
    def test_disabled_by_default(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop)
        run(loop, server.start())
        run(loop, server.read_reply())
        ehlo = run(loop, server.command(b"EHLO example.com"))
        assert b"CHUNKING" not in ehlo
        # BDAT behaves like an unknown command when the extension is off.
        run(loop, server.command(b"MAIL FROM:<a@example.com>"))
        run(loop, server.command(b"RCPT TO:<b@example.com>"))
        resp = run(loop, server.command(b"BDAT 0 LAST"))
        assert resp.startswith(b"500")
        run(loop, server.close())

    def test_enabled_advertises_chunking(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        ehlo = run(loop, server.command(b"EHLO example.com"))
        assert b"250-CHUNKING\r\n" in ehlo
        run(loop, server.close())

    def test_bdat_requires_esmtp(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        run(loop, server.command(b"HELO example.com"))
        run(loop, server.command(b"MAIL FROM:<a@example.com>"))
        run(loop, server.command(b"RCPT TO:<b@example.com>"))
        resp = run(loop, server.bdat(b"", last=True))
        assert resp.startswith(b"500")
        assert handler.calls == 0
        run(loop, server.close())


class TestBdatDelivery:
    def test_two_messages_fragmented_byte_stream(self, event_loop_factory):
        loop = event_loop_factory()
        handler = CommandProbeHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None,
            timeout=30,
        )
        run(loop, server.start())
        run(loop, server.read_reply())

        # First transaction: command-shaped binary body, sent in deliberately
        # awkward fragments that split header lines and bodies across writes.
        prepare_transaction(server)
        sixth = len(SMUGGLE_BODY) // 6
        sizes = [1, 7, 13, sixth, sixth,
                 len(SMUGGLE_BODY) - (1 + 7 + 13 + 2 * sixth)]
        assert all(size > 0 for size in sizes)
        pieces = chunked(SMUGGLE_BODY, sizes)
        replies: List[bytes] = []
        for index, piece in enumerate(pieces):
            last = index == len(pieces) - 1
            header = (
                b"BDAT " + str(len(piece)).encode()
                + (b" LAST" if last else b"")
            )
            # Split every write so the server cannot rely on boundaries.
            server.send_raw(header[:4])
            server.send_raw(header[4:] + b"\r")
            run(loop, asyncio.sleep(0))
            server.send_raw(b"\n" + piece[:1])
            run(loop, asyncio.sleep(0))
            server.send_raw(piece[1:])
            replies.append(run(loop, server.read_reply()))
        # One 250 per chunk; the handler must not run before the LAST chunk.
        assert len(replies) == len(pieces)
        assert all(reply.startswith(b"250") for reply in replies)
        assert handler.calls == 1
        # The embedded RSET/NOOP/QUIT lines are body, never executed.
        assert handler.leaked_commands == []
        delivered_one = handler.box[0]
        assert delivered_one.original_content == SMUGGLE_BODY
        assert digest(delivered_one.original_content) == digest(SMUGGLE_BODY)

        # Second transaction: an ordinary message on the same connection.
        run(loop, server.command(b"MAIL FROM:<cate@example.com>"))
        run(loop, server.command(b"RCPT TO:<dave@example.com>"))
        normal_pieces = chunked(NORMAL_BODY, [10, 50, len(NORMAL_BODY) - 60])
        for index, piece in enumerate(normal_pieces):
            reply = run(
                loop, server.bdat(piece, last=index == len(normal_pieces) - 1)
            )
            assert reply.startswith(b"250")
        assert handler.calls == 2
        delivered_two = handler.box[1]
        assert delivered_two.original_content == NORMAL_BODY
        assert digest(delivered_two.original_content) == digest(NORMAL_BODY)

        run(loop, server.close())

    def test_handler_not_called_before_last(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        for size in (4, 8):
            resp = run(loop, server.bdat(b"x" * size))
            assert resp == b"250 OK\r\n"
            assert handler.calls == 0
        resp = run(loop, server.bdat(b"", last=True))
        assert resp == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == b"x" * 12
        run(loop, server.close())

    def test_zero_length_last_chunk(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"hello")) == b"250 OK\r\n"
        assert run(loop, server.bdat(b"", last=True)) == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == b"hello"
        run(loop, server.close())

    def test_zero_length_only_chunk(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"", last=True)) == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == b""
        run(loop, server.close())

    def test_data_still_works_alongside_bdat(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        run(loop, server.command(b"DATA"))
        server.send_raw(b"classic DATA body\r\n.\r\n")
        resp = run(loop, server.read_reply())
        assert resp == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == b"classic DATA body\r\n"
        run(loop, server.close())


class TestBdatLimitsAndErrors:
    def test_need_rcpt(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        run(loop, server.command(b"EHLO example.com"))
        run(loop, server.command(b"MAIL FROM:<a@example.com>"))
        resp = run(loop, server.bdat(b"x", last=True))
        assert resp.startswith(b"503")
        assert handler.calls == 0
        run(loop, server.close())

    def test_bad_syntax(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(handler, loop, enable_chunking=True)
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        for bad in (b"BDAT", b"BDAT xyz", b"BDAT 5 FOO", b"BDAT 5 10"):
            resp = run(loop, server.command(bad))
            assert resp.startswith(b"501"), bad
        assert handler.calls == 0
        run(loop, server.close())

    def test_chunk_size_limit(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler,
            loop,
            enable_chunking=True,
            bdat_chunk_size_limit=10,
            data_size_limit=None,
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        # Declared chunk exceeds the per-chunk limit: rejected before any
        # body byte is consumed and the connection is dropped.
        resp = run(loop, server.command(b"BDAT 11"))
        assert resp.startswith(b"552")
        assert handler.calls == 0
        # Nothing pipelined behind the rejected chunk is parsed as a command.
        assert run(loop, server.read_reply()) == b""
        run(loop, server.close())

    def test_total_size_limit(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler,
            loop,
            enable_chunking=True,
            data_size_limit=10,
            bdat_chunk_size_limit=None,
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"abcdef")) == b"250 OK\r\n"
        # 6 + 5 > 10; rejected up front and connection closed.
        resp = run(loop, server.command(b"BDAT 5"))
        assert resp.startswith(b"552")
        assert handler.calls == 0
        run(loop, server.close())

    def test_short_read_aborts_without_delivery(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        # Declare 100 octets but send only 5 then hang up (FIN).
        server.send_raw(b"BDAT 100 LAST\r\nabcde")
        run(loop, asyncio.sleep(0.05))
        assert server.writer is not None
        server.writer.close()
        # Server closes without a delivery reply and never calls the handler.
        assert run(loop, server.read_reply()) == b""
        run(loop, asyncio.sleep(0.05))
        assert handler.calls == 0
        assert handler.box == []
        run(loop, server.close())

    def test_rset_mid_transaction_discards_chunks(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"first")) == b"250 OK\r\n"
        assert run(loop, server.command(b"RSET")) == b"250 OK\r\n"
        assert handler.calls == 0
        # Fresh transaction after RSET delivers only the new body.
        run(loop, server.command(b"MAIL FROM:<a@example.com>"))
        run(loop, server.command(b"RCPT TO:<b@example.com>"))
        assert run(loop, server.bdat(b"mail", last=True)) == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == b"mail"
        run(loop, server.close())

    def test_data_after_bdat_rejected(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"abc")) == b"250 OK\r\n"
        resp = run(loop, server.command(b"DATA"))
        assert resp.startswith(b"503")
        # The aborted transaction must not deliver; RSET clears it.
        assert run(loop, server.command(b"RSET")) == b"250 OK\r\n"
        assert handler.calls == 0
        run(loop, server.close())

    def test_bdat_after_last_is_illegal(self, event_loop_factory):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"hi", last=True)) == b"250 OK\r\n"
        assert handler.calls == 1
        resp = run(loop, server.bdat(b"x", last=True))
        assert resp.startswith(b"503")
        # Only the first, completed transaction was delivered.
        assert handler.calls == 1
        run(loop, server.close())

    def test_command_shaped_body_is_never_executed(
        self, event_loop_factory
    ):
        loop = event_loop_factory()
        handler = CommandProbeHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        body = b"RSET\r\nMAIL FROM:<x@example.com>\r\nNOOP\r\nQUIT\r\n"
        resp = run(loop, server.bdat(body, last=True))
        assert resp == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == body
        # None of the embedded command-shaped lines was executed.
        assert handler.leaked_commands == []
        # Session is still alive and responsive; embedded QUIT did not run.
        assert run(loop, server.command(b"NOOP")) == b"250 OK\r\n"
        assert handler.leaked_commands == ["NOOP"]
        run(loop, server.close())

    def test_failed_transaction_no_partial_delivery(
        self, event_loop_factory
    ):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler,
            loop,
            enable_chunking=True,
            data_size_limit=8,
            bdat_chunk_size_limit=None,
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"abcd")) == b"250 OK\r\n"
        # Oversized final chunk fails; no partial delivery may occur.
        resp = run(loop, server.command(b"BDAT 5 LAST"))
        assert resp.startswith(b"552")
        assert handler.calls == 0
        assert handler.box == []
        run(loop, server.close())

    def test_nested_mail_mid_transaction_rejected(
        self, event_loop_factory
    ):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler, loop, enable_chunking=True, data_size_limit=None
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        assert run(loop, server.bdat(b"abc")) == b"250 OK\r\n"
        resp = run(loop, server.command(b"MAIL FROM:<x@y.com>"))
        assert resp.startswith(b"503")
        assert handler.calls == 0
        # RSET still recovers the session cleanly.
        assert run(loop, server.command(b"RSET")) == b"250 OK\r\n"
        run(loop, server.close())

    def test_zero_chunk_limit_allows_only_empty_chunks(
        self, event_loop_factory
    ):
        loop = event_loop_factory()
        handler = RecordingHandler()
        server = BdatServer(
            handler,
            loop,
            enable_chunking=True,
            bdat_chunk_size_limit=0,
            data_size_limit=None,
        )
        run(loop, server.start())
        run(loop, server.read_reply())
        prepare_transaction(server)
        # A zero-length LAST chunk is within the limit and delivers.
        assert run(loop, server.bdat(b"", last=True)) == b"250 OK\r\n"
        assert handler.calls == 1
        assert handler.box[0].original_content == b""
        run(loop, server.close())
