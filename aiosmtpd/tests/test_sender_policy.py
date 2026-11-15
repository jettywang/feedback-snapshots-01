# Copyright 2014-2026 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Protocol-level tests for envelope-sender authorization.

Each live test drives a real ``SMTP`` protocol object over a socketpair: the
client side writes SMTP command bytes and reads the server's replies, and the
handler is the example's reusable authorization policy.  Authorization is
never decided by calling the policy directly in these tests, so hook wiring
and aiosmtpd's parsed address form are both exercised.
"""

import asyncio
import contextlib
from base64 import b64encode
from dataclasses import dataclass
from socket import socketpair
from typing import AsyncIterator, List

import pytest

from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP

pytest.importorskip("examples.authenticated_relayer.sender_policy")
from examples.authenticated_relayer.sender_policy import (  # noqa: E402
    AddressError,
    AuthIdentity,
    SenderAuthorizedHandler,
    SenderPolicy,
    authenticated_username,
    parse_envelope_address,
    safe_log_value,
)

EXAMPLE_DOMAIN = "example.com"
IDN_DOMAIN = "例え.example"
IDN_ALABEL = "xn--r8jz45g.example"


# region #### Live protocol harness ###############################################


class RecordingHandler(SenderAuthorizedHandler):
    """Authorize MAIL, then accept RCPT/DATA so the result can be inspected."""

    def __init__(self, policy: SenderPolicy) -> None:
        super().__init__(policy)
        self.transactions: List[dict] = []

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.transactions.append(
            {
                "mail_from": envelope.mail_from,
                "rcpt_tos": list(envelope.rcpt_tos),
                "content": envelope.original_content,
            }
        )
        return "250 OK"


class WireClient:
    """A raw SMTP client: writes command bytes and reads server replies."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.transcript: List[bytes] = []

    async def read_reply(self) -> List[bytes]:
        lines = []
        while True:
            line = await asyncio.wait_for(self.reader.readline(), timeout=5)
            assert line.endswith(b"\r\n"), line
            lines.append(line)
            if len(line) < 4 or line[3:4] != b"-":
                break
        self.transcript.extend(lines)
        return lines

    async def send(self, line: bytes) -> List[bytes]:
        self.transcript.append(b"> " + line)
        self.writer.write(line + b"\r\n")
        await self.writer.drain()
        return await self.read_reply()

    async def auth_plain(self, username: str, password: str) -> List[bytes]:
        blob = b64encode(
            b"\x00" + username.encode() + b"\x00" + password.encode()
        )
        return await self.send(b"AUTH PLAIN " + blob)

    async def data(self, content: bytes) -> List[bytes]:
        reply = await self.send(b"DATA")
        assert reply[0].startswith(b"354"), reply
        self.writer.write(content + b".\r\n")
        await self.writer.drain()
        return await self.read_reply()

    def close(self) -> None:
        self.writer.close()


class PasswordAuthenticator:
    """A real authenticator over a fixed password table."""

    def __init__(self, passwords: dict[str, str]) -> None:
        self.passwords = passwords

    def __call__(self, server, session, envelope, mechanism, auth_data):
        if mechanism not in ("PLAIN", "LOGIN") or not isinstance(
            auth_data, LoginPassword
        ):
            return AuthResult(success=False, handled=False)
        try:
            username = auth_data.login.decode("utf-8")
            password = auth_data.password.decode("utf-8")
        except UnicodeDecodeError:
            return AuthResult(success=False, handled=False)
        if self.passwords.get(username) != password:
            return AuthResult(success=False, handled=False)
        return AuthResult(success=True, auth_data=AuthIdentity(username=username))


@dataclass
class LiveServer:
    handler: RecordingHandler
    client: WireClient
    transport: asyncio.BaseTransport

    def close(self) -> None:
        self.client.close()
        self.transport.close()


@contextlib.asynccontextmanager
async def live_server(
    policy: SenderPolicy, *, enable_SMTPUTF8: bool = True
) -> AsyncIterator[LiveServer]:
    """Run a handler over a real bidirectional SMTP byte stream."""
    handler = RecordingHandler(policy)
    loop = asyncio.get_running_loop()
    server_sock, client_sock = socketpair()

    def factory() -> SMTP:
        return SMTP(
            handler,
            loop=loop,
            enable_SMTPUTF8=enable_SMTPUTF8,
            # The harness has no STARTTLS; production policy instead assumes
            # AUTH occurs over an encrypted channel.
            auth_require_tls=False,
            authenticator=PasswordAuthenticator(
                {"alice": "alicepw", "bob": "bobpw", "carol": "carolpw"}
            ),
        )

    transport, _protocol = await loop.create_connection(factory, sock=server_sock)
    reader, writer = await asyncio.open_connection(sock=client_sock)
    client = WireClient(reader, writer)
    await client.read_reply()
    live = LiveServer(handler=handler, client=client, transport=transport)
    try:
        yield live
    finally:
        live.close()
        await asyncio.sleep(0)


def scenario(coro) -> None:
    """Run one protocol scenario without requiring pytest-asyncio."""
    asyncio.run(coro)


@pytest.fixture
def policy() -> SenderPolicy:
    return SenderPolicy(
        {
            "alice": [f"alice@{EXAMPLE_DOMAIN}", f"alice+lists@{EXAMPLE_DOMAIN}"],
            "bob": [f"bob@{EXAMPLE_DOMAIN}", f"bob@{IDN_DOMAIN}"],
        },
        allow_null_reverse_path=False,
    )


# endregion

# region #### Parsing boundaries ##################################################


def test_null_reverse_path_is_not_a_mailbox() -> None:
    identity = parse_envelope_address("<>", smtp_utf8=False)
    assert identity.null is True
    assert identity.identity == "<>"
    assert identity.match_key == ("null",)


def test_empty_quoted_local_part_is_malformed() -> None:
    with pytest.raises(AddressError):
        parse_envelope_address('""@example.com', smtp_utf8=False)


def test_quoted_and_unquoted_forms_match_but_spaces_are_exact() -> None:
    unquoted = parse_envelope_address(f"alice@{EXAMPLE_DOMAIN}", smtp_utf8=True)
    quoted = parse_envelope_address(f'"alice"@{EXAMPLE_DOMAIN}', smtp_utf8=True)
    spaced = parse_envelope_address(f'"alice "@{EXAMPLE_DOMAIN}', smtp_utf8=True)
    assert unquoted.match_key == quoted.match_key
    assert spaced.match_key != unquoted.match_key
    assert spaced.local == "alice "


def test_local_part_case_and_unicode_are_not_folded() -> None:
    lower = parse_envelope_address(f"alice@{EXAMPLE_DOMAIN}", smtp_utf8=True)
    upper = parse_envelope_address(f"Alice@{EXAMPLE_DOMAIN}", smtp_utf8=True)
    assert lower.match_key != upper.match_key

    decomposed = parse_envelope_address(f"bücher@{EXAMPLE_DOMAIN}", smtp_utf8=True)
    precomposed = parse_envelope_address(f"bücher@{EXAMPLE_DOMAIN}", smtp_utf8=True)
    assert decomposed.local != precomposed.local
    assert decomposed.match_key != precomposed.match_key


def test_domain_is_case_insensitive_and_idna_mapped() -> None:
    ascii_form = parse_envelope_address(f"bob@{IDN_ALABEL.upper()}", smtp_utf8=False)
    u_label = parse_envelope_address(f"bob@{IDN_DOMAIN}", smtp_utf8=True)
    assert ascii_form.domain == IDN_ALABEL
    assert u_label.domain == IDN_ALABEL
    assert ascii_form.match_key == u_label.match_key


def test_fullwidth_homoglyph_is_rejected_not_folded(policy: SenderPolicy) -> None:
    homoglyph = "bob@ｅxample.com"  # FULLWIDTH LATIN SMALL E
    with pytest.raises(AddressError):
        parse_envelope_address(homoglyph, smtp_utf8=True)
    decision = policy.authorize("bob", homoglyph, smtp_utf8=True)
    assert decision.allowed is False
    assert decision.basis == "invalid-address"


def test_cyrillic_homoglyph_domain_is_a_different_identity(
    policy: SenderPolicy,
) -> None:
    # The "o" in the TLD is CYRILLIC SMALL LETTER O (U+043E).  IDNA maps it
    # to a different A-label, so it must not match bob@example.com.
    homoglyph = "bob@example.c\u043em"
    identity = parse_envelope_address(homoglyph, smtp_utf8=True)
    assert identity.domain == "example.xn--cm-fmc"
    decision = policy.authorize("bob", homoglyph, smtp_utf8=True)
    assert decision.allowed is False
    assert decision.basis == "no-authorized-alias"


def test_unicode_without_smtputf8_assertion_is_rejected() -> None:
    with pytest.raises(AddressError):
        parse_envelope_address(f"bob@{IDN_DOMAIN}", smtp_utf8=False)
    with pytest.raises(AddressError):
        parse_envelope_address("böb@example.com", smtp_utf8=False)


def test_unicode_with_smtputf8_disabled_on_server_is_rejected() -> None:
    with pytest.raises(AddressError):
        parse_envelope_address(
            f"bob@{IDN_DOMAIN}", smtp_utf8=True, smtp_utf8_enabled=False
        )


def test_bidi_override_is_rejected() -> None:
    with pytest.raises(AddressError):
        parse_envelope_address("bob@exam‮ple.com", smtp_utf8=True)


def test_authenticated_username_rejects_invalid_utf8_bytes() -> None:
    class FakeSession:
        authenticated = True
        auth_data = None
        _login_data = b"\xff\xfealice"

    assert authenticated_username(FakeSession()) is None

    class BytesSession(FakeSession):
        _login_data = b"alice"

    assert authenticated_username(BytesSession()) == "alice"


def test_address_literal_is_validated_and_canonicalized() -> None:
    v4 = parse_envelope_address("alice@[127.0.0.1]", smtp_utf8=False)
    assert v4.domain == "[127.0.0.1]"
    assert v4.address_literal is True
    v6 = parse_envelope_address("alice@[IPv6:2001:DB8::1]", smtp_utf8=False)
    assert v6.domain == "[IPv6:2001:db8::1]"
    with pytest.raises(AddressError):
        parse_envelope_address("alice@[127.0.0.999]", smtp_utf8=False)


def test_safe_log_escapes_newlines_and_controls() -> None:
    rendered = safe_log_value("alice@example.com\r\nMAIL FROM:<evil@example.com>")
    assert "\r" not in rendered and "\n" not in rendered
    assert "\\u000d" in rendered and "\\u000a" in rendered


def test_log_records_safe_input_and_match_basis(policy: SenderPolicy, caplog) -> None:
    caplog.set_level("INFO", logger="mail.log")
    decision = policy.authorize("alice", f"alice@{EXAMPLE_DOMAIN}", smtp_utf8=False)
    from examples.authenticated_relayer.sender_policy import log_sender_decision

    log_sender_decision("alice", f"alice@{EXAMPLE_DOMAIN}\r\nX: y", decision)
    record = caplog.records[-1].getMessage()
    assert "original=" in record
    assert "\\u000d\\u000a" in record
    assert "identity=alice@example.com" in record
    assert "basis=alias:alice@example.com" in record


# endregion

# region #### Live SMTP interactions ###############################################


def test_authorized_alias_reaches_data(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            assert (await client.send(b"EHLO test.example"))[0].startswith(b"250")
            assert (await client.auth_plain("alice", "alicepw"))[0].startswith(b"235")
            assert (await client.send(
                b"MAIL FROM:<alice@example.com>"
            ))[0].startswith(b"250")
            assert (await client.send(
                b"RCPT TO:<to@example.net>"
            ))[0].startswith(b"250")
            body = b"From: forged@example.org\r\nSubject: t\r\n\r\nhi\r\n"
            assert (await client.data(body))[0].startswith(b"250")
            transaction = live.handler.transactions[-1]
            assert transaction["mail_from"] == f"alice@{EXAMPLE_DOMAIN}"
            assert transaction["rcpt_tos"] == ["to@example.net"]

    scenario(run())


def test_header_from_cannot_grant_envelope_authority(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            reply = await client.send(b"MAIL FROM:<mallory@example.com>")
            assert reply[0].startswith(b"550"), reply
            # No sender identity may remain for RCPT/DATA to consume.
            assert (await client.send(
                b"RCPT TO:<to@example.net>"
            ))[0].startswith(b"503")
            assert (await client.send(b"DATA"))[0].startswith(b"503")
            assert live.handler.transactions == []

    scenario(run())


def test_same_domain_different_local_part_rejected(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            for local in ("alic", "alice2", "alice+other", "ALICE"):
                reply = await client.send(
                    f"MAIL FROM:<{local}@example.com>".encode("ascii")
                )
                assert reply[0].startswith(b"550"), (local, reply)
                await client.send(b"RSET")

    scenario(run())


def test_authorized_plus_alias_is_exact(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            reply = await client.send(b"MAIL FROM:<alice+lists@example.com>")
            assert reply[0].startswith(b"250"), reply
            assert (await client.send(b"RCPT TO:<to@example.net>"))[0].startswith(
                b"250"
            )

    scenario(run())


def test_unicode_alias_requires_client_smtputf8_assertion(
    policy: SenderPolicy,
) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("bob", "bobpw")

            # The server offers SMTPUTF8 and aiosmtpd decodes the bytes, but
            # this client did not assert SMTPUTF8 on MAIL, so EAI is not
            # negotiated for this transaction.
            reply = await client.send(
                f"MAIL FROM:<bob@{IDN_DOMAIN}>".encode("utf-8")
            )
            assert reply[0].startswith(b"550 5.6.7"), reply

            reply = await client.send(
                "MAIL FROM:<böb@example.com>".encode("utf-8")
            )
            assert reply[0].startswith(b"550 5.6.7"), reply

            reply = await client.send(
                f"MAIL FROM:<bob@{IDN_DOMAIN}> SMTPUTF8".encode("utf-8")
            )
            assert reply[0].startswith(b"250"), reply

    scenario(run())


def test_quoted_local_part_matches_unquoted_alias(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            # RFC 5321 says quoted and unquoted forms of the same local-part
            # are equivalent; only the quoting differs, not the identity.
            reply = await client.send(b'MAIL FROM:<"alice"@example.com>')
            assert reply[0].startswith(b"250"), reply
            assert (await client.send(b"RCPT TO:<to@example.net>"))[0].startswith(
                b"250"
            )

    scenario(run())


def test_ascii_alias_written_as_a_label_matches(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("bob", "bobpw")
            reply = await client.send(
                f"MAIL FROM:<bob@{IDN_ALABEL.upper()}>".encode("ascii")
            )
            assert reply[0].startswith(b"250"), reply

    scenario(run())


def test_authenticated_user_without_aliases_is_rejected(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("carol", "carolpw")
            reply = await client.send(b"MAIL FROM:<carol@example.com>")
            assert reply[0].startswith(b"550"), reply
            assert (await client.send(b"RCPT TO:<to@example.net>"))[0].startswith(
                b"503"
            )

    scenario(run())


def test_live_denial_and_allow_log_safe_input_and_basis(
    policy: SenderPolicy, caplog
) -> None:
    caplog.set_level("INFO", logger="mail.log")

    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("bob", "bobpw")
            # Cyrillic homoglyph in the TLD, with SMTPUTF8 asserted so the
            # command is parsed as EAI and the identity is compared.
            await client.send(
                "MAIL FROM:<bob@example.c\u043em> SMTPUTF8".encode("utf-8")
            )
            await client.send(b"RSET")
            await client.send(b"MAIL FROM:<bob@example.com>")

    scenario(run())
    messages = [r.getMessage() for r in caplog.records]
    denied = [m for m in messages if "allowed=False" in m]
    allowed = [m for m in messages if "allowed=True" in m]
    assert denied and allowed
    assert "original=bob@example.c\u043em" in denied[0]
    assert "identity=bob@example.xn--cm-fmc" in denied[0]
    assert "basis=no-authorized-alias" in denied[0]
    assert "identity=bob@example.com" in allowed[0]
    assert "basis=alias:bob@example.com" in allowed[0]


def test_unauthenticated_mail_is_rejected(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            reply = await client.send(b"MAIL FROM:<alice@example.com>")
            assert reply[0].startswith(b"530"), reply

    scenario(run())


def test_null_reverse_path_denied_by_default(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            reply = await client.send(b"MAIL FROM:<>")
            assert reply[0].startswith(b"550"), reply
            assert (await client.send(b"RCPT TO:<to@example.net>"))[0].startswith(
                b"503"
            )

    scenario(run())


def test_null_reverse_path_opt_in(policy: SenderPolicy) -> None:
    permissive = SenderPolicy(
        {"alice": [f"alice@{EXAMPLE_DOMAIN}"]},
        allow_null_reverse_path=True,
    )
    assert permissive.null_allowed_for("alice") is True

    async def run() -> None:
        async with live_server(permissive) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            assert (await client.send(b"MAIL FROM:<>"))[0].startswith(b"250")
            assert (await client.send(b"RCPT TO:<to@example.net>"))[0].startswith(
                b"250"
            )

    scenario(run())


def test_rejected_mail_clears_previous_envelope(policy: SenderPolicy) -> None:
    async def run() -> None:
        async with live_server(policy) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("alice", "alicepw")
            assert (await client.send(b"MAIL FROM:<alice@example.com>"))[0].startswith(
                b"250"
            )
            await client.send(b"RSET")
            reply = await client.send(b"MAIL FROM:<alice@evil.example>")
            assert reply[0].startswith(b"550"), reply
            assert (await client.send(b"RCPT TO:<to@example.net>"))[0].startswith(
                b"503"
            )

    scenario(run())


def test_smtputf8_disabled_server_rejects_unicode_before_alias(
    policy: SenderPolicy,
) -> None:
    async def run() -> None:
        async with live_server(policy, enable_SMTPUTF8=False) as live:
            client = live.client
            await client.send(b"EHLO test.example")
            await client.auth_plain("bob", "bobpw")
            # The server announced no SMTPUTF8, so the parameter itself is
            # rejected by the protocol layer even for an ASCII alias.
            reply = await client.send(
                f"MAIL FROM:<bob@{IDN_ALABEL}> SMTPUTF8".encode("ascii")
            )
            assert reply[0].startswith(b"501"), reply

    scenario(run())


# endregion
