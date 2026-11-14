"""In-process demo: RelayPolicy handler vs. three attack/usage patterns.

Drives the real aiosmtpd.smtp.SMTP protocol machine through a fake
transport (no sockets needed), so the SMTP replies shown are the exact
bytes the server produces.

Scenarios:
  1. Anonymous client, mixed local+external recipients (incl. RSET test)
  2. Authenticated clients: authorized relayer vs. non-authorized user
  3. Forged EHLO name + forged PROXY header + forged message headers
  4. (control) Verified proxy: trusted proxy + trusted source network

After each scenario the script asserts that the final delivery list matches
exactly the RCPTs that received a 250 reply.
"""

import asyncio
import base64
import warnings

from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP

from relay_policy import RelayPolicy

LOCAL_DOMAINS = {"example.com"}
USERS = {"relay-user": "s3cret", "user2": "hunter2"}
AUTHORIZED_RELAYERS = {"relay-user"}
TRUSTED_NETWORKS = ["10.0.0.0/8"]
TRUSTED_PROXIES = ["127.0.0.1/32"]
UNTRUSTED_PEER = ("203.0.113.9", 51000)      # some internet host
TRUSTED_PROXY_PEER = ("127.0.0.1", 41000)    # our edge proxy


def auth_callback(server, session, envelope, mechanism, auth_data):
    if mechanism not in ("LOGIN", "PLAIN"):
        return AuthResult(success=False)
    if not isinstance(auth_data, LoginPassword):
        return AuthResult(success=False)
    try:
        username = auth_data.login.decode("utf-8")
        password = auth_data.password.decode("utf-8")
    except UnicodeDecodeError:
        return AuthResult(success=False)
    if USERS.get(username) == password:
        # Bind the authenticated principal to the connection session; the
        # handler snapshots it into each transaction at MAIL time.
        session.auth_identity = username
        return AuthResult(success=True)
    return AuthResult(success=False)


def make_handler(**overrides):
    kwargs = dict(
        local_domains=LOCAL_DOMAINS,
        authorized_relayers=AUTHORIZED_RELAYERS,
        trusted_networks=TRUSTED_NETWORKS,
    )
    kwargs.update(overrides)
    return RelayPolicy(**kwargs)


class FakeTransport:
    """Minimal asyncio transport stand-in capturing server output."""

    def __init__(self, peer):
        self._peer = peer
        self.buf = bytearray()
        self.closed = False

    def write(self, data):
        self.buf += data

    def get_extra_info(self, name, default=None):
        return {"peername": self._peer}.get(name, default)

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed


class SMTPClient:
    """Scripted client speaking to an in-process aiosmtpd SMTP instance."""

    def __init__(self, loop, handler, peer, proxy_protocol=False):
        kwargs = {}
        if proxy_protocol:
            kwargs["proxy_protocol_timeout"] = 5
        self.smtp = SMTP(handler, hostname="mx.example.com",
                         authenticator=auth_callback,
                         auth_require_tls=False, loop=loop, **kwargs)
        self.transport = FakeTransport(peer)
        self.smtp.connection_made(self.transport)
        self.read_at = 0
        self.transcript = []

    async def _reply(self):
        """Wait for a complete (possibly multiline) SMTP reply."""
        for _ in range(1000):
            data = bytes(self.transport.buf[self.read_at:])
            lines = data.split(b"\r\n")
            complete = lines[:-1] if data.endswith(b"\r\n") else []
            if complete and complete[-1][3:4] == b" ":
                self.read_at += sum(len(l) + 2 for l in complete)
                for l in complete:
                    self.transcript.append(f"S: {l.decode()}")
                return int(complete[-1][:3]), complete[-1][4:].decode()
            await asyncio.sleep(0.001)
        raise TimeoutError("no reply from server")

    async def cmd(self, line, note=None):
        self.transcript.append(f"C: {line}" + (f"   ({note})" if note else ""))
        self.smtp.data_received(line.encode() + b"\r\n")
        return await self._reply()

    async def data(self, payload):
        code, _ = await self.cmd("DATA")
        assert code == 354
        self.transcript.append("C: <message body>")
        self.smtp.data_received(payload.encode() + b"\r\n.\r\n")
        return await self._reply()

    async def auth_plain(self, user, password):
        blob = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
        return await self.cmd(f"AUTH PLAIN {blob}", note=f"login as {user}")

    async def start(self):
        return await self._reply()  # 220 greeting


def show(title, transcript):
    print(f"\n=== {title} ===")
    for line in transcript:
        print(" ", line)


def check_delivery(handler, expected, label):
    actual = list(handler.deliveries[-1].rcpt_tos) if handler.deliveries else []
    status = "OK " if actual == expected else "FAIL"
    print(f"  [{status}] {label}: final delivery list = {actual}")
    assert actual == expected, f"{label}: {actual} != {expected}"


async def scenario_1(loop, handler):
    c = SMTPClient(loop, handler, peer=UNTRUSTED_PEER)
    await c.start()
    await c.cmd("EHLO random-pc.example.net", note="anonymous")
    await c.cmd("MAIL FROM:<alice@example.com>")
    accepted = []
    for rcpt in ("bob@example.com", "carol@external.net", "dave@example.com"):
        code, _ = await c.cmd(f"RCPT TO:<{rcpt}>")
        if code == 250:
            accepted.append(rcpt)
    await c.data("Subject: hi\r\n\r\nmixed recipients")
    show("Scenario 1: anonymous, mixed local+external recipients",
         c.transcript)
    check_delivery(handler, accepted, "anonymous mixed")

    # RSET must not inherit anything from previous transactions.
    c.transcript.clear()
    await c.cmd("MAIL FROM:<alice@example.com>")
    await c.cmd("RCPT TO:<bob@example.com>", note="approved local recipient")
    await c.cmd("RSET", note="abort transaction")
    await c.cmd("MAIL FROM:<alice@example.com>")
    code, _ = await c.cmd("RCPT TO:<carol@external.net>",
                          note="must NOT inherit prior state")
    await c.cmd("RSET")
    show("Scenario 1b: RSET does not inherit permissions", c.transcript)
    assert code == 550, "external relay must still be denied after RSET"
    assert len(handler.deliveries) == 1, "aborted tx must not deliver"
    print("  [OK ] post-RSET external RCPT still 550; no phantom delivery")


async def scenario_2(loop, handler):
    c = SMTPClient(loop, handler, peer=UNTRUSTED_PEER)
    await c.start()
    await c.cmd("EHLO relay-client")
    await c.auth_plain("relay-user", "s3cret")
    await c.cmd("MAIL FROM:<relay-user@example.com>")
    accepted = []
    for rcpt in ("carol@external.net", "bob@example.com"):
        code, _ = await c.cmd(f"RCPT TO:<{rcpt}>")
        if code == 250:
            accepted.append(rcpt)
    await c.data("Subject: relay\r\n\r\nauthenticated relay")
    show("Scenario 2: authenticated authorized relayer", c.transcript)
    check_delivery(handler, accepted, "authorized relay")

    c = SMTPClient(loop, handler, peer=UNTRUSTED_PEER)
    await c.start()
    await c.cmd("EHLO user2-client")
    await c.auth_plain("user2", "hunter2")
    await c.cmd("MAIL FROM:<user2@example.com>")
    code, _ = await c.cmd("RCPT TO:<carol@external.net>")
    show("Scenario 2b: authenticated but NOT an authorized relayer",
         c.transcript)
    assert code == 550
    print("  [OK ] valid login without relay authorization still gets 550")


async def scenario_3(loop, handler):
    # Server requires PROXY protocol, but the direct peer is NOT a trusted
    # proxy, so a forged PROXY line must be ignored.
    c = SMTPClient(loop, handler, peer=UNTRUSTED_PEER, proxy_protocol=True)
    c.smtp.data_received(b"PROXY TCP4 10.1.2.3 192.0.2.10 51000 25\r\n")
    c.transcript.append("C: PROXY TCP4 10.1.2.3 ...   (FORGED: claims "
                        "trusted source 10.1.2.3)")
    await c.start()
    await c.cmd("EHLO mx1.example.com", note="FORGED local name")
    await c.cmd("MAIL FROM:<boss@example.com>")
    code, _ = await c.cmd("RCPT TO:<carol@external.net>")
    assert code == 550
    await c.cmd("RCPT TO:<bob@example.com>")
    await c.data("From: boss@example.com\r\n"
                 "X-Real-IP: 10.1.2.3\r\n"
                 "Received: from trusted.internal (forged headers)\r\n"
                 "\r\n"
                 "forged everything")
    show("Scenario 3: forged PROXY line + EHLO name + message headers",
         c.transcript)
    check_delivery(handler, ["bob@example.com"], "forged-origin attempt")


async def scenario_4(loop, handler):
    # Same PROXY line, but now the direct peer IS a trusted proxy, so the
    # claimed source 10.1.2.3 (trusted network) is honored.
    c = SMTPClient(loop, handler, peer=TRUSTED_PROXY_PEER, proxy_protocol=True)
    c.smtp.data_received(b"PROXY TCP4 10.1.2.3 192.0.2.10 51000 25\r\n")
    c.transcript.append("C: PROXY TCP4 10.1.2.3 ...   (from TRUSTED proxy "
                        "127.0.0.1)")
    await c.start()
    await c.cmd("EHLO edge-proxy")
    await c.cmd("MAIL FROM:<alice@example.com>")
    code, _ = await c.cmd("RCPT TO:<carol@external.net>")
    assert code == 250
    await c.data("Subject: via trusted proxy\r\n\r\nhello")
    show("Scenario 4 (control): verified proxy + trusted source network",
         c.transcript)
    check_delivery(handler, ["carol@external.net"], "verified proxy relay")


async def amain(loop):
    h_main = make_handler()
    h_forged = make_handler(trusted_proxies=[])
    h_proxy = make_handler(trusted_proxies=TRUSTED_PROXIES)
    await scenario_1(loop, h_main)
    await scenario_2(loop, h_main)
    await scenario_3(loop, h_forged)
    await scenario_4(loop, h_proxy)

    print("\n=== Audit trail (every RCPT decision, incl. aborted tx) ===")
    for h, name in ((h_main, "main"), (h_forged, "forged"), (h_proxy, "proxy")):
        for d in h.audit_log:
            print(f"  [{name:6s}] {d.address:22s} "
                  f"{'ACCEPT' if d.accepted else 'REJECT':6s} {d.reason:20s} "
                  f"auth={d.auth_identity!r} src={d.source_ip} "
                  f"{d.policy_version}")
    print("\nAll consistency checks passed.")


if __name__ == "__main__":
    # aiosmtpd 1.4.6 internally touches the deprecated Session.login_data
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(amain(loop))
    finally:
        for task in asyncio.all_tasks(loop):
            task.cancel()
        loop.run_until_complete(
            asyncio.gather(*asyncio.all_tasks(loop), return_exceptions=True))
        loop.close()
