"""Transports for the Dynamic Authorization policy adapter.

Both transports run the real RADIUS wire processing before the policy engine
is consulted:

* requests are decoded with the shared secret of the authenticated sender;
* the RFC 5176 Request Authenticator is verified (and Message-Authenticator,
  when present);
* replies are signed with the Response Authenticator and verified by the
  client with :meth:`pyrad.packet.Packet.VerifyReply`.

:class:`UdpTransport` is the production transport on UDP port 3799.
:class:`LoopbackTransport` exchanges raw packets in one process so the demo
and the tests exercise the same code in environments where binding a UDP
socket is not permitted.
"""

import socket

from pyrad import dictionary, packet

from .constants import COA_REQUEST, DISCONNECT_REQUEST
from .policy import PolicyEngine


class AuthenticatedSender:
    """A sender known to the adapter: source address, secret and identity."""

    def __init__(self, address, secret, sender_id, name=""):
        self.address = address
        self.secret = secret
        self.sender_id = sender_id
        self.name = name


class BaseTransport:
    """Common receive path: authenticate, then delegate to the engine."""

    def __init__(self, engine, senders, dict_path):
        self.engine = engine
        self.senders = {sender.address: sender for sender in senders}
        self.dictionary = dictionary.Dictionary(dict_path)
        engine.dictionary = self.dictionary

    def _lookup_sender(self, source):
        return self.senders.get(source[0])

    def receive(self, raw, source):
        """Authenticate one datagram and return the signed raw reply, or None.

        Returns ``None`` for packets that must be silently discarded per
        RFC 5176: unknown sender, bad shared secret / authenticator, or a
        packet that is not a CoA- or Disconnect-Request.
        """
        sender = self._lookup_sender(source)
        if sender is None:
            return None
        try:
            request = packet.CoAPacket(
                dict=self.dictionary, secret=sender.secret, packet=raw)
        except packet.PacketError:
            return None
        if request.code not in (COA_REQUEST, DISCONNECT_REQUEST):
            return None
        if not request.VerifyCoARequest():
            return None
        if request.message_authenticator and \
                not request.verify_message_authenticator():
            return None
        decision = self.engine.handle(request, raw, sender.sender_id)
        return decision.reply.ReplyPacket()


class LoopbackTransport(BaseTransport):
    """In-process transport; the client reads replies from :attr:`outbox`."""

    def __init__(self, engine, senders, dict_path):
        super().__init__(engine, senders, dict_path)
        self.outbox = []

    def send(self, raw, source):
        """Deliver a raw datagram as if it arrived from ``source``."""
        reply = self.receive(raw, source)
        if reply is not None:
            self.outbox.append((reply, source))
        return reply


class UdpTransport(BaseTransport):
    """Blocking UDP server implementing the receive path."""

    def __init__(self, engine, senders, dict_path, bind_address="127.0.0.1",
                 port=3799):
        super().__init__(engine, senders, dict_path)
        self.bind_address = bind_address
        self.port = port
        self.socket = None

    def bind(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.bind_address, self.port))
        return self.socket.getsockname()

    def serve_once(self):
        """Process one datagram and send the signed reply."""
        raw, source = self.socket.recvfrom(4096)
        reply = self.receive(raw, source)
        if reply is not None:
            self.socket.sendto(reply, source)

    def run(self):
        while True:
            self.serve_once()


def build_engine(store, sender_policies, audit=None, cache=None):
    return PolicyEngine(store, sender_policies, audit=audit, cache=cache)
