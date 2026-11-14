"""In-memory asyncio transport for fully offline SNMPv3 manager testing.

No sockets are opened. Outgoing datagrams are captured for inspection and
incoming datagrams are delivered through the real AsyncioDispatcher ->
MsgAndPduDispatcher -> mpmod/secmod -> cmdgen path, so every layer under
investigation (engine-ID cache, USM timeline, msgID cache, retry logic) is
exercised with production code.
"""

from pysnmp.carrier.asyncio.dgram.udp import UdpTransportAddress
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.carrier.base import AbstractTransport


class InMemoryTransport(AbstractTransport):
    """Drop-in UDP transport that never touches a socket."""

    PROTO_TRANSPORT_DISPATCHER = AsyncioDispatcher
    ADDRESS_TYPE = UdpTransportAddress

    def __init__(self):
        self.sent = []  # list of (message_bytes, transportAddress)
        self.dispatcher = None
        self._registered = True

    def open_client_mode(self, iface=None, allow_broadcast=False):
        return self

    def open_server_mode(self, iface=None, sock=None):
        return self

    def normalize_address(self, transportAddress):
        if not isinstance(transportAddress, self.ADDRESS_TYPE):
            transportAddress = self.ADDRESS_TYPE(transportAddress)
        return transportAddress

    def send_message(self, outgoingMessage, transportAddress):
        self.sent.append((bytes(outgoingMessage), transportAddress))

    def deliver(self, loop, incomingMessage, transportAddress):
        """Feed a datagram as if it arrived from ``transportAddress``.

        Scheduled via ``call_soon``; if the transport has already been
        unregistered by teardown, the datagram is silently dropped instead of
        raising, mirroring a socket that no longer exists.
        """
        address = self.normalize_address(transportAddress)
        loop.call_soon(self._safe_deliver, address, bytes(incomingMessage))

    def _safe_deliver(self, address, message):
        if self._callback_function is None:
            return
        self._callback_function(self, address, message)

    def last_sent(self):
        return self.sent[-1] if self.sent else None

    def close_transport(self):
        self._registered = False
        self.unregister_callback()
