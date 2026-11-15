"""Client-side helper for the Dynamic Authorization demo.

Requests are real RADIUS packets signed with the shared secret (RFC 5176
Request Authenticator, optionally with a Message-Authenticator). Replies are
decoded and their Response Authenticator is verified with
:meth:`pyrad.packet.Packet.VerifyReply`, so a tampered or wrongly signed reply
is rejected rather than accepted.
"""

from pyrad import dictionary, packet

from .constants import COA_REQUEST, DISCONNECT_REQUEST


class DynAuthClient:
    """Builds signed CoA / Disconnect requests and verifies the replies."""

    def __init__(self, secret, dict_path, source_address,
                 with_message_authenticator=False):
        self.secret = secret
        self.dictionary = dictionary.Dictionary(dict_path)
        self.source_address = source_address
        self.with_message_authenticator = with_message_authenticator

    def build_request(self, code=COA_REQUEST, identifier=None, **attributes):
        """Encode a signed request; returns ``(raw_bytes, packet)``."""
        kwargs = {"code": code, "secret": self.secret,
                  "dict": self.dictionary}
        if identifier is not None:
            kwargs["id"] = identifier
        if self.with_message_authenticator:
            kwargs["message_authenticator"] = True
        request = packet.CoAPacket(**kwargs)
        for name, value in attributes.items():
            request.AddAttribute(name, value)
        return request.RequestPacket(), request

    def disconnect(self, identifier=None, **attributes):
        return self.build_request(DISCONNECT_REQUEST, identifier, **attributes)

    def verify_reply(self, request, raw_reply):
        """Decode and cryptographically verify a reply to ``request``."""
        reply = packet.CoAPacket(
            dict=self.dictionary, secret=self.secret, packet=raw_reply)
        if not request.VerifyReply(reply, rawreply=raw_reply):
            raise packet.PacketError("reply authenticator verification failed")
        return reply
