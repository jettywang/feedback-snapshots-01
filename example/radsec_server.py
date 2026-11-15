#!/usr/bin/python
"""Example RadSec (RFC 6614) server: RADIUS over mutually authenticated TLS.

The trust decision is the peer_factory callback: it maps the certificate
TLS already verified to a RadSecPeer, and only that identity (never the
connection address or a packet attribute) is used to authorize the client.
Run example/radsec_client.py against it with certificates signed by the same
CA.
"""
import asyncio
import logging

from pyrad import packet
from pyrad.dictionary import Dictionary
from pyrad.radsec import (
    RadSecPeer,
    RadSecServer,
    certificate_identity,
    server_ssl_context,
)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)-8s] %(message)s')


def peer_factory(peercert):
    # TLS has already verified the certificate against the trusted CA; map
    # its identity to a RADIUS peer, or return None to refuse the connection
    identity = certificate_identity(peercert)
    if identity == 'trusted-client':
        return RadSecPeer(identity=identity)
    return None


class RadSecExampleServer(RadSecServer):
    def handle_auth_packet(self, connection, pkt, addr):
        print('Access-Request from', pkt.radsec_peer, 'user', pkt.get('User-Name'))
        reply = self.create_reply_packet(pkt, Reply_Message='hello over RadSec')
        if pkt.PwDecrypt(pkt['User-Password'][0]) == 'password':
            reply.code = packet.AccessAccept
        else:
            reply.code = packet.AccessReject
        connection.send_response(reply)

    def handle_acct_packet(self, connection, pkt, addr):
        print('Accounting-Request from', pkt.radsec_peer)
        connection.send_response(self.create_reply_packet(pkt))

    def handle_coa_packet(self, connection, pkt, addr):
        connection.send_response(self.create_reply_packet(pkt))

    def handle_disconnect_packet(self, connection, pkt, addr):
        reply = self.create_reply_packet(pkt)
        reply.code = packet.DisconnectACK
        connection.send_response(reply)


async def main():
    dictionary = Dictionary('dictionary')
    ssl_context = server_ssl_context(
        certfile='certs/server.crt', keyfile='certs/server.key',
        cafile='certs/ca.crt')
    server = RadSecExampleServer(
        ssl_context, dictionary, peer_factory, secret=b'radsec')
    await server.start(host='127.0.0.1', port=2083)
    print('RadSec server listening on 127.0.0.1:2083')
    try:
        await asyncio.Event().wait()
    finally:
        await server.close()


if __name__ == '__main__':
    asyncio.run(main())
