#!/usr/bin/python
"""Example RadSec (RFC 6614) client: mutual TLS over one connection."""
import asyncio
import logging

from pyrad.dictionary import Dictionary
from pyrad.radsec import RadSecClient, client_ssl_context

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)-8s] %(message)s')


async def main():
    dictionary = Dictionary('dictionary')
    ssl_context, hostname = client_ssl_context(
        certfile='certs/client.crt', keyfile='certs/client.key',
        cafile='certs/ca.crt', server_hostname='radsec-server')
    client = RadSecClient(ssl_context, hostname, dictionary,
                          secret=b'radsec')
    await client.connect(host='127.0.0.1', port=2083)
    try:
        for _ in range(3):
            req = client.create_auth_packet(User_Name='alice')
            req['User-Password'] = req.PwCrypt('password')
            reply = await client.send_packet(req)
            print('reply code', reply.code, reply.get('Reply-Message'))
    finally:
        await client.close()


if __name__ == '__main__':
    asyncio.run(main())
