#!/usr/bin/env python3
"""Two-hop RADIUS proxy demo: client -> proxy -> home server.

Each hop has its own shared secret.  The proxy (a pyrad Proxy) keeps its
own original-request context for each hop, correlates replies with a
random Proxy-State token (never by Identifier alone), verifies the
upstream reply before touching it, and only then removes this hop's
state and rebuilds the response authentication for the downstream hop.

No network is used: the three parties exchange raw datagrams through
MemorySocket inboxes, so every hop can print and check the exact bytes
on the wire.  Scenarios:

1. a successful proxied Access-Request, verified hop by hop
2. concurrent transactions: out-of-order replies, no cross-delivery
3. upstream tampering: a Reject flipped to an Accept is dropped and
   never re-signed into a downstream-verifiable Accept
4. forged and missing Proxy-State are dropped
5. replies from a wrong source are dropped
6. late replies after the timeout cleanup are dropped, the cleanup does
   not affect new transactions, and duplicate replies are dropped

Run with:  python example/proxy.py
"""

import collections
import os
import time

from pyrad import dictionary
from pyrad import host
from pyrad import packet
from pyrad import server
from pyrad.proxy import Proxy
from pyrad.server import RemoteHost
from pyrad.server import ServerPacketError

# the three parties; each hop has its own shared secret
CLIENT_ADDR = ('10.0.0.1', 4812)
PROXY_DOWN_ADDR = ('10.0.0.2', 1812)    # client-facing socket of the proxy
PROXY_UP_ADDR = ('10.0.0.2', 40000)     # proxy socket towards the home server
HOME_ADDR = ('10.0.0.3', 1812)
STRANGER_ADDR = ('10.9.9.9', 9999)      # unknown to the proxy
OTHER_ADDR = ('10.0.0.9', 1812)         # known to the proxy, but not the home server

DOWNSTREAM_SECRET = b'downstream-secret'
UPSTREAM_SECRET = b'upstream-secret'
OTHER_SECRET = b'other-secret'

USERS = {'alice': 's3cret', 'bob': 'hunter2'}

TIMEOUT = 5.0  # seconds a proxied transaction stays pending

CODE_NAMES = {
    packet.AccessRequest: 'Access-Request',
    packet.AccessAccept: 'Access-Accept',
    packet.AccessReject: 'Access-Reject',
}


class MemorySocket:
    """An in-memory datagram socket: sendto() fills the peer's inbox."""

    network = {}

    def __init__(self, address):
        self.address = address
        self.inbox = collections.deque()
        MemorySocket.network[address] = self

    def sendto(self, data, address):
        MemorySocket.network[address].inbox.append((bytes(data), self.address))


class PendingRequest:
    """One in-flight transaction: this hop's own original request context.

    client_pkt/client_fd are the downstream original request and the
    socket it arrived on; upstream_pkt is the request this hop sent to
    the home server, needed to verify the reply.
    """

    def __init__(self, client_pkt, client_fd, upstream_pkt, home_server,
                 expires):
        self.client_pkt = client_pkt
        self.client_fd = client_fd
        self.upstream_pkt = upstream_pkt
        self.home_server = home_server
        self.expires = expires


class TwoHopProxy(Proxy):
    """A pyrad Proxy which forwards Access-Requests to one home server.

    Requests are correlated by a random Proxy-State token, not by the
    Identifier: the token is appended after any Proxy-State the client
    sent (their order is kept) and removed again from the reply.  The
    upstream Identifier is unique among pending transactions, so a reply
    can never be matched to the wrong client by ID.
    """

    def __init__(self, home_server, upstream_secret, timeout=TIMEOUT,
                 **kwargs):
        Proxy.__init__(self, **kwargs)
        self.home_server = home_server
        self.upstream_secret = upstream_secret
        self.timeout = timeout
        self.pending = {}          # Proxy-State token -> PendingRequest
        self._pending_ids = set()  # upstream Identifiers in use

    def _new_upstream_id(self):
        # an Identifier which no pending transaction uses, so identical
        # IDs of different transactions can never collide upstream
        while True:
            new_id = packet.CreateID()
            if new_id not in self._pending_ids:
                return new_id

    def _expire(self, now):
        # remove only expired transactions, keyed by their own token;
        # transactions created afterwards are not affected
        for token in [t for t, c in self.pending.items()
                      if c.expires <= now]:
            self._pending_ids.discard(self.pending[token].upstream_pkt.id)
            del self.pending[token]

    def HandleAuthPacket(self, pkt):
        self._expire(time.monotonic())

        token = packet.Packet.CreateAuthenticator()
        upstream = self.CreateAuthPacket(
            code=packet.AccessRequest,
            secret=self.upstream_secret,
            authenticator=packet.Packet.CreateAuthenticator(),
            message_authenticator=True)
        upstream.id = self._new_upstream_id()

        for key in pkt.keys():
            if key in ('User-Password', 'Message-Authenticator'):
                continue
            upstream[key] = pkt[key]  # keeps the Proxy-State order
        if 'User-Password' in pkt:
            # User-Password is hidden with the downstream secret and the
            # client Request Authenticator; re-hide it for the new hop.
            upstream['User-Password'] = upstream.PwCrypt(
                pkt.PwDecrypt(pkt['User-Password'][0]))
        # our state goes last, after any Proxy-State the client sent
        upstream.AddAttribute('Proxy-State', token)

        self.pending[token] = PendingRequest(
            client_pkt=pkt, client_fd=pkt.fd, upstream_pkt=upstream,
            home_server=self.home_server,
            expires=time.monotonic() + self.timeout)
        self._pending_ids.add(upstream.id)
        self._proxyfd.sendto(upstream.RequestPacket(), self.home_server)

    def _HandleProxyPacket(self, pkt):
        Proxy._HandleProxyPacket(self, pkt)  # known source and reply code
        self._expire(time.monotonic())

        # correlate by our Proxy-State token, never by Identifier alone
        states = pkt.get('Proxy-State', [])
        token = states[-1] if states else None
        ctx = self.pending.get(token)
        if ctx is None:
            raise ServerPacketError(
                'Reply without our Proxy-State, or too late')
        if pkt.source != ctx.home_server:
            raise ServerPacketError('Reply from the wrong home server')
        # verify the upstream reply first: Identifier, Response
        # Authenticator, Message-Authenticator and Proxy-State
        if not ctx.upstream_pkt.VerifyReply(pkt):
            raise ServerPacketError('Reply verification failed')

        # verified: remove this hop's state, then rebuild the response
        # authentication for the downstream hop
        del self.pending[token]
        self._pending_ids.discard(ctx.upstream_pkt.id)

        down = ctx.client_pkt.CreateReply()
        down.code = pkt.code
        for key in pkt.keys():
            if key in ('Proxy-State', 'Message-Authenticator'):
                # our Proxy-State is removed; the client's own ones are
                # copied by CreateReply; a fresh Message-Authenticator
                # and Response Authenticator are computed by ReplyPacket
                continue
            down[key] = pkt[key]
        down.source = ctx.client_pkt.source
        self.SendReplyPacket(ctx.client_fd, down)


class HomeServer(server.Server):
    """The home server: accepts the users of USERS, rejects the rest."""

    def HandleAuthPacket(self, pkt):
        name = pkt.get('User-Name', ['?'])[0]
        ok = pkt.get('User-Password') and \
            pkt.PwDecrypt(pkt['User-Password'][0]) == USERS.get(name)
        reply = self.CreateReplyPacket(
            pkt, Reply_Message='welcome %s' % name if ok else 'go away')
        reply.code = packet.AccessAccept if ok else packet.AccessReject
        self.SendReplyPacket(pkt.fd, reply)


class Topology:
    """The three parties and their memory sockets."""

    def __init__(self):
        radict = dictionary.Dictionary(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'dictionary'))
        self.client_host = host.Host(dict=radict)
        self.client_fd = MemorySocket(CLIENT_ADDR)
        self.proxy_down_fd = MemorySocket(PROXY_DOWN_ADDR)
        self.home_fd = MemorySocket(HOME_ADDR)

        self.proxy = TwoHopProxy(
            home_server=HOME_ADDR,
            upstream_secret=UPSTREAM_SECRET,
            hosts={
                CLIENT_ADDR[0]: RemoteHost(CLIENT_ADDR[0],
                                           DOWNSTREAM_SECRET, 'client'),
                HOME_ADDR[0]: RemoteHost(HOME_ADDR[0],
                                         UPSTREAM_SECRET, 'home'),
                OTHER_ADDR[0]: RemoteHost(OTHER_ADDR[0],
                                          OTHER_SECRET, 'other-proxy'),
            },
            dict=radict, enforce_ma=True)
        self.proxy._proxyfd = MemorySocket(PROXY_UP_ADDR)

        self.home = HomeServer(
            hosts={PROXY_UP_ADDR[0]: RemoteHost(PROXY_UP_ADDR[0],
                                                UPSTREAM_SECRET, 'proxy')},
            dict=radict, enforce_ma=True)


def new_request(topo, username, password, proxy_states=()):
    """A client Access-Request with a Message-Authenticator."""
    req = topo.client_host.CreateAuthPacket(
        secret=DOWNSTREAM_SECRET,
        authenticator=packet.Packet.CreateAuthenticator(),
        message_authenticator=True,
        User_Name=username)
    for state in proxy_states:
        req.AddAttribute('Proxy-State', state)
    req['User-Password'] = req.PwCrypt(password)
    return req


def pump_request(srv, fd):
    """Deliver the next datagram of fd's inbox as a request to srv."""
    data, source = fd.inbox.popleft()
    pkt = srv.CreateAuthPacket(packet=data)
    pkt.source = source
    pkt.fd = fd
    srv._HandleAuthPacket(pkt)
    return pkt, data


def deliver_reply(topo, data=None, source=None):
    """Deliver one upstream reply to the proxy.

    With ``data`` None the next datagram of the proxy's upstream inbox
    is used.  Returns the reason the proxy dropped the reply, or None
    if the proxy accepted and forwarded it.
    """
    if data is None:
        data, real_source = topo.proxy._proxyfd.inbox.popleft()
    else:
        real_source = HOME_ADDR
    pkt = topo.proxy.CreatePacket(packet=data)
    pkt.source = source or real_source
    pkt.fd = topo.proxy._proxyfd
    try:
        topo.proxy._HandleProxyPacket(pkt)
    except ServerPacketError as err:
        return str(err)
    return None


def client_receive(topo, req):
    """Pop the client's inbox and verify the reply against the request."""
    data, source = topo.client_fd.inbox.popleft()
    reply = topo.client_host.CreatePacket(packet=data)
    assert req.VerifyReply(reply, rawreply=data), \
        'the client rejects the reply'
    return reply, data


def show(tag, data):
    print('    %-18s %-14s id=%-3d %s' % (
        tag, CODE_NAMES.get(data[0], data[0]), data[1], data.hex()))


def send_request(topo, req):
    """Send a client request through the proxy to the home server."""
    raw = req.RequestPacket()
    topo.client_fd.sendto(raw, PROXY_DOWN_ADDR)
    show('client -> proxy', raw)
    pump_request(topo.proxy, topo.proxy_down_fd)
    pump_request(topo.home, topo.home_fd)
    return raw


def scenario_success():
    print('== Scenario 1: successful proxied Access-Request ==')
    topo = Topology()
    req = new_request(topo, 'alice', 's3cret',
                      proxy_states=(b'nas-state-1', b'nas-state-2'))
    raw1 = req.RequestPacket()
    topo.client_fd.sendto(raw1, PROXY_DOWN_ADDR)
    show('client -> proxy', raw1)

    # hop 1: the proxy checks the source and the Message-Authenticator
    pump_request(topo.proxy, topo.proxy_down_fd)
    assert len(topo.proxy.pending) == 1
    print('    proxy: downstream Message-Authenticator ok, state saved')

    # hop 2: the home server checks its own hop of the same request
    upstream_req, raw2 = pump_request(topo.home, topo.home_fd)
    show('proxy -> home', raw2)
    states = upstream_req['Proxy-State']
    assert states[:2] == [b'nas-state-1', b'nas-state-2']
    assert len(states) == 3 and states[2] in topo.proxy.pending
    print('    home: upstream Message-Authenticator ok, '
          'Proxy-State %r' % (states,))

    # hop 3: the proxy verifies the reply before touching it
    raw3 = topo.proxy._proxyfd.inbox[0][0]
    show('home -> proxy', raw3)
    assert deliver_reply(topo) is None
    assert not topo.proxy.pending
    print('    proxy: upstream reply verified, state removed')

    # hop 4: the client verifies the final raw packet
    reply, raw4 = client_receive(topo, req)
    show('proxy -> client', raw4)
    assert reply.code == packet.AccessAccept
    assert reply.id == req.id
    assert reply['Proxy-State'] == [b'nas-state-1', b'nas-state-2']
    print('    client: VerifyReply ok, external Proxy-State order kept, '
          'reply: %s' % reply['Reply-Message'][0])


def scenario_concurrent():
    print('== Scenario 2: concurrent transactions, out-of-order replies ==')
    topo = Topology()
    req1 = new_request(topo, 'alice', 's3cret')
    req2 = new_request(topo, 'bob', 'hunter2')
    req2.id = (req1.id + 1) % 256
    send_request(topo, req1)
    send_request(topo, req2)
    # each transaction got its own upstream Identifier
    assert len(topo.proxy._pending_ids) == 2

    # a reply with a valid upstream Identifier but a foreign Proxy-State
    # must not be correlated by ID alone and reach the wrong client
    ctx = next(iter(topo.proxy.pending.values()))
    forged = topo.client_host.CreatePacket(
        code=packet.AccessAccept, id=ctx.upstream_pkt.id,
        secret=UPSTREAM_SECRET,
        authenticator=ctx.upstream_pkt.authenticator,
        Proxy_State=b'forged-token')
    reason = deliver_reply(topo, data=forged.ReplyPacket())
    assert reason is not None
    assert not topo.client_fd.inbox
    print('    proxy dropped a reply with a known ID but foreign '
          'Proxy-State: %s' % reason)

    # the genuine replies arrive out of order; each reaches its client
    raw_r1 = topo.proxy._proxyfd.inbox.popleft()
    raw_r2 = topo.proxy._proxyfd.inbox.popleft()
    assert deliver_reply(topo, data=raw_r2[0]) is None
    assert deliver_reply(topo, data=raw_r1[0]) is None
    replies = {}
    while topo.client_fd.inbox:
        data, _ = topo.client_fd.inbox.popleft()
        reply = topo.client_host.CreatePacket(packet=data)
        replies[reply.id] = (reply, data)
    for req in (req1, req2):
        reply, data = replies[req.id]
        assert req.VerifyReply(reply, rawreply=data)
        assert reply.code == packet.AccessAccept
    print('    both clients verified their own reply '
          '(ids %d and %d)' % (req1.id, req2.id))


def scenario_tampered():
    print('== Scenario 3: upstream tampering (Reject flipped to Accept) ==')
    topo = Topology()
    req = new_request(topo, 'alice', 'wrong-password')
    send_request(topo, req)

    raw3 = topo.proxy._proxyfd.inbox[0][0]
    assert raw3[0] == packet.AccessReject
    show('home -> proxy', raw3)

    # an attacker flips the Reject into an Accept; the proxy must not
    # re-sign it into a downstream-verifiable success response
    tampered = bytes([packet.AccessAccept]) + raw3[1:]
    reason = deliver_reply(topo, data=tampered)
    assert reason is not None
    assert not topo.client_fd.inbox
    print('    proxy dropped the tampered packet: %s' % reason)
    print('    client received nothing; no re-signed Accept exists')

    # the genuine Reject still arrives and is delivered as a Reject
    assert deliver_reply(topo) is None
    reply, raw4 = client_receive(topo, req)
    assert reply.code == packet.AccessReject
    show('proxy -> client', raw4)
    print('    client verified the genuine Access-Reject')


def scenario_proxy_state():
    print('== Scenario 4: forged and missing Proxy-State ==')
    topo = Topology()
    req = new_request(topo, 'alice', 's3cret')
    send_request(topo, req)
    ctx = next(iter(topo.proxy.pending.values()))

    # a correctly signed Accept which does not carry our Proxy-State
    for label, states in (('missing', []), ('forged', [b'guessed-token'])):
        accept = topo.client_host.CreatePacket(
            code=packet.AccessAccept, id=ctx.upstream_pkt.id,
            secret=UPSTREAM_SECRET,
            authenticator=ctx.upstream_pkt.authenticator)
        for state in states:
            accept.AddAttribute('Proxy-State', state)
        reason = deliver_reply(topo, data=accept.ReplyPacket())
        assert reason is not None
        assert not topo.client_fd.inbox
        print('    proxy dropped a signed reply with %s Proxy-State: %s'
              % (label, reason))

    # the genuine reply is still accepted afterwards
    assert deliver_reply(topo) is None
    reply, _ = client_receive(topo, req)
    assert reply.code == packet.AccessAccept
    print('    genuine reply still delivered and verified')


def scenario_wrong_source():
    print('== Scenario 5: replies from a wrong source ==')
    topo = Topology()
    req = new_request(topo, 'alice', 's3cret')
    send_request(topo, req)
    raw3 = topo.proxy._proxyfd.inbox[0][0]

    # a perfect copy of the genuine reply from an unknown host
    reason = deliver_reply(topo, data=raw3, source=STRANGER_ADDR)
    assert reason is not None
    print('    proxy dropped the copy from a stranger: %s' % reason)

    # and from a known host which is not this transaction's home server
    reason = deliver_reply(topo, data=raw3, source=OTHER_ADDR)
    assert reason is not None
    assert not topo.client_fd.inbox
    print('    proxy dropped the copy from the wrong home server: %s'
          % reason)

    assert deliver_reply(topo) is None
    reply, _ = client_receive(topo, req)
    assert reply.code == packet.AccessAccept
    print('    genuine reply from the home server delivered and verified')


def scenario_timeout():
    print('== Scenario 6: late replies, timeout cleanup, duplicates ==')
    topo = Topology()
    req = new_request(topo, 'alice', 's3cret')
    send_request(topo, req)

    # the cleanup timer fires after the timeout
    topo.proxy._expire(time.monotonic() + TIMEOUT + 1)
    assert not topo.proxy.pending
    reason = deliver_reply(topo)
    assert reason is not None
    assert not topo.client_fd.inbox
    print('    proxy dropped the late reply: %s' % reason)

    # the cleanup did not affect new transactions: a full run succeeds
    req2 = new_request(topo, 'bob', 'hunter2')
    send_request(topo, req2)
    raw3 = topo.proxy._proxyfd.inbox[0][0]
    assert deliver_reply(topo) is None
    reply, _ = client_receive(topo, req2)
    assert reply.code == packet.AccessAccept
    print('    new transaction after the cleanup succeeded')

    # a duplicate of that reply finds no state and is dropped
    reason = deliver_reply(topo, data=raw3)
    assert reason is not None
    assert not topo.client_fd.inbox
    print('    proxy dropped the duplicate reply: %s' % reason)


def main():
    scenario_success()
    scenario_concurrent()
    scenario_tampered()
    scenario_proxy_state()
    scenario_wrong_source()
    scenario_timeout()
    print('All scenarios passed.')


if __name__ == '__main__':
    main()
