# server.py
#
# Copyright 2003-2004,2007,2016 Wichert Akkerman <wichert@wiggy.net>

import ipaddress
import select
import socket
import hashlib
import hmac
from pyrad import host
from pyrad import packet
from pyrad.secrets import SecretRing, SharedSecret
import logging


logger = logging.getLogger('pyrad')


class RemoteHost:
    """A RADIUS client or server and its shared secrets.

    Used as the values of the ``hosts`` mapping of :class:`Server`,
    :class:`pyrad.server_async.ServerAsync` and :class:`pyrad.proxy.Proxy`.
    pyrad only uses the secrets: the servers look up the client by the
    key of the ``hosts`` mapping (the IP address as the socket reports it),
    not by ``address``. The address, name and ports are stored for the
    application and are not used by pyrad.

    A peer normally has one secret, passed as ``secret``. To rotate the
    secret without dropping the requests of clients that still use the old
    one, pass a list of :class:`~pyrad.secrets.SharedSecret` entries to
    ``secrets`` instead: one current secret and retired secrets, each with
    an expiry time and an attempt limit. The server then authenticates each
    request against the still-valid candidates and pins the secret that
    verified it to the whole processing of that request, including the
    reply. Assign a new :class:`RemoteHost` (or a new ring) to the
    ``hosts`` mapping to reload the configuration; a request already being
    processed keeps the secret it was authenticated with.
    """

    def __init__(self, address, secret=None, name=None, authport=1812,
                 acctport=1813, coaport=3799, secrets=None, clock=None):
        """
        :param  address: IP address of the host (informational)
        :type   address: str
        :param   secret: RADIUS shared secret
        :type    secret: bytes
        :param     name: short name of the host (informational)
        :type      name: str
        :param authport: authentication port of the host (informational)
        :type  authport: int
        :param acctport: accounting port of the host (informational)
        :type  acctport: int
        :param  coaport: CoA port of the host (informational)
        :type   coaport: int
        :param secrets: current and retired shared secrets with their
            validity constraints, instead of a single ``secret``
        :type  secrets: list[pyrad.secrets.SharedSecret]
        :param clock: callable returning the current timezone-aware
            moment, used to evaluate retired-secret expiry; inject a fake
            clock in tests
        """
        self.address = address
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport
        self.name = name
        if secrets is not None:
            if secret is not None:
                raise ValueError('pass either secret or secrets, not both')
            self._secrets = SecretRing(secrets, clock=clock)
        else:
            self._secrets = SecretRing(
                [SharedSecret(secret if secret is not None else b'')],
                clock=clock)

    @property
    def secret(self):
        """The current shared secret (bytes).

        Retired secrets are not exposed here; they are only tried while a
        request is authenticated. Assigning a secret replaces the whole
        ring with a single current secret, as the single-secret API did.
        """
        return self._secrets.secret

    @secret.setter
    def secret(self, value):
        self._secrets = SecretRing([SharedSecret(value)])

    @property
    def secrets(self):
        """The :class:`~pyrad.secrets.SecretRing` with the current and
        retired secrets of the peer."""
        return self._secrets

    @secrets.setter
    def secrets(self, ring):
        if not isinstance(ring, SecretRing):
            raise TypeError('expected a SecretRing')
        self._secrets = ring


class ServerPacketError(Exception):
    """A received packet is dropped.

    Raised by :class:`Server`, :class:`pyrad.server_async.ServerAsync` and
    :class:`pyrad.proxy.Proxy` for packets they don't accept: packets from
    an unknown client, packets of the wrong type for the port they were
    received on, and Access-Requests with an invalid or (with
    ``enforce_ma``) a missing Message-Authenticator.

    A packet handler may raise it to drop a request: the server then logs
    a single line with the message instead of a traceback.
    """


def CheckMessageAuthenticator(pkt, enforce_ma=False):
    """Check the Message-Authenticator of a received Access-Request.

    This is the BlastRADIUS countermeasure (CVE-2024-3596) of the servers.
    An invalid Message-Authenticator is always rejected, a missing one only
    with ``enforce_ma``.

    :param        pkt: received packet with the secret set
    :type         pkt: pyrad.packet.Packet
    :param enforce_ma: require a Message-Authenticator
    :type  enforce_ma: bool
    :raise ServerPacketError: if the packet should be dropped
    """
    if pkt.message_authenticator:
        if not pkt.verify_message_authenticator():
            raise ServerPacketError(
                'Received Access-Request with invalid Message-Authenticator')
    elif enforce_ma:
        raise ServerPacketError(
            'Received Access-Request without Message-Authenticator')


def _verify_with_secret(pkt, secret):
    """Return True if ``secret`` authenticates the received ``pkt``.

    Access-Requests are authenticated with their Message-Authenticator;
    Accounting, CoA and Disconnect requests with their Request
    Authenticator. A packet without a Message-Authenticator cannot be
    distinguished between secrets, so the current secret is assumed for it
    (the legacy single-secret behaviour).

    :param pkt: received packet
    :type  pkt: pyrad.packet.Packet
    :param secret: candidate shared secret
    :type  secret: bytes
    :return: True if the secret authenticates the packet
    :rtype: bool
    """
    if pkt.code == packet.AccessRequest:
        if not pkt.message_authenticator:
            return False
        return pkt.verify_message_authenticator(secret=secret)
    if pkt.code in (packet.AccountingRequest, packet.CoARequest,
                    packet.DisconnectRequest):
        return _request_authenticator_matches(pkt, secret)
    return False


def _request_authenticator_matches(pkt, secret):
    hash = hashlib.md5(pkt.raw_packet[0:4] + 16 * b'\x00' +
                       pkt.raw_packet[20:] + secret).digest()
    return hmac.compare_digest(hash, pkt.authenticator)


def _host_ring(remote_host):
    """Return the :class:`~pyrad.secrets.SecretRing` of a peer.

    Accepts both a :class:`RemoteHost` and a plain object with a single
    ``secret`` attribute (the historical hosts value).

    :param remote_host: configured peer or a legacy single-secret object
    :return: secret ring of the peer
    :rtype: pyrad.secrets.SecretRing
    """
    ring = getattr(remote_host, 'secrets', None)
    if isinstance(ring, SecretRing):
        return ring
    return SecretRing([SharedSecret(getattr(remote_host, 'secret', b''))])


def SelectSecret(remote_host, pkt):
    """Authenticate a received packet against the peer's candidate secrets.

    The candidates are only the still-valid secrets configured for the
    peer (the current secret first, then retired secrets inside their
    compatibility window and attempt budget); nothing is learned from the
    packet and a successful match is not cached, so an expired or removed
    secret can not be re-admitted by a retry. The secret that verifies the
    packet is pinned to it: it is stored on the packet as ``pkt.secret``
    together with its non-secret label as ``pkt.matched_secret_label`` and
    the configuration version as ``pkt.matched_secret_version``, and the
    reply and hidden attributes use that same secret. An accepted retired
    secret has one attempt charged to it.

    A single-secret peer keeps the legacy behaviour: the secret is used
    without verification here, and the caller performs the usual checks.
    A peer configured for rotation (current plus retired secrets) is always
    authenticated against the candidates, even once the retired secrets
    have expired and only the current secret is still valid.

    :param remote_host: configuration of the peer the packet came from
    :type  remote_host: RemoteHost
    :param pkt: received packet, with ``raw_packet`` set
    :type  pkt: pyrad.packet.Packet
    :return: the selected secret entry
    :rtype: pyrad.secrets.SharedSecret
    :raise ServerPacketError: if no secret is configured, or if the peer is
        configured for rotation and no candidate authenticates the packet
    """
    ring = _host_ring(remote_host)
    entries = ring.candidates()
    if not entries:
        raise ServerPacketError('No shared secret configured for peer')

    if not ring.rotation_configured:
        # legacy single-secret peer: trust the secret, the caller runs
        # the existing Message-Authenticator / Request-Authenticator checks
        entry = entries[0]
        pkt.secret = entry.secret
        pkt.matched_secret_label = entry.label
        pkt.matched_secret_version = entry.version
        if not entry.current:
            ring.record_attempt(entry)
        return entry

    if pkt.code == packet.AccessRequest and not pkt.message_authenticator:
        # without a Message-Authenticator an Access-Request can not be
        # attributed to one of several secrets; keep the current one
        entry = ring.current
        if entry is None or entry.expired(ring.clock()):
            raise ServerPacketError(
                'No current secret for Access-Request without '
                'Message-Authenticator')
        pkt.secret = entry.secret
        pkt.matched_secret_label = entry.label
        pkt.matched_secret_version = entry.version
        return entry

    for entry in entries:
        if _verify_with_secret(pkt, entry.secret):
            pkt.secret = entry.secret
            pkt.matched_secret_label = entry.label
            pkt.matched_secret_version = entry.version
            ring.record_attempt(entry)
            logger.debug('Authenticated request with secret label=%s '
                         'config version=%s', entry.label, entry.version)
            return entry

    logger.info('Dropping packet: no configured shared secret '
                'authenticates it')
    raise ServerPacketError(
        'Received packet that no configured shared secret authenticates')


def _HostAddresses(address):
    """Return the keys under which a source address is looked up in hosts.

    These are the address as received and, for an IPv4-mapped IPv6 address
    (an IPv4 client of a dual stack socket bound to '::'), its IPv4 form.

    :param address: source address of a packet
    :type  address: str
    :return: addresses to look up, in order
    :rtype:  list[str]
    """
    addresses = [address]
    try:
        mapped = ipaddress.ip_address(address).ipv4_mapped
    except (ValueError, AttributeError, TypeError):
        mapped = None
    if mapped is not None:
        addresses.append(str(mapped))
    return addresses


def _LookupHost(hosts, address):
    """Return the hosts entry of a source address, or None.

    :param   hosts: hosts who are allowed to talk to us
    :type    hosts: dict[str, RemoteHost]
    :param address: source address of a packet
    :type  address: str
    """
    for key in _HostAddresses(address):
        if key in hosts:
            return hosts[key]
    return None


class Server(host.Host):
    """Basic blocking RADIUS server.

    The server receives and decodes requests, checks that they come from a
    known client and are valid, and passes them to the packet handlers.
    Derive from it and override :meth:`HandleAuthPacket`,
    :meth:`HandleAcctPacket`, :meth:`HandleCoaPacket` and
    :meth:`HandleDisconnectPacket`; the default handlers ignore the
    request. Then call :meth:`Run`.

    :ivar hosts: clients allowed to send requests, see the ``hosts``
        parameter
    :vartype hosts: dict[str, RemoteHost]
    :cvar MaxPacketSize: size of the receive buffer (RADIUS packets are at
        most 4096 octets)
    :vartype MaxPacketSize: int
    """
    MaxPacketSize = 8192

    def __init__(self, addresses=[], authport=1812, acctport=1813, coaport=3799,
                 hosts=None, dict=None, auth_enabled=True, acct_enabled=True, coa_enabled=False,
                 enforce_ma=False, enable_pkt_verify=True):
        """
        :param addresses: IP addresses or host names to listen on. The
            constructor binds them with :meth:`~pyrad.server.Server.BindToAddress`. Without
            addresses no packets are received unless :meth:`~pyrad.server.Server.BindToAddress`
            is called.
        :type  addresses: list[str]
        :param authport: port to listen on for authentication packets
        :type  authport: int
        :param acctport: port to listen on for accounting packets
        :type  acctport: int
        :param coaport: port to listen on for CoA and Disconnect packets
        :type  coaport: int
        :param hosts: clients allowed to send requests, mapping their IP
            address to a :class:`~pyrad.server.RemoteHost` with the shared secret. The
            entry ``'0.0.0.0'`` is used for all other clients. IPv4 clients
            of a socket bound to ``'::'`` are looked up by their IPv4
            address. Requests of other clients are dropped.
        :type  hosts: dict[str, pyrad.server.RemoteHost]
        :param dict: RADIUS dictionary used to decode the requests
        :type  dict: pyrad.dictionary.Dictionary
        :param auth_enabled: listen for authentication packets
        :type  auth_enabled: bool
        :param acct_enabled: listen for accounting packets
        :type  acct_enabled: bool
        :param coa_enabled: listen for CoA and Disconnect packets
        :type  coa_enabled: bool
        :param enforce_ma: drop Access-Requests without a Message-Authenticator
            (an invalid Message-Authenticator is always dropped)
        :type  enforce_ma: bool
        :param enable_pkt_verify: drop Accounting, CoA and Disconnect requests
            with an invalid Request Authenticator
        :type  enable_pkt_verify: bool
        """
        host.Host.__init__(self, authport, acctport, coaport, dict)
        if hosts is None:
            self.hosts = {}
        else:
            self.hosts = hosts

        self.auth_enabled = auth_enabled
        self.authfds = []
        self.acct_enabled = acct_enabled
        self.acctfds = []
        self.coa_enabled = coa_enabled
        self.coafds = []
        self.enforce_ma = enforce_ma
        self.enable_pkt_verify = enable_pkt_verify

        for addr in addresses:
            self.BindToAddress(addr)

    def _GetAddrInfo(self, addr):
        """Use getaddrinfo to look up all addresses of an address.

        Returns a set of (family, address) tuples, or an empty list if the
        address can't be resolved.

        :param addr: IP address or host name to look up
        :type  addr: str
        """
        results = set()
        try:
            tmp = socket.getaddrinfo(addr, 80)
        except socket.gaierror:
            return []

        for el in tmp:
            results.add((el[0], el[4][0]))

        return results

    def BindToAddress(self, addr):
        """Listen on an address.

        Opens a socket for each enabled port (authentication, accounting,
        CoA). ``'0.0.0.0'`` listens on all IPv4 addresses, ``'::'`` on all
        IPv6 addresses and, on a dual stack host, on all IPv4 addresses as
        well. A host name is resolved and every address it resolves to is
        bound; a name that can't be resolved is ignored silently. Call it
        before :meth:`Run`.

        :param addr: IP address or host name to listen on
        :type  addr: str
        """
        addrFamily = self._GetAddrInfo(addr)
        for (family, address) in addrFamily:
            if self.auth_enabled:
                authfd = socket.socket(family, socket.SOCK_DGRAM)
                authfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                authfd.bind((address, self.authport))
                self.authfds.append(authfd)

            if self.acct_enabled:
                acctfd = socket.socket(family, socket.SOCK_DGRAM)
                acctfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                acctfd.bind((address, self.acctport))
                self.acctfds.append(acctfd)

            if self.coa_enabled:
                coafd = socket.socket(family, socket.SOCK_DGRAM)
                coafd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                coafd.bind((address, self.coaport))
                self.coafds.append(coafd)

    def HandleAuthPacket(self, pkt):
        """Handle an Access-Request.

        Called by :meth:`Run` for each Access-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        A Message-Authenticator in the request has been verified, and with
        ``enforce_ma`` requests without one have been dropped. The
        User-Password is not verified: decrypt it with
        :meth:`pkt.PwDecrypt <pyrad.packet.AuthPacket.PwDecrypt>` and check
        it yourself.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.AuthPacket
        """

    def HandleAcctPacket(self, pkt):
        """Handle an Accounting-Request.

        Called by :meth:`Run` for each Accounting-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        With ``enable_pkt_verify`` its Request Authenticator has been
        verified.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.AcctPacket
        """

    def HandleCoaPacket(self, pkt):
        """Handle a CoA-Request.

        Called by :meth:`Run` for each CoA-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        With ``enable_pkt_verify`` its Request Authenticator has been
        verified.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.CoAPacket
        """

    def HandleDisconnectPacket(self, pkt):
        """Handle a Disconnect-Request.

        Called by :meth:`Run` for each Disconnect-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        With ``enable_pkt_verify`` its Request Authenticator has been
        verified. :meth:`CreateReplyPacket` creates a Disconnect-ACK; set
        ``reply.code`` to ``pyrad.packet.DisconnectNAK`` to refuse it.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.CoAPacket
        """

    def _ResolveHost(self, pkt):
        """Return the configured peer of a received packet.

        Raises :class:`ServerPacketError` for unknown hosts.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        :return: the peer configuration
        :rtype: RemoteHost
        """
        remote_host = _LookupHost(self.hosts, pkt.source[0])
        if remote_host is None and '0.0.0.0' in self.hosts:
            remote_host = self.hosts['0.0.0.0']
        if remote_host is None:
            raise ServerPacketError('Received packet from unknown host')
        return remote_host

    def _HandleAuthPacket(self, pkt):
        """Process a packet received on the authentication port.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        remote_host = self._ResolveHost(pkt)
        if pkt.code != packet.AccessRequest:
            raise ServerPacketError(
                'Received non-authentication packet on authentication port')
        SelectSecret(remote_host, pkt)
        CheckMessageAuthenticator(pkt, self.enforce_ma)
        self.HandleAuthPacket(pkt)

    def _HandleAcctPacket(self, pkt):
        """Process a packet received on the accounting port.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        remote_host = self._ResolveHost(pkt)
        if pkt.code != packet.AccountingRequest:
            raise ServerPacketError(
                    'Received non-accounting packet on accounting port')
        multi = self._multiple_secrets(remote_host)
        # with several candidates SelectSecret only returns once the
        # Request Authenticator has been verified, so the legacy check is
        # skipped in that case
        SelectSecret(remote_host, pkt)
        if not multi and self.enable_pkt_verify and \
                not pkt.VerifyAcctRequest():
            raise packet.PacketError('Packet verification failed')
        self.HandleAcctPacket(pkt)

    def _HandleCoaPacket(self, pkt):
        """Process a packet received on the CoA port.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        remote_host = self._ResolveHost(pkt)
        if pkt.code not in (packet.CoARequest, packet.DisconnectRequest):
            raise ServerPacketError('Received non-coa packet on coa port')
        multi = self._multiple_secrets(remote_host)
        # with several candidates SelectSecret only returns once the
        # Request Authenticator has been verified, so the legacy check is
        # skipped in that case
        SelectSecret(remote_host, pkt)
        if not multi and self.enable_pkt_verify and \
                not pkt.VerifyCoARequest():
            raise packet.PacketError('Packet verification failed')
        if pkt.code == packet.CoARequest:
            self.HandleCoaPacket(pkt)
        else:
            self.HandleDisconnectPacket(pkt)

    @staticmethod
    def _multiple_secrets(remote_host):
        """Whether the peer is configured for secret rotation, so that
        :func:`SelectSecret` already authenticated the request."""
        return _host_ring(remote_host).rotation_configured

    def _GrabPacket(self, pktgen, fd):
        """Read a packet from a network connection.

        This method assumes there is data waiting to be read.

        :param fd: socket to read packet from
        :type  fd: socket.socket
        :return: RADIUS packet
        :rtype:  pyrad.packet.Packet
        """
        (data, source) = fd.recvfrom(self.MaxPacketSize)
        try:
            pkt = pktgen(data)
        except packet.PacketError:
            raise
        except Exception as err:
            # the packet is not authenticated yet, never let it stop the
            # main loop
            raise packet.PacketError('%s: %s' % (type(err).__name__, err))
        pkt.source = source
        pkt.fd = fd
        return pkt

    def _PrepareSockets(self):
        """Prepare all sockets to receive packets."""
        for fd in self.authfds + self.acctfds + self.coafds:
            self._fdmap[fd.fileno()] = fd
            self._poll.register(fd.fileno(), select.POLLIN | select.POLLPRI | select.POLLERR)
        if self.auth_enabled:
            self._realauthfds = list(map(lambda x: x.fileno(), self.authfds))
        if self.acct_enabled:
            self._realacctfds = list(map(lambda x: x.fileno(), self.acctfds))
        if self.coa_enabled:
            self._realcoafds = list(map(lambda x: x.fileno(), self.coafds))

    def CreateReplyPacket(self, pkt, **attributes):
        """Create a reply to a received request.

        The reply is an Access-Accept for an Access-Request, an
        Accounting-Response for an Accounting-Request, a CoA-ACK for a
        CoA-Request and a Disconnect-ACK for a Disconnect-Request; change
        ``reply.code`` for another reply, e.g. ``pyrad.packet.AccessReject``
        or ``pyrad.packet.CoANAK``. The Proxy-State attributes of
        the request are copied, replies to Access-Requests get a
        Message-Authenticator, and ``reply.source`` is set to the client
        address so the reply can be sent with
        :meth:`pyrad.host.Host.SendReplyPacket`.

        :param pkt: received request
        :type  pkt: pyrad.packet.Packet
        :param attributes: attributes to add to the reply, as keyword
            arguments like for :class:`pyrad.packet.Packet`
        :return: reply packet
        :rtype:  pyrad.packet.Packet
        """
        reply = pkt.CreateReply(**attributes)
        reply.source = pkt.source
        return reply

    def _ProcessInput(self, fd):
        """Process available data.

        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls _HandleAuthPacket(), _HandleAcctPacket() or
        _HandleCoaPacket() depending on which socket is being processed.

        :param fd: socket to read packet from
        :type  fd: socket.socket
        """
        if self.auth_enabled and fd.fileno() in self._realauthfds:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateAuthPacket(packet=data), fd)
            self._HandleAuthPacket(pkt)
        elif self.acct_enabled and fd.fileno() in self._realacctfds:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateAcctPacket(packet=data), fd)
            self._HandleAcctPacket(pkt)
        elif self.coa_enabled:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateCoAPacket(packet=data), fd)
            self._HandleCoaPacket(pkt)
        else:
            raise ServerPacketError('Received packet for unknown handler')

    def Run(self):
        """Run the server; this method never returns.

        Waits for packets on the sockets opened by :meth:`BindToAddress`
        and passes valid requests to the packet handlers. Invalid packets
        are dropped and logged, and so are packets for which a handler
        raises an exception, so that a malformed packet can't stop the
        server. Uses :func:`select.poll`, which is not available on Windows.
        """
        self._poll = select.poll()
        self._fdmap = {}
        self._PrepareSockets()

        while True:
            for (fd, event) in self._poll.poll():
                if event == select.POLLIN:
                    try:
                        fdo = self._fdmap[fd]
                        self._ProcessInput(fdo)
                    except ServerPacketError as err:
                        logger.info('Dropping packet: ' + str(err))
                    except packet.PacketError as err:
                        logger.info('Received a broken packet: ' + str(err))
                    except Exception:
                        logger.exception('Error processing packet')
                else:
                    logger.error('Unexpected event in server main loop')
