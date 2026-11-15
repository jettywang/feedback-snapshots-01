"""
Per-target notification filtering and result contract (RFC 3413 section 3.3).

These tests drive the entity-level NotificationOriginator over an in-memory
datagram transport so that no real sockets are required. They cover:

* independent filtering per management target -- one rejected target must
  neither suppress the others nor receive any bytes;
* RFC 3413 section 6 snmpNotifyFilterTable profile matching, including the
  NOTIFICATION-TYPE OID taken from snmpTrapOID.0 and excluded subtrees;
* VACM notify-view authorization (section 3.3 steps 2 and 3);
* distinct terminal states for Trap handoff versus Inform acknowledgement
  and timeout;
* order independence: swapping target configuration order must not change
  the per-target outcome;
* wire-level protection of legitimate messages through each target's own
  security parameters.
"""

import asyncio

import pytest

from pysnmp.carrier.asyncio.base import AbstractAsyncioTransport
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import ntforg, ntfrcv
from pysnmp.proto.api import v2c

# Well-known OIDs used below (numeric, so no external MIB package is needed).
SYSUPTIME_0 = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SYSDESCR_0 = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYSNAME_0 = (1, 3, 6, 1, 2, 1, 1, 5, 0)
SNMPTRAPOID_0 = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
COLD_START = (1, 3, 6, 1, 6, 3, 1, 1, 5, 1)
WARM_START = (1, 3, 6, 1, 6, 3, 1, 1, 5, 2)

AGENT_PORT = 50001
MANAGER_PORT = 50002
BLACK_HOLE_PORT = 50099

SECRET_PAYLOAD = "secret system description"


class MemoryBus:
    """In-memory UDP-like datagram bus keyed by destination port."""

    def __init__(self, loop):
        self.loop = loop
        self._endpoints = {}

    def attach(self, port, transport, snmpEngine):
        self._endpoints[port] = (transport, snmpEngine)

    def deliver(self, senderTransport, transportAddress, message):
        port = transportAddress[1]
        endpoint = self._endpoints.get(port)
        if endpoint is None:
            # No receiver: emulate a silent black hole, so Inform requests
            # time out instead of getting an ICMP-style error.
            return
        recvTransport, recvEngine = endpoint
        sourceAddress = recvTransport.ADDRESS_TYPE(
            ("127.0.0.1", senderTransport.local_port)
        )
        self.loop.call_soon(
            recvEngine.transport_dispatcher._callback_function,
            recvTransport,
            sourceAddress,
            message,
        )


class MemoryTransport(AbstractAsyncioTransport):
    """Transport that records every outgoing message and relays it via a bus."""

    ADDRESS_TYPE = udp.UdpTransportAddress

    def __init__(self, bus, local_port, loop):
        self.bus = bus
        self.local_port = local_port
        self.loop = loop
        self.outgoing = []

    def open_client_mode(self, iface=None, allow_broadcast=False):
        return self

    def close_transport(self):
        self.unregister_callback()

    def normalize_address(self, transportAddress):
        if not isinstance(transportAddress, self.ADDRESS_TYPE):
            transportAddress = self.ADDRESS_TYPE(transportAddress)
        return transportAddress

    def send_message(self, outgoingMessage, transportAddress):
        address = self.normalize_address(transportAddress)
        message = bytes(outgoingMessage)
        self.outgoing.append((address, message))
        self.bus.deliver(self, address, message)

    def bytes_to(self, port):
        return sum(len(message) for address, message in self.outgoing if address[1] == port)

    def messages_to(self, port):
        return [message for address, message in self.outgoing if address[1] == port]


class NotificationHarness:
    """Builds an agent + manager pair connected through an in-memory bus."""

    def __init__(self, loop):
        self.loop = loop
        self.bus = MemoryBus(loop)

        self.manager = engine.SnmpEngine()
        self.manager_transport = MemoryTransport(self.bus, MANAGER_PORT, loop)
        config.add_transport(self.manager, udp.DOMAIN_NAME, self.manager_transport)
        self.bus.attach(MANAGER_PORT, self.manager_transport, self.manager)
        config.add_v1_system(self.manager, "public", "public")
        self.manager_varbinds = []
        ntfrcv.NotificationReceiver(
            self.manager,
            lambda *args: self.manager_varbinds.append(args[4]),
        )

        self.agent = engine.SnmpEngine()
        self.agent_transport = MemoryTransport(self.bus, AGENT_PORT, loop)
        config.add_transport(self.agent, udp.DOMAIN_NAME, self.agent_transport)
        self.bus.attach(AGENT_PORT, self.agent_transport, self.agent)
        # Incoming Inform responses arrive from a target address tagged
        # "all-managers"; the community entry must carry the same tag.
        config.add_v1_system(
            self.agent,
            "allowed-user",
            "public",
            transportTag="all-managers",
        )
        config.add_context(self.agent, "")

        self.results = []
        self.completion = []

    def close(self):
        self.agent.close_dispatcher()
        self.manager.close_dispatcher()

    def target_callback(self, snmpEngine, notificationHandle, targetAddrName,
                        state, errorIndication, varBinds, cbCtx):
        self.results.append(
            {
                "target": str(targetAddrName),
                "state": state,
                "errorIndication": errorIndication,
                "varBinds": varBinds,
            }
        )

    def completion_callback(self, *args):
        self.completion.append(args)

    def result_for(self, targetName):
        matches = [r for r in self.results if r["target"] == targetName]
        assert len(matches) == 1, f"expected exactly one terminal state for {targetName}"
        return matches[0]

    async def send(self, notify_type, target_order):
        self._configure_targets(target_order)
        config.add_notification_target(
            self.agent,
            "test-notification",
            "creds-allowed",
            "all-managers",
            notify_type,
        )
        originator = ntforg.NotificationOriginator()
        originator.send_varbinds(
            self.agent,
            "test-notification",
            None,
            "",
            [
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            self.completion_callback,
            None,
            targetCbFun=self.target_callback,
        )
        # Allow Inform acknowledgement and full retry/timeout processing.
        await asyncio.sleep(0.6)

    def _configure_targets(self, target_order):
        # Two principals: a fully authorized one and one whose notify view
        # excludes both the notification OID and the data varbind.
        config.add_target_parameters(
            self.agent, "creds-allowed", "allowed-user", "noAuthNoPriv", 1
        )
        config.add_v1_system(self.agent, "restricted-user", "public")
        config.add_target_parameters(
            self.agent, "creds-restricted", "restricted-user", "noAuthNoPriv", 1
        )

        config.add_vacm_user(
            self.agent, 2, "allowed-user", "noAuthNoPriv", (), (), (1, 3, 6)
        )
        config.add_vacm_group(self.agent, "restricted-group", 2, "restricted-user")
        config.add_vacm_access(
            self.agent,
            "restricted-group",
            b"",
            2,
            1,
            "exact",
            "",
            "",
            "restricted-notify-view",
        )
        # Only sysUpTime's subtree is visible; snmpTrapOID and sysDescr fail.
        config.add_vacm_view(
            self.agent,
            "restricted-notify-view",
            "included",
            SYSUPTIME_0,
            b"",
        )

        ports_and_creds = {
            "target-denied": (BLACK_HOLE_PORT, "creds-restricted"),
            "target-ack": (MANAGER_PORT, "creds-allowed"),
            "target-timeout": (BLACK_HOLE_PORT + 1, "creds-allowed"),
        }
        for name in target_order:
            port, creds = ports_and_creds[name]
            config.add_target_address(
                self.agent,
                name,
                udp.DOMAIN_NAME,
                ("127.0.0.1", port),
                creds,
                timeout=20,
                retryCount=0,
                tagList="all-managers",
                sourceAddress=("127.0.0.1", AGENT_PORT),
            )


@pytest.mark.asyncio
async def test_inform_per_target_states_and_zero_byte_rejection():
    harness = NotificationHarness(asyncio.get_running_loop())
    try:
        await harness.send(
            "inform",
            ["target-denied", "target-ack", "target-timeout"],
        )

        denied = harness.result_for("target-denied")
        acknowledged = harness.result_for("target-ack")
        timed_out = harness.result_for("target-timeout")

        assert denied["state"] == ntforg.TARGET_STATE_FILTERED
        assert isinstance(denied["errorIndication"], type(ntforg.errind.notificationFiltered))
        assert acknowledged["state"] == ntforg.TARGET_STATE_ACKNOWLEDGED
        assert acknowledged["errorIndication"] is None
        assert timed_out["state"] == ntforg.TARGET_STATE_FAILED
        assert isinstance(timed_out["errorIndication"], type(ntforg.errind.requestTimedOut))

        # The rejected target must never be handed to the transport.
        assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT) == 0

        # Both legitimate targets actually got a full, non-empty message.
        ack_messages = harness.agent_transport.messages_to(MANAGER_PORT)
        assert len(ack_messages) == 1
        assert len(ack_messages[0]) > 0
        assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT + 1) > 0

        # The manager decoded the complete notification, sensitive varbind
        # included -- nothing was stripped to force a pass.
        assert len(harness.manager_varbinds) == 1
        varbinds = harness.manager_varbinds[0]
        names = [tuple(name) for name, _value in varbinds]
        assert names == [SYSUPTIME_0, SNMPTRAPOID_0, SYSDESCR_0]
        assert str(varbinds[2][1]) == SECRET_PAYLOAD
        assert tuple(varbinds[1][1]) == COLD_START

        # Exactly one Inform completion callback after all targets settle.
        assert len(harness.completion) == 1
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_results_independent_of_configuration_order():
    orders = [
        ["target-denied", "target-ack", "target-timeout"],
        ["target-ack", "target-timeout", "target-denied"],
        ["target-timeout", "target-denied", "target-ack"],
    ]
    for order in orders:
        harness = NotificationHarness(asyncio.get_running_loop())
        try:
            await harness.send("inform", order)
            states = {
                result["target"]: result["state"] for result in harness.results
            }
            assert states == {
                "target-denied": ntforg.TARGET_STATE_FILTERED,
                "target-ack": ntforg.TARGET_STATE_ACKNOWLEDGED,
                "target-timeout": ntforg.TARGET_STATE_FAILED,
            }
            assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT) == 0
        finally:
            harness.close()


@pytest.mark.asyncio
async def test_trap_handoff_state_distinct_from_inform_ack():
    harness = NotificationHarness(asyncio.get_running_loop())
    try:
        # No manager endpoint for these targets: Trap handoff still succeeds
        # because the transport accepted the unconfirmed message.
        config.add_target_parameters(
            harness.agent, "creds-allowed", "allowed-user", "noAuthNoPriv", 1
        )
        config.add_vacm_user(
            harness.agent, 2, "allowed-user", "noAuthNoPriv", (), (), (1, 3, 6)
        )
        config.add_target_address(
            harness.agent,
            "trap-target",
            udp.DOMAIN_NAME,
            ("127.0.0.1", BLACK_HOLE_PORT),
            "creds-allowed",
            tagList="all-managers",
            sourceAddress=("127.0.0.1", AGENT_PORT),
        )
        config.add_notification_target(
            harness.agent,
            "trap-notification",
            "creds-allowed",
            "all-managers",
            "trap",
        )
        ntforg.NotificationOriginator().send_varbinds(
            harness.agent,
            "trap-notification",
            None,
            "",
            [
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            targetCbFun=harness.target_callback,
        )
        await asyncio.sleep(0.1)

        result = harness.result_for("trap-target")
        assert result["state"] == ntforg.TARGET_STATE_SENT
        assert result["errorIndication"] is None
        # Unconfirmed handoff is recorded even though nobody acknowledges.
        assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT) > 0
        assert harness.completion == []
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_filter_profile_excludes_notification_type():
    """RFC 3413 section 6: notification name must be specifically included."""
    harness = NotificationHarness(asyncio.get_running_loop())
    try:
        config.add_target_parameters(
            harness.agent, "creds-allowed", "allowed-user", "noAuthNoPriv", 1
        )
        config.add_vacm_user(
            harness.agent, 2, "allowed-user", "noAuthNoPriv", (), (), (1, 3, 6)
        )
        config.add_target_address(
            harness.agent,
            "profile-target",
            udp.DOMAIN_NAME,
            ("127.0.0.1", BLACK_HOLE_PORT),
            "creds-allowed",
            tagList="all-managers",
            sourceAddress=("127.0.0.1", AGENT_PORT),
        )
        # Profile includes only warmStart while the notification is coldStart.
        config.add_notification_target(
            harness.agent,
            "profiled-notification",
            "creds-allowed",
            "all-managers",
            "trap",
            filterSubtree=WARM_START,
            filterMask=b"",
            filterType="included",
        )
        ntforg.NotificationOriginator().send_varbinds(
            harness.agent,
            "profiled-notification",
            None,
            "",
            [
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            targetCbFun=harness.target_callback,
        )
        await asyncio.sleep(0.1)

        result = harness.result_for("profile-target")
        assert result["state"] == ntforg.TARGET_STATE_FILTERED
        assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT) == 0
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_filter_profile_excluded_data_subtree_drops_notification():
    """An explicitly excluded object instance drops the whole notification."""
    harness = NotificationHarness(asyncio.get_running_loop())
    try:
        config.add_target_parameters(
            harness.agent, "creds-allowed", "allowed-user", "noAuthNoPriv", 1
        )
        config.add_vacm_user(
            harness.agent, 2, "allowed-user", "noAuthNoPriv", (), (), (1, 3, 6)
        )
        config.add_target_address(
            harness.agent,
            "exclusion-target",
            udp.DOMAIN_NAME,
            ("127.0.0.1", BLACK_HOLE_PORT),
            "creds-allowed",
            tagList="all-managers",
            sourceAddress=("127.0.0.1", AGENT_PORT),
        )
        config.add_notification_target(
            harness.agent,
            "excluded-notification",
            "creds-allowed",
            "all-managers",
            "trap",
            filterSubtree=SYSDESCR_0,
            filterMask=b"",
            filterType="excluded",
        )
        ntforg.NotificationOriginator().send_varbinds(
            harness.agent,
            "excluded-notification",
            None,
            "",
            [
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            targetCbFun=harness.target_callback,
        )
        await asyncio.sleep(0.1)

        result = harness.result_for("exclusion-target")
        assert result["state"] == ntforg.TARGET_STATE_FILTERED
        assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT) == 0
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_v3_notification_protected_by_target_security_parameters():
    """A legitimate USM target receives the full PDU under authPriv protection."""
    loop = asyncio.get_running_loop()
    bus = MemoryBus(loop)

    manager = engine.SnmpEngine()
    manager_transport = MemoryTransport(bus, MANAGER_PORT, loop)
    config.add_transport(manager, udp.DOMAIN_NAME, manager_transport)
    bus.attach(MANAGER_PORT, manager_transport, manager)
    config.add_v3_user(
        manager,
        "usr-sha-aes",
        config.USM_AUTH_HMAC96_SHA,
        "authkey1",
        config.USM_PRIV_CFB128_AES,
        "privkey1",
    )
    manager_varbinds = []
    ntfrcv.NotificationReceiver(
        manager, lambda *args: manager_varbinds.append(args[4])
    )

    agent = engine.SnmpEngine()
    agent_transport = MemoryTransport(bus, AGENT_PORT, loop)
    config.add_transport(agent, udp.DOMAIN_NAME, agent_transport)
    bus.attach(AGENT_PORT, agent_transport, agent)
    config.add_v3_user(
        agent,
        "usr-sha-aes",
        config.USM_AUTH_HMAC96_SHA,
        "authkey1",
        config.USM_PRIV_CFB128_AES,
        "privkey1",
    )
    config.add_target_parameters(agent, "v3-creds", "usr-sha-aes", "authPriv", 3)
    config.add_context(agent, "")
    config.add_vacm_user(agent, 3, "usr-sha-aes", "authPriv", (), (), (1, 3, 6))
    config.add_target_address(
        agent,
        "v3-target",
        udp.DOMAIN_NAME,
        ("127.0.0.1", MANAGER_PORT),
        "v3-creds",
        timeout=30,
        retryCount=0,
        tagList="v3-tag",
        sourceAddress=("127.0.0.1", AGENT_PORT),
    )
    config.add_notification_target(
        agent, "v3-notification", "v3-creds", "v3-tag", "inform"
    )

    results = []
    try:
        ntforg.NotificationOriginator().send_varbinds(
            agent,
            "v3-notification",
            None,
            "",
            [
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            targetCbFun=lambda *args: results.append(
                (str(args[2]), args[3], args[4])
            ),
        )
        await asyncio.sleep(1.0)

        assert results == [
            ("v3-target", ntforg.TARGET_STATE_ACKNOWLEDGED, None)
        ]

        # The authorized manager decodes the complete notification.
        assert len(manager_varbinds) == 1
        varbinds = manager_varbinds[0]
        assert [tuple(name) for name, _value in varbinds] == [
            SYSUPTIME_0,
            SNMPTRAPOID_0,
            SYSDESCR_0,
        ]
        assert str(varbinds[2][1]) == SECRET_PAYLOAD

        # Every on-wire message is encrypted: the sensitive value must not
        # appear in plaintext in any captured datagram (including discovery).
        wire_messages = agent_transport.messages_to(MANAGER_PORT)
        assert wire_messages
        for message in wire_messages:
            assert SECRET_PAYLOAD.encode() not in message
    finally:
        agent.close_dispatcher()
        manager.close_dispatcher()


class TestFilterMatching:
    """Unit tests for RFC 3413 section 6 filter entry matching."""

    originator = ntforg.NotificationOriginator()

    def test_exact_subtree_prefix_match(self):
        match = self.originator._filter_entry_matches
        assert match((1, 3, 6, 1, 2, 1, 1, 1, 0), (1, 3, 6, 1, 2), b"")
        assert not match((1, 3, 6, 2), (1, 3, 6, 1, 2), b"")

    def test_oid_shorter_than_subtree_does_not_match(self):
        match = self.originator._filter_entry_matches
        assert not match((1, 3, 6), (1, 3, 6, 1), b"")

    def test_wildcard_mask_skips_subidentifier(self):
        match = self.originator._filter_entry_matches
        # The 4th sub-id is wildcarded: its bit (0x80 >> 3) is zero while
        # the first three sub-identifiers still require exact matches.
        mask = b"\xef"
        assert match((1, 3, 6, 99), (1, 3, 6, 1), mask)
        assert not match((1, 3, 7, 1), (1, 3, 6, 1), mask)

    def test_short_mask_extends_with_ones(self):
        match = self.originator._filter_entry_matches
        # Two-byte mask covers only the first two sub-identifiers; the rest
        # must be compared exactly.
        mask = b"\xff\xff"
        assert match((1, 3, 6, 1), (1, 3, 6, 1), mask)
        assert not match((1, 3, 9, 1), (1, 3, 6, 1), mask)

    def test_notification_name_must_be_included(self):
        # Profile includes a different notification subtree only.
        entries = ((WARM_START, b"", 1),)
        allowed = self.originator._is_allowed_by_filter_profile(
            entries,
            [
                (SYSUPTIME_0, v2c.TimeTicks(0)),
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            SNMPTRAPOID_0,
        )
        assert allowed is False

    def test_most_specific_subtree_wins(self):
        entries = (
            ((1, 3, 6), b"", 1),
            (SYSDESCR_0, b"", 2),
        )
        allowed = self.originator._is_allowed_by_filter_profile(
            entries,
            [
                (SYSUPTIME_0, v2c.TimeTicks(0)),
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            SNMPTRAPOID_0,
        )
        # The longer, more specific excluded subtree overrides the broad
        # included subtree, so the data varbind is excluded.
        assert allowed is False

    def test_object_included_by_default_without_matching_entry(self):
        entries = ((COLD_START, b"", 1),)
        allowed = self.originator._is_allowed_by_filter_profile(
            entries,
            [
                (SYSUPTIME_0, v2c.TimeTicks(0)),
                (SNMPTRAPOID_0, v2c.ObjectIdentifier(COLD_START)),
                (SYSDESCR_0, v2c.OctetString(SECRET_PAYLOAD)),
            ],
            SNMPTRAPOID_0,
        )
        # Notification name included; unmatched object instances default in.
        assert allowed is True


def test_notify_filters_isolated_between_profiles():
    """get_notify_filters must not stop at another profile's rows."""
    from pysnmp.carrier.asyncio.base import AbstractAsyncioTransport
    from pysnmp.entity import config as entity_config
    from pysnmp.entity.rfc3413 import config as rfc3413_config

    class _NullTransport(AbstractAsyncioTransport):
        ADDRESS_TYPE = udp.UdpTransportAddress

        def open_client_mode(self, iface=None, allow_broadcast=False):
            return self

        def close_transport(self):
            self.unregister_callback()

        def send_message(self, outgoingMessage, transportAddress):
            pass

    snmp_engine = engine.SnmpEngine()
    try:
        entity_config.add_transport(snmp_engine, udp.DOMAIN_NAME, _NullTransport())
        for user in ("user-a", "user-b"):
            entity_config.add_v1_system(snmp_engine, user, "public")
            entity_config.add_target_parameters(
                snmp_engine, "params-" + user, user, "noAuthNoPriv", 1
            )

        # Profiles land in lexicographic order different from creation order.
        entity_config.add_notification_target(
            snmp_engine,
            "notify-b",
            "params-user-b",
            "tag-b",
            "trap",
            filterSubtree=(1, 3, 6, 1, 2),
            filterMask=b"",
            filterType="included",
        )
        entity_config.add_notification_target(
            snmp_engine,
            "notify-a",
            "params-user-a",
            "tag-a",
            "trap",
            filterSubtree=(1, 3, 6, 1, 4),
            filterMask=b"",
            filterType="excluded",
        )

        profile_a = rfc3413_config.get_notify_filter_profile_name(
            snmp_engine, "params-user-a"
        )
        profile_b = rfc3413_config.get_notify_filter_profile_name(
            snmp_engine, "params-user-b"
        )

        filters_a = rfc3413_config.get_notify_filters(snmp_engine, profile_a)
        filters_b = rfc3413_config.get_notify_filters(snmp_engine, profile_b)

        assert filters_a == (((1, 3, 6, 1, 4), b"", 2),)
        assert filters_b == (((1, 3, 6, 1, 2), b"", 1),)
    finally:
        snmp_engine.close_dispatcher()


@pytest.mark.asyncio
async def test_inform_completion_resolves_when_every_target_filtered():
    """A fully filtered Inform must not leave the completion callback pending."""
    harness = NotificationHarness(asyncio.get_running_loop())
    try:
        await harness.send("inform", ["target-denied"])

        assert len(harness.results) == 1
        assert harness.results[0]["state"] == ntforg.TARGET_STATE_FILTERED
        assert len(harness.completion) == 1
        assert isinstance(
            harness.completion[0][2],
            type(ntforg.errind.notificationFiltered),
        )
        # Nothing was transmitted for the rejected target.
        assert harness.agent_transport.bytes_to(BLACK_HOLE_PORT) == 0
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_each_target_reports_exactly_one_terminal_state():
    """The per-target callback fires once per target even across retries."""
    harness = NotificationHarness(asyncio.get_running_loop())
    try:
        await harness.send(
            "inform",
            ["target-ack", "target-denied", "target-timeout"],
        )
        target_names = [result["target"] for result in harness.results]
        assert sorted(target_names) == [
            "target-ack",
            "target-denied",
            "target-timeout",
        ]
        assert len(target_names) == len(set(target_names))
    finally:
        harness.close()
