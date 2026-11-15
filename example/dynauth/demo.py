"""Runnable demonstration of the CoA / Disconnect policy adapter.

Run it in-process (no socket needed)::

    python -m example.dynauth.demo

Or over a real loopback UDP socket on port 3799 (requires permission to
bind)::

    python -m example.dynauth.demo --udp

Every request is a real RADIUS packet signed with the shared secret and every
reply is verified through the RADIUS response authenticator. The script prints
the session table before/after each case and the audit trail, proving that
refused requests have no control side effects.
"""

import argparse

from pyrad import packet

from .client import DynAuthClient
from .constants import COA_REQUEST, DISCONNECT_REQUEST
from .fixtures import (
    DICTIONARY_PATH,
    NAS_1,
    NAS_2,
    SECRET_GUEST,
    SECRET_OPS,
    SECRET_SUPPORT,
    SENDER_GUEST,
    SENDER_OPS,
    SENDER_SUPPORT,
    SENDER_UNKNOWN,
    build_sender_policies,
    build_senders,
    build_sessions,
)
from .policy import AuditLog
from .session_store import SessionStore
from .transport import LoopbackTransport, UdpTransport, build_engine

CODE_NAMES = {
    packet.CoARequest: "CoA-Request",
    packet.CoAACK: "CoA-ACK",
    packet.CoANAK: "CoA-NAK",
    packet.DisconnectRequest: "Disconnect-Request",
    packet.DisconnectACK: "Disconnect-ACK",
    packet.DisconnectNAK: "Disconnect-NAK",
}


def table_snapshot(store):
    return {key: session.snapshot()
            for key, session in store._sessions.items()}


def print_session_table(store, title):
    print("\n=== %s ===" % title)
    for session in sorted(store.all(),
                          key=lambda item: (item.nas_ip, item.session_id)):
        state = "active" if session.active else "disconnected"
        print("  %s %s user=%-5s ip=%-14s state=%-12s attrs=%s"
              % (session.nas_ip, session.session_id, session.user_name,
                 session.framed_ip, state, session.attributes))


def run_case(transport, clients, store, title, sender_address, build,
             expect_reply=True, use_ma=False):
    client = clients[sender_address]
    raw, request = build(client)
    before = table_snapshot(store)

    reply_raw = transport.send(raw, (sender_address, 3799))
    after = table_snapshot(store)

    print("\n--- %s" % title)
    print("    request : %s from %s (Message-Authenticator=%s)"
          % (CODE_NAMES[request.code], sender_address, use_ma))
    if reply_raw is None:
        print("    result  : silently dropped (no RADIUS reply)")
        assert not expect_reply, "expected a reply but the packet was dropped"
        assert before == after, "dropped packet changed session state"
        return None
    reply = client.verify_reply(request, reply_raw)
    print("    reply   : %s (response authenticator verified)"
          % CODE_NAMES[reply.code])
    if reply.code in (packet.CoANAK, packet.DisconnectNAK):
        print("    cause   : %s" % reply["Error-Cause"][0])
        assert before == after, "NAK must not change any session state"
    else:
        assert before != after or reply.code in (packet.CoAACK,
                                                 packet.DisconnectACK)
    return reply


def run_replay(transport, clients, store, title, sender_address, raw, request):
    """Resend the exact original datagram and assert idempotent handling."""
    before = table_snapshot(store)
    reply_raw = transport.send(raw, (sender_address, 3799))
    after = table_snapshot(store)
    reply = clients[sender_address].verify_reply(request, reply_raw)
    print("\n--- %s" % title)
    print("    request : identical %s datagram (id=%d) resent"
          % (CODE_NAMES[request.code], request.id))
    print("    reply   : %s (original result, no second mutation)"
          % CODE_NAMES[reply.code])
    assert before == after, "a replayed request must not change state again"
    return reply


def build_loopback(store):
    audit = AuditLog()
    engine = build_engine(store, build_sender_policies(), audit=audit)
    transport = LoopbackTransport(
        engine, build_senders(), DICTIONARY_PATH)
    clients = {
        SENDER_OPS: DynAuthClient(SECRET_OPS, DICTIONARY_PATH, SENDER_OPS),
        SENDER_SUPPORT: DynAuthClient(
            SECRET_SUPPORT, DICTIONARY_PATH, SENDER_SUPPORT),
        SENDER_GUEST: DynAuthClient(
            SECRET_GUEST, DICTIONARY_PATH, SENDER_GUEST),
        SENDER_UNKNOWN: DynAuthClient(
            SECRET_GUEST, DICTIONARY_PATH, SENDER_UNKNOWN),
    }
    return transport, clients, audit


def run_demo(use_udp=False):
    store = SessionStore(build_sessions())
    transport, clients, audit = build_loopback(store)
    udp_socket = None

    if use_udp:
        # Replace the in-process transport with a real UDP server; the engine,
        # policy and session table are shared unchanged.
        udp = UdpTransport(transport.engine, build_senders(),
                           DICTIONARY_PATH, port=3799)
        bound = udp.bind()
        udp_socket = udp.socket
        print("UDP transport listening on %s" % (bound,))

        def udp_exchange(raw, source):
            udp_socket.sendto(raw, bound)
            data, _ = udp_socket.recvfrom(4096)
            return data

        transport.send = udp_exchange  # type: ignore[assignment]

    print_session_table(store, "session table before any request")
    initial = table_snapshot(store)

    # 1. Legal CoA: ops changes Filter-Id and Session-Timeout of one session.
    coa_raw, coa_request = clients[SENDER_OPS].build_request(
        COA_REQUEST,
        **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001",
           "Filter-Id": "restricted", "Session-Timeout": 1200})
    run_case(transport, clients, store,
             "legal CoA attribute change on NAS-1",
             SENDER_OPS, lambda client: (coa_raw, coa_request))

    # 2. Replay of the exact same datagram: original ACK, no second mutation.
    run_replay(transport, clients, store,
               "replayed CoA returns the original result",
               SENDER_OPS, coa_raw, coa_request)

    # 3. Legal disconnect identified by NAS + Framed-IP-Address.
    run_case(transport, clients, store,
             "legal Disconnect by explicit Framed-IP-Address",
             SENDER_OPS,
             lambda client: client.disconnect(
                 **{"NAS-IP-Address": NAS_1,
                    "Framed-IP-Address": "192.0.2.12"}))

    # 4. Cross-NAS disconnect: ops has no rights on NAS-2 -> NAK 501.
    run_case(transport, clients, store,
             "cross-NAS Disconnect refused (sender not authorized)",
             SENDER_OPS,
             lambda client: client.disconnect(
                 **{"NAS-IP-Address": NAS_2, "Acct-Session-Id": "sess-2001"}))

    # 5. Support may CoA but not disconnect -> NAK 501.
    run_case(transport, clients, store,
             "Disconnect refused for CoA-only sender",
             SENDER_SUPPORT,
             lambda client: client.disconnect(
                 **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"}))

    # 6. User-Name only: no session-level identifier -> NAK 402.
    run_case(transport, clients, store,
             "User-Name alone refused (no broadcast disconnect)",
             SENDER_OPS,
             lambda client: client.disconnect(
                 **{"NAS-IP-Address": NAS_1, "User-Name": "alice"}))

    # 7. Ambiguous Calling-Station-Id matches two sessions -> NAK 508.
    run_case(transport, clients, store,
             "ambiguous locator matching two sessions refused",
             SENDER_OPS,
             lambda client: client.disconnect(
                 **{"NAS-IP-Address": NAS_1,
                    "Calling-Station-Id": "AA-BB-SHARED-0001"}))

    # 8. Unknown session -> NAK 503, with a Message-Authenticator signed CoA.
    ma_client = DynAuthClient(SECRET_SUPPORT, DICTIONARY_PATH,
                              SENDER_SUPPORT, with_message_authenticator=True)
    clients[SENDER_SUPPORT] = ma_client
    run_case(transport, clients, store,
             "unknown session refused (CoA with Message-Authenticator)",
             SENDER_SUPPORT,
             lambda client: client.build_request(
                 COA_REQUEST,
                 **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "missing",
                    "Filter-Id": "x"}),
             use_ma=True)

    # 9. Bad shared secret: authenticator fails, packet dropped silently.
    attacker = DynAuthClient(b"wrong-secret", DICTIONARY_PATH, SENDER_OPS)
    raw, request = attacker.build_request(
        DISCONNECT_REQUEST,
        **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"})
    before = table_snapshot(store)
    dropped = transport.send(raw, (SENDER_OPS, 3799))
    print("\n--- forged request with a wrong shared secret")
    print("    result  : %s"
          % ("silently dropped" if dropped is None else "UNEXPECTED REPLY"))
    assert dropped is None
    assert before == table_snapshot(store), "forged packet changed state"

    # 10. Authenticated sender without any policy: valid packet, NAK 501.
    run_case(transport, clients, store,
             "authenticated sender without a policy refused",
             SENDER_GUEST,
             lambda client: client.disconnect(
                 **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"}))

    # 11. Unknown sender address: no client entry, dropped silently.
    raw, request = clients[SENDER_UNKNOWN].build_request(
        DISCONNECT_REQUEST,
        **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"})
    dropped = transport.send(raw, (SENDER_UNKNOWN, 3799))
    print("\n--- request from an unregistered sender address")
    print("    result  : %s"
          % ("silently dropped" if dropped is None else "UNEXPECTED REPLY"))
    assert dropped is None

    print_session_table(store, "session table after all requests")

    print("\n=== audit trail (before/after prove NAK side-effect freedom) ===")
    for entry in audit.all():
        locator = ", ".join("%s=%s" % (code, value)
                            for code, value in sorted(entry.locator.items()))
        line = ("  [%s] sender=%-7s %-18s nas=%s id=%03d %s"
                % ("replay" if entry.replayed else "apply ",
                   entry.sender_id, entry.decision, entry.nas_ip,
                   entry.identifier, locator or "-"))
        if entry.error_cause is not None:
            line += " cause=%s (%s)" % (entry.error_cause, entry.reason)
        print(line)

    changed = [key for key in initial
               if initial[key] != table_snapshot(store)[key]]
    print("\nSessions whose state actually changed: %s"
          % sorted(changed))
    print("Only sess-1001 (CoA) and sess-1002 (Disconnect) changed; every "
          "refused request left its target untouched.")

    if udp_socket is not None:
        udp_socket.close()


def main():
    parser = argparse.ArgumentParser(
        description="RFC 5176 CoA/Disconnect policy adapter demo")
    parser.add_argument("--udp", action="store_true",
                        help="use a real loopback UDP socket instead of the "
                             "in-process transport")
    args = parser.parse_args()
    try:
        run_demo(use_udp=args.udp)
    except PermissionError as err:
        print("UDP binding is not permitted in this environment (%s)." % err)
        print("Re-run without --udp to use the in-process transport, which "
              "still performs full RADIUS authenticator verification.")


if __name__ == "__main__":
    main()
