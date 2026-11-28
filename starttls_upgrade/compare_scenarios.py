"""
Print a side-by-side comparison of the three STARTTLS upgrade scenarios.

Run from the starttls_upgrade directory:
    ../.venv/bin/python compare_scenarios.py
"""

from twisted.internet.ssl import optionsForClientTLS
from twisted.internet.task import Clock
from twisted.test.test_sslverify import certificatesForAuthorityAndServer

from starttls_upgrade.client import ReconnectingStartTLSFactory
from starttls_upgrade.memorytransport import connectedPair
from starttls_upgrade.testingpeers import RecordingProducer, StartTLSServer

TLS_HEADER = b"\x16\x03"


def _setup():
    authority, serverCert = certificatesForAuthorityAndServer()
    clock = Clock()
    factory = ReconnectingStartTLSFactory(
        optionsForClientTLS("example.com", trustRoot=authority)
    )
    client = factory.buildProtocol(None)
    server = StartTLSServer(serverCert.options())
    ct, st, pump = connectedPair(client, server, clock)
    pump.flush()  # open the protected upgrade window
    return factory, client, server, ct, st, pump


def _wireSummary(transport):
    blob = b"".join(transport.wire)
    kind = "TLS records" if TLS_HEADER in blob else "plaintext only"
    return f"{len(blob)} bytes, {kind}, business-data leaked: {b'BIZ-' in blob}"


def run(name, breakFn):
    factory, client, server, ct, st, pump = _setup()
    client.sendBusinessData(b"BIZ-pending\n")
    producer = RecordingProducer()
    client.registerProducer(producer, True)

    # Observe the upgrade result explicitly so a failed Deferred is never
    # left unhandled (the unit tests do the same via failureResultOf).
    upgrade = client._upgradeDeferred
    upgrade.addErrback(lambda _failure: None)

    breakFn(client, server, ct, st, pump)

    ct.pauseProducing()
    result = {
        "scenario": name,
        "underlying client wire": _wireSummary(ct),
        "producer pause count": producer.pauseCount,
        "client close notice": None
        if client.closeNotice is None
        else client.closeNotice.type.__name__,
        "server close notice": None
        if server.closeNotice is None
        else server.closeNotice.type.__name__,
        "protected data retained": client.pendingProtectedData,
        "secured": client.isSecured,
    }

    # Reconnect on a fresh pair and replay whatever was retained.
    _f, newClient, newServer, nct, nst, newPump = _setup()
    newPump.drain()
    factory.replayOn(newClient)
    newPump.drain()
    result["reconnect usable"] = newClient.isSecured
    result["replayed over new TLS"] = newServer.receivedAfterTLS
    return result


def successCase():
    factory, client, server, ct, st, pump = _setup()
    client.sendBusinessData(b"BIZ-one\n")
    producer = RecordingProducer()
    client.registerProducer(producer, True)
    pump.drain()
    client.sendBusinessData(b"BIZ-two\n")
    pump.drain()
    ct.pauseProducing()
    return {
        "scenario": "successful upgrade",
        "underlying client wire": _wireSummary(ct),
        "producer pause count": producer.pauseCount,
        "client close notice": client.closeNotice,
        "server close notice": server.closeNotice,
        "protected data retained": client.pendingProtectedData,
        "secured": client.isSecured,
        "reconnect usable": "n/a (never failed)",
        "replayed over new TLS": server.receivedAfterTLS,
    }


def main():
    rows = [
        successCase(),
        run(
            "cancel from application",
            lambda c, s, ct, st, p: (c._upgradeDeferred.cancel(), p.flush()),
        ),
        run(
            "peer transport dies",
            lambda c, s, ct, st, p: (st.abortConnection(), p.flush()),
        ),
    ]
    for row in rows:
        print("=" * 72)
        for key, value in row.items():
            print(f"{key:28}: {value}")
    print("=" * 72)


if __name__ == "__main__":
    main()
