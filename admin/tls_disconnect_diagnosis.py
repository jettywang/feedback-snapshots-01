#!/usr/bin/env python
"""
Trace where a Twisted TLS client gets its disconnect reason.

This is an offline diagnostic: it never opens a socket.  TCP is simulated with
twisted.test.iosim.ConnectionCompleter and all certificates are generated into a
TemporaryDirectory.  The same code path is used as in production:
HostnameEndpoint/TCP4ClientEndpoint -> wrapClientTLS -> TLSMemoryBIOFactory ->
TLSMemoryBIOProtocol -> application protocol.

Usage, from the repository root:

    .venv/bin/python admin/tls_disconnect_diagnosis.py
    .venv/bin/python admin/tls_disconnect_diagnosis.py --json
    .venv/bin/python admin/tls_disconnect_diagnosis.py --check
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from zope.interface import implementer

from twisted.internet import error
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint, wrapClientTLS
from twisted.internet.interfaces import IHandshakeListener
from twisted.internet.protocol import ClientFactory, Factory, Protocol
from twisted.internet.ssl import Certificate, PrivateCertificate, optionsForClientTLS
from twisted.internet.task import Clock
from twisted.internet.testing import MemoryReactorClock
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.python.failure import Failure
from twisted.test.iosim import ConnectionCompleter

try:
    from service_identity.exceptions import VerificationError as PeerIdentityError
except ImportError:  # pragma: no cover
    PeerIdentityError = None  # type: ignore[assignment]


# --------------------------------------------------------------------------
# Temporary certificate material
# --------------------------------------------------------------------------


class Authority:
    """A throw-away CA and server-cert factory; files live in a temp dir."""

    def __init__(self, directory: Path, name: str) -> None:
        self.directory = directory
        self.name = name
        now = datetime.datetime.now(datetime.timezone.utc)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=9), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def trust_root(self) -> Certificate:
        return Certificate.loadPEM(self.cert.public_bytes(serialization.Encoding.PEM))

    def server_certificate(self, hostname: str) -> PrivateCertificate:
        now = datetime.datetime.now(datetime.timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        path = self.directory / f"server-{hostname}.pem"
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            + cert.public_bytes(serialization.Encoding.PEM)
        )
        return PrivateCertificate.loadPEM(path.read_bytes())


# --------------------------------------------------------------------------
# Recording and classifying
# --------------------------------------------------------------------------


def describe(reason: Failure | None) -> str | None:
    if reason is None:
        return None
    return f"{type(reason.value).__module__}.{type(reason.value).__name__}: {reason.value}"


def reason_type(reason: Failure | None) -> str | None:
    if reason is None:
        return None
    return f"{type(reason.value).__module__}.{type(reason.value).__name__}"


def normalized_detail(detail: object) -> object:
    """Drop environment-dependent OpenSSL error-queue noise."""
    if isinstance(detail, str) and "certificate verify failed" in detail:
        return "OpenSSL.SSL.Error: certificate verify failed"
    if isinstance(detail, str) and "tlsv1 alert unknown ca" in detail:
        return "OpenSSL.SSL.Error: tlsv1 alert unknown ca"
    if isinstance(detail, str) and "Unexpected EOF" in detail:
        return "OpenSSL.SSL.SysCallError: Unexpected EOF"
    return detail


class Recorder:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, source: str, event: str, detail: object = None) -> None:
        self.events.append(
            {"seq": len(self.events) + 1, "source": source, "event": event, "detail": detail}
        )

    def instrument(self, target: object, method: str, source: str) -> None:
        original = getattr(target, method)

        def wrapper(*args: object, **kwargs: object) -> object:
            if args and isinstance(args[0], Failure):
                detail = describe(args[0])
            elif method in {"_tlsShutdownFinished", "connectionLost"}:
                detail = "reason=None"
            else:
                detail = None
            self.record(source, method, detail)
            return original(*args, **kwargs)

        setattr(target, method, wrapper)

    def marker(self, source: str, event: str) -> int:
        self.record(source, event, "<-- action")
        return len(self.events)


@implementer(IHandshakeListener)
class WatchedProtocol(Protocol):
    def __init__(self, name: str, recorder: Recorder) -> None:
        self.name = name
        self.recorder = recorder
        self.handshake_completed = False
        self.reason: Failure | None = None
        self.received: list[bytes] = []
        self.local_actions: list[str] = []

    def connectionMade(self) -> None:
        self.recorder.record(self.name, "connectionMade", type(self.transport).__name__)

    def handshakeCompleted(self) -> None:
        self.handshake_completed = True
        self.recorder.record(self.name, "handshakeCompleted")

    def dataReceived(self, data: bytes) -> None:
        self.received.append(data)
        self.recorder.record(self.name, "dataReceived", repr(data))

    def connectionLost(self, reason: Failure) -> None:
        self.reason = reason
        self.recorder.record(self.name, "connectionLost", describe(reason))

    def loseConnection(self) -> None:
        self.local_actions.append("loseConnection")
        self.recorder.record(self.name, "local.loseConnection")
        self.transport.loseConnection()

    def abortConnection(self) -> None:
        self.local_actions.append("abortConnection")
        self.recorder.record(self.name, "local.abortConnection")
        self.transport.abortConnection()


class ClientFactoryFor(ClientFactory):
    def __init__(self, protocol: WatchedProtocol, recorder: Recorder) -> None:
        self.protocol = lambda: protocol  # type: ignore[assignment]
        self.recorder = recorder

    def clientConnectionFailed(self, connector, reason):
        self.recorder.record("client-factory", "clientConnectionFailed", describe(reason))

    def clientConnectionLost(self, connector, reason):
        self.recorder.record("client-factory", "clientConnectionLost", describe(reason))


def classify(reason: Failure | None, action: str, handshake_completed: bool) -> dict[str, object]:
    if action.startswith("cancel"):
        if reason is not None and reason.check(error.ConnectingCancelledError):
            return {
                "cause": "application-cancel:before-connect",
                "attribution": "attributable",
                "signal": "ConnectingCancelledError on the endpoint Deferred",
            }
        return {
            "cause": "application-cancel:not-observable-after-connect",
            "attribution": "caller-must-record-intent",
            "signal": "Deferred.cancel() is a no-op after the Deferred fired",
        }
    if reason is None:
        return {"cause": "no-loss-observed", "attribution": "n/a", "signal": None}
    if PeerIdentityError is not None and reason.check(PeerIdentityError):
        return {
            "cause": "trust-failure:peer-identity",
            "attribution": "attributable",
            "signal": "service_identity.VerificationError in connectionLost",
        }
    if "certificate verify failed" in str(reason.value):
        return {
            "cause": "trust-failure:certificate-chain",
            "attribution": "attributable",
            "signal": "OpenSSL.SSL.Error containing 'certificate verify failed'",
        }
    if action in {"client-lose", "client-abort"}:
        return {
            "cause": "application-close:" + action.split("-", 1)[1],
            "attribution": "attributable-if-locally-observed",
            "signal": "the caller's own close/abort call; reasons are ConnectionDone/ConnectionAborted",
        }
    if reason.check(error.ConnectionAborted):
        return {
            "cause": "local-abort",
            "attribution": "attributable-if-locally-observed",
            "signal": "ConnectionAborted is generated by local abortConnection",
        }
    if reason.check(error.ConnectionDone):
        return {
            "cause": "clean-close:peer-or-local",
            "attribution": "closed-only",
            "signal": "ConnectionDone (close_notify or local loseConnection); identical values",
            "handshake_completed": handshake_completed,
        }
    if reason.check(error.ConnectionLost):
        return {
            "cause": "transport-loss-or-truncated-TLS",
            "attribution": "closed-only",
            "signal": "ConnectionLost; TLS 'unexpected eof' is squashed to it",
            "handshake_completed": handshake_completed,
        }
    return {"cause": "other", "attribution": "inspect", "signal": reason_type(reason)}


# --------------------------------------------------------------------------
# One scenario
# --------------------------------------------------------------------------


SCENARIOS = {
    "hostname-mismatch": ("client-view.example.com", "server-view.example.com", True, "none"),
    "untrusted-ca": ("client-view.example.com", "client-view.example.com", False, "none"),
    "peer-clean-close": ("client-view.example.com", "client-view.example.com", True, "server-lose"),
    "peer-abrupt-fin": ("client-view.example.com", "client-view.example.com", True, "raw-fin"),
    "app-cancel-before-connect": ("client-view.example.com", "client-view.example.com", True, "cancel-before"),
    "app-clean-close": ("client-view.example.com", "client-view.example.com", True, "client-lose"),
    "app-abort": ("client-view.example.com", "client-view.example.com", True, "client-abort"),
    "app-abort-tcp": ("client-view.example.com", "client-view.example.com", True, "abort-tcp"),
    "app-cancel-after-connect": ("client-view.example.com", "client-view.example.com", True, "cancel-after"),
}


def run_scenario(name: str) -> dict[str, object]:
    verify_hostname, certificate_hostname, trust_server_ca, action = SCENARIOS[name]
    directory = tempfile.TemporaryDirectory(prefix="twisted-tls-diag-")
    directory_path = Path(directory.name)
    trusted = Authority(directory_path, "trusted-ca")
    untrusted = Authority(directory_path, "untrusted-ca")
    server_ca = trusted if trust_server_ca else untrusted
    server_certificate = server_ca.server_certificate(certificate_hostname)

    recorder = Recorder()
    reactor = MemoryReactorClock()

    server_app = WatchedProtocol("server-app", recorder)
    TCP4ServerEndpoint(reactor, 4321).listen(
        TLSMemoryBIOFactory(
            PrivateCertificate.options(server_certificate),
            isClient=False,
            wrappedFactory=Factory.forProtocol(lambda: server_app),
            clock=Clock(),
        )
    )

    client_app = WatchedProtocol("client-app", recorder)
    client_factory = ClientFactoryFor(client_app, recorder)
    hold: dict[str, Failure] = {}
    deferred = wrapClientTLS(
        optionsForClientTLS(verify_hostname, trustRoot=trusted.trust_root()),
        TCP4ClientEndpoint(reactor, "127.0.0.1", 4321),
        clock=reactor,
    ).connect(client_factory)
    deferred.addCallbacks(
        lambda protocol: recorder.record(
            "client-endpoint", "Deferred.callback", "protocol (TLS handshake not implied)"
        ),
        lambda failure: (
            hold.setdefault("deferred_failure", failure),
            recorder.record("client-endpoint", "Deferred.errback", describe(failure)),
            None,
        )[-1],
    )

    recorder.record("harness", "policy", f"verify={verify_hostname!r} cert={certificate_hostname!r} trustedCA={trust_server_ca}")

    if action == "cancel-before":
        recorder.marker("harness", "Deferred.cancel() before TCP connect")
        deferred.cancel()
        completer = ConnectionCompleter(reactor)
        recorder.record("harness", "connector.stoppedConnecting", completer._reactor.connectors[0].stoppedConnecting)
        return finish(name, recorder, client_app, server_app, deferred, hold, action, directory)

    completer = ConnectionCompleter(reactor)
    pump = completer.succeedOnce(greet=False)
    assert pump is not None, "in-memory connection did not complete"
    client_tls = pump.client._wrappedProtocol
    recorder.instrument(client_tls, "connectionLost", "client-tls")
    for method in ("_checkHandshakeStatus", "failVerification", "abortConnection", "loseConnection", "_tlsShutdownFinished"):
        recorder.instrument(client_tls, method, "client-tls")
    for method in ("_checkHandshakeStatus", "_tlsShutdownFinished", "connectionLost", "loseConnection"):
        recorder.instrument(pump.server, method, "server-tls")

    pump.flush()
    marker = len(recorder.events)
    recorder.record(
        "harness",
        "post-handshake",
        f"client_handshakeCompleted={client_app.handshake_completed} "
        f"server_handshakeCompleted={server_app.handshake_completed} deferred_called={deferred.called}",
    )

    if action == "server-lose":
        marker = recorder.marker("harness", "server app loseConnection")
        server_app.loseConnection()
    elif action == "client-lose":
        marker = recorder.marker("harness", "client app loseConnection")
        client_app.loseConnection()
    elif action == "client-abort":
        marker = recorder.marker("harness", "client app abortConnection")
        client_app.abortConnection()
    elif action == "abort-tcp":
        marker = recorder.marker("harness", "client app abortConnection (TCP semantics)")
        client_app.abortConnection()
        # Real tcp._AbortingMixin.abortConnection schedules connectionLost with
        # Failure(ConnectionAborted()); represent that on the in-memory link.
        pump.clientIO.disconnectReason = error.ConnectionAborted("local abort")
        pump.clientIO.disconnecting = True
    elif action == "cancel-after":
        marker = recorder.marker("harness", "Deferred.cancel() after Deferred fired")
        deferred.cancel()
        recorder.record("harness", "Deferred.cancel", f"still_called={deferred.called}")
    elif action == "raw-fin":
        # Model tcp.Client.doRead(): a bare FIN becomes CONNECTION_DONE and the
        # TCP transport forwards that Failure to its protocol.
        marker = recorder.marker("harness", "raw TCP FIN -> Failure(ConnectionDone('raw FIN'))")
        pump.clientIO.disconnectReason = error.ConnectionDone("raw FIN")
        pump.clientIO.disconnecting = True

    if action in {"server-lose", "client-lose", "client-abort", "abort-tcp", "raw-fin", "none"}:
        pump.flush()
    elif action == "cancel-after":
        pump.flush()
        pump.flush(advanceClock=False)

    return finish(name, recorder, client_app, server_app, deferred, hold, action, directory, marker)


def finish(name, recorder, client_app, server_app, deferred, hold, action, directory, marker=0):
    deferred_failure = hold.get("deferred_failure")
    observed = client_app.reason or deferred_failure
    result = {
        "scenario": name,
        "action": action,
        "events": recorder.events,
        "client_final": describe(client_app.reason),
        "server_final": describe(server_app.reason),
        "client_handshake_completed": client_app.handshake_completed,
        "server_handshake_completed": server_app.handshake_completed,
        "deferred_called": deferred.called,
        "deferred_failure": describe(deferred_failure),
        "observed_by": "connectionLost" if client_app.reason is not None else ("Deferred errback" if deferred_failure else "nothing"),
        "classification": classify(observed, action, client_app.handshake_completed),
        "first_signal_after_action": next(
            (
                f"{event['source']}:{event['event']}"
                for event in recorder.events
                if event["seq"] > marker and event["source"] in {"client-tls", "client-app"}
            ),
            None,
        ),
    }
    directory.cleanup()
    return result


def normalized(result: dict[str, object]) -> dict[str, object]:
    return {
        "scenario": result["scenario"],
        "events": [
            (event["source"], event["event"], normalized_detail(event["detail"]))
            for event in result["events"]
        ],
        "client_final_type": reason_type_from_string(result["client_final"]),
        "server_final_type": reason_type_from_string(result["server_final"]),
        "classification": result["classification"]["cause"],
        "first_signal_after_action": result["first_signal_after_action"],
    }


def reason_type_from_string(text: object) -> object:
    if not isinstance(text, str):
        return None
    return text.split(": ", 1)[0]


def run_all() -> dict[str, dict[str, object]]:
    return {name: run_scenario(name) for name in SCENARIOS}


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------


def print_results(results: dict[str, dict[str, object]]) -> None:
    for name, result in results.items():
        print(f"\n=== {name} ===")
        for event in result["events"]:
            print(
                f"[{event['seq']:02d}] {event['source']:<18} {event['event']:<26} "
                f"{event['detail'] if event['detail'] is not None else ''}"
            )
        print(f"FINAL client-app: {result['client_final']}")
        print(f"FINAL server-app: {result['server_final']}")
        print(f"FIRST SIGNAL AFTER ACTION: {result['first_signal_after_action']}")
        print(f"CLASSIFICATION: {json.dumps(result['classification'], sort_keys=True)}")

    if "peer-clean-close" not in results or "app-clean-close" not in results:
        return
    peer = results["peer-clean-close"]
    local = results["app-clean-close"]
    print("\n=== identical final error, different first known cause ===")
    print(f"peer-clean-close  final={peer['client_final']}")
    print(f"                  first signal after action={peer['first_signal_after_action']}")
    print(f"app-clean-close   final={local['client_final']}")
    print(f"                  first signal after action={local['first_signal_after_action']}")
    print(f"identical final value: {peer['client_final'] == local['client_final']}")
    print(f"identical classification: {peer['classification'] == local['classification']}")


def check_repeatable() -> int:
    first = run_all()
    second = run_all()
    different = [
        name
        for name in SCENARIOS
        if normalized(first[name]) != normalized(second[name])
    ]
    if different:
        print(f"NOT repeatable: {different}", file=sys.stderr)
        for name in different:
            a, b = normalized(first[name]), normalized(second[name])
            print(f"\n{name}\nfirst:  {a}\nsecond: {b}", file=sys.stderr)
        return 1
    print(f"repeatable: {len(SCENARIOS)} scenarios produced identical normalized traces")
    for name, result in first.items():
        print(f"  {name:<28} {result['classification']['cause']}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Offline TLS disconnect attribution trace")
    parser.add_argument("scenario", nargs="?", choices=list(SCENARIOS))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true", help="run all scenarios twice and compare")
    args = parser.parse_args(argv)

    if args.check:
        return check_repeatable()

    chosen = [args.scenario] if args.scenario else list(SCENARIOS)
    results = {name: run_scenario(name) for name in chosen}
    if args.json:
        json.dump(results, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    print_results(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
