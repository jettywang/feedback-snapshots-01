"""Offline end-to-end regression tests for the ROBOT plugin.

These tests never open a real network socket: a programmable, in-process TLS
connection double stands in for the server. The *real* ROBOT collection code
(``test_robot`` -> ``_send_robot_payload`` -> ``do_handshake_with_robot``) drives
the double, so every response is genuinely produced by sending the five RSA/PMS
padding payloads over a (simulated) TLS handshake. Nothing is pre-fed to
``RobotServerResponsesAnalyzer``; the analyzer only sees what the collection
layer actually recorded.

The double is programmed per padding variant with one of four behaviours:

* a stable TLS alert response,
* a fluctuating response (the answer changes between the three attempts),
* a timeout while waiting for the server's answer,
* a handshake rejection (an alert received before the ClientKeyExchange stage).

Every test asserts both the final plugin verdict and the concrete attempts /
response attribution observed on the wire, and checks that the JSON and console
conclusions agree.
"""

import datetime
import socket
import types
from dataclasses import dataclass
from threading import Lock
from typing import Callable, Dict, List, Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tls_parser.alert_protocol import TlsAlertRecord, TlsAlertSeverityByte
from tls_parser.handshake_protocol import (
    TlsHandshakeMessage,
    TlsHandshakeRecord,
    TlsHandshakeTypeByte,
)
from tls_parser.record_protocol import TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum

from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.plugins.robot._robot_tester import (
    RobotPmsPaddingPayloadEnum,
    RobotScanResultEnum,
    RobotServerResponsesAnalyzer,
    do_handshake_with_robot,
)
from sslyze.plugins.robot.implementation import (
    RobotImplementation,
    RobotScanResult,
    RobotScanResultAsJson,
)
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum as SslyzeTlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation

# ---------------------------------------------------------------------------
# Shared, in-memory RSA material (the server double's certificate / key)
# ---------------------------------------------------------------------------

_RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_NUMBERS = _RSA_PRIVATE_KEY.public_key().public_numbers()

_RSA_CERTIFICATE = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "robot-double.local")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "robot-double.local")]))
    .public_key(_RSA_PRIVATE_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime(2020, 1, 1))
    .not_valid_after(datetime.datetime(2030, 1, 1))
    .sign(_RSA_PRIVATE_KEY, hashes.SHA256())
)
_RSA_CERTIFICATE_PEM = _RSA_CERTIFICATE.public_bytes(serialization.Encoding.PEM).decode("ascii")

# Distinct, stable TLS alert descriptions used to program the server double.
_ALERT_DECRYPT_ERROR = 51
_ALERT_HANDSHAKE_FAILURE = 40
_ALERT_INTERNAL_ERROR = 80
_ALERT_ILLEGAL_PARAMETER = 47
_ALERT_UNEXPECTED_MESSAGE = 10


def _alert_response(alert_description: int) -> str:
    """The exact text produced by ``do_handshake_with_robot`` for an alert."""
    severity = TlsAlertSeverityByte.FATAL
    return "TLS Alert {} {}".format(alert_description, severity)


# Pre-compute the on-the-wire ClientKeyExchange record of every padding variant
# so the double can attribute an incoming connection to the right payload.
_CKE_BYTES_TO_PAYLOAD: Dict[bytes, RobotPmsPaddingPayloadEnum] = {}
for _payload_enum in RobotPmsPaddingPayloadEnum:
    from sslyze.plugins.robot._robot_tester import _RobotTlsRecordPayloads

    _cke_record = _RobotTlsRecordPayloads.get_client_key_exchange_record(
        _payload_enum, TlsVersionEnum.TLSV1_2, _RSA_NUMBERS.n, _RSA_NUMBERS.e
    )
    _CKE_BYTES_TO_PAYLOAD[_cke_record.to_bytes()] = _payload_enum


# ---------------------------------------------------------------------------
# Programming model for the server double
# ---------------------------------------------------------------------------


@dataclass
class PayloadBehavior:
    """How the simulated server answers one padding variant."""

    # Called once per attempt with the 1-based attempt number; returns the
    # response text the collection layer should record.
    response_factory: Callable[[int], str]
    # When True the answer is delivered as an alert during the ClientHello
    # stage, before any ClientKeyExchange can be sent (a handshake rejection).
    reject_during_hello: bool = False
    # When True the connection raises socket.timeout instead of answering.
    times_out: bool = False


def stable_alert(alert_description: int) -> PayloadBehavior:
    return PayloadBehavior(lambda attempt: _alert_response(alert_description))


def fluctuating_alerts(alert_descriptions: List[int]) -> PayloadBehavior:
    def _factory(attempt: int) -> str:
        return _alert_response(alert_descriptions[(attempt - 1) % len(alert_descriptions)])

    return PayloadBehavior(_factory)


def timeout_behavior() -> PayloadBehavior:
    return PayloadBehavior(lambda attempt: "Connection timed out", times_out=True)


def handshake_rejection(alert_description: int = _ALERT_HANDSHAKE_FAILURE) -> PayloadBehavior:
    return PayloadBehavior(
        lambda attempt: _alert_response(alert_description), reject_during_hello=True
    )


class _HardDiscoveryFailure:
    """A discovery handshake that hard-fails (timeout) instead of cleanly rejecting.

    A clean rejection is how the real plugin learns that RSA is unsupported; a
    timeout must instead propagate as a connection error.
    """

    times_out = True
    reject_during_hello = False

    def response_factory(self, attempt: int) -> str:
        return "Connection timed out"

    def __call__(self, client: "_FakeRobotSslClient") -> None:
        raise TlsHandshakeTimedOut(
            server_location=client._controller.server_info.server_location,
            network_configuration=client._controller.server_info.network_configuration,
            error_message="Simulated discovery handshake timeout",
        )


@dataclass
class _RecordedConnection:
    use_legacy_openssl: Optional[bool]
    cipher_string: Optional[str]
    tls_version: SslyzeTlsVersionEnum
    payload: Optional[RobotPmsPaddingPayloadEnum]
    response: str
    rejected_during_hello: bool
    timed_out: bool


# ---------------------------------------------------------------------------
# The in-process TLS double: fake socket, fake SSL client, fake connection
# ---------------------------------------------------------------------------


class _FakeRobotSocket:
    """An in-memory socket implementing only what ``do_handshake_with_robot`` uses."""

    def __init__(self, controller: "RobotServerDouble") -> None:
        self._controller = controller
        self._recv_buffer = bytearray()
        self._closed = False

    def queue_server_hello_done(self) -> None:
        # A single handshake record carrying a ServerHelloDone message is enough
        # for the real parser loop to progress to the ClientKeyExchange stage.
        message = TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_DONE, b"")
        header = TlsRecordHeader(TlsRecordTypeByte.HANDSHAKE, TlsVersionEnum.TLSV1_2, message.size)
        self._recv_buffer += TlsHandshakeRecord(header, [message]).to_bytes()

    def queue_alert(self, alert_description: int) -> None:
        self._recv_buffer += TlsAlertRecord.from_parameters(
            TlsVersionEnum.TLSV1_2, TlsAlertSeverityByte.FATAL, alert_description
        ).to_bytes()

    def send(self, data: bytes) -> int:
        self._controller.handle_outbound_bytes(bytes(data), self)
        return len(data)

    def recv(self, _bufsize: int) -> bytes:
        if not self._recv_buffer:
            raise AssertionError("Robot double was asked to recv() with nothing queued")
        chunk = bytes(self._recv_buffer)
        self._recv_buffer = bytearray()
        return chunk

    def close(self) -> None:
        self._closed = True

    def settimeout(self, _value: object) -> None:
        pass


class _FakeNetworkBio:
    def __init__(self) -> None:
        self._pending = bytearray(b"\x00")

    def pending(self) -> int:
        return len(self._pending)

    def read(self, length: int) -> bytes:
        chunk = bytes(self._pending[:length])
        del self._pending[:length]
        return chunk


class _FakeSsl:
    def __init__(self) -> None:
        self._ssl_version = types.SimpleNamespace(name=TlsVersionEnum.TLSV1_2.name)

    def do_handshake(self) -> None:
        # Mirrors nassl: the very first call asks the caller to write ClientHello.
        from nassl._nassl import WantReadError

        raise WantReadError()


class _FakeRobotSslClient:
    """Stand-in for ``nassl.ssl_client.SslClient`` used by the ROBOT collection code."""

    def __init__(self, controller: "RobotServerDouble", use_legacy_openssl: Optional[bool]) -> None:
        self._controller = controller
        self._use_legacy_openssl = use_legacy_openssl
        self._sock = _FakeRobotSocket(controller)
        self._network_bio = _FakeNetworkBio()
        self._ssl = _FakeSsl()
        # nassl's SslClient exposes the negotiated SSL version at this path; the
        # ROBOT handshake uses it to build the ChangeCipherSpec record.
        self._ssl_version = types.SimpleNamespace(name=TlsVersionEnum.TLSV1_2.name)
        self._cipher_string: Optional[str] = None
        # Attributes injected by _send_robot_payload() before connect().
        self._robot_cke_record: object = None
        self._robot_should_finish_handshake: bool = True

    def set_cipher_list(self, cipher_string: str) -> None:
        self._cipher_string = cipher_string

    def set_underlying_socket(self, sock: _FakeRobotSocket) -> None:
        # SslConnection passes the socket it "opened"; keep the double's socket.
        self._sock = sock

    def get_received_chain(self) -> List[str]:
        return [_RSA_CERTIFICATE_PEM]

    def shutdown(self) -> None:
        self._sock.close()

    def _rsa_parameter_handshake(self) -> None:
        # Default do_handshake(): a normal RSA handshake used by _get_rsa_parameters().
        behavior = self._controller.rsa_handshake_behavior
        if behavior is None:
            return
        if callable(behavior):
            behavior(self)
            return
        if behavior.times_out:
            raise socket.timeout()
        if behavior.reject_during_hello:
            raise ServerRejectedTlsHandshake(
                server_location=self._controller.server_info.server_location,
                network_configuration=self._controller.server_info.network_configuration,
                error_message="Simulated RSA handshake rejection",
            )

    do_handshake = _rsa_parameter_handshake


class _FakeRobotSslConnection:
    """Stand-in for ``SslConnection`` returned by ``get_preconfigured_tls_connection``."""

    def __init__(
        self,
        controller: "RobotServerDouble",
        tls_version: SslyzeTlsVersionEnum,
        should_use_legacy_openssl: Optional[bool],
    ) -> None:
        self._controller = controller
        self.tls_version = tls_version
        self.should_use_legacy_openssl = should_use_legacy_openssl
        self.ssl_client = _FakeRobotSslClient(controller, should_use_legacy_openssl)

    def connect(self) -> None:
        client = self.ssl_client
        if client._robot_cke_record is not None:
            # _send_robot_payload() attached a CKE record and replaced do_handshake
            # with the ROBOT handshake.
            self._controller.begin_robot_connection(self, client)  # programs the socket, then:
            do_handshake_with_robot(client)
        else:
            # Plain RSA parameter discovery handshake.
            self._controller.record_connection_open(self, client, payload=None)
            self._controller.record_rsa_handshake_outcome(self, client)
            client.do_handshake()

    def close(self) -> None:
        self.ssl_client.shutdown()


class RobotServerDouble:
    """Programmable, fully in-process server double for one ROBOT scan."""

    def __init__(
        self,
        behaviors: Dict[RobotPmsPaddingPayloadEnum, PayloadBehavior],
        rsa_handshake_behavior: Optional[object] = None,
    ) -> None:
        self._behaviors = behaviors
        self.rsa_handshake_behavior = rsa_handshake_behavior
        self._lock = Lock()
        # Per-payload list of recorded response texts, in attempt order.
        self.recorded_responses: Dict[RobotPmsPaddingPayloadEnum, List[str]] = {
            payload: [] for payload in RobotPmsPaddingPayloadEnum
        }
        self.connection_log: List[_RecordedConnection] = []
        self.robot_connections = 0
        self.rsa_discovery_connections = 0
        self.cipher_strings_used: List[Optional[str]] = []
        self.legacy_openssl_uses: List[Optional[bool]] = []
        self.tls_versions_used: List[SslyzeTlsVersionEnum] = []
        self.server_info = self._build_server_info()
        # Patch the connection factory so the real plugin code talks to the double.
        self._original_factory = ServerConnectivityInfo.get_preconfigured_tls_connection

        def _preconfigured_tls_connection(
            target_server_info: ServerConnectivityInfo,
            override_tls_version: Optional[SslyzeTlsVersionEnum] = None,
            ca_certificates_path: object = None,
            should_use_legacy_openssl: Optional[bool] = None,
            should_enable_server_name_indication: bool = True,
        ) -> _FakeRobotSslConnection:
            tls_version = (
                override_tls_version or target_server_info.tls_probing_result.highest_tls_version_supported
            )
            return _FakeRobotSslConnection(self, tls_version, should_use_legacy_openssl)

        self._factory = _preconfigured_tls_connection
        ServerConnectivityInfo.get_preconfigured_tls_connection = (  # type: ignore[method-assign]
            self._factory
        )

    def stop(self) -> None:
        ServerConnectivityInfo.get_preconfigured_tls_connection = (  # type: ignore[method-assign]
            self._original_factory
        )

    def __enter__(self) -> "RobotServerDouble":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    @staticmethod
    def _build_server_info() -> ServerConnectivityInfo:
        location = ServerNetworkLocation(hostname="robot-double.local", port=443, ip_address="10.0.0.1")
        return ServerConnectivityInfo(
            server_location=location,
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication=location.hostname),
            tls_probing_result=ServerTlsProbingResult(
                highest_tls_version_supported=SslyzeTlsVersionEnum.TLS_1_2,
                cipher_suite_supported="AES128-GCM-SHA256",
                client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
                supports_ecdh_key_exchange=True,
            ),
        )

    # -- bookkeeping --------------------------------------------------------

    def record_connection_open(
        self,
        connection: _FakeRobotSslConnection,
        client: _FakeRobotSslClient,
        payload: Optional[RobotPmsPaddingPayloadEnum],
    ) -> None:
        with self._lock:
            self.cipher_strings_used.append(client._cipher_string)
            self.legacy_openssl_uses.append(connection.should_use_legacy_openssl)
            self.tls_versions_used.append(connection.tls_version)

    def _record(
        self,
        connection: _FakeRobotSslConnection,
        client: _FakeRobotSslClient,
        entry: _RecordedConnection,
    ) -> None:
        with self._lock:
            self.connection_log.append(entry)
            if entry.payload is not None:
                self.recorded_responses[entry.payload].append(entry.response)

    def record_rsa_handshake_outcome(
        self, connection: _FakeRobotSslConnection, client: _FakeRobotSslClient
    ) -> None:
        with self._lock:
            self.rsa_discovery_connections += 1

    # -- ROBOT handshake orchestration -------------------------------------

    def begin_robot_connection(
        self, connection: _FakeRobotSslConnection, client: _FakeRobotSslClient
    ) -> None:
        with self._lock:
            self.robot_connections += 1
        self.record_connection_open(connection, client, payload=None)
        # Make the simulated server immediately present ServerHelloDone so the
        # real handshake loop progresses to the ClientKeyExchange stage. A
        # rejection variant replaces it with an alert once the payload is known.
        client._sock.queue_server_hello_done()
        # The active payload is derived from the CKE record the collection layer
        # attached to this SSL client; resolve it lazily from the outgoing bytes.
        client._sock._double_connection = (connection, client)  # type: ignore[attr-defined]

    def handle_outbound_bytes(self, data: bytes, sock: _FakeRobotSocket) -> None:
        connection, client = sock._double_connection  # type: ignore[attr-defined]
        payload = self._identify_payload(data)
        if payload is None:
            # ClientHello / CCS / Finished bytes: nothing to attribute yet.
            return

        behavior = self._behaviors[payload]
        attempt_number = len(self.recorded_responses[payload]) + 1
        response_text = behavior.response_factory(attempt_number)

        if behavior.reject_during_hello:
            # Answer with an alert before a ClientKeyExchange can be accepted:
            # drain the queued ServerHelloDone and present an alert instead. The
            # parser loop stops on the alert and never reaches the CKE stage.
            sock._recv_buffer = bytearray()
            alert_description = int(response_text.split()[2])
            sock.queue_alert(alert_description)
            self._record(
                connection,
                client,
                _RecordedConnection(
                    use_legacy_openssl=connection.should_use_legacy_openssl,
                    cipher_string=client._cipher_string,
                    tls_version=connection.tls_version,
                    payload=payload,
                    response=response_text,
                    rejected_during_hello=True,
                    timed_out=False,
                ),
            )
            return

        if behavior.times_out:
            self._record(
                connection,
                client,
                _RecordedConnection(
                    use_legacy_openssl=connection.should_use_legacy_openssl,
                    cipher_string=client._cipher_string,
                    tls_version=connection.tls_version,
                    payload=payload,
                    response="Connection timed out",
                    rejected_during_hello=False,
                    timed_out=True,
                ),
            )
            # Make the post-CKE read block forever, exactly like a silent server.
            def _timeout_recv(_bufsize: int) -> bytes:
                raise socket.timeout()

            sock.recv = _timeout_recv  # type: ignore[method-assign]
            return

        alert_description = int(response_text.split()[2])
        sock.queue_alert(alert_description)
        self._record(
            connection,
            client,
            _RecordedConnection(
                use_legacy_openssl=connection.should_use_legacy_openssl,
                cipher_string=client._cipher_string,
                tls_version=connection.tls_version,
                payload=payload,
                response=response_text,
                rejected_during_hello=False,
                timed_out=False,
            ),
        )

    @staticmethod
    def _identify_payload(data: bytes) -> Optional[RobotPmsPaddingPayloadEnum]:
        for cke_bytes, payload in _CKE_BYTES_TO_PAYLOAD.items():
            if cke_bytes in data:
                return payload
        return None


# ---------------------------------------------------------------------------
# Helpers shared by the tests
# ---------------------------------------------------------------------------


def _all_variants(
    behavior_factory: Callable[[RobotPmsPaddingPayloadEnum], PayloadBehavior]
) -> Dict[RobotPmsPaddingPayloadEnum, PayloadBehavior]:
    return {payload: behavior_factory(payload) for payload in RobotPmsPaddingPayloadEnum}


def _assert_json_and_console_agree(result: RobotScanResult, expected_enum: RobotScanResultEnum) -> None:
    # The JSON conclusion must carry the same enum value as the in-memory result.
    result_as_json = RobotScanResultAsJson.model_validate(result).model_dump_json()
    assert f'"robot_result":"{expected_enum.value}"' in result_as_json

    # The console conclusion must contain the human-readable verdict for that enum.
    console_lines = RobotImplementation.cli_connector_cls.result_to_console_output(result)
    console_text = "\n".join(console_lines)
    expected_fragments = {
        RobotScanResultEnum.VULNERABLE_STRONG_ORACLE: "Strong oracle",
        RobotScanResultEnum.VULNERABLE_WEAK_ORACLE: "Weak oracle",
        RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE: "OK - Not vulnerable.",
        RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED: "RSA cipher suites not supported",
        RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS: "UNKNOWN - Received inconsistent results.",
    }
    assert expected_fragments[expected_enum] in console_text
    assert result.robot_result == expected_enum


def _assert_full_attempt_attribution(server_double: RobotServerDouble) -> None:
    # Three full scans x five padding variants = 15 ROBOT connections, each
    # attributed to exactly one payload and answered exactly three times.
    assert server_double.robot_connections == RobotImplementation._TEST_ATTEMPTS_NB * len(
        RobotPmsPaddingPayloadEnum
    )
    for payload in RobotPmsPaddingPayloadEnum:
        assert len(server_double.recorded_responses[payload]) == RobotImplementation._TEST_ATTEMPTS_NB


# ---------------------------------------------------------------------------
# End-to-end regression scenarios
# ---------------------------------------------------------------------------


class TestRobotOfflineEndToEndRegression:
    def test_strong_oracle_is_classified_from_real_probes(self) -> None:
        # Every padding variant gets its own distinct, stable answer -> strong oracle.
        distinct_alerts = [
            _ALERT_DECRYPT_ERROR,
            _ALERT_HANDSHAKE_FAILURE,
            _ALERT_INTERNAL_ERROR,
            _ALERT_ILLEGAL_PARAMETER,
            _ALERT_UNEXPECTED_MESSAGE,
        ]
        behaviors = {
            payload: stable_alert(distinct_alerts[index])
            for index, payload in enumerate(RobotPmsPaddingPayloadEnum)
        }
        with RobotServerDouble(behaviors) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.VULNERABLE_STRONG_ORACLE)
        _assert_full_attempt_attribution(server_double)
        # The responses genuinely differ per payload and are stable across attempts.
        first_answers = {
            payload: responses[0]
            for payload, responses in server_double.recorded_responses.items()
        }
        assert len(set(first_answers.values())) == len(RobotPmsPaddingPayloadEnum)
        for responses in server_double.recorded_responses.values():
            assert len(set(responses)) == 1

    def test_weak_oracle_is_classified_from_real_probes(self) -> None:
        # The three invalid-PKCS#1 variants answer identically; the remaining two
        # differ from them -> weak oracle (never a strong one).
        weak_shared = _ALERT_DECRYPT_ERROR
        behaviors = {
            RobotPmsPaddingPayloadEnum.VALID: stable_alert(_ALERT_INTERNAL_ERROR),
            RobotPmsPaddingPayloadEnum.WRONG_FIRST_TWO_BYTES: stable_alert(weak_shared),
            RobotPmsPaddingPayloadEnum.WRONG_POSITION_00: stable_alert(weak_shared),
            RobotPmsPaddingPayloadEnum.NO_00_IN_THE_MIDDLE: stable_alert(weak_shared),
            RobotPmsPaddingPayloadEnum.WRONG_VERSION_NUMBER: stable_alert(_ALERT_HANDSHAKE_FAILURE),
        }
        with RobotServerDouble(behaviors) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.VULNERABLE_WEAK_ORACLE)
        _assert_full_attempt_attribution(server_double)

    def test_no_oracle_when_all_responses_identical(self) -> None:
        # A fully completed scan whose answers never differ is NOT an oracle.
        behaviors = _all_variants(lambda payload: stable_alert(_ALERT_DECRYPT_ERROR))
        with RobotServerDouble(behaviors) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)
        _assert_full_attempt_attribution(server_double)
        every_answer = {
            answer for responses in server_double.recorded_responses.values() for answer in responses
        }
        assert every_answer == {_alert_response(_ALERT_DECRYPT_ERROR)}

    def test_completed_but_undifferentiated_timeouts_are_no_oracle(self) -> None:
        # All five variants time out, consistently, across all three attempts.
        # The scan completes but cannot distinguish payloads -> no oracle, and it
        # must never be promoted to a strong oracle or "safe" RSA-not-supported.
        behaviors = _all_variants(lambda payload: timeout_behavior())
        with RobotServerDouble(behaviors) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)
        _assert_full_attempt_attribution(server_double)
        assert all(entry.timed_out for entry in server_double.connection_log)
        assert all(
            responses == ["Connection timed out"] * RobotImplementation._TEST_ATTEMPTS_NB
            for responses in server_double.recorded_responses.values()
        )

    def test_fluctuating_response_yields_inconsistent_verdict(self) -> None:
        # One variant answers differently on the second attempt; all others stable.
        behaviors = _all_variants(lambda payload: stable_alert(_ALERT_DECRYPT_ERROR))
        behaviors[RobotPmsPaddingPayloadEnum.WRONG_VERSION_NUMBER] = fluctuating_alerts(
            [_ALERT_DECRYPT_ERROR, _ALERT_INTERNAL_ERROR, _ALERT_DECRYPT_ERROR]
        )
        with RobotServerDouble(behaviors) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS)
        _assert_full_attempt_attribution(server_double)
        fluctuating = server_double.recorded_responses[
            RobotPmsPaddingPayloadEnum.WRONG_VERSION_NUMBER
        ]
        assert len(set(fluctuating)) == 2

    def test_handshake_rejection_before_cke_is_not_a_strong_oracle(self) -> None:
        # The server rejects every ClientHello with an alert before a CKE is sent.
        # The collection layer still records one answer per variant; because they
        # are all identical the verdict is NO_ORACLE - never a strong oracle.
        behaviors = _all_variants(lambda payload: handshake_rejection(_ALERT_HANDSHAKE_FAILURE))
        with RobotServerDouble(behaviors) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)
        _assert_full_attempt_attribution(server_double)
        assert all(entry.rejected_during_hello for entry in server_double.connection_log)
        # No variant ever reached the ClientKeyExchange stage.
        assert all(
            entry.response == _alert_response(_ALERT_HANDSHAKE_FAILURE)
            for entry in server_double.connection_log
        )

    def test_rsa_not_supported_is_handled_separately(self) -> None:
        # Both RSA discovery handshakes (GCM then generic RSA) are rejected, so the
        # plugin short-circuits to RSA_NOT_SUPPORTED without sending ROBOT payloads.
        rejection = handshake_rejection(_ALERT_HANDSHAKE_FAILURE)
        with RobotServerDouble(
            behaviors={}, rsa_handshake_behavior=rejection
        ) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(
            result, RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED
        )
        assert server_double.robot_connections == 0
        # Every one of the three scan jobs tries GCM then generic RSA before giving
        # up on RSA; the plugin then short-circuits while aggregating the jobs.
        assert server_double.rsa_discovery_connections == 2 * RobotImplementation._TEST_ATTEMPTS_NB
        # GCM ciphers are tried first, then the generic RSA string, on every job.
        assert server_double.cipher_strings_used == [
            "AES128-GCM-SHA256:AES256-GCM-SHA384",
            "RSA",
        ] * RobotImplementation._TEST_ATTEMPTS_NB
        assert server_double.legacy_openssl_uses == [True, True] * RobotImplementation._TEST_ATTEMPTS_NB

    def test_gcm_discovery_failure_falls_back_to_generic_rsa_cipher(self) -> None:
        # The GCM RSA handshake is rejected but the generic RSA handshake succeeds;
        # the ROBOT probes then run over the generic RSA cipher string.
        gcm_cipher_string = "AES128-GCM-SHA256:AES256-GCM-SHA384"

        class _ConditionalRsaBehavior:
            times_out = False
            reject_during_hello = False

            def response_factory(self, attempt: int) -> str:
                return ""

            def __call__(self, client: _FakeRobotSslClient) -> None:
                if client._cipher_string == gcm_cipher_string:
                    raise ServerRejectedTlsHandshake(
                        server_location=client._controller.server_info.server_location,
                        network_configuration=client._controller.server_info.network_configuration,
                        error_message="Simulated GCM handshake rejection",
                    )

        conditional_behavior = _ConditionalRsaBehavior()
        behaviors = _all_variants(lambda payload: stable_alert(_ALERT_DECRYPT_ERROR))
        with RobotServerDouble(
            behaviors, rsa_handshake_behavior=conditional_behavior
        ) as server_double:
            result = RobotImplementation.scan_server(server_double.server_info)

        _assert_json_and_console_agree(result, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)
        # Each of the three jobs first fails GCM discovery then succeeds on generic RSA.
        assert server_double.rsa_discovery_connections == 2 * RobotImplementation._TEST_ATTEMPTS_NB
        # ROBOT probes reuse the generic RSA cipher that actually worked.
        robot_cipher_strings = {
            entry.cipher_string
            for entry in server_double.connection_log
            if entry.payload is not None
        }
        assert robot_cipher_strings == {"RSA"}
        assert all(entry.tls_version == SslyzeTlsVersionEnum.TLS_1_2 for entry in server_double.connection_log)

    def test_classifier_only_consumes_responses_from_real_handshakes(self) -> None:
        # Guard against "bypassing" the collection logic: nothing here builds a
        # dictionary and hands it to RobotServerResponsesAnalyzer. Instead the real
        # do_handshake_with_robot() must run for every payload and every attempt, and
        # the responses the classifier eventually consumed must be exactly the ones
        # observed on those simulated handshakes (same objects, same ordering).
        behaviors = {
            payload: stable_alert(
                [
                    _ALERT_DECRYPT_ERROR,
                    _ALERT_HANDSHAKE_FAILURE,
                    _ALERT_INTERNAL_ERROR,
                    _ALERT_ILLEGAL_PARAMETER,
                    _ALERT_UNEXPECTED_MESSAGE,
                ][index]
            )
            for index, payload in enumerate(RobotPmsPaddingPayloadEnum)
        }
        captured_analyzer_input: Dict[RobotPmsPaddingPayloadEnum, List[str]] = {}

        original_init = RobotServerResponsesAnalyzer.__init__

        def _spying_init(
            analyzer: RobotServerResponsesAnalyzer,
            payload_responses: Dict[RobotPmsPaddingPayloadEnum, List[str]],
            attempts_count: int,
        ) -> None:
            # Keep a reference to the exact mapping the production code hands over.
            captured_analyzer_input.update(payload_responses)
            original_init(analyzer, payload_responses, attempts_count)

        RobotServerResponsesAnalyzer.__init__ = _spying_init  # type: ignore[method-assign]
        try:
            with RobotServerDouble(behaviors) as server_double:
                result = RobotImplementation.scan_server(server_double.server_info)
        finally:
            RobotServerResponsesAnalyzer.__init__ = original_init  # type: ignore[method-assign]

        assert result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
        # The analyzer was fed precisely the five payloads x three attempts recorded
        # by driving the actual ROBOT handshake - no extra or missing entries.
        assert set(captured_analyzer_input.keys()) == set(RobotPmsPaddingPayloadEnum)
        for payload in RobotPmsPaddingPayloadEnum:
            assert (
                captured_analyzer_input[payload]
                == server_double.recorded_responses[payload]
            )
            assert len(captured_analyzer_input[payload]) == RobotImplementation._TEST_ATTEMPTS_NB


class TestRobotIncompleteAttemptHandling:
    def test_missing_one_attempt_is_rejected_not_classified(self) -> None:
        # Responses collected from only two attempts when three were expected must
        # fail loudly instead of silently returning a strong oracle / safe verdict.
        payload_responses = {
            payload: [_alert_response(_ALERT_DECRYPT_ERROR), _alert_response(_ALERT_INTERNAL_ERROR)]
            for payload in RobotPmsPaddingPayloadEnum
        }
        with pytest.raises(ValueError):
            RobotServerResponsesAnalyzer(payload_responses, attempts_count=3)

    def test_timeout_during_rsa_discovery_fails_the_scan_job(self) -> None:
        # A timeout while discovering RSA parameters is a connection failure, not
        # evidence that RSA is unsupported: it aborts the scan job before any ROBOT
        # payload is sent, rather than being misread as "RSA not supported".
        with RobotServerDouble(
            behaviors={}, rsa_handshake_behavior=timeout_behavior()
        ) as server_double:
            jobs = RobotImplementation.scan_jobs_for_scan_command(server_double.server_info)
            results = []
            for job in jobs:
                try:
                    job.function_to_call(*job.function_arguments)
                    raised = None
                except Exception as exception:  # noqa: BLE001
                    raised = exception
                results.append(raised)

        assert len(results) == RobotImplementation._TEST_ATTEMPTS_NB
        assert all(isinstance(exception, socket.timeout) for exception in results)
        assert server_double.robot_connections == 0
        # The first (GCM) discovery attempt times out and aborts the job, so the
        # generic RSA fallback is never reached: exactly one discovery per job.
        assert server_double.rsa_discovery_connections == RobotImplementation._TEST_ATTEMPTS_NB
        assert all(
            cipher_string == "AES128-GCM-SHA256:AES256-GCM-SHA384"
            for cipher_string in server_double.cipher_strings_used
        )

    def test_failed_jobs_propagate_as_errors_not_as_a_safe_verdict(self) -> None:
        # Through the full scan_server() aggregation path, a hard failure while
        # discovering RSA parameters must surface as an error. It must never be
        # collapsed into NOT_VULNERABLE / a strong-oracle verdict.
        with RobotServerDouble(
            behaviors={}, rsa_handshake_behavior=_HardDiscoveryFailure()
        ) as server_double:
            with pytest.raises(TlsHandshakeTimedOut):
                RobotImplementation.scan_server(server_double.server_info)

        assert server_double.robot_connections == 0
        assert server_double.rsa_discovery_connections == RobotImplementation._TEST_ATTEMPTS_NB
