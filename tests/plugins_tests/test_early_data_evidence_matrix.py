"""Offline evidence matrix for SSLyze's TLS 1.3 early-data probe.

The real ``_test_early_data_support()`` function is executed against scripted connection
doubles. No DNS lookup, socket, TLS handshake, or application request is performed.

Run it directly to print the matrix::

    .venv/bin/python -m tests.plugins_tests.test_early_data_evidence_matrix

Or run it with pytest::

    .venv/bin/python -m pytest -q tests/plugins_tests/test_early_data_evidence_matrix.py
"""

import json
import queue
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple


from nassl._nassl import OpenSSLError
from nassl.ssl_client import ClientCertificateRequested, OpenSslEarlyDataStatusEnum, SslClient

from sslyze.errors import ConnectionToServerTimedOut, ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.plugins.early_data_plugin import EarlyDataScanResult, EarlyDataScanResultAsJson, _test_early_data_support
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner._jobs_worker_thread import CompletedScanJob
from sslyze.scanner._mass_scanner import _OngoingServerScan, _generate_result_for_completed_server_scan
from sslyze.scanner.models import ServerScanRequest, ServerScanResult
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


SERVER_LOCATION = ServerNetworkLocation(hostname="early-data.invalid", ip_address="192.0.2.1", port=443)
NETWORK_CONFIGURATION = ServerNetworkConfiguration(tls_server_name_indication=SERVER_LOCATION.hostname)
SESSION_MARKER = object()
EARLY_DATA_BYTE = b"E"


@dataclass
class ScriptedConnection:
    """One scripted TLS connection, with all network effects replaced by values or exceptions."""

    connect_error: Optional[BaseException] = None
    read_error: Optional[BaseException] = None
    session: Optional[object] = SESSION_MARKER
    pre_handshake_error: Optional[BaseException] = None
    write_early_data_error: Optional[BaseException] = None
    handshake_error: Optional[BaseException] = None
    early_data_status: OpenSslEarlyDataStatusEnum = OpenSslEarlyDataStatusEnum.NOT_SENT


class ScriptedSslClient(SslClient):
    """A nassl SslClient replacement that records calls instead of touching a socket."""

    def __init__(self, script: ScriptedConnection) -> None:
        self.script = script
        self.writes: List[bytes] = []
        self.read_sizes: List[int] = []
        self.session_returned: Optional[object] = None
        self.get_session_calls = 0
        self.session_set: Optional[object] = None
        self.early_data_writes: List[bytes] = []
        self.handshake_called = False
        self.status_called = False

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def read(self, size: int, handshake_must_be_completed: bool = True) -> bytes:
        self.read_sizes.append(size)
        if self.script.read_error is not None:
            raise self.script.read_error
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    def get_session(self) -> object:
        self.get_session_calls += 1
        self.session_returned = self.script.session
        return self.script.session  # type: ignore[return-value]

    def set_session(self, ssl_session: object) -> None:
        self.session_set = ssl_session

    def write_early_data(self, data: bytes) -> int:
        self.early_data_writes.append(data)
        if self.script.write_early_data_error is not None:
            raise self.script.write_early_data_error
        return len(data)

    def do_handshake(self) -> None:
        self.handshake_called = True
        if self.script.handshake_error is not None:
            raise self.script.handshake_error

    def get_early_data_status(self) -> OpenSslEarlyDataStatusEnum:
        self.status_called = True
        return self.script.early_data_status

    def shutdown(self) -> None:
        pass


class ScriptedTlsConnection:
    """The small part of SslConnection used by the early-data plugin."""

    def __init__(self, script: ScriptedConnection) -> None:
        self.script = script
        self.ssl_client = ScriptedSslClient(script)
        self.connect_called = False
        self.pre_handshake_called = False
        self.closed = False

    def connect(self, should_retry_connection: bool = True) -> None:
        self.connect_called = True
        if self.script.connect_error is not None:
            raise self.script.connect_error

    def _do_pre_handshake(self) -> None:
        self.pre_handshake_called = True
        if self.script.pre_handshake_error is not None:
            raise self.script.pre_handshake_error

    def close(self) -> None:
        self.closed = True


class ScriptedServerInfo:
    def __init__(self, scripts: Tuple[ScriptedConnection, ScriptedConnection]) -> None:
        self.server_location = SERVER_LOCATION
        self.network_configuration = NETWORK_CONFIGURATION
        self._scripts = scripts
        self.connections: List[ScriptedTlsConnection] = []
        self.requested_tls_versions: List[Optional[TlsVersionEnum]] = []

    def get_preconfigured_tls_connection(
        self, override_tls_version: Optional[TlsVersionEnum] = None, **kwargs: object
    ) -> ScriptedTlsConnection:
        self.requested_tls_versions.append(override_tls_version)
        if override_tls_version is not TlsVersionEnum.TLS_1_3:
            raise AssertionError(f"Expected TLS 1.3, got {override_tls_version}")
        connection = ScriptedTlsConnection(self._scripts[len(self.connections)])
        self.connections.append(connection)
        return connection


@dataclass(frozen=True)
class Observation:
    case: str
    plugin_value: Optional[bool]
    error_type: Optional[str]
    attempt_status: str
    error_reason: Optional[str]
    session_obtained: bool
    early_data_write_attempted: bool
    early_data_handshake_attempted: bool
    early_data_status: str
    payloads_written: Tuple[bytes, ...]
    reads_after_early_data: int
    interpretation: str

    @property
    def attempt_result(self) -> str:
        if self.error_reason is not None:
            return f"ERROR ({self.error_reason})"
        if self.attempt_status != "COMPLETED":
            return self.attempt_status
        return f"COMPLETED ({str(self.plugin_value).lower()})"

    def serialized_attempt(self) -> str:
        return json.dumps(
            {
                "status": self.attempt_status,
                "error_reason": self.error_reason,
                "result": {"supports_early_data": self.plugin_value} if self.attempt_status == "COMPLETED" else None,
            },
            sort_keys=True,
        )


@dataclass(frozen=True)
class Case:
    name: str
    scripts: Tuple[ScriptedConnection, ScriptedConnection]
    expected_value: Optional[bool]
    expected_error_type: Optional[type]
    expected_interpretation: str
    expected_session_obtained: bool
    expected_write_attempted: bool
    expected_handshake_attempted: bool
    expected_status: str
    expected_reads_after_early_data: int = 0
    expected_attempt_status: str = "COMPLETED"
    expected_error_reason: Optional[str] = None


def _rejected_handshake() -> ServerRejectedTlsHandshake:
    return ServerRejectedTlsHandshake(
        server_location=SERVER_LOCATION,
        network_configuration=NETWORK_CONFIGURATION,
        error_message="Server rejected TLS 1.3 handshake",
    )


def _handshake_timeout() -> TlsHandshakeTimedOut:
    return TlsHandshakeTimedOut(
        server_location=SERVER_LOCATION,
        network_configuration=NETWORK_CONFIGURATION,
        error_message="TLS handshake timed out",
    )


def _second_connection_timeout() -> ConnectionToServerTimedOut:
    return ConnectionToServerTimedOut(
        server_location=SERVER_LOCATION,
        network_configuration=NETWORK_CONFIGURATION,
        error_message="Second connection timed out",
    )


def _first_connection_timeout() -> ConnectionToServerTimedOut:
    return ConnectionToServerTimedOut(
        server_location=SERVER_LOCATION,
        network_configuration=NETWORK_CONFIGURATION,
        error_message="Connection to the server timed out",
    )


CASES: Tuple[Case, ...] = (
    Case(
        name="tls_1_3_rejected",
        scripts=(ScriptedConnection(connect_error=_rejected_handshake()), ScriptedConnection()),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation=(
            "TLS 1.3 handshake rejected; no early-data attempt; not evidence that early data is disabled"
        ),
        expected_session_obtained=False,
        expected_write_attempted=False,
        expected_handshake_attempted=False,
        expected_status="-",
    ),
    Case(
        name="tls_1_3_handshake_timeout",
        scripts=(ScriptedConnection(connect_error=_handshake_timeout()), ScriptedConnection()),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation=(
            "TLS 1.3 handshake timed out; no early-data attempt; inconclusive, not a negative finding"
        ),
        expected_session_obtained=False,
        expected_write_attempted=False,
        expected_handshake_attempted=False,
        expected_status="-",
    ),
    Case(
        name="http_read_timeout_no_session",
        scripts=(ScriptedConnection(read_error=socket.timeout("read timed out")), ScriptedConnection()),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation=(
            "TLS 1.3 handshake completed but HTTP read timed out before a session was saved; inconclusive"
        ),
        expected_session_obtained=False,
        expected_write_attempted=False,
        expected_handshake_attempted=False,
        expected_status="-",
    ),
    Case(
        name="first_connection_timeout",
        scripts=(ScriptedConnection(connect_error=_first_connection_timeout()), ScriptedConnection()),
        expected_value=None,
        expected_error_type=ConnectionToServerTimedOut,
        expected_interpretation=(
            "First connection timed out before TLS 1.3; scan attempt is ERROR, unlike the plugin's own read timeout"
        ),
        expected_session_obtained=False,
        expected_write_attempted=False,
        expected_handshake_attempted=False,
        expected_status="-",
        expected_attempt_status="ERROR",
        expected_error_reason="CONNECTIVITY_ISSUE",
    ),
    Case(
        name="no_session_or_ticket",
        scripts=(ScriptedConnection(session=None, read_error=None), ScriptedConnection()),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation=(
            "Full TLS 1.3 exchange succeeded but no resumable session/ticket was returned; no 0-RTT attempted"
        ),
        expected_session_obtained=False,
        expected_write_attempted=False,
        expected_handshake_attempted=False,
        expected_status="-",
    ),
    Case(
        name="write_early_data_refused",
        scripts=(
            ScriptedConnection(),
            ScriptedConnection(write_early_data_error=OpenSSLError("called a function you should not call")),
        ),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation="Session obtained; OpenSSL refused the 0-RTT write before a handshake; maps to False",
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=False,
        expected_status="-",
    ),
    Case(
        name="handshake_rejected_early_data",
        scripts=(
            ScriptedConnection(),
            ScriptedConnection(early_data_status=OpenSslEarlyDataStatusEnum.REJECTED),
        ),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation="One byte of 0-RTT sent and handshake completed, but server reported REJECTED",
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=True,
        expected_status="REJECTED",
    ),
    Case(
        name="early_data_status_not_sent",
        scripts=(
            ScriptedConnection(),
            ScriptedConnection(early_data_status=OpenSslEarlyDataStatusEnum.NOT_SENT),
        ),
        expected_value=False,
        expected_error_type=None,
        expected_interpretation=(
            "Handshake completed but status was NOT_SENT; no acceptance observed, so the result is inconclusive"
        ),
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=True,
        expected_status="NOT_SENT",
    ),
    Case(
        name="early_data_accepted_no_app_observation",
        scripts=(
            ScriptedConnection(),
            ScriptedConnection(early_data_status=OpenSslEarlyDataStatusEnum.ACCEPTED),
        ),
        expected_value=True,
        expected_error_type=None,
        expected_interpretation=(
            "TLS stack accepted one byte b'E'; no HTTP request or response was sent/read in 0-RTT; "
            "app replay unproven"
        ),
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=True,
        expected_status="ACCEPTED",
    ),
    Case(
        name="second_connection_timeout",
        scripts=(ScriptedConnection(), ScriptedConnection(pre_handshake_error=_second_connection_timeout())),
        expected_value=None,
        expected_error_type=ConnectionToServerTimedOut,
        expected_interpretation=(
            "Session obtained but the second connection timed out; scan attempt is ERROR, not False"
        ),
        expected_session_obtained=True,
        expected_write_attempted=False,
        expected_handshake_attempted=False,
        expected_status="-",
        expected_attempt_status="ERROR",
        expected_error_reason="CONNECTIVITY_ISSUE",
    ),
    Case(
        name="second_handshake_timeout",
        scripts=(ScriptedConnection(), ScriptedConnection(handshake_error=_handshake_timeout())),
        expected_value=None,
        expected_error_type=TlsHandshakeTimedOut,
        expected_interpretation=(
            "0-RTT written but the resumed handshake timed out; scan attempt is ERROR, not a rejection"
        ),
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=True,
        expected_status="-",
        expected_attempt_status="ERROR",
        expected_error_reason="CONNECTIVITY_ISSUE",
    ),
    Case(
        name="client_certificate_required",
        scripts=(ScriptedConnection(), ScriptedConnection(handshake_error=ClientCertificateRequested([]))),
        expected_value=None,
        expected_error_type=ClientCertificateRequested,
        expected_interpretation=(
            "Server requested a client certificate; scan attempt is ERROR, so inventory logic does not see False"
        ),
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=True,
        expected_status="-",
        expected_attempt_status="ERROR",
        expected_error_reason="CLIENT_CERTIFICATE_NEEDED",
    ),
    Case(
        name="unexpected_openssl_error",
        scripts=(ScriptedConnection(), ScriptedConnection(write_early_data_error=OpenSSLError("unexpected error"))),
        expected_value=None,
        expected_error_type=OpenSSLError,
        expected_interpretation="Unexpected OpenSSL error propagated; scan attempt is ERROR, not a negative result",
        expected_session_obtained=True,
        expected_write_attempted=True,
        expected_handshake_attempted=False,
        expected_status="-",
        expected_attempt_status="ERROR",
        expected_error_reason="BUG_IN_SSLYZE",
    ),
)


def _as_scan_command_attempt(
    plugin_value: Optional[bool], error: Optional[BaseException]
) -> Tuple[str, Optional[str]]:
    """Run the same result/error classification that the real scanner uses for one completed job."""
    server_scan_request = ServerScanRequest(
        server_location=SERVER_LOCATION,
        network_configuration=NETWORK_CONFIGURATION,
        scan_commands={ScanCommand.TLS_1_3_EARLY_DATA},
    )
    completed_job = CompletedScanJob(
        parent_server_scan_request_uuid=server_scan_request.uuid,
        for_scan_command=ScanCommand.TLS_1_3_EARLY_DATA,
        return_value=plugin_value,
        exception=error,
    )
    ongoing_scan = _OngoingServerScan(
        server_scan_request=server_scan_request,
        server_connectivity_result=ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_3,
            cipher_suite_supported="TLS_AES_256_GCM_SHA384",
            client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            supports_ecdh_key_exchange=True,
        ),
        assigned_queue=queue.Queue(),
        scan_command_errors_during_queuing={},
        queued_scan_jobs_count=1,
        completed_scan_jobs=[completed_job],
    )
    server_scan_result: ServerScanResult = _generate_result_for_completed_server_scan(ongoing_scan)
    assert server_scan_result.scan_result is not None
    attempt = server_scan_result.scan_result.tls_1_3_early_data
    return attempt.status.value, attempt.error_reason.value if attempt.error_reason is not None else None


def run_case(case: Case) -> Observation:
    server_info = ScriptedServerInfo(case.scripts)
    plugin_value: Optional[bool] = None
    error: Optional[BaseException] = None

    try:
        plugin_value = _test_early_data_support(server_info)  # type: ignore[arg-type]
    except BaseException as exc:
        error = exc

    attempt_status, error_reason = _as_scan_command_attempt(plugin_value, error)

    first = server_info.connections[0]
    second = server_info.connections[1] if len(server_info.connections) > 1 else None
    second_client = second.ssl_client if second is not None else None

    if first.ssl_client.writes:
        assert first.ssl_client.writes[0].startswith(b"GET / HTTP/1.1\r\n"), (
            f"The bootstrap request must be ordinary TLS, not early data: {first.ssl_client.writes[0][:40]!r}"
        )
    assert all(version is TlsVersionEnum.TLS_1_3 for version in server_info.requested_tls_versions), (
        server_info.requested_tls_versions
    )

    session_obtained = (
        first.ssl_client.get_session_calls > 0
        and first.ssl_client.session_returned is not None
        and first.script.read_error is None
    )
    early_data_write_attempted = bool(second_client and second_client.early_data_writes)
    early_data_handshake_attempted = bool(second_client and second_client.handshake_called)
    status = "-"
    if second_client is not None and second_client.status_called:
        status = second_client.script.early_data_status.name

    return Observation(
        case=case.name,
        plugin_value=plugin_value,
        error_type=type(error).__name__ if error is not None else None,
        attempt_status=attempt_status,
        error_reason=error_reason,
        session_obtained=session_obtained,
        early_data_write_attempted=early_data_write_attempted,
        early_data_handshake_attempted=early_data_handshake_attempted,
        early_data_status=status,
        payloads_written=tuple(
            [payload for connection in server_info.connections for payload in connection.ssl_client.writes]
            + [payload for connection in server_info.connections for payload in connection.ssl_client.early_data_writes]
        ),
        reads_after_early_data=len(second_client.read_sizes) if second_client is not None else 0,
        interpretation=case.expected_interpretation,
    )


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def print_matrix() -> None:
    observations = [run_case(case) for case in CASES]
    headers = ("case", "session", "0-RTT write", "handshake", "status", "plugin", "attempt", "post-0RTT reads")
    rows = [
        (
            observation.case,
            _yes_no(observation.session_obtained),
            _yes_no(observation.early_data_write_attempted),
            _yes_no(observation.early_data_handshake_attempted),
            observation.early_data_status,
            str(observation.plugin_value).lower() if observation.error_reason is None else "-",
            observation.attempt_result,
            str(observation.reads_after_early_data),
        )
        for observation in observations
    ]
    widths = [max(len(header), *(len(row[index]) for row in rows)) for index, header in enumerate(headers)]
    print(" | ".join(header.ljust(width) for header, width in zip(headers, widths)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(width) for value, width in zip(row, widths)))

    completed = [observation for observation in observations if observation.attempt_status == "COMPLETED"]
    completed_false = [observation for observation in completed if observation.plugin_value is False]
    print(f"\n{len(completed_false)} different causes collapse into the same JSON field:")
    print("  " + completed_false[0].serialized_attempt())
    for observation in completed_false:
        print(f"  - {observation.case}: {observation.interpretation}")
    errored = [observation for observation in observations if observation.attempt_status == "ERROR"]
    print("\nScan failures remain distinguishable only at the attempt level:")
    for observation in errored:
        print(f"  - {observation.case}: {observation.serialized_attempt()}")

    print("\nInterpretation:")
    for observation in observations:
        print(f"- {observation.case}: {observation.interpretation}")


class TestEarlyDataEvidenceMatrix:
    def test_each_double_matches_its_expected_outcome(self) -> None:
        for case in CASES:
            observation = run_case(case)

            assert observation.plugin_value == case.expected_value, case.name
            if case.expected_error_type is None:
                assert observation.error_type is None, case.name
            else:
                assert observation.error_type == case.expected_error_type.__name__, case.name
            assert observation.attempt_status == case.expected_attempt_status, case.name
            assert observation.error_reason == case.expected_error_reason, case.name
            assert observation.session_obtained == case.expected_session_obtained, case.name
            assert observation.early_data_write_attempted == case.expected_write_attempted, case.name
            assert observation.early_data_handshake_attempted == case.expected_handshake_attempted, case.name
            assert observation.early_data_status == case.expected_status, case.name
            assert observation.reads_after_early_data == case.expected_reads_after_early_data, case.name

    def test_plugin_never_sends_a_transaction_or_reads_after_early_data(self) -> None:
        for case in CASES:
            observation = run_case(case)
            assert observation.reads_after_early_data == 0, case.name

            if case.name == "early_data_accepted_no_app_observation":
                assert observation.payloads_written[-1] == EARLY_DATA_BYTE
                assert observation.payloads_written[-1] != b"GET / HTTP/1.1\r\n"

    def test_true_is_tls_acceptance_not_a_replay_finding(self) -> None:
        accepted_case = next(case for case in CASES if case.name == "early_data_accepted_no_app_observation")
        observation = run_case(accepted_case)

        assert observation.plugin_value is True
        assert observation.reads_after_early_data == 0
        assert observation.payloads_written[-1] == EARLY_DATA_BYTE

        result = EarlyDataScanResult(supports_early_data=True)
        result_as_json = EarlyDataScanResultAsJson.model_validate(result).model_dump()
        assert result_as_json == {"supports_early_data": True}


    def test_completed_false_collapses_distinct_causes(self) -> None:
        observations = [run_case(case) for case in CASES]
        completed_false = [
            observation
            for observation in observations
            if observation.attempt_status == "COMPLETED" and observation.plugin_value is False
        ]

        assert len(completed_false) >= 7
        assert len({observation.serialized_attempt() for observation in completed_false}) == 1
        assert {observation.case for observation in completed_false} >= {
            "tls_1_3_rejected",
            "tls_1_3_handshake_timeout",
            "http_read_timeout_no_session",
            "no_session_or_ticket",
            "write_early_data_refused",
            "handshake_rejected_early_data",
            "early_data_status_not_sent",
        }

    def test_scan_failures_are_not_silently_false(self) -> None:
        for name in ("first_connection_timeout", "second_connection_timeout", "second_handshake_timeout"):
            observation = run_case(next(case for case in CASES if case.name == name))
            assert observation.attempt_status == "ERROR"
            assert observation.error_reason == "CONNECTIVITY_ISSUE"
            assert observation.plugin_value is None


if __name__ == "__main__":
    print_matrix()
