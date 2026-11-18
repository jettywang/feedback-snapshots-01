import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from sslyze import TlsResumptionSupportEnum
from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.plugins.plugin_base import ScanJobResult
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportImplementation,
    SessionResumptionSupportScanResult,
    SessionResumptionSupportExtraArgument,
)
from sslyze.plugins.session_resumption._resumption_with_id import (
    ResumptionAttemptEvidence,
    ResumptionAttemptOutcomeEnum,
    ResumptionMechanismEnum,
    ServerOnlySupportsTls13,
    resume_with_session_id,
)
from sslyze.plugins.session_resumption.json_output import SessionResumptionSupportScanResultAsJson
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


def _make_server_info(hostname: str, ip_address: str) -> ServerConnectivityInfo:
    return ServerConnectivityInfo(
        server_location=ServerNetworkLocation(hostname=hostname, ip_address=ip_address, port=443),
        network_configuration=ServerNetworkConfiguration(tls_server_name_indication=hostname),
        tls_probing_result=ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
            cipher_suite_supported="AES",
            client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            supports_ecdh_key_exchange=True,
        ),
    )


class _FakeSslSession:
    """Stands in for nassl's SSL_SESSION; only as_text() is used by the resumption plugin."""

    def __init__(self, session_id: Optional[str], tls_ticket: Optional[str]):
        self._session_id = session_id
        self._tls_ticket = tls_ticket

    def as_text(self) -> str:
        sections = []
        if self._session_id is not None:
            sections.append(f"Session-ID: {self._session_id}\nSession-ID-ctx: ctx")
        if self._tls_ticket is not None:
            sections.append(f"TLS session ticket: {self._tls_ticket}\nCompression: none")
        return "\n".join(sections)


class _TargetStandIn:
    """Simulates the TLS stack of one specific server.

    It issues its own sessions on initial connections and only resumes sessions it issued itself;
    a session presented by another target triggers a full handshake with fresh material.
    """

    def __init__(
        self,
        hostname: str,
        session_id: Optional[str] = "session-id",
        tls_ticket: Optional[str] = "tls-ticket",
        should_resume_own_sessions: bool = True,
        initial_handshake_barrier: Optional[threading.Barrier] = None,
        should_fail_initial_handshake: bool = False,
        should_fail_resumption_handshake: bool = False,
        shared_handshake_log: Optional[List[Tuple[str, bool]]] = None,
    ):
        self.hostname = hostname
        self._session_id = session_id
        self._tls_ticket = tls_ticket
        self._should_resume_own_sessions = should_resume_own_sessions
        self._initial_handshake_barrier = initial_handshake_barrier
        self._should_fail_initial_handshake = should_fail_initial_handshake
        self._should_fail_resumption_handshake = should_fail_resumption_handshake
        self._shared_handshake_log = shared_handshake_log
        self.issued_sessions: List[_FakeSslSession] = []
        self._lock = threading.Lock()

    def connect(
        self,
        server_info: ServerConnectivityInfo,
        session_to_resume: Optional[_FakeSslSession] = None,
        should_enable_tls_ticket: bool = False,
    ) -> _FakeSslSession:
        assert server_info.server_location.hostname == self.hostname
        is_resumption = session_to_resume is not None
        if self._shared_handshake_log is not None:
            with self._lock:
                self._shared_handshake_log.append((self.hostname, is_resumption))

        if not is_resumption and self._initial_handshake_barrier is not None:
            # Hold every initial handshake until all targets have started theirs, to force interleaving
            self._initial_handshake_barrier.wait(timeout=30)

        if not is_resumption and self._should_fail_initial_handshake:
            raise ServerRejectedTlsHandshake(
                server_location=server_info.server_location,
                network_configuration=server_info.network_configuration,
                error_message="Server rejected the initial handshake",
            )
        if is_resumption and self._should_fail_resumption_handshake:
            raise ServerRejectedTlsHandshake(
                server_location=server_info.server_location,
                network_configuration=server_info.network_configuration,
                error_message="Server rejected the resumption handshake",
            )

        if not is_resumption:
            new_session = _FakeSslSession(session_id=self._session_id, tls_ticket=self._tls_ticket)
            with self._lock:
                self.issued_sessions.append(new_session)
            return new_session

        with self._lock:
            is_own_session = session_to_resume in self.issued_sessions
        if is_own_session and self._should_resume_own_sessions:
            # The server recognized its own session and resumed it
            return session_to_resume

        # The server does not recognize the session: full re-handshake with fresh material
        return _FakeSslSession(
            session_id=f"{self._session_id}-fresh" if self._session_id is not None else None,
            tls_ticket=f"{self._tls_ticket}-fresh" if self._tls_ticket is not None else None,
        )


def _patch_connections(mocker, stand_ins: Dict[str, _TargetStandIn]) -> None:
    def _dispatch(
        server_info: ServerConnectivityInfo,
        session_to_resume: Optional[_FakeSslSession] = None,
        should_enable_tls_ticket: bool = False,
    ) -> _FakeSslSession:
        hostname = server_info.server_location.hostname
        return stand_ins[hostname].connect(
            server_info, session_to_resume=session_to_resume, should_enable_tls_ticket=should_enable_tls_ticket
        )

    mocker.patch("sslyze.plugins.session_resumption._resumption_with_id.retrieve_tls_session", _dispatch)
    mocker.patch("sslyze.plugins.session_resumption._resumption_with_ticket.retrieve_tls_session", _dispatch)


def _run_jobs_interleaved(jobs_per_target: Dict[str, list]) -> Dict[str, List[ScanJobResult]]:
    """Run all targets' scan jobs concurrently and collect the results in actual completion order."""
    results_per_target: Dict[str, List[ScanJobResult]] = {hostname: [] for hostname in jobs_per_target}
    with ThreadPoolExecutor(max_workers=8) as thread_pool:
        future_to_hostname = {}
        for hostname, jobs in jobs_per_target.items():
            for job in jobs:
                future = thread_pool.submit(job.function_to_call, *job.function_arguments)
                future_to_hostname[future] = hostname
        for future in as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            try:
                job_result = ScanJobResult(_return_value=future.result(), _exception=None)
            except Exception as e:
                job_result = ScanJobResult(_return_value=None, _exception=e)
            results_per_target[hostname].append(job_result)
    return results_per_target


class TestResumptionAttemptEvidence:
    def test_attempts_are_attributed_to_their_own_target_despite_interleaved_completion(self, mocker) -> None:
        # Given two similarly-configured targets (same port and TLS configuration, different hostname/SNI/IP)
        info_alpha = _make_server_info("alpha.test", "10.0.0.1")
        info_beta = _make_server_info("beta.test", "10.0.0.2")
        attempts_count = 2
        extra_arg = SessionResumptionSupportExtraArgument(number_of_resumptions_to_attempt=attempts_count)

        # And connection stand-ins whose initial handshakes all complete before any resumption starts,
        # so that the two targets' connections are guaranteed to complete interleaved
        jobs_count_per_target = attempts_count * 2
        initial_handshake_barrier = threading.Barrier(jobs_count_per_target * 2)
        shared_handshake_log: List[Tuple[str, bool]] = []
        stand_in_alpha = _TargetStandIn(
            "alpha.test",
            session_id="sid-issued-by-alpha",
            tls_ticket="ticket-issued-by-alpha",
            initial_handshake_barrier=initial_handshake_barrier,
            shared_handshake_log=shared_handshake_log,
        )
        stand_in_beta = _TargetStandIn(
            "beta.test",
            session_id="sid-issued-by-beta",
            tls_ticket="ticket-issued-by-beta",
            initial_handshake_barrier=initial_handshake_barrier,
            shared_handshake_log=shared_handshake_log,
        )
        _patch_connections(mocker, {"alpha.test": stand_in_alpha, "beta.test": stand_in_beta})

        # When running both targets' scan jobs concurrently, with results collected in completion order
        jobs_per_target = {
            "alpha.test": SessionResumptionSupportImplementation.scan_jobs_for_scan_command(info_alpha, extra_arg),
            "beta.test": SessionResumptionSupportImplementation.scan_jobs_for_scan_command(info_beta, extra_arg),
        }
        results_per_target = _run_jobs_interleaved(jobs_per_target)

        # Then the connections did interleave: every initial handshake (from both targets) happened
        # before any resumption handshake
        total_jobs_count = jobs_count_per_target * 2
        assert len(shared_handshake_log) == total_jobs_count * 2
        first_half = shared_handshake_log[:total_jobs_count]
        second_half = shared_handshake_log[total_jobs_count:]
        assert all(not is_resumption for _, is_resumption in first_half)
        assert all(is_resumption for _, is_resumption in second_half)
        assert {hostname for hostname, _ in first_half} == {"alpha.test", "beta.test"}

        # And each target's result only contains evidence attributed to that target
        result_alpha = SessionResumptionSupportImplementation.result_for_completed_scan_jobs(
            info_alpha, results_per_target["alpha.test"]
        )
        result_beta = SessionResumptionSupportImplementation.result_for_completed_scan_jobs(
            info_beta, results_per_target["beta.test"]
        )

        for result, hostname, ip_address in [
            (result_alpha, "alpha.test", "10.0.0.1"),
            (result_beta, "beta.test", "10.0.0.2"),
        ]:
            assert result.session_id_resumption_result == TlsResumptionSupportEnum.FULLY_SUPPORTED
            assert result.session_id_attempted_resumptions_count == attempts_count
            assert result.session_id_successful_resumptions_count == attempts_count
            assert result.tls_ticket_resumption_result == TlsResumptionSupportEnum.FULLY_SUPPORTED
            assert result.tls_ticket_attempted_resumptions_count == attempts_count
            assert result.tls_ticket_successful_resumptions_count == attempts_count

            assert len(result.session_id_attempts) == attempts_count
            assert len(result.tls_ticket_attempts) == attempts_count
            for attempt in (*result.session_id_attempts, *result.tls_ticket_attempts):
                # The evidence records exactly where the initial session came from and how it was obtained
                assert attempt.server_hostname == hostname
                assert attempt.server_port == 443
                assert attempt.server_ip_address == ip_address
                assert attempt.tls_server_name_indication == hostname
                assert attempt.tls_version_used == TlsVersionEnum.TLS_1_2
                assert attempt.outcome == ResumptionAttemptOutcomeEnum.RESUMED
                # The initial session was verifiably resumed: both fingerprints match
                assert attempt.initial_session_fingerprint is not None
                assert attempt.initial_session_fingerprint == attempt.resumed_session_fingerprint

        # And the session ID evidence of each target matches its own session material, not the other target's
        expected_alpha_fingerprint = hashlib.sha256(b"sid-issued-by-alpha").hexdigest()
        expected_beta_fingerprint = hashlib.sha256(b"sid-issued-by-beta").hexdigest()
        for attempt in result_alpha.session_id_attempts:
            assert attempt.initial_session_fingerprint == expected_alpha_fingerprint
        for attempt in result_beta.session_id_attempts:
            assert attempt.initial_session_fingerprint == expected_beta_fingerprint

    def test_session_issued_by_one_target_cannot_be_resumed_on_another(self, mocker) -> None:
        # Given two similarly-configured targets
        info_alpha = _make_server_info("alpha.test", "10.0.0.1")
        info_beta = _make_server_info("beta.test", "10.0.0.2")
        stand_in_alpha = _TargetStandIn("alpha.test", session_id="sid-issued-by-alpha")
        stand_in_beta = _TargetStandIn("beta.test", session_id="sid-issued-by-beta")

        # And a mix-up where beta's resumption attempt starts from the session issued by alpha
        session_issued_by_alpha = stand_in_alpha.connect(info_alpha)

        def _mixup_dispatch(
            server_info: ServerConnectivityInfo,
            session_to_resume: Optional[_FakeSslSession] = None,
            should_enable_tls_ticket: bool = False,
        ) -> _FakeSslSession:
            if server_info.server_location.hostname == "beta.test" and session_to_resume is None:
                return session_issued_by_alpha
            return stand_in_beta.connect(
                server_info, session_to_resume=session_to_resume, should_enable_tls_ticket=should_enable_tls_ticket
            )

        mocker.patch("sslyze.plugins.session_resumption._resumption_with_id.retrieve_tls_session", _mixup_dispatch)

        # When a resumption attempt runs on beta with alpha's initial session
        _, attempt = resume_with_session_id(info_beta)

        # Then it is NOT reported as a successful resumption: beta did a full re-handshake
        assert attempt.outcome == ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE
        # And the evidence is still attributed to beta, where the attempt actually ran
        assert attempt.server_hostname == "beta.test"
        assert attempt.initial_session_fingerprint == hashlib.sha256(b"sid-issued-by-alpha").hexdigest()
        assert attempt.resumed_session_fingerprint == hashlib.sha256(b"sid-issued-by-beta-fresh").hexdigest()
        assert attempt.initial_session_fingerprint != attempt.resumed_session_fingerprint

    def test_outcome_full_rehandshake_when_server_ignores_the_session(self, mocker) -> None:
        # Given a server that never resumes sessions and always performs a full handshake
        info = _make_server_info("noresume.test", "10.0.0.3")
        stand_in = _TargetStandIn("noresume.test", should_resume_own_sessions=False)
        _patch_connections(mocker, {"noresume.test": stand_in})
        extra_arg = SessionResumptionSupportExtraArgument(number_of_resumptions_to_attempt=2)

        # When testing for resumption
        result = SessionResumptionSupportImplementation.scan_server(info, extra_arguments=extra_arg)

        # Then every attempt is individually reported as a full re-handshake, not a resumption
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.NOT_SUPPORTED
        assert result.session_id_attempted_resumptions_count == 2
        assert result.session_id_successful_resumptions_count == 0
        for attempt in result.session_id_attempts:
            assert attempt.outcome == ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE
            assert attempt.initial_session_fingerprint is not None
            assert attempt.resumed_session_fingerprint is not None
            assert attempt.initial_session_fingerprint != attempt.resumed_session_fingerprint

    def test_outcome_initial_handshake_failed(self, mocker) -> None:
        # Given a server that rejects the very first handshake
        info = _make_server_info("rejecting.test", "10.0.0.4")
        stand_in = _TargetStandIn("rejecting.test", should_fail_initial_handshake=True)
        _patch_connections(mocker, {"rejecting.test": stand_in})
        extra_arg = SessionResumptionSupportExtraArgument(number_of_resumptions_to_attempt=1)

        # When testing for resumption
        result = SessionResumptionSupportImplementation.scan_server(info, extra_arguments=extra_arg)

        # Then the attempt is reported as incomplete because the initial handshake failed
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.NOT_SUPPORTED
        assert result.session_id_attempted_resumptions_count == 1
        assert result.session_id_successful_resumptions_count == 0
        (attempt,) = result.session_id_attempts
        assert attempt.outcome == ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED
        assert attempt.error_message is not None
        assert "Server rejected the initial handshake" in attempt.error_message
        assert attempt.initial_session_fingerprint is None

    def test_outcome_resumption_handshake_failed(self, mocker) -> None:
        # Given a server that accepts the initial handshake but rejects the resumption handshake
        info = _make_server_info("flaky.test", "10.0.0.5")
        stand_in = _TargetStandIn("flaky.test", should_fail_resumption_handshake=True)
        _patch_connections(mocker, {"flaky.test": stand_in})
        extra_arg = SessionResumptionSupportExtraArgument(number_of_resumptions_to_attempt=1)

        # When testing for resumption
        result = SessionResumptionSupportImplementation.scan_server(info, extra_arguments=extra_arg)

        # Then the attempt is reported as incomplete because the resumption handshake failed
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.NOT_SUPPORTED
        (attempt,) = result.session_id_attempts
        assert attempt.outcome == ResumptionAttemptOutcomeEnum.RESUMPTION_HANDSHAKE_FAILED
        assert attempt.error_message is not None
        assert "Server rejected the resumption handshake" in attempt.error_message
        # And the initial session was still obtained and fingerprinted before the failure
        assert attempt.initial_session_fingerprint == hashlib.sha256(b"session-id").hexdigest()
        assert attempt.resumed_session_fingerprint is None

    def test_outcome_no_session_assigned(self, mocker) -> None:
        # Given a server that does not assign any session ID
        info = _make_server_info("nosession.test", "10.0.0.6")
        stand_in = _TargetStandIn("nosession.test", session_id="")
        _patch_connections(mocker, {"nosession.test": stand_in})
        extra_arg = SessionResumptionSupportExtraArgument(number_of_resumptions_to_attempt=1)

        # When testing for resumption
        result = SessionResumptionSupportImplementation.scan_server(info, extra_arguments=extra_arg)

        # Then the attempt is reported as not resumable because no session was assigned
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.NOT_SUPPORTED
        (attempt,) = result.session_id_attempts
        assert attempt.outcome == ResumptionAttemptOutcomeEnum.NO_SESSION_ASSIGNED
        assert attempt.initial_session_fingerprint is None

    def test_server_only_supports_tls_1_3(self, mocker) -> None:
        # Given a server that only supports TLS 1.3
        info = _make_server_info("tls13.test", "10.0.0.7")

        def _tls_13_only(*args, **kwargs):
            raise ServerOnlySupportsTls13()

        mocker.patch("sslyze.plugins.session_resumption._resumption_with_id.retrieve_tls_session", _tls_13_only)
        mocker.patch("sslyze.plugins.session_resumption._resumption_with_ticket.retrieve_tls_session", _tls_13_only)

        # When testing for resumption
        result = SessionResumptionSupportImplementation.scan_server(info)

        # Then the previous behavior is preserved and no attempt evidence is produced
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.SERVER_IS_TLS_1_3_ONLY
        assert result.tls_ticket_resumption_result == TlsResumptionSupportEnum.SERVER_IS_TLS_1_3_ONLY
        assert result.session_id_attempts == ()
        assert result.tls_ticket_attempts == ()

    def test_console_output_explains_each_attempt(self) -> None:
        # Given a result with a mix of successful, failed and incomplete attempts
        attempts = tuple(
            ResumptionAttemptEvidence(
                mechanism=ResumptionMechanismEnum.SESSION_ID,
                server_hostname="alpha.test",
                server_port=443,
                server_ip_address="10.0.0.1",
                tls_server_name_indication="alpha.test",
                tls_version_used=TlsVersionEnum.TLS_1_2,
                outcome=outcome,
                initial_session_fingerprint=None
                if outcome == ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED
                else "a" * 64,
                resumed_session_fingerprint="a" * 64 if outcome == ResumptionAttemptOutcomeEnum.RESUMED else None,
                error_message="boom" if outcome == ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED else None,
            )
            for outcome in (
                ResumptionAttemptOutcomeEnum.RESUMED,
                ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE,
                ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED,
            )
        )
        result = SessionResumptionSupportScanResult(
            session_id_resumption_result=TlsResumptionSupportEnum.PARTIALLY_SUPPORTED,
            session_id_attempted_resumptions_count=3,
            session_id_successful_resumptions_count=1,
            tls_ticket_resumption_result=TlsResumptionSupportEnum.NOT_SUPPORTED,
            tls_ticket_attempted_resumptions_count=0,
            tls_ticket_successful_resumptions_count=0,
            session_id_attempts=attempts,
        )

        # When generating the console output
        output_as_txt = "\n".join(
            SessionResumptionSupportImplementation.cli_connector_cls.result_to_console_output(result)
        )

        # Then the support rate is explained attempt by attempt, including the incomplete one
        assert "(1 successful resumptions out of 3 attempts)" in output_as_txt
        assert "#1 alpha.test:443 (SNI: alpha.test, TLS_1_2): RESUMED" in output_as_txt
        assert (
            "#2 alpha.test:443 (SNI: alpha.test, TLS_1_2): NOT RESUMED - the server performed a full handshake"
            in output_as_txt
        )
        assert (
            "#3 alpha.test:443 (SNI: alpha.test, TLS_1_2): INCOMPLETE - the initial handshake failed (boom)"
            in output_as_txt
        )

    def test_json_output_contains_fingerprints_but_no_raw_session_material(self, mocker) -> None:
        # Given a server that supports resumption
        info = _make_server_info("alpha.test", "10.0.0.1")
        stand_in = _TargetStandIn(
            "alpha.test", session_id="raw-sid-must-not-leak", tls_ticket="raw-ticket-must-not-leak"
        )
        _patch_connections(mocker, {"alpha.test": stand_in})
        extra_arg = SessionResumptionSupportExtraArgument(number_of_resumptions_to_attempt=1)

        # When testing for resumption and converting the result to JSON
        result = SessionResumptionSupportImplementation.scan_server(info, extra_arguments=extra_arg)
        result_as_json = SessionResumptionSupportScanResultAsJson.model_validate(result).model_dump_json()

        # Then the evidence is present with one-way fingerprints only
        assert hashlib.sha256(b"raw-sid-must-not-leak").hexdigest() in result_as_json
        # And the raw session ID and raw TLS ticket (which could be replayed) never appear
        assert "raw-sid-must-not-leak" not in result_as_json
        assert "raw-ticket-must-not-leak" not in result_as_json

        # And the JSON can be parsed again
        parsed_result = SessionResumptionSupportScanResultAsJson.model_validate_json(result_as_json)
        assert parsed_result.session_id_attempts[0].outcome == ResumptionAttemptOutcomeEnum.RESUMED
        assert parsed_result.session_id_attempts[0].mechanism == ResumptionMechanismEnum.SESSION_ID
        assert parsed_result.session_id_attempts[0].tls_version_used == "TLS_1_2"
        assert parsed_result.tls_ticket_attempts[0].mechanism == ResumptionMechanismEnum.TLS_TICKET

    def test_json_output_remains_compatible_with_results_without_evidence(self) -> None:
        # Given a result in the previous format, without any attempt evidence
        result_as_json = (
            '{"session_id_resumption_result": "FULLY_SUPPORTED",'
            ' "session_id_attempted_resumptions_count": 5,'
            ' "session_id_successful_resumptions_count": 5,'
            ' "tls_ticket_resumption_result": "NOT_SUPPORTED",'
            ' "tls_ticket_attempted_resumptions_count": 5,'
            ' "tls_ticket_successful_resumptions_count": 0}'
        )

        # When parsing it, it succeeds and the evidence defaults to empty
        parsed_result = SessionResumptionSupportScanResultAsJson.model_validate_json(result_as_json)
        assert parsed_result.session_id_attempts == []
        assert parsed_result.tls_ticket_attempts == []
