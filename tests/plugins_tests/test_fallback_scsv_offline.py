"""Offline, deterministic tests for the TLS_FALLBACK_SCSV plugin.

These tests reproduce handshake sequences a real server could produce (a support matrix) without any network
access, by scripting a fake TLS connection layer. They focus on the requirement that a plain connection failure
must never be turned into a definitive "secure" conclusion, and that the report must state which evidence is
missing when the test is inconclusive.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest
from nassl import _nassl

from sslyze.errors import (
    ConnectionToServerFailed,
    ServerRejectedTlsHandshake,
    TlsHandshakeTimedOut,
)
from sslyze.plugins.fallback_scsv_plugin import (
    FallbackScsvConclusionEnum,
    FallbackScsvHandshakeOutcomeEnum,
    FallbackScsvImplementation,
    FallbackScsvInconclusiveReasonEnum,
    FallbackScsvScanResultAsJson,
)
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


# ----------------------------------------------------------------------------------
# Scripted fake TLS connection: reproduces a server support matrix through handshakes
# ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class ScriptedHandshakeReaction:
    """What a scripted server does for a given (attempted TLS version, SCSV enabled) pair."""

    raises: Optional[Exception] = None
    completes: bool = False


@dataclass
class _FakeLegacySslClient:
    reaction_lookup: Dict[Tuple[TlsVersionEnum, bool], ScriptedHandshakeReaction]
    tls_version: TlsVersionEnum
    calls: List[Tuple[TlsVersionEnum, bool]] = field(default_factory=list)
    scsv_enabled: bool = False

    def enable_fallback_scsv(self) -> None:
        self.scsv_enabled = True

    def do_handshake(self) -> None:
        key = (self.tls_version, self.scsv_enabled)
        self.calls.append(key)
        reaction = self.reaction_lookup[key]
        if reaction.raises is not None:
            raise reaction.raises
        assert reaction.completes

    def shutdown(self) -> None:
        pass


@dataclass
class _FakeSslConnection:
    reaction_lookup: Dict[Tuple[TlsVersionEnum, bool], ScriptedHandshakeReaction]
    tls_version: TlsVersionEnum
    ssl_client: _FakeLegacySslClient

    @classmethod
    def factory(
        cls,
        reaction_lookup: Dict[Tuple[TlsVersionEnum, bool], ScriptedHandshakeReaction],
        recorded_clients: List[_FakeLegacySslClient],
    ):
        def _create(*args, **kwargs):
            assert kwargs["should_use_legacy_openssl"] is True
            tls_version = kwargs["override_tls_version"]
            ssl_client = _FakeLegacySslClient(
                reaction_lookup=reaction_lookup,
                tls_version=tls_version,
            )
            recorded_clients.append(ssl_client)
            return cls(
                reaction_lookup=reaction_lookup,
                tls_version=tls_version,
                ssl_client=ssl_client,
            )

        return _create

    def connect(self) -> None:
        self.ssl_client.do_handshake()

    def close(self) -> None:
        self.ssl_client.shutdown()


def _server_info(highest_version: TlsVersionEnum) -> ServerConnectivityInfo:
    location = ServerNetworkLocation(hostname="example.test", port=443, ip_address="10.0.0.1")
    configuration = ServerNetworkConfiguration(tls_server_name_indication="example.test")
    probing_result = ServerTlsProbingResult(
        highest_tls_version_supported=highest_version,
        cipher_suite_supported="AES128-SHA",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=False,
    )
    return ServerConnectivityInfo(
        server_location=location,
        network_configuration=configuration,
        tls_probing_result=probing_result,
    )


def _run_plugin(
    mocker,
    highest_version: TlsVersionEnum,
    reaction_lookup: Dict[Tuple[TlsVersionEnum, bool], ScriptedHandshakeReaction],
):
    recorded_clients: List[_FakeLegacySslClient] = []
    server_info = _server_info(highest_version)
    # ServerConnectivityInfo is a frozen dataclass, so the connection factory is patched at module level
    mocker.patch(
        "sslyze.plugins.fallback_scsv_plugin.ServerConnectivityInfo.get_preconfigured_tls_connection",
        side_effect=_FakeSslConnection.factory(reaction_lookup, recorded_clients),
    )

    result = FallbackScsvImplementation.scan_server(server_info)

    # The plugin must always enable SCSV on exactly one of the two handshakes and never on the baseline
    if recorded_clients:
        scsv_flags = [client.scsv_enabled for client in recorded_clients]
        assert scsv_flags == [False, True]
    return result, recorded_clients


def _rejected_handshake(message: str) -> ServerRejectedTlsHandshake:
    location = ServerNetworkLocation(hostname="example.test", port=443, ip_address="10.0.0.1")
    configuration = ServerNetworkConfiguration(tls_server_name_indication="example.test")
    return ServerRejectedTlsHandshake(
        server_location=location,
        network_configuration=configuration,
        error_message=message,
    )


def _timed_out_handshake() -> TlsHandshakeTimedOut:
    location = ServerNetworkLocation(hostname="example.test", port=443, ip_address="10.0.0.1")
    configuration = ServerNetworkConfiguration(tls_server_name_indication="example.test")
    return TlsHandshakeTimedOut(
        server_location=location,
        network_configuration=configuration,
        error_message="Connection to server timed out during the TLS handshake",
    )


def _interrupted_connection() -> ConnectionToServerFailed:
    location = ServerNetworkLocation(hostname="example.test", port=443, ip_address="10.0.0.1")
    configuration = ServerNetworkConfiguration(tls_server_name_indication="example.test")
    return ConnectionToServerFailed(
        server_location=location,
        network_configuration=configuration,
        error_message="Server interrupted the TLS handshake",
    )


INAPPROPRIATE_FALLBACK = _nassl.OpenSSLError("tlsv1 alert inappropriate fallback")
PROTOCOL_VERSION_REJECTION = _rejected_handshake("TLS alert: protocol version ")


# ----------------------------------------------------------------------------------
# A realistic support matrix, replayed through the full plugin (plugin result -> report)
# ----------------------------------------------------------------------------------


class TestFallbackScsvSupportMatrix:
    def test_modern_server_enforces_scsv(self, mocker) -> None:
        # Support matrix of a modern server (TLS 1.2 highest): both TLS 1.1 handshakes are accepted without SCSV,
        # but the SCSV-signaled fallback attempt is rejected with the RFC 7507 alert
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(completes=True),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(raises=INAPPROPRIATE_FALLBACK),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        # Plugin result
        assert result.conclusion == FallbackScsvConclusionEnum.SUPPORTED
        assert result.supports_fallback_scsv is True
        assert result.inconclusive_reason is None
        self._assert_observations_match_matrix(result, reaction_lookup)

        # Report (CLI) mapping
        console_output = FallbackScsvImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("OK - Supported" in line for line in console_output)
        assert any("REJECTED_INAPPROPRIATE_FALLBACK" in line for line in console_output)
        assert any("SCSV enabled" in line for line in console_output)

        # Report (JSON) mapping
        json_output = FallbackScsvScanResultAsJson.model_validate(result).model_dump_json()
        assert '"conclusion":"SUPPORTED"' in json_output
        assert '"supports_fallback_scsv":true' in json_output
        assert FallbackScsvScanResultAsJson.model_validate_json(json_output)

    def test_legacy_server_ignores_scsv(self, mocker) -> None:
        # Support matrix of a vulnerable legacy server: TLS 1.1 completes whether or not SCSV is signaled
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(completes=True),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(completes=True),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        assert result.conclusion == FallbackScsvConclusionEnum.NOT_SUPPORTED
        assert result.supports_fallback_scsv is False
        assert result.inconclusive_reason is None
        assert result.downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.COMPLETED
        assert result.downgrade_observation.negotiated_tls_version == TlsVersionEnum.TLS_1_1
        self._assert_observations_match_matrix(result, reaction_lookup)

        console_output = FallbackScsvImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("VULNERABLE - Signaling cipher suite not supported" in line for line in console_output)

    def test_tls_13_server_uses_tls_12_as_baseline(self, mocker) -> None:
        # A TLS 1.3 server is tested on TLS 1.2 (downgrade to TLS 1.1): SCSV enforced at the lower version
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(completes=True),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(raises=INAPPROPRIATE_FALLBACK),
        }

        result, recorded_clients = _run_plugin(mocker, TlsVersionEnum.TLS_1_3, reaction_lookup)

        # Both handshakes were attempted at the version below the TLS 1.2 cap
        assert {client.tls_version for client in recorded_clients} == {TlsVersionEnum.TLS_1_1}
        assert result.conclusion == FallbackScsvConclusionEnum.SUPPORTED

    def test_narrow_server_does_not_support_downgrade_version(self, mocker) -> None:
        # Support matrix of a server that only supports TLS 1.2: the lower TLS 1.1 version is rejected even
        # without SCSV, so the downgrade premise cannot be established
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(raises=PROTOCOL_VERSION_REJECTION),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(raises=PROTOCOL_VERSION_REJECTION),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        assert result.conclusion == FallbackScsvConclusionEnum.INCONCLUSIVE
        assert result.supports_fallback_scsv is None
        assert result.inconclusive_reason == FallbackScsvInconclusiveReasonEnum.LOWER_VERSION_NOT_SUPPORTED
        assert result.baseline_observation.outcome == FallbackScsvHandshakeOutcomeEnum.REJECTED_OTHER_ALERT
        assert "protocol version" in result.baseline_observation.alert_or_error

        console_output = FallbackScsvImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("UNKNOWN" in line and "LOWER_VERSION_NOT_SUPPORTED" in line for line in console_output)

    @staticmethod
    def _assert_observations_match_matrix(result, reaction_lookup) -> None:
        for observation in [result.baseline_observation, result.downgrade_observation]:
            key = (observation.tls_version_attempted, observation.scsv_enabled)
            reaction = reaction_lookup[key]
            if reaction.completes:
                assert observation.outcome == FallbackScsvHandshakeOutcomeEnum.COMPLETED
                assert observation.negotiated_tls_version == observation.tls_version_attempted
            else:
                assert observation.outcome != FallbackScsvHandshakeOutcomeEnum.COMPLETED
                assert observation.negotiated_tls_version is None
                assert observation.alert_or_error


# ----------------------------------------------------------------------------------
# Two incomplete observations: transport failures cannot prove SCSV support or absence
# ----------------------------------------------------------------------------------


class TestFallbackScsvIncompleteObservations:
    def test_downgrade_attempt_times_out_is_inconclusive(self, mocker) -> None:
        # First incomplete observation: the baseline works, but the SCSV-signaled attempt times out (CloudFront-style
        # behavior on unsupported versions). A timeout is not the RFC 7507 alert and proves nothing.
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(completes=True),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(raises=_timed_out_handshake()),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        assert result.conclusion == FallbackScsvConclusionEnum.INCONCLUSIVE
        assert result.supports_fallback_scsv is None
        assert result.inconclusive_reason == FallbackScsvInconclusiveReasonEnum.DOWNGRADE_TIMED_OUT
        assert result.downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.TIMED_OUT
        assert result.downgrade_observation.alert_or_error

        console_output = FallbackScsvImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("UNKNOWN" in line for line in console_output)
        assert any("TIMED_OUT" in line for line in console_output)

        json_output = FallbackScsvScanResultAsJson.model_validate(result).model_dump_json()
        assert '"conclusion":"INCONCLUSIVE"' in json_output
        assert '"supports_fallback_scsv":null' in json_output
        assert '"inconclusive_reason":"DOWNGRADE_TIMED_OUT"' in json_output

    def test_connection_interrupted_is_inconclusive(self, mocker) -> None:
        # Second incomplete observation: the peer resets/closes the connection during the SCSV-signaled attempt
        # without sending any TLS alert. A plain transport failure can neither prove nor disprove SCSV protection.
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(completes=True),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(raises=_interrupted_connection()),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        assert result.conclusion == FallbackScsvConclusionEnum.INCONCLUSIVE
        assert result.supports_fallback_scsv is None
        assert result.inconclusive_reason == FallbackScsvInconclusiveReasonEnum.DOWNGRADE_CONNECTION_INTERRUPTED
        assert result.downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.CONNECTION_INTERRUPTED
        assert result.downgrade_observation.alert_or_error

        console_output = FallbackScsvImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("UNKNOWN" in line and "DOWNGRADE_CONNECTION_INTERRUPTED" in line for line in console_output)

    def test_baseline_transport_failure_is_inconclusive(self, mocker) -> None:
        # The baseline itself cannot be established: nothing can be said about downgrade protection at all
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(raises=_interrupted_connection()),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(raises=_interrupted_connection()),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        assert result.conclusion == FallbackScsvConclusionEnum.INCONCLUSIVE
        assert result.supports_fallback_scsv is None
        assert result.inconclusive_reason == FallbackScsvInconclusiveReasonEnum.BASELINE_CONNECTION_INTERRUPTED

    def test_other_alert_on_downgrade_is_inconclusive(self, mocker) -> None:
        # A generic handshake_failure alert on the SCSV attempt is not the specific "inappropriate fallback" alert
        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(completes=True),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(
                raises=_rejected_handshake("TLS alert: handshake failure")
            ),
        }

        result, _ = _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)

        assert result.conclusion == FallbackScsvConclusionEnum.INCONCLUSIVE
        assert result.inconclusive_reason == FallbackScsvInconclusiveReasonEnum.DOWNGRADE_REJECTED_WITH_OTHER_ALERT
        assert result.downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.REJECTED_OTHER_ALERT

    def test_no_lower_version_available_is_inconclusive(self, mocker) -> None:
        # Highest version is TLS 1.0: the legacy client cannot test a lower version, so the premise is missing
        reaction_lookup: Dict[Tuple[TlsVersionEnum, bool], ScriptedHandshakeReaction] = {}

        result, recorded_clients = _run_plugin(mocker, TlsVersionEnum.TLS_1_0, reaction_lookup)

        assert recorded_clients == []
        assert result.conclusion == FallbackScsvConclusionEnum.INCONCLUSIVE
        assert result.inconclusive_reason == FallbackScsvInconclusiveReasonEnum.NO_LOWER_TLS_VERSION_AVAILABLE
        assert result.baseline_observation.outcome == FallbackScsvHandshakeOutcomeEnum.NOT_ATTEMPTED
        assert result.downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.NOT_ATTEMPTED


class TestUnexpectedExceptionsAreNotSwallowed:
    def test_client_certificate_requested_propagates(self, mocker) -> None:
        # Exceptions that are not part of the modeled transport/TLS outcomes must surface instead of being
        # silently turned into a (possibly "secure") conclusion
        from nassl.ssl_client import ClientCertificateRequested

        reaction_lookup = {
            (TlsVersionEnum.TLS_1_1, False): ScriptedHandshakeReaction(raises=ClientCertificateRequested(ca_list=[])),
            (TlsVersionEnum.TLS_1_1, True): ScriptedHandshakeReaction(completes=True),
        }

        with pytest.raises(ClientCertificateRequested):
            _run_plugin(mocker, TlsVersionEnum.TLS_1_2, reaction_lookup)
