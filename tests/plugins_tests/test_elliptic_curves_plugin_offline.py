"""Offline regression tests for the elliptic curves scan command.

These tests replace the network connection with a programmable stand-in, in order to verify that the
curves reported by the scan come from the ECDHE key exchange that actually happened (the ephemeral key
returned by the handshake), and never from the server certificate's public key curve nor from the list
of groups the client itself offered.
"""

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Union
from unittest import mock

import pytest
from nassl._nassl import OpenSSLError
from nassl.ephemeral_key_info import (
    _OPENSSL_NID_TO_SECG_ANSI_X9_62,
    EcDhEphemeralKeyInfo,
    OpenSslEcNidEnum,
    OpenSslEvpPkeyEnum,
)
from nassl.ssl_client import ClientCertificateRequested

from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.plugins import elliptic_curves_plugin
from sslyze.plugins.elliptic_curves_plugin import (
    SupportedEllipticCurvesImplementation,
    SupportedEllipticCurvesScanResult,
    SupportedEllipticCurvesScanResultAsJson,
)
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


def _ephemeral_key_for_curve(curve_nid: OpenSslEcNidEnum) -> EcDhEphemeralKeyInfo:
    """The proof that a curve was really used: the ephemeral key resulting from the ECDHE key exchange."""
    return EcDhEphemeralKeyInfo(
        type=OpenSslEvpPkeyEnum.EC,
        size=256,
        public_bytes=bytearray(b"\x04\x01"),
        curve=curve_nid,
    )


class _SpecialOutcome(Enum):
    CLIENT_CERTIFICATE_REQUESTED = auto()
    SUBSTITUTE_WITH_CERTIFICATE_CURVE = auto()


@dataclass
class _ProgrammableBackend:
    """An independent support matrix: which groups the fake server accepts in the key exchange, per TLS version.

    Because the matrix is keyed by TLS version, any version mix-up in the scanner (e.g. probing a TLS 1.3-only
    group over TLS 1.2) produces a different result and is caught by the tests.
    """

    supported_groups: Dict[TlsVersionEnum, Set[OpenSslEcNidEnum]]
    certificate_curve: OpenSslEcNidEnum
    special_outcomes: Dict[OpenSslEcNidEnum, Union[Exception, _SpecialOutcome]] = field(default_factory=dict)


class _FakeSslClient:
    """Stands in for nassl's SslClient: records what the scanner configured and replays the backend's answers."""

    def __init__(self) -> None:
        self.groups_offered_by_scanner: List[OpenSslEcNidEnum] = []
        self.cipher_list_from_scanner: Optional[str] = None
        self.cipher_suites_from_scanner: Optional[str] = None
        self.negotiated_ephemeral_key: Optional[EcDhEphemeralKeyInfo] = None

    def set_groups(self, groups: List[OpenSslEcNidEnum]) -> None:
        self.groups_offered_by_scanner.extend(groups)

    def set_cipher_list(self, cipher_list: str) -> None:
        self.cipher_list_from_scanner = cipher_list

    def set_ciphersuites(self, cipher_suites: str) -> None:
        self.cipher_suites_from_scanner = cipher_suites

    def get_ephemeral_key(self) -> Optional[EcDhEphemeralKeyInfo]:
        return self.negotiated_ephemeral_key


class _FakeTlsConnection:
    """A programmable stand-in for SslConnection: plays the server side of the handshake, offline."""

    def __init__(
        self,
        backend: _ProgrammableBackend,
        tls_version_requested_by_scanner: Optional[TlsVersionEnum],
        server_info: ServerConnectivityInfo,
    ) -> None:
        self._backend = backend
        self._server_info = server_info
        self.tls_version_requested_by_scanner = tls_version_requested_by_scanner
        self.ssl_client = _FakeSslClient()
        self.was_closed = False

    def connect(self, should_retry_connection: bool = True) -> None:
        offered_groups = self.ssl_client.groups_offered_by_scanner
        if len(offered_groups) != 1:
            raise AssertionError(f"The scanner must probe one group per connection; got {offered_groups}")
        curve_nid = offered_groups[0]

        special_outcome = self._backend.special_outcomes.get(curve_nid)
        if isinstance(special_outcome, Exception):
            raise special_outcome

        if special_outcome is _SpecialOutcome.SUBSTITUTE_WITH_CERTIFICATE_CURVE:
            # A buggy peer completes the handshake but with a key on a different curve than the offered one
            self.ssl_client.negotiated_ephemeral_key = _ephemeral_key_for_curve(self._backend.certificate_curve)
            return

        if self.tls_version_requested_by_scanner is None:
            raise AssertionError("The scanner must always probe with an explicit TLS version")
        supported_groups = self._backend.supported_groups.get(self.tls_version_requested_by_scanner, set())
        if curve_nid not in supported_groups:
            raise ServerRejectedTlsHandshake(
                server_location=self._server_info.server_location,
                network_configuration=self._server_info.network_configuration,
                error_message=f"Backend rejected group {curve_nid.name}",
            )

        # The handshake succeeded: the key exchange produced an ephemeral key on the offered curve
        self.ssl_client.negotiated_ephemeral_key = _ephemeral_key_for_curve(curve_nid)
        if special_outcome is _SpecialOutcome.CLIENT_CERTIFICATE_REQUESTED:
            raise ClientCertificateRequested(ca_list=[])

    def close(self) -> None:
        self.was_closed = True


@dataclass
class _OfflineScanHarness:
    """Runs the real scan command against a _ProgrammableBackend, without any network or local TLS server."""

    server_info: ServerConnectivityInfo
    backend: _ProgrammableBackend
    connections: List[_FakeTlsConnection] = field(default_factory=list)

    def run_scan(self) -> SupportedEllipticCurvesScanResult:
        def fake_get_preconfigured_tls_connection(
            server_info: ServerConnectivityInfo,
            override_tls_version: Optional[TlsVersionEnum] = None,
            should_use_legacy_openssl: Optional[bool] = None,
            **kwargs,
        ) -> _FakeTlsConnection:
            if should_use_legacy_openssl is not False:
                raise AssertionError("Curve probing must use the modern SSL client")
            connection = _FakeTlsConnection(self.backend, override_tls_version, server_info)
            self.connections.append(connection)
            return connection

        with mock.patch.object(
            ServerConnectivityInfo, "get_preconfigured_tls_connection", new=fake_get_preconfigured_tls_connection
        ), mock.patch.object(elliptic_curves_plugin, "SslClient", _FakeSslClient):
            return SupportedEllipticCurvesImplementation.scan_server(self.server_info)


def _harness_for_backend(
    backend: _ProgrammableBackend,
    highest_tls_version: TlsVersionEnum,
    supports_ecdh_key_exchange: bool = True,
) -> _OfflineScanHarness:
    tls_probing_result = ServerTlsProbingResult(
        highest_tls_version_supported=highest_tls_version,
        cipher_suite_supported="ECDHE-RSA-AES128-SHA",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=supports_ecdh_key_exchange,
    )
    server_location = ServerNetworkLocation(hostname="localhost", port=443, ip_address="127.0.0.1")
    server_info = ServerConnectivityInfo(
        server_location=server_location,
        network_configuration=ServerNetworkConfiguration(tls_server_name_indication=server_location.hostname),
        tls_probing_result=tls_probing_result,
    )
    return _OfflineScanHarness(server_info=server_info, backend=backend)


def _rejected_handshake(error_message: str = "Rejected by test") -> ServerRejectedTlsHandshake:
    return ServerRejectedTlsHandshake(
        server_location=ServerNetworkLocation(hostname="localhost", port=443, ip_address="127.0.0.1"),
        network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
        error_message=error_message,
    )


class TestEllipticCurvesPluginOffline:
    def test_one_scan_job_per_candidate_group(self) -> None:
        # Given a server that supports ECDH key exchange
        backend = _ProgrammableBackend(supported_groups={}, certificate_curve=OpenSslEcNidEnum.SECP256R1)
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_2)

        # When generating the scan jobs
        scan_jobs = SupportedEllipticCurvesImplementation.scan_jobs_for_scan_command(harness.server_info)

        # Then there is one job per candidate group known to the SSL client, each targeting a distinct group
        probed_curves = [job.function_arguments[1] for job in scan_jobs]
        assert set(probed_curves) == OpenSslEcNidEnum.get_supported_by_ssl_client()
        assert len(probed_curves) == len(set(probed_curves))

    @pytest.mark.parametrize("tls_version", [TlsVersionEnum.TLS_1_2, TlsVersionEnum.TLS_1_3])
    def test_probes_every_candidate_with_the_server_tls_version(self, tls_version: TlsVersionEnum) -> None:
        # Given a backend that supports no group at all, so every probe fails
        backend = _ProgrammableBackend(supported_groups={}, certificate_curve=OpenSslEcNidEnum.SECP256R1)
        harness = _harness_for_backend(backend, highest_tls_version=tls_version)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        assert result.supported_curves is not None
        assert result.rejected_curves is not None

        # Then every candidate group was offered exactly once, on its own connection
        all_offered_groups = [connection.ssl_client.groups_offered_by_scanner[0] for connection in harness.connections]
        assert set(all_offered_groups) == OpenSslEcNidEnum.get_supported_by_ssl_client()
        assert len(all_offered_groups) == len(set(all_offered_groups))

        # And every probe used the server's highest TLS version: no version mixing
        assert {connection.tls_version_requested_by_scanner for connection in harness.connections} == {tls_version}

        # And the ECDH cipher suites were enabled with the API matching the TLS version
        for connection in harness.connections:
            if tls_version == TlsVersionEnum.TLS_1_3:
                assert connection.ssl_client.cipher_suites_from_scanner
                assert connection.ssl_client.cipher_list_from_scanner is None
            else:
                assert connection.ssl_client.cipher_list_from_scanner == "ECDH"
                assert connection.ssl_client.cipher_suites_from_scanner is None

        # And every connection was closed, and since no key exchange succeeded, every group was rejected
        assert all(connection.was_closed for connection in harness.connections)
        assert result.supports_ecdh_key_exchange
        assert not result.supported_curves
        assert len(result.rejected_curves) == len(all_offered_groups)

    @pytest.mark.parametrize(
        "tls_version,groups_supported_by_backend,expected_supported",
        [
            (
                TlsVersionEnum.TLS_1_2,
                {OpenSslEcNidEnum.SECP256R1, OpenSslEcNidEnum.SECP384R1},
                {"secp256r1": 415, "secp384r1": 715},
            ),
            (
                TlsVersionEnum.TLS_1_3,
                {OpenSslEcNidEnum.X25519, OpenSslEcNidEnum.SECP256R1},
                {"X25519": 1034, "secp256r1": 415},
            ),
            (
                TlsVersionEnum.TLS_1_3,
                {
                    OpenSslEcNidEnum.X25519,
                    OpenSslEcNidEnum.X448,
                    OpenSslEcNidEnum.SECP256R1,
                    OpenSslEcNidEnum.SECP384R1,
                    OpenSslEcNidEnum.SECP521R1,
                },
                {"X25519": 1034, "X448": 1035, "secp256r1": 415, "secp384r1": 715, "secp521r1": 716},
            ),
        ],
    )
    def test_only_key_exchange_confirmed_groups_are_reported(
        self,
        tls_version: TlsVersionEnum,
        groups_supported_by_backend: Set[OpenSslEcNidEnum],
        expected_supported: Dict[str, int],
    ) -> None:
        # Given a backend with an independent support matrix for the server's TLS version
        backend = _ProgrammableBackend(
            supported_groups={tls_version: groups_supported_by_backend},
            certificate_curve=OpenSslEcNidEnum.SECT571R1,
        )
        harness = _harness_for_backend(backend, highest_tls_version=tls_version)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        assert result.supported_curves is not None
        assert result.rejected_curves is not None

        # Then exactly the groups confirmed by a key exchange are reported as supported: one success does not
        # pull the other (rejected) groups into the supported list
        assert {curve.name: curve.openssl_nid for curve in result.supported_curves} == expected_supported

        # And every other probed group was rejected: failures did not erase the confirmed results either
        all_candidates = OpenSslEcNidEnum.get_supported_by_ssl_client()
        assert len(result.supported_curves) + len(result.rejected_curves) == len(all_candidates)
        assert {curve.openssl_nid for curve in result.rejected_curves} == {
            nid.value for nid in all_candidates if nid not in groups_supported_by_backend
        }

        # And the final JSON contains exactly the negotiated groups, with their own identifiers, sorted by name
        result_as_json = json.loads(SupportedEllipticCurvesScanResultAsJson.model_validate(result).model_dump_json())
        assert result_as_json["supports_ecdh_key_exchange"] is True
        assert {curve["name"]: curve["openssl_nid"] for curve in result_as_json["supported_curves"]} == (
            expected_supported
        )
        supported_names = [curve["name"] for curve in result_as_json["supported_curves"]]
        assert supported_names == sorted(supported_names)

    def test_certificate_curve_is_not_reported_unless_used_in_key_exchange(self) -> None:
        # Given a TLS 1.3 server whose certificate uses secp256r1 but which only negotiates X25519 in ECDHE
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_3: {OpenSslEcNidEnum.X25519}},
            certificate_curve=OpenSslEcNidEnum.SECP256R1,
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_3)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        assert result.supported_curves is not None
        assert result.rejected_curves is not None

        # Then the certificate's curve is not reported as supported: only the key exchange counts
        assert {curve.name for curve in result.supported_curves} == {"X25519"}
        assert "secp256r1" in {curve.name for curve in result.rejected_curves}

    def test_groups_known_under_several_names_keep_their_own_identifier(self) -> None:
        # Given a backend supporting two groups with look-alike names: secp256r1 (a.k.a. prime256v1, NID 415)
        # and secp256k1 (NID 714)
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_2: {OpenSslEcNidEnum.SECP256R1, OpenSslEcNidEnum.SECP256K1}},
            certificate_curve=OpenSslEcNidEnum.SECP256R1,
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_2)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        assert result.supported_curves is not None

        # Then each reported curve carries the identifier of the group that was actually negotiated in its key
        # exchange, not the identifier of another group with a similar name
        assert {curve.name: curve.openssl_nid for curve in result.supported_curves} == {
            "secp256r1": 415,
            "secp256k1": 714,
        }

    def test_curve_substitution_during_key_exchange_is_detected(self) -> None:
        # Given a backend that completes the handshake for X25519 but returns an ephemeral key on the
        # certificate's curve instead of the offered one
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_3: {OpenSslEcNidEnum.X25519}},
            certificate_curve=OpenSslEcNidEnum.SECP256R1,
            special_outcomes={OpenSslEcNidEnum.X25519: _SpecialOutcome.SUBSTITUTE_WITH_CERTIFICATE_CURVE},
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_3)

        # When scanning for supported elliptic curves, the substitution is detected instead of being reported
        with pytest.raises(RuntimeError):
            harness.run_scan()

    def test_failed_probes_do_not_erase_confirmed_results(self) -> None:
        # Given a backend that confirms two groups, while other probes fail in the various ways real servers fail
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_2: {OpenSslEcNidEnum.SECP256R1, OpenSslEcNidEnum.SECP384R1}},
            certificate_curve=OpenSslEcNidEnum.SECP256R1,
            special_outcomes={
                OpenSslEcNidEnum.X25519: TlsHandshakeTimedOut(
                    server_location=ServerNetworkLocation(hostname="localhost", port=443, ip_address="127.0.0.1"),
                    network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
                    error_message="Timed out",
                ),
                OpenSslEcNidEnum.X448: OpenSSLError("error:0A000172:SSL routines::wrong curve"),
                OpenSslEcNidEnum.SECP521R1: OpenSSLError("error:0A00010B:SSL routines::sslv3 alert unexpected message"),
                OpenSslEcNidEnum.SECP256K1: OpenSSLError(
                    "error:00000001:lib(0)::reason(1):ossl_statem_client_read_transition:unexpected message"
                ),
            },
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_2)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        assert result.supported_curves is not None
        assert result.rejected_curves is not None

        # Then the confirmed groups are still reported as supported
        assert {curve.name for curve in result.supported_curves} == {"secp256r1", "secp384r1"}

        # And the groups whose probe failed are reported as rejected
        assert {"X25519", "X448", "secp521r1", "secp256k1"} <= {curve.name for curve in result.rejected_curves}

    def test_client_certificate_request_still_confirms_the_curve(self) -> None:
        # Given a backend that completes the key exchange for secp256r1 but then requests a client certificate
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_2: {OpenSslEcNidEnum.SECP256R1}},
            certificate_curve=OpenSslEcNidEnum.SECP256R1,
            special_outcomes={OpenSslEcNidEnum.SECP256R1: _SpecialOutcome.CLIENT_CERTIFICATE_REQUESTED},
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_2)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        assert result.supported_curves is not None

        # Then the curve is still confirmed thanks to the ephemeral key from the completed key exchange
        assert {curve.name for curve in result.supported_curves} == {"secp256r1"}

    def test_unexpected_openssl_error_fails_the_scan(self) -> None:
        # Given a backend that triggers an OpenSSL error the plugin does not know how to classify
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_2: {OpenSslEcNidEnum.SECP256R1}},
            certificate_curve=OpenSslEcNidEnum.SECP256R1,
            special_outcomes={OpenSslEcNidEnum.SECP384R1: OpenSSLError("some unexpected failure")},
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_2)

        # When scanning for supported elliptic curves, the error is propagated instead of being swallowed
        with pytest.raises(OpenSSLError):
            harness.run_scan()

    def test_server_without_ecdh_cipher_suites(self) -> None:
        # Given a server that does not support any ECDH cipher suite
        backend = _ProgrammableBackend(supported_groups={}, certificate_curve=OpenSslEcNidEnum.SECP256R1)
        harness = _harness_for_backend(
            backend, highest_tls_version=TlsVersionEnum.TLS_1_2, supports_ecdh_key_exchange=False
        )

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        # Then no probing connection was even attempted
        assert not harness.connections

        # And the result states that ECDH key exchange is not supported, with no curve lists
        assert not result.supports_ecdh_key_exchange
        assert result.supported_curves is None
        assert result.rejected_curves is None

        # And a CLI output can be generated
        console_output = SupportedEllipticCurvesImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("does not support" in line for line in console_output)

        # And the JSON output has null curve lists
        result_as_json = json.loads(SupportedEllipticCurvesScanResultAsJson.model_validate(result).model_dump_json())
        assert result_as_json == {
            "supports_ecdh_key_exchange": False,
            "supported_curves": None,
            "rejected_curves": None,
        }

    def test_json_output_reflects_the_negotiated_groups(self) -> None:
        # Given a TLS 1.3 backend that negotiates X25519 and secp256r1
        groups_supported_by_backend = {OpenSslEcNidEnum.X25519, OpenSslEcNidEnum.SECP256R1}
        backend = _ProgrammableBackend(
            supported_groups={TlsVersionEnum.TLS_1_3: groups_supported_by_backend},
            certificate_curve=OpenSslEcNidEnum.SECP384R1,
        )
        harness = _harness_for_backend(backend, highest_tls_version=TlsVersionEnum.TLS_1_3)

        # When scanning for supported elliptic curves
        result = harness.run_scan()

        # Then the final JSON matches the full support matrix: every probed group appears exactly once, with the
        # name and identifier of the group itself
        result_as_json = json.loads(SupportedEllipticCurvesScanResultAsJson.model_validate(result).model_dump_json())
        assert result_as_json["supported_curves"] == [
            {"name": "X25519", "openssl_nid": 1034},
            {"name": "secp256r1", "openssl_nid": 415},
        ]
        expected_rejected = [
            {"name": _OPENSSL_NID_TO_SECG_ANSI_X9_62[nid], "openssl_nid": nid.value}
            for nid in OpenSslEcNidEnum.get_supported_by_ssl_client()
            if nid not in groups_supported_by_backend
        ]
        expected_rejected.sort(key=lambda curve: curve["name"])
        assert result_as_json["rejected_curves"] == expected_rejected
