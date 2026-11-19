from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
    CipherSuiteTransportError,
    CipherSuiteNotCapable,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult, Tlsv13ScanImplementation
from sslyze.plugins.openssl_cipher_suites.json_output import CipherSuitesScanResultAsJson
from sslyze.server_connectivity import TlsVersionEnum


def _suite(name: str) -> CipherSuite:
    return CipherSuite(name=name, is_anonymous=False, key_size=128, openssl_name=name)


def _incomplete_result() -> CipherSuitesScanResult:
    accepted = CipherSuiteAcceptedByServer(cipher_suite=_suite("TLS_AES_128_GCM_SHA256"), ephemeral_key=None)
    rejected = CipherSuiteRejectedByServer(
        cipher_suite=_suite("TLS_AES_256_GCM_SHA384"), error_message="handshake failure"
    )
    errored = CipherSuiteTransportError(
        cipher_suite=_suite("TLS_CHACHA20_POLY1305_SHA256"),
        error_message="Connection to server timed out during the TLS handshake",
    )
    not_capable = CipherSuiteNotCapable(cipher_suite=_suite("TLS_AES_128_CCM_SHA256"), reason="no ciphers available")
    return CipherSuitesScanResult(
        tls_version_used=TlsVersionEnum.TLS_1_3,
        accepted_cipher_suites=[accepted],
        rejected_cipher_suites=[rejected],
        errored_cipher_suites=[errored],
        not_capable_cipher_suites=[not_capable],
        total_connection_attempts=4,
    )


class TestCliReporting:
    def test_incomplete_cells_are_named_not_hidden(self):
        result = _incomplete_result()

        output = Tlsv13ScanImplementation.cli_connector_cls.result_to_console_output(result)
        output_text = "\n".join(output)

        # The untested cell is explicitly flagged rather than being presented as a rejected/complete list
        assert "TLS_CHACHA20_POLY1305_SHA256" in output_text
        assert "UNTESTED" in output_text
        assert "incomplete" in output_text
        # The actual number of connections is reported to prove retries did not re-run everything
        assert "Total number of connections opened to the server: 4" in output_text

    def test_all_errored_result_does_not_claim_all_rejected(self):
        errored = CipherSuiteTransportError(cipher_suite=_suite("TLS_AES_128_GCM_SHA256"), error_message="timed out")
        result = CipherSuitesScanResult(
            tls_version_used=TlsVersionEnum.TLS_1_3,
            accepted_cipher_suites=[],
            rejected_cipher_suites=[],
            errored_cipher_suites=[errored],
            total_connection_attempts=2,
        )

        output = "\n".join(Tlsv13ScanImplementation.cli_connector_cls.result_to_console_output(result))

        assert "rejected all cipher suites" in output
        assert "remain untested" in output
        assert "TLS_AES_128_GCM_SHA256" in output

    def test_complete_result_has_no_warning(self):
        accepted = CipherSuiteAcceptedByServer(cipher_suite=_suite("TLS_AES_128_GCM_SHA256"), ephemeral_key=None)
        result = CipherSuitesScanResult(
            tls_version_used=TlsVersionEnum.TLS_1_3,
            accepted_cipher_suites=[accepted],
            rejected_cipher_suites=[],
            errored_cipher_suites=[],
            total_connection_attempts=1,
        )

        output = "\n".join(Tlsv13ScanImplementation.cli_connector_cls.result_to_console_output(result))

        assert "UNTESTED" not in output
        assert "WARNING" not in output


class TestJsonReporting:
    def test_incomplete_result_serializes_all_four_categories_and_round_trips(self):
        result = _incomplete_result()

        json_model = CipherSuitesScanResultAsJson.model_validate(result)
        serialized = json_model.model_dump_json()

        # The incomplete cell and the not-capable cell are present as distinct categories
        assert "errored_cipher_suites" in serialized
        assert "not_capable_cipher_suites" in serialized
        assert "TLS_CHACHA20_POLY1305_SHA256" in serialized
        assert json_model.is_complete is False
        assert json_model.total_connection_attempts == 4
        assert len(json_model.accepted_cipher_suites) == 1
        assert len(json_model.rejected_cipher_suites) == 1
        assert len(json_model.errored_cipher_suites) == 1
        assert len(json_model.not_capable_cipher_suites) == 1

        # And it can be parsed back
        reparsed = CipherSuitesScanResultAsJson.model_validate_json(serialized)
        assert reparsed.model_dump() == json_model.model_dump()

    def test_complete_result_serializes_is_complete_true(self):
        accepted = CipherSuiteAcceptedByServer(cipher_suite=_suite("TLS_AES_128_GCM_SHA256"), ephemeral_key=None)
        result = CipherSuitesScanResult(
            tls_version_used=TlsVersionEnum.TLS_1_3,
            accepted_cipher_suites=[accepted],
            rejected_cipher_suites=[],
            total_connection_attempts=1,
        )

        json_model = CipherSuitesScanResultAsJson.model_validate(result)
        assert json_model.is_complete is True
        assert json_model.errored_cipher_suites == []
        assert json_model.not_capable_cipher_suites == []
