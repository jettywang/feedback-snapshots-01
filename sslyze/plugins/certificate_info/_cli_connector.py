import binascii
from pathlib import Path
from typing import List, Union, Dict, Optional, Tuple, TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate
from cryptography.x509.ocsp import OCSPResponseStatus

from sslyze.plugins.certificate_info._cert_chain_analyzer import CertificateDeploymentAnalysisResult
from sslyze.plugins.certificate_info._certificate_utils import (
    get_common_names,
    parse_subject_alternative_name_extension,
)
from sslyze.plugins.certificate_info.trust_stores.trust_store import PathValidationResult

from sslyze.plugins.plugin_base import ScanCommandCliConnector, OptParseCliOption

if TYPE_CHECKING:
    from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
    from sslyze.plugins.certificate_info.implementation import CertificateInfoExtraArgument  # noqa: F401


class _CertificateInfoCliConnector(
    ScanCommandCliConnector["CertificateInfoScanResult", "CertificateInfoExtraArgument"]
):
    _cli_option = "certinfo"
    _cli_description = "Retrieve and analyze a server's certificate(s) to verify its validity."

    @classmethod
    def get_cli_options(cls) -> List[OptParseCliOption]:
        scan_command_option = super().get_cli_options()
        scan_command_option.append(
            OptParseCliOption(
                option="certinfo_ca_file",
                help="To be used with --certinfo. Path to a file containing root certificates in PEM format that will"
                " be used to verify the validity of the server's certificate.",
                action="store",
            )
        )
        return scan_command_option

    @classmethod
    def find_cli_options_in_command_line(
        cls, parsed_command_line: Dict[str, Union[None, bool, str]]
    ) -> Tuple[bool, Optional["CertificateInfoExtraArgument"]]:
        # Avoid circular imports
        from sslyze.plugins.certificate_info.implementation import CertificateInfoExtraArgument  # noqa: F811

        # Check if --certinfo was used
        is_scan_cmd_enabled, _ = super().find_cli_options_in_command_line(parsed_command_line)

        # Check if --certinfo_ca_file was used
        extra_arguments = None
        try:
            certinfo_ca_file = parsed_command_line["certinfo_ca_file"]
            if certinfo_ca_file:
                if not isinstance(certinfo_ca_file, str):
                    raise TypeError(f"Expected a str for certinfo_ca_file but received {certinfo_ca_file}")
                extra_arguments = CertificateInfoExtraArgument(custom_ca_file=Path(certinfo_ca_file))
        except KeyError:
            pass

        return is_scan_cmd_enabled, extra_arguments

    TRUST_FORMAT = "{store_name} CA Store ({store_version}):"
    TRUST_FORMAT_INLINE = "{store_name} CA Store ({store_version})"
    NO_VERIFIED_CHAIN_ERROR_TXT = "ERROR - Could not build verified chain (certificate untrusted?)"

    @classmethod
    def result_to_console_output(cls, result: "CertificateInfoScanResult") -> List[str]:
        result_as_txt = [cls._format_title("Certificates Information")]

        # SNI
        server_name_indication = result.hostname_used_for_server_name_indication
        result_as_txt.append(cls._format_field("Hostname sent for SNI:", server_name_indication))

        # Display a summary of the certificate deployments
        all_leaf_public_key_names = []
        for cert_deployment in result.certificate_deployments:
            leaf_certificate = cert_deployment.received_certificate_chain[0]
            all_leaf_public_key_names.append(leaf_certificate.public_key().__class__.__name__)

        leaf_certs_description = str(len(result.certificate_deployments))
        if result.certificate_deployments:
            leaf_certs_description += " (" + ", ".join(all_leaf_public_key_names) + ")"

        result_as_txt.append(cls._format_field("Number of cert chains detected:", leaf_certs_description))
        no_sni_cert_txt = "Yes" if result.certificate_deployment_with_sni_disabled else "No"
        result_as_txt.append(cls._format_field("Cert chain with SNI disabled:", no_sni_cert_txt))

        # Display each certificate deployment
        for index, cert_deployment in enumerate(result.certificate_deployments):
            result_as_txt.append("\n")
            result_as_txt.extend(
                cls._cert_deployment_to_console_output(index + 1, cert_deployment, was_sni_disabled=False)
            )

        # Display the non-SNI certificate deployment if present
        if result.certificate_deployment_with_sni_disabled:
            result_as_txt.append("")
            result_as_txt.extend(
                cls._cert_deployment_to_console_output(
                    None, result.certificate_deployment_with_sni_disabled, was_sni_disabled=True
                )
            )

        return result_as_txt

    @classmethod
    def _cert_deployment_to_console_output(
        cls, index: Optional[int], cert_deployment: CertificateDeploymentAnalysisResult, was_sni_disabled: bool
    ) -> List[str]:
        leaf_certificate = cert_deployment.received_certificate_chain[0]
        if was_sni_disabled:
            deployment_as_txt = [cls._format_subtitle("Certificate Chain with SNI disabled - can be ignored")]
        else:
            deployment_as_txt = [
                cls._format_subtitle(
                    f"Certificate Chain #{index} ({leaf_certificate.public_key().__class__.__name__}, SNI enabled)"
                )
            ]

        deployment_as_txt.extend(cls._get_basic_certificate_text(leaf_certificate))

        # Trust section
        deployment_as_txt.append(cls._format_subtitle("Trust"))

        # Path validation that was successfully tested
        for path_result in cert_deployment.path_validation_results:
            store_name = cls.TRUST_FORMAT.format(
                store_name=path_result.trust_store.name, store_version=path_result.trust_store.version
            )

            if path_result.was_validation_successful:
                # EV certs - Only Mozilla supported for now
                ev_txt = ""
                if cert_deployment.leaf_certificate_is_ev and path_result.trust_store.ev_oids:
                    ev_txt = ", Extended Validation"
                path_txt = f"OK - Certificate is trusted{ev_txt}"

            else:
                path_txt = f"FAILED - Certificate is NOT Trusted: {path_result.validation_error}"

            deployment_as_txt.append(cls._format_field(store_name, path_txt))

            # Report the path that this specific trust store built, if any. Cross-signed deployments can lead each
            # store to build a different path, so this cannot be replaced by a single deployment-wide chain.
            if path_result.verified_certificate_chain:
                path_cns = [_get_subject_as_short_text(cert) for cert in path_result.verified_certificate_chain]
                deployment_as_txt.append(cls._format_field("  Built Path:", " --> ".join(path_cns)))
                deployment_as_txt.extend(cls._per_store_conclusions_to_console_output(path_result))
            else:
                deployment_as_txt.append(cls._format_field("  Built Path:", cls.NO_VERIFIED_CHAIN_ERROR_TXT))
                deployment_as_txt.append(
                    cls._format_field(
                        "  SHA1 / Symantec / Anchor:",
                        "UNKNOWN - no path was built with this trust store",
                    )
                )

        # Deployment-wide legacy summary. It is explicitly tied to the trust store whose path was selected above, and
        # is therefore not a statement about every trust store.
        has_convenience_path = cert_deployment.verified_certificate_chain_trust_store is not None
        if cert_deployment.verified_certificate_chain_trust_store:
            convenience_store_name = cls.TRUST_FORMAT_INLINE.format(
                store_name=cert_deployment.verified_certificate_chain_trust_store.name,
                store_version=cert_deployment.verified_certificate_chain_trust_store.version,
            )
        else:
            convenience_store_name = "none - no trust store built a path"

        unknown_convenience_txt = cls.NO_VERIFIED_CHAIN_ERROR_TXT
        if not has_convenience_path:
            unknown_convenience_txt = "UNKNOWN - no trust store built a path"

        if cert_deployment.verified_chain_has_legacy_symantec_anchor is None:
            symantec_str = "UNKNOWN - no trust store built a path"
        elif cert_deployment.verified_chain_has_legacy_symantec_anchor is True:
            symantec_str = "WARNING: Certificate distrusted by Google and Mozilla since 2018"
        elif cert_deployment.verified_chain_has_legacy_symantec_anchor is False:
            symantec_str = "OK - Not a Symantec-issued certificate"
        else:
            raise RuntimeError("Should never happen")
        deployment_as_txt.append(
            cls._format_field(
                "Symantec 2018 Deprecation:",
                f"{symantec_str} (path built by {convenience_store_name}; see per-store results above)",
            )
        )

        # Print the Common Names within the received certificate chain. This is the chain as sent by the server, which
        # is independent from any verified chain built locally by a trust store.
        cns_in_received_chain: List[str] = [
            _get_subject_as_short_text(cert) for cert in cert_deployment.received_certificate_chain
        ]
        deployment_as_txt.append(cls._format_field("Received Chain:", " --> ".join(cns_in_received_chain)))

        # Print the Common Names within the convenience verified certificate chain if validation was successful
        if cert_deployment.verified_certificate_chain:
            cns_in_certificate_chain = [
                _get_subject_as_short_text(cert) for cert in cert_deployment.verified_certificate_chain
            ]
            verified_chain_txt = " --> ".join(cns_in_certificate_chain)
        else:
            verified_chain_txt = unknown_convenience_txt
        deployment_as_txt.append(
            cls._format_field(
                "Verified Chain (convenience):",
                f"{verified_chain_txt} [built by {convenience_store_name}]",
            )
        )

        if cert_deployment.verified_certificate_chain:
            chain_with_anchor_txt = (
                "OK - Anchor certificate not sent"
                if not cert_deployment.received_chain_contains_anchor_certificate
                else "WARNING - Received certificate chain contains the anchor certificate"
            )
        else:
            chain_with_anchor_txt = unknown_convenience_txt
        deployment_as_txt.append(
            cls._format_field(
                "Received Chain Contains Anchor:",
                f"{chain_with_anchor_txt} [{convenience_store_name}]",
            )
        )

        chain_order_txt = (
            "OK - Order is valid"
            if cert_deployment.received_chain_has_valid_order
            else "FAILED - Certificate chain out of order!"
        )
        deployment_as_txt.append(cls._format_field("Received Chain Order:", chain_order_txt))

        if cert_deployment.verified_certificate_chain:
            sha1_text = (
                "OK - No SHA1-signed certificate in the verified certificate chain"
                if not cert_deployment.verified_chain_has_sha1_signature
                else "INSECURE - SHA1-signed certificate in the verified certificate chain"
            )
        else:
            sha1_text = unknown_convenience_txt
        deployment_as_txt.append(
            cls._format_field(
                "Verified Chain contains SHA1:",
                f"{sha1_text} [{convenience_store_name}]",
            )
        )

        # Extensions section
        deployment_as_txt.append(cls._format_subtitle("Certificate Extensions"))

        # OCSP must-staple
        must_staple_txt = (
            "OK - Extension present"
            if cert_deployment.leaf_certificate_has_must_staple_extension
            else "NOT SUPPORTED - Extension not found"
        )
        deployment_as_txt.append(cls._format_field("OCSP Must-Staple:", must_staple_txt))

        # Look for SCT extension
        scts_count = cert_deployment.leaf_certificate_signed_certificate_timestamps_count
        if scts_count is None:
            sct_txt = "OK - Extension present"
        elif scts_count == 0:
            sct_txt = "NOT SUPPORTED - Extension not found"
        elif scts_count < 3:
            sct_txt = "WARNING - Only {} SCTs included but Google recommends 3 or more".format(str(scts_count))
        else:
            sct_txt = "OK - {} SCTs included".format(str(scts_count))
        deployment_as_txt.append(cls._format_field("Certificate Transparency:", sct_txt))

        # OCSP stapling
        deployment_as_txt.append(cls._format_subtitle("OCSP Stapling"))

        if cert_deployment.ocsp_response is None:
            deployment_as_txt.append(cls._format_field("", "NOT SUPPORTED - Server did not send back an OCSP response"))

        else:
            if cert_deployment.ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
                ocsp_resp_txt = [
                    cls._format_field(
                        "",
                        "ERROR - OCSP response status is not successful: {}".format(
                            cert_deployment.ocsp_response.response_status.name
                        ),
                    )
                ]
            else:
                ocsp_trust_txt = (
                    "OK - Response is trusted"
                    if cert_deployment.ocsp_response_is_trusted
                    else "FAILED - Response is NOT trusted"
                )

                ocsp_resp_txt = [
                    cls._format_field("OCSP Response Status:", cert_deployment.ocsp_response.response_status.name),
                    cls._format_field("Validation w/ Mozilla Store:", ocsp_trust_txt),
                ]

                if cert_deployment.ocsp_response.responder_key_hash:
                    ocsp_resp_txt.append(
                        cls._format_field("Responder Key Hash:", str(cert_deployment.ocsp_response.responder_key_hash))
                    )

                if cert_deployment.ocsp_response.responder_name:
                    ocsp_resp_txt.append(
                        cls._format_field(
                            "Responder Name:", cert_deployment.ocsp_response.responder_name.rfc4514_string()
                        )
                    )

                if cert_deployment.ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL:
                    ocsp_resp_txt.extend(
                        [
                            cls._format_field("Cert Status:", cert_deployment.ocsp_response.certificate_status.name),
                            cls._format_field("Cert Serial Number:", str(cert_deployment.ocsp_response.serial_number)),
                            cls._format_field(
                                "This Update:", cert_deployment.ocsp_response.this_update_utc.date().isoformat()
                            ),
                        ]
                    )

                    # The Next Update field is optional: https://github.com/nabla-c0d3/sslyze/issues/481
                    if cert_deployment.ocsp_response.next_update_utc is None:
                        next_update_str = "None"
                    else:
                        next_update_str = cert_deployment.ocsp_response.next_update_utc.date().isoformat()
                    ocsp_resp_txt.append(cls._format_field("Next Update:", next_update_str))

            deployment_as_txt.extend(ocsp_resp_txt)

        # All done
        return deployment_as_txt

    @classmethod
    def _per_store_conclusions_to_console_output(cls, path_result: PathValidationResult) -> List[str]:
        # All of these conclusions are derived from the path built by this trust store only.
        verified_chain = path_result.verified_certificate_chain
        if not verified_chain:
            return []
        anchor_certificate = verified_chain[-1]
        signature_algorithms = []
        for certificate in verified_chain:
            if certificate.signature_hash_algorithm:
                signature_algorithms.append(certificate.signature_hash_algorithm.name)
            else:
                signature_algorithms.append(certificate.signature_algorithm_oid.dotted_string)

        anchor_txt = (
            "WARNING - The path anchor was also sent by the server"
            if path_result.received_chain_contains_anchor_certificate
            else "OK - Path anchor was not sent by the server"
        )
        sha1_txt = (
            "INSECURE - SHA1-signed leaf or intermediate certificate in this path"
            if path_result.verified_chain_has_sha1_signature
            else "OK - No SHA1-signed certificate in this path"
        )
        symantec_txt = (
            "WARNING - Distrusted Symantec anchor in this path"
            if path_result.verified_chain_has_legacy_symantec_anchor
            else "OK - No distrusted Symantec anchor in this path"
        )
        return [
            cls._format_field(
                "  Anchor:",
                f"{_get_subject_as_short_text(anchor_certificate)}"
                f" (not after {anchor_certificate.not_valid_after_utc.date().isoformat()})",
            ),
            cls._format_field("  Signature Algorithms:", " --> ".join(signature_algorithms)),
            cls._format_field("  Anchor Sent:", anchor_txt),
            cls._format_field("  SHA1 Signature:", sha1_txt),
            cls._format_field("  Symantec Anchor:", symantec_txt),
        ]

    @classmethod
    def _get_basic_certificate_text(cls, certificate: Certificate) -> List[str]:
        text_output = [
            cls._format_field(
                "SHA1 Fingerprint:", binascii.hexlify(certificate.fingerprint(hashes.SHA1())).decode("ascii")
            ),
            cls._format_field("Common Name:", _get_subject_as_short_text(certificate)),
            cls._format_field("Issuer:", _get_issuer_as_short_text(certificate)),
            cls._format_field("Serial Number:", str(certificate.serial_number)),
            cls._format_field("Not Before:", certificate.not_valid_before_utc.date().isoformat()),
            cls._format_field("Not After:", certificate.not_valid_after_utc.date().isoformat()),
            cls._format_field("Public Key Algorithm:", certificate.public_key().__class__.__name__),
        ]

        if certificate.signature_hash_algorithm:
            # The signature_hash_algorithm can be None if signature did not use separate hash (ED25519, ED448)
            # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.signature_hash_algorithm
            text_output.append(cls._format_field("Signature Algorithm:", certificate.signature_hash_algorithm.name))

        public_key = certificate.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            text_output.append(cls._format_field("Key Size:", str(public_key.curve.key_size)))
            text_output.append(cls._format_field("Curve:", str(public_key.curve.name)))
        elif isinstance(public_key, RSAPublicKey):
            text_output.append(cls._format_field("Key Size:", str(public_key.key_size)))
            text_output.append(cls._format_field("Exponent:", str(public_key.public_numbers().e)))  # type: ignore
        else:
            # DSA Key? https://github.com/nabla-c0d3/sslyze/issues/314
            pass

        # Print the SAN extension if there's one
        subj_alt_name_ext = parse_subject_alternative_name_extension(certificate)
        if subj_alt_name_ext.dns_names:
            text_output.append(cls._format_field("SubjAltName - DNS Names:", str(subj_alt_name_ext.dns_names)))
        if subj_alt_name_ext.ip_addresses:
            text_output.append(cls._format_field("SubjAltName - IP Addresses", str(subj_alt_name_ext.ip_addresses)))

        return text_output


def _get_subject_as_short_text(certificate: Certificate) -> str:
    try:
        final_subject_field = _get_name_as_short_text(certificate.subject)
    except ValueError:
        # Cryptography could not parse the certificate https://github.com/nabla-c0d3/sslyze/issues/495
        final_subject_field = "Invalid Cert: Subject could not be parsed"
    return final_subject_field


def _get_issuer_as_short_text(certificate: Certificate) -> str:
    try:
        final_issuer_field = _get_name_as_short_text(certificate.issuer)
    except ValueError:
        # Cryptography could not parse the certificate https://github.com/nabla-c0d3/sslyze/issues/495
        final_issuer_field = "Invalid Cert: Issuer could not be parsed"
    return final_issuer_field


def _get_name_as_short_text(name_field: x509.Name) -> str:
    """Convert a name field returned by the cryptography module to a string suitable for displaying it to the user."""
    # Name_field is supposed to be a Subject or an Issuer; print the CN if there is one
    common_names = get_common_names(name_field)
    if common_names:
        # We don't support certs with multiple CNs
        return common_names[0]
    else:
        # Otherwise show the whole field
        return name_field.rfc4514_string()
