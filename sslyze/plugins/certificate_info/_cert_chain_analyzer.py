from dataclasses import dataclass

from typing import Optional, List, Union, cast, Tuple

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    ExtensionNotFound,
    ExtensionOID,
    Certificate,
    load_pem_x509_certificate,
    TLSFeature,
    DNSName,
    IPAddress,
)
from cryptography.x509.ocsp import load_der_ocsp_response, OCSPResponseStatus, OCSPResponse
import nassl.ocsp_response

from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore, PathValidationResult


@dataclass(frozen=True)
class CertificateDeploymentAnalysisResult:
    """The result of analyzing a server's certificate to verify its validity.

    Any certificate available within the fields that follow is parsed as a ``Certificate`` object using the cryptography
    module; documentation is available at
    https://cryptography.io/en/latest/x509/reference.html?highlight=Certificate#cryptography.x509.Certificate

    Attributes:
        received_certificate_chain: The certificate chain sent by the server; index 0 is the leaf certificate.
        verified_certificate_chain: A convenience view of the chain built by
            ``verified_certificate_chain_trust_store``, which is the first trust store that successfully built a path
            when ``path_validation_results`` is in deterministic order. Will be ``None`` if no trust store was able to
            build a path. This must not be treated as the result for every trust store: for cross-signed deployments,
            different trust stores can build different paths with different anchors, signature algorithms and validity
            periods. Use ``path_validation_results`` to get each trust store's own path and conclusions.
        verified_certificate_chain_trust_store: The trust store whose path is exposed by the convenience fields
            ``verified_certificate_chain``, ``received_chain_contains_anchor_certificate``,
            ``verified_chain_has_sha1_signature`` and ``verified_chain_has_legacy_symantec_anchor``. Will be ``None`` if
            no trust store built a path; in that case those convenience fields are ``None`` (unknown) as well. Other
            trust stores may have different conclusions.
        path_validation_results: The per-trust-store validation results, ordered deterministically by trust store name,
            version and path, regardless of the order in which the trust stores were configured. Each result contains
            the verified chain that this specific trust store built and the conclusions derived from it.
        leaf_certificate_is_ev: ``True`` if the leaf certificate is Extended Validation, according to Mozilla.
        leaf_certificate_has_must_staple_extension: ``True`` if the OCSP must-staple extension is present in the leaf
            certificate.
        leaf_certificate_signed_certificate_timestamps_count: The number of Signed Certificate
            Timestamps (SCTs) for Certificate Transparency embedded in the leaf certificate. ``None`` if the version of
            OpenSSL installed on the system is too old to be able to parse the SCT extension.
        received_chain_has_valid_order: ``True`` if the certificate chain returned by the server was sent in the right
            order. `None`` if any of the certificates in the chain could not be parsed.
        received_chain_contains_anchor_certificate: Convenience warning derived only from the path built by
            ``verified_certificate_chain_trust_store``. ``True`` if the server also sent that anchor certificate.
            ``None`` if no trust store built a path, in which case this is unknown; it is not a statement about other
            trust stores.
        verified_chain_has_sha1_signature: Convenience check derived only from the path built by
            ``verified_certificate_chain_trust_store``. ``True`` if a leaf or intermediate certificate in that path is
            signed using SHA-1. ``None`` if no trust store built a path, in which case this is unknown; other trust
            stores may have built paths with different signature algorithms.
        verified_chain_has_legacy_symantec_anchor: Convenience check derived only from the path built by
            ``verified_certificate_chain_trust_store``. ``True`` if that path contains a distrusted Symantec anchor
            (https://blog.qualys.com/ssllabs/2017/09/26/google-and-mozilla-deprecating-existing-symantec-certificates).
            ``None`` if no trust store built a path, in which case this is unknown.
        ocsp_response: The OCSP response returned by the server. ``None`` if no response was sent by the server or if
            the scan was run through an HTTP proxy (the proxy will not forward the server's OCSP response). If present,
            the OCSP response is an ``OCSPResponse`` object parsed using the cryptography module; documentation is
            available at
            https://cryptography.io/en/latest/x509/ocsp.html?highlight=OCSPResponse#cryptography.x509.ocsp.OCSPResponse
        ocsp_response_is_trusted: ``True`` if the OCSP response is trusted using
            ``verified_certificate_chain_trust_store``, the trust store that built the convenience verified chain.
            ``None`` if no OCSP response was sent by the server or if no trust store built a verified chain.

    """

    received_certificate_chain: List[Certificate]
    leaf_certificate_has_must_staple_extension: bool
    leaf_certificate_is_ev: bool
    leaf_certificate_signed_certificate_timestamps_count: Optional[int]
    received_chain_contains_anchor_certificate: Optional[bool]
    received_chain_has_valid_order: Optional[bool]

    path_validation_results: List[PathValidationResult]
    verified_certificate_chain_trust_store: Optional[TrustStore]
    verified_chain_has_sha1_signature: Optional[bool]
    verified_chain_has_legacy_symantec_anchor: Optional[bool]

    ocsp_response: Optional[OCSPResponse]
    ocsp_response_is_trusted: Optional[bool]

    @property
    def verified_certificate_chain(self) -> Optional[List[Certificate]]:
        """Get the convenience verified chain, built by ``verified_certificate_chain_trust_store``.

        Use ``path_validation_results`` to get the chain built by each individual trust store.
        """
        if self.verified_certificate_chain_trust_store is None:
            return None

        for path_result in self.path_validation_results:
            if path_result.trust_store is self.verified_certificate_chain_trust_store:
                return path_result.verified_certificate_chain
        return None

    @property
    def verified_certificate_chain_as_pem(self) -> Optional[List[str]]:
        if self.verified_certificate_chain is None:
            return None

        pem_certs = []
        for certificate in self.verified_certificate_chain:
            pem_certs.append(certificate.public_bytes(Encoding.PEM).decode("ascii"))
        return pem_certs

    @property
    def received_certificate_chain_as_pem(self) -> List[str]:
        pem_certs = []
        for certificate in self.received_certificate_chain:
            pem_certs.append(certificate.public_bytes(Encoding.PEM).decode("ascii"))
        return pem_certs


class CertificateDeploymentAnalyzer:
    """Utility class for analyzing a certificate chain as deployed on a specific server.

    Useful for checking a server's certificate chain without having to use the CertificateInfoPlugin.
    """

    def __init__(
        self,
        server_subject: Union[IPAddress, DNSName],
        server_certificate_chain_as_pem: List[str],
        server_ocsp_response: Optional[nassl._nassl.OCSP_RESPONSE],
        trust_stores_for_validation: List[TrustStore],
    ) -> None:
        self.server_subject = server_subject
        self.server_certificate_chain_as_pem = server_certificate_chain_as_pem
        self.server_ocsp_response = server_ocsp_response
        self.trust_stores_for_validation = trust_stores_for_validation

    def perform(self) -> CertificateDeploymentAnalysisResult:
        received_certificate_chain = [
            load_pem_x509_certificate(pem_cert.encode("ascii"), backend=default_backend())
            for pem_cert in self.server_certificate_chain_as_pem
        ]
        leaf_cert = received_certificate_chain[0]

        # OCSP Must-Staple
        has_ocsp_must_staple = False
        try:
            tls_feature_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
            tls_feature_value = cast(TLSFeature, tls_feature_ext.value)
            for feature_type in tls_feature_value:
                if feature_type == cryptography.x509.TLSFeatureType.status_request:
                    has_ocsp_must_staple = True
                    break
        except ExtensionNotFound:
            pass

        # Received chain order
        is_chain_order_valid: Optional[bool] = True
        previous_issuer = None
        for index, cert in enumerate(received_certificate_chain):
            try:
                current_subject = cert.subject
            except ValueError:
                # Cryptography could not parse the certificate https://github.com/nabla-c0d3/sslyze/issues/495
                is_chain_order_valid = None
                break

            if index > 0:
                # Compare the current subject with the previous issuer in the chain
                if current_subject != previous_issuer:
                    is_chain_order_valid = False
                    break
            try:
                previous_issuer = cert.issuer
            except KeyError:
                # Missing issuer; this is okay if this is the last cert
                previous_issuer = None
            except ValueError:
                # Cryptography could not parse the certificate https://github.com/nabla-c0d3/sslyze/issues/495
                is_chain_order_valid = None
                break

        # Check if the leaf certificate is Extended Validation
        is_leaf_certificate_ev = False
        for trust_store in self.trust_stores_for_validation:
            if trust_store.ev_oids is None:
                # We only have the EV OIDs for Mozilla - skip other stores
                continue

            is_leaf_certificate_ev = trust_store.is_certificate_extended_validation(leaf_cert)

        # Check for Signed Timestamps
        number_of_scts: Optional[int] = 0
        try:
            # Look for the x509 extension
            sct_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
            if isinstance(sct_ext.value, cryptography.x509.UnrecognizedExtension):
                # The version of OpenSSL on the system is too old and can't parse the SCT extension
                number_of_scts = None

            # Count the number of entries in the extension
            sct_ext_value = cast(cryptography.x509.PrecertificateSignedCertificateTimestamps, sct_ext.value)
            number_of_scts = len(sct_ext_value)
        except ExtensionNotFound:
            pass

        # Try to generate the verified certificate chain using each trust store
        all_path_validation_results = []
        for trust_store in self.trust_stores_for_validation:
            path_validation_result = trust_store.verify_certificate_chain(
                self.server_certificate_chain_as_pem, self.server_subject
            )
            all_path_validation_results.append(path_validation_result)

        # Sort deterministically so that the result order never depends on the order in which the trust stores were
        # configured. Name alone is not enough: a custom CA file can share a name with a packaged store, and two custom
        # CA files can share the same name.
        def sort_function(path_validation: PathValidationResult) -> Tuple[str, str, str]:
            return (
                path_validation.trust_store.name.lower(),
                path_validation.trust_store.version.lower(),
                str(path_validation.trust_store.path),
            )

        all_path_validation_results.sort(key=sort_function)

        # Keep the first trust store that built a verified chain. This selection is deterministic, and the convenience
        # fields below are explicitly documented as being about this one trust store; each other trust store's path and
        # conclusions stay available in all_path_validation_results.
        trust_store_that_can_build_verified_chain = None
        convenience_path_validation_result = None
        for path_validation_result in all_path_validation_results:
            if path_validation_result.was_validation_successful:
                trust_store_that_can_build_verified_chain = path_validation_result.trust_store
                convenience_path_validation_result = path_validation_result
                break

        # The convenience fields mirror the path built by the selected trust store, including "unknown" (None) when it
        # could not build a path. They are never populated from a different trust store's path.
        has_anchor_in_certificate_chain = (
            convenience_path_validation_result.received_chain_contains_anchor_certificate
            if convenience_path_validation_result
            else None
        )
        has_sha1_in_certificate_chain = (
            convenience_path_validation_result.verified_chain_has_sha1_signature
            if convenience_path_validation_result
            else None
        )
        verified_chain_has_legacy_symantec_anchor = (
            convenience_path_validation_result.verified_chain_has_legacy_symantec_anchor
            if convenience_path_validation_result
            else None
        )

        # Check the OCSP response if there is one
        is_ocsp_response_trusted = None
        final_ocsp_response = None
        if self.server_ocsp_response:
            # Parse the OCSP response returned by nassl
            final_ocsp_response = load_der_ocsp_response(self.server_ocsp_response.as_der_bytes())

            # Check if the OCSP response is trusted
            if (
                trust_store_that_can_build_verified_chain
                and final_ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL
            ):
                try:
                    nassl.ocsp_response.verify_ocsp_response(
                        self.server_ocsp_response, trust_store_that_can_build_verified_chain.path
                    )
                    is_ocsp_response_trusted = True
                except nassl.ocsp_response.OcspResponseNotTrustedError:
                    is_ocsp_response_trusted = False

        # All done
        return CertificateDeploymentAnalysisResult(
            received_certificate_chain=received_certificate_chain,
            leaf_certificate_has_must_staple_extension=has_ocsp_must_staple,
            leaf_certificate_is_ev=is_leaf_certificate_ev,
            leaf_certificate_signed_certificate_timestamps_count=number_of_scts,
            received_chain_contains_anchor_certificate=has_anchor_in_certificate_chain,
            received_chain_has_valid_order=is_chain_order_valid,
            verified_chain_has_sha1_signature=has_sha1_in_certificate_chain,
            verified_chain_has_legacy_symantec_anchor=verified_chain_has_legacy_symantec_anchor,
            path_validation_results=all_path_validation_results,
            verified_certificate_chain_trust_store=trust_store_that_can_build_verified_chain,
            ocsp_response=final_ocsp_response,
            ocsp_response_is_trusted=is_ocsp_response_trusted,
        )
