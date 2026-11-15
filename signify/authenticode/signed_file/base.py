from __future__ import annotations

import datetime
import hashlib
import logging
import os
import pathlib
from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO, Literal

from typing_extensions import Self

from signify._typing import HashFunction
from signify.asn1.hashing import ACCEPTED_DIGEST_ALGORITHMS
from signify.authenticode.indirect_data import IndirectData
from signify.authenticode.publisher import (
    PublisherPolicy,
    PublisherVerification,
    evaluate_publisher,
)
from signify.authenticode.signed_data import (
    AuthenticodeSignature,
)
from signify.authenticode.trust_list import (
    CertificateTrustList,
    CertificateTrustSubject,
)
from signify.authenticode.verification_result import AuthenticodeVerificationResult
from signify.exceptions import (
    AuthenticodeFingerprintNotProvidedError,
    AuthenticodeInvalidDigestError,
    AuthenticodeNotSignedError,
    AuthenticodeVerificationError,
    ParseError,
)
from signify.pkcs7 import SignedData
from signify.x509 import Certificate

logger = logging.getLogger(__name__)


class AuthenticodeFile:
    """An Authenticode-signed file that is to be parsed to find the relevant
    sections for Authenticode parsing.
    """

    catalogs: Iterable[CertificateTrustList] = ()

    @classmethod
    def from_stream(
        cls,
        file_obj: BinaryIO,
        file_name: str | None = None,
        *,
        allow_flat: bool = False,
    ) -> AuthenticodeFile:
        """This initializer will return a concrete subclass that is compatible with the
        provided file object, and otherwise throw an error.

        :param file_obj: The file-like object to read from
        :param file_name: The optional argument can be used to specify the file name.
        :param allow_flat: Indicates whether FlatFile is allowed as a subclass. As
            this matches anything, this will always be available.
        """
        if file_name is None and hasattr(file_obj, "name"):
            file_name = pathlib.Path(file_obj.name).name

        # Peek for the first 8 bytes
        file_obj.seek(0, os.SEEK_SET)
        header = file_obj.read(8)
        file_obj.seek(0, os.SEEK_SET)

        for subclass in cls.__subclasses__():
            try:
                attempt = subclass._try_open(file_obj, file_name, header)
            except Exception as e:  # noqa: PERF203
                logger.debug(f"Error while trying {subclass.__name__}: {e!r}")
            else:
                if attempt is not None:
                    return attempt

        # If we are not AuthenticodeFile ourselves, we are already a subclass
        # of AuthenticodeFile. Perhaps we know how to open this file.
        if cls is not AuthenticodeFile:
            try:
                attempt = cls._try_open(file_obj, file_name, header)
            except Exception as e:
                logger.debug(f"Error while trying {cls.__name__}: {e!r}")
            else:
                if attempt is not None:
                    return attempt

        if allow_flat:
            from .flat import FlatFile

            return FlatFile(file_obj)

        raise ParseError("Unable to determine file type with available parsers.")

    @classmethod
    def _try_open(
        cls, file_obj: BinaryIO, file_name: str | None, header: bytes
    ) -> Self | None:
        """Returns a specific :class:`AuthenticodeFile` object for the specified file,
        if compatible, or :const:`None` otherwise. Errors are silently ignored by
        :meth:`from_stream`.

        Since most files will use the header for detection, a header of at least 8
        bytes is provided for convenience.
        """
        return None

    def add_catalog(
        self, catalog: CertificateTrustList | BinaryIO, check: bool = False
    ) -> None:
        """Add a catalog file for validation. Catalog files can contain additional
        signatures for signed files. Note that :meth:`get_fingerprint` must be
        implemented.

        :param catalog: The catalog to add. Can be a :class:`CertificateTrustList` or
            a file-like object opened in binary mode.
        :param check:  If `check` is :const:`False`, the catalog will be added
            regardless of whether the current file is actually in the file.

            If `check` is :const:`True`, the current file will be hashed according to
            the hashing scheme of the catalog to verify it is contained within the
            catalog.
        """
        if isinstance(catalog, CertificateTrustList):
            catalog_ = catalog
        else:
            catalog_ = CertificateTrustList.from_envelope(catalog.read())

        if not check or catalog_.find_subject(self):
            self.catalogs = (*self.catalogs, catalog_)

    @property
    def embedded_signatures(self) -> Iterator[AuthenticodeSignature]:
        """Returns an iterator over :class:`AuthenticodeSignature` objects relevant for
        this file. See :meth:`iter_embedded_signatures`
        """

        yield from self.iter_embedded_signatures()

    def iter_embedded_signatures(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[AuthenticodeSignature]:
        """Returns an iterator over :class:`AuthenticodeSignature` objects embedded
        in this Authenticode-signed file.

        :param include_nested: If :const:`True`, will also iterate over all nested
            SignedData structures
        :param ignore_parse_errors: Indicates how to handle
            :exc:`ParseError` that may be raised while fetching
            embedded :class:`AuthenticodeSignature` structures.

            When :const:`True`, which is the default and seems to be how Windows
            handles this as well, this will fetch as many valid
            :class:`AuthenticodeSignature` structures until an exception
            occurs.

            Note that this will also silence the :exc:`ParseError` that occurs
            when there's no valid :class:`AuthenticodeSignature` to fetch.

            When :const:`False`, this will raise the :exc:`ParseError` as
            soon as one occurs.
        :raises ParseError: For parse errors in the signed file
        :raises signify.authenticode.AuthenticodeParseError: For parse errors in the
            SignedData
        """
        raise NotImplementedError

    @property
    def signatures(self) -> Iterator[AuthenticodeSignature | CertificateTrustList]:
        """Returns an iterator over :class:`AuthenticodeSignature` objects embedded
        in this Authenticode-signed file and :class:`CertificateTrustList` objects
        with signatures for this file. See :meth:`iter_signatures`
        """

        yield from self.iter_signatures()

    def iter_signatures(
        self,
        *,
        signature_types: Literal[
            "all", "all+", "catalog", "catalog+", "embedded"
        ] = "all",
        expected_hashes: dict[str, bytes] | None = None,
        include_nested: bool = True,
        ignore_parse_errors: bool = True,
    ) -> Iterator[AuthenticodeSignature | CertificateTrustList]:
        """Returns an iterator over :class:`AuthenticodeSignature` objects embedded
        in this Authenticode-signed file and :class:`CertificateTrustList` objects
        with signatures for this file.

        :param signature_types: Defines which signatures are allowed:

            * ``embedded`` will only consider signatures embedded in the file
            * ``catalog`` will only consider catalog files added through
              :meth:`add_catalog`, excluding those where the current file is not
              listed in the catalog
            * ``catalog+`` same as ``catalog``, but including those catalog files where
              the current file is not listed in the catalog, mostly affecting
              ``multi_verify_mode`` when set to ``all``
            * ``all`` combines ``embedded`` with ``catalog``
            * ``all+`` combines ``embedded`` with ``catalog+``

            Embedded signatures are evaluated before catalog signatures.
        :param expected_hashes: When provided, should be a mapping of hash names to
            digests. This is used when using ``catalog`` or ``all``. The dictionary is
            updated to reflect newly-retrieved hashes.
        :param include_nested: See :meth:`iter_embedded_signatures`
        :param ignore_parse_errors: See :meth:`iter_embedded_signatures`
        :raises AuthenticodeVerificationError: when the verification failed
        :raises ParseError: for parse errors in the signed file
        """
        if signature_types in ("embedded", "all", "all+"):
            yield from self.iter_embedded_signatures(
                ignore_parse_errors=ignore_parse_errors, include_nested=include_nested
            )
        if signature_types in ("catalog+", "all+") and self.catalogs:
            yield from self.catalogs
        elif signature_types in ("catalog", "all") and self.catalogs:
            # Update the expected hashes to include those used for fetching the
            # subjects from the catalogs
            expected_hashes = self._calculate_expected_hashes(
                self.catalogs, expected_hashes
            )
            for catalog in self.catalogs:
                if self._get_subject_from_catalog(catalog, expected_hashes):
                    yield catalog

    def iter_indirect_data(
        self, **kwargs: Any
    ) -> Iterable[tuple[AuthenticodeSignature | CertificateTrustList, IndirectData]]:
        """Simple helper method that allows iterating over all signatures for this
        Authenticode-signed file with their contained :class:`IndirectData` objects.
        The arguments are the same as for :meth:`iter_signatures`.

        Using :meth:`verify_signature` to retrieve the signature, with its
        :class:`IndirectData` and verification result, is often the more appropriate
        method to use.
        """
        for signature in self.iter_signatures(**kwargs):
            if isinstance(signature, AuthenticodeSignature):
                yield signature, signature.indirect_data
            elif isinstance(signature, CertificateTrustList):
                subject = self._get_subject_from_catalog(
                    signature, kwargs.get("expected_hashes", {})
                )
                if subject and subject.indirect_data:
                    yield signature, subject.indirect_data

    def verify(
        self,
        *,
        multi_verify_mode: Literal["any", "first", "all", "best"] = "any",
        signature_types: Literal[
            "all", "all+", "catalog", "catalog+", "embedded"
        ] = "all",
        expected_hashes: dict[str, bytes] | None = None,
        ignore_parse_errors: bool = True,
        publisher_policy: PublisherPolicy | None = None,
        publisher_at: datetime.datetime | None = None,
        **kwargs: Any,
    ) -> list[tuple[SignedData, IndirectData | None, Iterable[list[Certificate]]]]:
        """Verifies the SignedData structures. This is a little bit more efficient than
        calling all verify-methods separately.

        :param multi_verify_mode: Indicates how to verify when there are multiple
            :class:`AuthenticodeSignature` objects in this file. Can be:

            * ``any`` (default) to indicate that any of the signatures must validate
              correctly.
            * ``first`` to indicate that the first signature must verify correctly
              (the default of tools such as sigcheck.exe); this is done in file order,
              followed by any provided catalog signatures
            * ``all`` to indicate that all signatures must verify
            * ``best`` to indicate that the signature using the best hashing algorithm
              must verify (e.g. if both SHA-1 and SHA-256 are present, only SHA-256
              is checked); if multiple signatures exist with the same algorithm,
              any may verify

            This argument has no effect when only one signature is present.
        :param signature_types: See :meth:`iter_signatures`. Note that this affects the
            `multi_verify_mode` as well. Embedded signatures are evaluated before
            catalog signatures.
        :param expected_hashes: When provided, should be a mapping of hash names to
            digests. This could speed up the verification process.
        :param ignore_parse_errors: :meth:`iter_embedded_signatures`
        :return: the used structure(s) in validation, as a list of tuples, in the form
            ``(signed data object, indirect data object, certificate chain)``
        :raises AuthenticodeVerificationError: when the verification failed
        :raises ParseError: for parse errors in the signed file
        """

        # we need to iterate it twice, so we need to prefetch all signed_datas
        signed_datas = list(
            self.iter_signatures(
                signature_types=signature_types,
                expected_hashes=expected_hashes,
                ignore_parse_errors=ignore_parse_errors,
            )
        )

        # if there are no signed_datas, the binary is not signed
        if not signed_datas:
            raise AuthenticodeNotSignedError("No signature was found.")

        # only consider the first signed_data; by selecting it here we prevent
        # calculating more hashes than needed
        if multi_verify_mode == "first":
            signed_datas = [signed_datas[0]]
        elif multi_verify_mode == "best":
            # ACCEPTED_DIGEST_ALGORITHMS contains the algorithms in worst to best order
            best_algorithm = max(
                (sd.digest_algorithm for sd in signed_datas),
                key=lambda alg: [
                    getattr(hashlib, alg) for alg in ACCEPTED_DIGEST_ALGORITHMS
                ].index(alg),
            )
            signed_datas = [
                sd for sd in signed_datas if sd.digest_algorithm == best_algorithm
            ]

        # Calculate all remaining hashes, so excluding those already-provided or
        # previously calculated for the catalog files.
        expected_hashes = self._calculate_expected_hashes(signed_datas, expected_hashes)

        # Now iterate over all SignedDatas
        chains: list[
            tuple[SignedData, IndirectData | None, Iterable[list[Certificate]]]
        ] = []
        last_error = None
        assert signed_datas
        for signed_data in signed_datas:
            try:
                chains.append(
                    self.verify_signature(
                        signed_data, expected_hashes=expected_hashes, **kwargs
                    )
                )
            except Exception as e:  # noqa: PERF203
                # best and any are interpreted as any; first doesn't matter either way,
                # but raising where it is raised is a little bit clearer
                if multi_verify_mode in ("all", "first"):
                    raise
                last_error = e
            else:
                if multi_verify_mode not in ("all", "first"):
                    # only return the last one, as we are in mode any/best
                    if publisher_policy is not None:
                        moment = publisher_at
                        if moment is None:
                            moment = datetime.datetime.now(datetime.timezone.utc)
                        signed_data, _indirect_data, verified_chains = chains[-1]
                        leaf = self._signer_leaf(signed_data, verified_chains)
                        evaluate_publisher(
                            signed_data, leaf, publisher_policy, moment
                        ).raise_if_rejected()
                    return chains[-1:]
        if last_error is None:
            if publisher_policy is not None:
                moment = publisher_at
                if moment is None:
                    moment = datetime.datetime.now(datetime.timezone.utc)
                for signed_data, _indirect_data, verified_chains in chains:
                    leaf = self._signer_leaf(signed_data, verified_chains)
                    evaluate_publisher(
                        signed_data, leaf, publisher_policy, moment
                    ).raise_if_rejected()
            return chains
        raise last_error

    def verify_signature(
        self,
        signed_data: AuthenticodeSignature | CertificateTrustList,
        *,
        expected_hashes: dict[str, bytes],
        **kwargs: Any,
    ) -> tuple[SignedData, IndirectData | None, Iterable[list[Certificate]]]:
        """Verifies a SignedData object, returning the object itself,
        the :class:`IndirectData` object and the :class:`SignedData` verification
        result (i.e. the validation chain).

        If the provided object is :class:`AuthenticodeSignature`, the verification is
        very straightforward, using ``signed_data.indirect_data`` for validation.

        If the provided object is :class:`CertificateTrustList`, the appropriate
        subject is located, and its :class:`IndirectData` is used for validation.
        """
        if isinstance(signed_data, AuthenticodeSignature):
            return (
                signed_data,
                signed_data.indirect_data,
                signed_data.verify(
                    expected_hash=expected_hashes.get(
                        signed_data.indirect_data.digest_algorithm().name
                    ),
                    **kwargs,
                ),
            )
        elif isinstance(signed_data, CertificateTrustList):
            # Attempt to find the subject by attempting to use the expected_hashes
            # dict (find_subject allows bytes), otherwise, simply pass in self
            subject = self._get_subject_from_catalog(signed_data, expected_hashes)
            if subject is None or subject.indirect_data is None:
                raise AuthenticodeNotSignedError(
                    "The provided catalog file does not contain a hash for the provided"
                    " subject."
                )

            # Pop the verify_additional_hashes argument from verify.
            verify_additional_hashes = kwargs.pop("verify_additional_hashes", True)

            # Validate the indirect data directly.
            self.verify_indirect_data(
                subject.indirect_data,
                expected_hash=expected_hashes.get(
                    subject.indirect_data.digest_algorithm().name
                ),
                verify_additional_hashes=verify_additional_hashes,
            )
            return signed_data, subject.indirect_data, signed_data.verify(**kwargs)
        raise AuthenticodeNotSignedError("Unknown SignedData object passed.")

    @staticmethod
    def _signer_leaf(
        signed_data: AuthenticodeSignature | CertificateTrustList,
        chains: Iterable[list[Certificate]],
    ) -> Certificate:
        """Resolves the end-entity (signer) certificate that actually completed
        verification for one SignedData.

        The chains returned by verification run from the trusted anchor to the
        end-entity certificate, so the signer leaf is the *last* certificate. We
        additionally confirm that this is the exact certificate referenced by the
        SignerInfo (issuer + serial number), rather than some other certificate in the
        chain, so a same-named CA in the chain can never be mistaken for the publisher.
        """
        chain = next(iter(chains))
        leaf = chain[-1]

        if isinstance(signed_data, AuthenticodeSignature):
            signer_info = signed_data.signer_info
            if (
                leaf.issuer != signer_info.issuer
                or leaf.serial_number != signer_info.serial_number
            ):
                # Locate the referenced certificate explicitly within the verified
                # chain instead of trusting the chain's last position.
                for certificate in reversed(chain):
                    if (
                        certificate.issuer == signer_info.issuer
                        and certificate.serial_number == signer_info.serial_number
                    ):
                        return certificate
                raise AuthenticodeVerificationError(
                    "The verified chain does not contain the certificate referenced"
                    " by the SignerInfo."
                )

        return leaf

    def verify_publishers(
        self,
        publisher_policy: PublisherPolicy,
        *,
        at: datetime.datetime | None = None,
        expected_hashes: dict[str, bytes] | None = None,
        signature_types: Literal[
            "all", "all+", "catalog", "catalog+", "embedded"
        ] = "all",
        multi_verify_mode: Literal["any", "first", "all", "best"] = "all",
        ignore_parse_errors: bool = True,
        **kwargs: Any,
    ) -> list[PublisherVerification]:
        """Verifies every signature fully (file digest, code signature and trust
        chain) and then constrains each one against the publisher policy.

        Unlike :meth:`verify`, this never short-circuits: each signature is evaluated
        independently and one :class:`PublisherVerification` is returned per
        successfully verified signature, reporting the exact policy entry (or entries)
        on which its signer leaf is accepted. A signature that fails cryptographic or
        chain verification raises before any publisher identity is granted, so a
        rejected signature can never obtain publisher status from another, valid
        signature present in the same file.

        :param publisher_policy: The explicit set of trusted leaf SPKIs and their
            validity intervals.
        :param at: Timestamp used for the publisher validity interval. When
            :const:`None`, the current time is used.
        :return: One publisher decision per fully verified signature.
        :raises AuthenticodePublisherVerificationError: if any verified signer leaf is
            not an allowed publisher.
        :raises AuthenticodeVerificationError: if any signature fails verification.
        """
        # ``all`` makes verify() return every successfully verified structure instead
        # of only the first one, so each publisher can be reported on its own basis.
        results = self.verify(
            multi_verify_mode=multi_verify_mode,
            signature_types=signature_types,
            expected_hashes=expected_hashes,
            ignore_parse_errors=ignore_parse_errors,
            **kwargs,
        )

        moment = at
        if moment is None:
            moment = datetime.datetime.now(datetime.timezone.utc)

        decisions: list[PublisherVerification] = []
        for signed_data, _indirect_data, chains in results:
            leaf = self._signer_leaf(signed_data, chains)
            decision = evaluate_publisher(signed_data, leaf, publisher_policy, moment)
            decision.raise_if_rejected()
            decisions.append(decision)
        return decisions

    def explain_verify(
        self, *args: Any, **kwargs: Any
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        """This will return a value indicating the signature status of this PE file.
        This will not raise an error when the verification fails, but rather
        indicate this through the resulting enum

        :returns: The verification result, and the exception containing
            more details (if available or None)
        """

        return AuthenticodeVerificationResult.call(self.verify, *args, **kwargs)

    def get_fingerprint(self, digest_algorithm: HashFunction) -> bytes:
        """Gets the fingerprint for this file"""
        raise AuthenticodeFingerprintNotProvidedError(
            f"Fingerprint for digest algorithm {digest_algorithm.__name__} could not "
            "be calculated and was not provided as pre-calculated expected hash."
        )

    def get_fingerprints(self, *digest_algorithms: HashFunction) -> dict[str, bytes]:
        """Calculate multiple fingerprints at once.

        This can sometimes provide a small speed-up by pre-calculating all hashes.
        """
        return {
            digest_algorithm().name: self.get_fingerprint(digest_algorithm)
            for digest_algorithm in digest_algorithms
        }

    @classmethod
    def _get_needed_hashes(
        cls,
        signed_datas: Iterable[SignedData],
        expected_hashes: dict[str, bytes],
    ) -> set[HashFunction]:
        """Provided the list of signed datas and already-provided hashes, returns a
        list of hashes that need to be calculated.

        Calculates the expected hashes that are needed for verification. This
        provides a small speed-up by pre-calculating all hashes, so that not each
        individual SignerInfo object is responsible for calculating their own hash.

        :param signed_datas: The signed datas of this object. Provided to allow
            :meth:`verify` to prefetch these
        :param expected_hashes: Hashes provided by the caller of :meth:`verify`
        :return: All required hashes
        """

        # Calculate which hashes we require for the signedinfos
        digest_algorithms = set()
        for signed_data in signed_datas:
            if isinstance(signed_data, AuthenticodeSignature):
                digest_algorithms.add(signed_data.indirect_data.digest_algorithm)
            if isinstance(signed_data, CertificateTrustList):
                digest_algorithms.add(signed_data.subject_algorithm)

        # Calculate which hashes are needed
        provided_hashes = {getattr(hashlib, t) for t in expected_hashes}
        return digest_algorithms - provided_hashes

    def _calculate_expected_hashes(
        self,
        signed_datas: Iterable[SignedData],
        expected_hashes: dict[str, bytes] | None = None,
    ) -> dict[str, bytes]:
        """Calculates the expected hashes that are needed for verification. This
        provides a small speed-up by pre-calculating all hashes, so that not each
        individual SignerInfo object is responsible for calculating their own hash.

        :param signed_datas: The signed datas of this object. Provided to allow
            :meth:`verify` to prefetch these
        :param expected_hashes: Hashes provided by the caller of :meth:`verify`
        :return: All required hashes
        """
        if expected_hashes is None:
            expected_hashes = {}

        return expected_hashes | self.get_fingerprints(
            *self._get_needed_hashes(signed_datas, expected_hashes)
        )

    def _get_subject_from_catalog(
        self, catalog: CertificateTrustList, expected_hashes: dict[str, bytes]
    ) -> CertificateTrustSubject | None:
        """Gets the CertificateTrustSubject from the CertificateTrustList, taking
        the already-provided hashes into account.

        The primary API for this is ``catalog.find_subject(self)``.
        """
        return catalog.find_subject(
            expected_hashes.get(catalog.subject_algorithm().name, self)
        )

    def verify_indirect_data(
        self,
        indirect_data: IndirectData,
        *,
        expected_hash: bytes | None = None,
        verify_additional_hashes: bool = True,
    ) -> None:
        """Verifies the provided IndirectData against the current file. This does not
        verify that the signature itself is properly signed, but verifies that the
        :class:`IndirectData` matches this file.

        This method is called from :meth:`AuthenticodeSignature.verify` for
        :class:`IndirectData` objects contained in an :class:`AuthenticodeSignature`,
        but :meth:`AuthenticodeSignature.verify` does perform some additional checks
        on the used hashing algorithms. Use :meth:`verify_signature` to call the method
        for verification.

        If no expected hash is provided, the hash is calculated by calling
        :meth:`get_fingerprint` with the appropriate algorithm.

        Then, this function will simply verify that the expected hash matches that
        in the provided :class:`IndirectData`.

        Finally, this function calls :meth:`verify_additional_hashes` if requested.

        :param expected_hash: The expected hash digest of the :class:`AuthenticodeFile`.
        :param verify_additional_hashes: Defines whether additional hashes, should
            be verified, such as page hashes for PE files and extended digests for
            MSI files.
        """
        # Check that the hashes are correct
        # 1. The hash of the file
        if expected_hash is None:
            expected_hash = self.get_fingerprint(indirect_data.digest_algorithm)

        if expected_hash != indirect_data.digest:
            raise AuthenticodeInvalidDigestError(
                "The expected hash does not match the digest in the indirect data."
            )

        if verify_additional_hashes:
            self.verify_additional_hashes(indirect_data)

    def verify_additional_hashes(self, indirect_data: IndirectData) -> None:
        """Verifies additional hashes that may be present in the :class:`IndirectData`
        referencing this data. Return :const:`None` when the verification succeeds, or
        raises an error otherwise.

        The default implementation is to do nothing.
        """
        return None
