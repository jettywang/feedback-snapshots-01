from __future__ import annotations

import hashlib
import logging
import os
import pathlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO, ClassVar, Literal

from typing_extensions import Self

from signify._typing import HashFunction
from signify.asn1.hashing import ACCEPTED_DIGEST_ALGORITHMS
from signify.authenticode.indirect_data import IndirectData
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
    ParseError,
    SignifyError,
    UnsupportedFileFormatError,
)
from signify.file_types import FailureStage, FileFormat
from signify.pkcs7 import SignedData
from signify.x509 import Certificate

logger = logging.getLogger(__name__)

#: Number of leading bytes read by the format sniffer.  File type detection is
#: intentionally based on these bytes only; it never attempts to parse (or
#: verify) a candidate format to see whether another parser might accept it.
DETECTION_HEADER_SIZE = 8


def _rewind_stream(file_obj: BinaryIO) -> None:
    """Move a seekable stream to offset 0, explaining the requirement if not."""
    try:
        file_obj.seek(0, os.SEEK_SET)
    except (AttributeError, OSError, ValueError) as e:
        raise UnsupportedFileFormatError(
            "File detection requires a seekable binary stream.",
            file_format=FileFormat.UNKNOWN,
        ) from e


def _header_matches_class(header: bytes, cls: type[AuthenticodeFile]) -> bool:
    magics = cls.detection_magic
    if magics is None:
        return True
    return any(header.startswith(magic) for magic in magics)


@dataclass(frozen=True)
class DetectionResult:
    """The outcome of :meth:`AuthenticodeFile.detect`.

    ``file_format`` records which container was selected by the magic-byte
    sniffer.  ``stage`` is set when detection or container parsing failed, and
    can be used by services to decide between rejection, accepting an unsigned
    file, and manual inspection.  ``signed_file`` is present when the container
    could be constructed, even if a subsequent validation step reported
    ``error``.
    """

    file_format: FileFormat
    signed_file: AuthenticodeFile | None = None
    error: SignifyError | None = None
    stage: FailureStage | None = None

    @property
    def format(self) -> FileFormat:
        """Alias for :attr:`file_format`."""
        return self.file_format

    @property
    def failure_stage(self) -> FailureStage | None:
        """Alias for :attr:`stage`."""
        return self.stage

    @property
    def is_supported(self) -> bool:
        """Whether the magic bytes selected a supported Authenticode container."""
        return self.file_format != FileFormat.UNKNOWN

    @property
    def is_usable(self) -> bool:
        """Whether a parser was constructed without a structural parse error."""
        return self.error is None

    @property
    def is_unsigned(self) -> bool:
        return self.stage == FailureStage.UNSIGNED

    @property
    def is_malformed(self) -> bool:
        return self.stage == FailureStage.MALFORMED_SIGNATURE

    @property
    def requires_manual_inspection(self) -> bool:
        return self.stage == FailureStage.MALFORMED_SIGNATURE

    def __iter__(self) -> Iterator[Any]:
        # Convenience for tuple-style use: ``format, signed_file = detect(...)``.
        yield self.file_format
        yield self.signed_file


#: Short alias for callers that prefer a compact name.
FileDetection = DetectionResult


class AuthenticodeFile:
    """An Authenticode-signed file that is to be parsed to find the relevant
    sections for Authenticode parsing.
    """

    catalogs: Iterable[CertificateTrustList] = ()

    #: Format selected by automatic detection.  Concrete parsers set this so
    #: errors raised during later verification can be attributed to the format
    #: that was actually recognized.
    file_format: ClassVar[FileFormat] = FileFormat.UNKNOWN

    #: Exact leading bytes accepted by the magic-based format sniffer.  A value
    #: of ``None`` means the class is not selected by automatic detection.
    detection_magic: ClassVar[tuple[bytes, ...] | None] = None

    #: Parse error class used when a recognized container cannot be opened.
    _parse_error_class: ClassVar[type[ParseError]] = ParseError

    #: Set by :meth:`iter_embedded_signatures` when a recognized container
    #: contains a damaged signature structure.  :meth:`verify` raises it rather
    #: than reporting the file as unsigned.
    signature_parse_error: ParseError | None = None

    @classmethod
    def detect(
        cls,
        file_obj: BinaryIO,
        file_name: str | None = None,
        *,
        allow_flat: bool = False,
    ) -> DetectionResult:
        """Identify the container format without guessing by trial verification.

        Detection is based on the leading magic bytes only.  A recognized
        container is opened with its own parser; if that parser rejects the
        structure, the failure is returned as
        :data:`~signify.file_types.FailureStage.MALFORMED_SIGNATURE` and is
        never retried as another file type (in particular, it is never silently
        downgraded to an unsigned flat image).

        Detection always starts at offset 0, never closes the stream, and
        leaves it at offset 0 on return.  The caller owns the stream and must
        close it.  The parser returned in ``signed_file`` keeps using the same
        stream, so it must remain open as long as signatures are inspected.

        :param file_obj: The seekable binary stream to inspect.
        :param file_name: Optional file name; read from ``file_obj.name`` when
            omitted.
        :param allow_flat: When :const:`True`, files whose magic bytes do not
            match a supported container are reported as ``FLAT`` and are
            opened as a :class:`FlatFile`.  The stream is not consumed beyond
            the detection header, and no fingerprint has been calculated yet.
        :return: A :class:`DetectionResult` describing the selected format,
            the constructed parser (when possible) and any failure stage.
        """
        if file_name is None and hasattr(file_obj, "name"):
            file_name = pathlib.Path(file_obj.name).name

        # Detection is defined relative to the beginning of the stream.  The
        # stream is explicitly rewound before and after the sniff so parsers
        # that use absolute offsets (PE/MSI) see the same layout they always
        # have.  Detection never closes the stream and never reads past the
        # header beyond the leading DETECTION_HEADER_SIZE bytes.
        _rewind_stream(file_obj)
        header = file_obj.read(DETECTION_HEADER_SIZE)
        _rewind_stream(file_obj)

        # Subclass entry points keep the historical behavior of being an
        # auto-detecting constructor: a known magic selects that parser even
        # when called on a different concrete class.  The class's own parser is
        # used only when no other magic matched.
        parser = cls._parser_for_header(header)
        if parser is None and cls is not AuthenticodeFile:
            if cls.detection_magic is None or _header_matches_class(header, cls):
                parser = cls
        if parser is None:
            if allow_flat:
                from .flat import FlatFile

                return DetectionResult(FileFormat.FLAT, signed_file=FlatFile(file_obj))
            error = UnsupportedFileFormatError(
                "Unable to determine file type with available parsers.",
                file_format=FileFormat.UNKNOWN,
            )
            return DetectionResult(FileFormat.UNKNOWN, error=error, stage=error.stage)

        result = cls._open_detected(parser, file_obj, file_name, header)
        # Constructors may seek while validating.  Leave the stream at a known
        # position whether construction succeeded or failed.
        _rewind_stream(file_obj)
        return result

    @classmethod
    def _open_detected(
        cls,
        parser: type[AuthenticodeFile],
        file_obj: BinaryIO,
        file_name: str | None,
        header: bytes,
    ) -> DetectionResult:
        """Open a recognized container, classifying any parse failure."""
        file_format = parser.file_format
        try:
            attempt = parser._try_open(file_obj, file_name, header)
        except Exception as e:
            # Log locally for debugging; the public error deliberately does not
            # chain the decoder exception, whose message may quote file content.
            logger.debug(
                f"Error while opening detected {parser.__name__}",
                exc_info=True,
            )
            error = parser._wrap_open_error(e, file_format=file_format)
            return DetectionResult(file_format, error=error, stage=error.stage)
        if attempt is None:
            # A magic match must produce a parser; anything else means the
            # container is recognized but structurally unusable.
            error = parser._parse_error_for_format(
                f"{parser.__name__} recognized the file but did not return a parser.",
                file_format=file_format,
            )
            return DetectionResult(file_format, error=error, stage=error.stage)
        # Instance-level format overrides the class default so even a parser
        # instantiated directly reports the format that was recognized.
        attempt.__dict__["file_format"] = file_format
        return DetectionResult(file_format, signed_file=attempt)

    @classmethod
    def _parser_for_header(cls, header: bytes) -> type[AuthenticodeFile] | None:
        """Return the parser selected by the magic bytes, without trying one.

        Ordering matters only for overlapping prefixes; pick the most specific
        first (e.g. ``PKCX`` before a generic ASN.1 ``0x30``).  MSI support is
        optional, so a missing ``olefile`` does not prevent detecting the other
        formats.
        """
        from . import ctl, pe, signature

        candidates: list[type[AuthenticodeFile]] = [
            signature.AuthenticodeSignatureFile,
            ctl.CtlFile,
            pe.SignedPEFile,
        ]

        try:
            from . import msi
        except ImportError:  # olefile is an optional dependency
            pass
        else:
            candidates.append(msi.SignedMsiFile)

        for parser in candidates:
            magics = parser.detection_magic
            if magics is None:
                continue
            if any(header.startswith(magic) for magic in magics):
                return parser
        return None

    @classmethod
    def _parse_error_for_format(
        cls, message: str, *, file_format: FileFormat
    ) -> ParseError:
        return cls._parse_error_class(message, file_format=file_format)

    @classmethod
    def _wrap_open_error(
        cls, error: Exception, *, file_format: FileFormat
    ) -> SignifyError:
        """Convert arbitrary parser failures into the public error contract.

        Messages are intentionally generic: exceptions raised by ASN.1 or
        certificate parsing must never include private key material or the full
        contents of the file being inspected.
        """
        if isinstance(error, SignifyError):
            if error.file_format is None:
                error.file_format = file_format
            if error.stage is None:
                error.stage = FailureStage.MALFORMED_SIGNATURE
            return error
        logger.debug(f"Third-party parser raised {type(error).__name__}", exc_info=True)
        return cls._parse_error_for_format(
            f"Unable to parse the recognized {file_format.value.upper()} container.",
            file_format=file_format,
        )

    def _signature_parse_error(self, error: Exception) -> ParseError:
        """Classify a failure while reading an embedded signature structure.

        Signify's own parse errors are preserved, because they describe the
        structural rule that failed and never contain key material or the full
        file body.  Errors from third-party decoders are replaced with a
        generic message; the original is retained as ``__cause__`` for local
        debugging only.
        """
        if isinstance(error, ParseError):
            if error.file_format is None:
                error.file_format = self.file_format
            if error.stage is None:
                error.stage = FailureStage.MALFORMED_SIGNATURE
            return error
        logger.debug(
            f"Third-party decoder raised {type(error).__name__}", exc_info=True
        )
        return self._parse_error_for_format(
            "The recognized file contains a damaged signature structure.",
            file_format=self.file_format,
        )

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

        Detection uses the file's magic bytes only; a recognized but damaged
        container raises a :class:`signify.exceptions.ParseError` subclass
        carrying ``file_format`` and ``stage`` rather than falling back to
        another parser.  Use :meth:`detect` when the selected format and
        failure stage are needed programmatically.

        :param file_obj: The file-like object to read from
        :param file_name: The optional argument can be used to specify the file name.
        :param allow_flat: Indicates whether FlatFile is allowed as a fallback
            for input whose magic bytes do not match a supported container.
        """
        result = cls.detect(file_obj, file_name, allow_flat=allow_flat)
        if result.error is not None:
            raise result.error
        if result.signed_file is None:
            raise UnsupportedFileFormatError(
                "Unable to determine file type with available parsers."
            )
        return result.signed_file

    @classmethod
    def _try_open(
        cls, file_obj: BinaryIO, file_name: str | None, header: bytes
    ) -> Self | None:
        """Returns a specific :class:`AuthenticodeFile` object for the specified file,
        if compatible, or :const:`None` otherwise.

        This remains available for direct construction of a known parser.  The
        automatic detection path does not use it as a fallback: it calls only
        the parser selected by :attr:`detection_magic`, and propagates any
        failure from that parser instead of trying another one.
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

        # Reset any failure recorded by a previous call; iteration below records
        # a fresh classification for this verification attempt.
        self.signature_parse_error = None

        # we need to iterate it twice, so we need to prefetch all signed_datas
        signed_datas = list(
            self.iter_signatures(
                signature_types=signature_types,
                expected_hashes=expected_hashes,
                ignore_parse_errors=ignore_parse_errors,
            )
        )

        # A failure recorded while collecting signatures must take precedence
        # over the empty-set path below.
        if self.signature_parse_error is not None:
            raise self.signature_parse_error

        # if there are no signed_datas, the binary is not signed
        if not signed_datas:
            raise AuthenticodeNotSignedError(
                "No signature was found.", file_format=self.file_format
            )

        try:
            return self._verify_signatures(
                signed_datas,
                multi_verify_mode=multi_verify_mode,
                expected_hashes=expected_hashes,
                **kwargs,
            )
        except SignifyError as e:
            # Attach the recognized format to verification failures so callers
            # can attribute them without re-detecting the file.
            if e.file_format is None:
                e.file_format = self.file_format
            raise

    def _verify_signatures(
        self,
        signed_datas: list[AuthenticodeSignature | CertificateTrustList],
        *,
        multi_verify_mode: Literal["any", "first", "all", "best"],
        expected_hashes: dict[str, bytes] | None,
        **kwargs: Any,
    ) -> list[tuple[SignedData, IndirectData | None, Iterable[list[Certificate]]]]:
        """Verify the prefetched signatures using the requested selection mode."""
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
                    return chains[-1:]
        if last_error is None:
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
