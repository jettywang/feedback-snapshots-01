from __future__ import annotations

import dataclasses
import datetime
import hashlib
import pathlib
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any, cast

import mscerts
from asn1crypto import cms
from typing_extensions import Self

from signify import asn1
from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
from signify.authenticode.signer_info import AuthenticodeSignerInfo
from signify.authenticode.verification_result import (
    AuthenticodeExplainVerifyMixin,
    AuthenticodeVerificationResult,
)
from signify.exceptions import (
    AuthenticodeCounterSignerError,
    AuthenticodeInvalidDigestError,
    CatalogAmbiguousMemberError,
    CatalogMemberNotFoundError,
    CatalogNotACatalogError,
    CertificateTrustListParseError,
    CounterSignerError,
    CTLCertificateVerificationError,
    InvalidDigestError,
)
from signify.pkcs7 import SignedData
from signify.x509 import Certificate, VerificationContext

if TYPE_CHECKING:
    from signify.authenticode import signed_file
    from signify.authenticode.indirect_data import IndirectData

AUTHROOTSTL_PATH = pathlib.Path(mscerts.where(stl=True))


@dataclasses.dataclass(frozen=True)
class CatalogVerificationResult:
    """The successful result of proving that a specific file is covered by a
    catalog.

    Unlike a bare boolean, this reports *how* the conclusion was reached: which
    catalog member was actually used (not merely a member that happened to share a
    display name), and which fingerprint of the target file matched its indirect
    digest.
    """

    catalog: CertificateTrustList
    """The catalog that contains the matching member."""
    member: CertificateTrustSubject
    """The single, unambiguously matched catalog member."""
    fingerprint: bytes
    """The digest calculated over the target file that matched the member."""
    digest_algorithm: HashFunction
    """The hash function used to calculate :attr:`fingerprint`. This is taken from the
    member's :class:`~signify.authenticode.IndirectData`, so that the digest algorithm
    and the member's file type are always interpreted together."""
    content_type: str
    """The Authenticode content type of the member's indirect data (e.g.
    ``microsoft_spc_cab_data`` or ``microsoft_spc_pe_image_data``)."""

    @property
    def fingerprint_hex(self) -> str:
        """The :attr:`fingerprint` as a lowercase hexadecimal string."""
        return self.fingerprint.hex().lower()

    @property
    def member_name(self) -> str | None:
        """The display name recorded in the member's ``catalog_namevalue``, if any.

        This is purely informational: it is never used to decide whether a file matches
        a member.
        """
        namevalue = self.member.catalog_namevalue
        if namevalue and "value" in namevalue:
            return cast(str, namevalue["value"])
        return None


class CertificateTrustListSignerInfo(AuthenticodeSignerInfo):
    parent: CertificateTrustList  # type: ignore[assignment]
    _expected_content_type = "microsoft_ctl"


class CertificateTrustList(AuthenticodeExplainVerifyMixin, SignedData):
    """A subclass of :class:`signify.pkcs7.SignedData`, containing a list of trusted
    root certificates. It is based on the following ASN.1 structure::

        CertificateTrustList ::= SEQUENCE {
          version CTLVersion DEFAULT v1,
          subjectUsage SubjectUsage,
          listIdentifier ListIdentifier OPTIONAL,
          sequenceNumber HUGEINTEGER OPTIONAL,
          ctlThisUpdate ChoiceOfTime,
          ctlNextUpdate ChoiceOfTime OPTIONAL,
          subjectAlgorithm AlgorithmIdentifier,
          trustedSubjects TrustedSubjects OPTIONAL,
          ctlExtensions [0] EXPLICIT Extensions OPTIONAL
        }
        CTLVersion ::= INTEGER {v1(0)}
        SubjectUsage ::= EnhancedKeyUsage
        ListIdentifier ::= OCTETSTRING
        TrustedSubjects ::= SEQUENCE OF TrustedSubject
        TrustedSubject ::= SEQUENCE{
          subjectIdentifier SubjectIdentifier,
          subjectAttributes Attributes OPTIONAL
        }
        SubjectIdentifier ::= OCTETSTRING

    .. warning::

       The CTL itself is currently not verifiable.

    """

    _signerinfo_class_name = CertificateTrustListSignerInfo
    _expected_content_type = "microsoft_ctl"
    content_asn1: asn1.ctl.CertificateTrustList

    def iter_recursive_nested(self) -> Iterator[CertificateTrustList]:
        """Returns an iterator over the current object. Included for compatibility
        with :class:`AuthenticodeSignature`.
        """
        yield self

    @property
    def subject_usage(self) -> list[str]:
        """Defines the EKU of the Certificate Trust List."""
        return cast(list[str], self.content_asn1["subject_usage"].native)

    @property
    def is_catalog(self) -> bool:
        return "microsoft_catalog_list" in self.subject_usage

    @property
    def list_identifier(self) -> bytes | None:
        """The name of the template of the list."""
        return cast("bytes | None", self.content_asn1["list_identifier"].native)

    @property
    def sequence_number(self) -> int:
        """The unique number of this list"""
        return cast(int, self.content_asn1["sequence_number"].native)

    @property
    def this_update(self) -> datetime.datetime | None:
        """The date of the current CTL."""
        return cast(
            "datetime.datetime | None", self.content_asn1["ctl_this_update"].native
        )

    @property
    def next_update(self) -> datetime.datetime | None:
        """The date of the next CTL."""
        return cast(
            "datetime.datetime | None", self.content_asn1["ctl_next_update"].native
        )

    @property
    def _subject_algorithm(self) -> str:
        return cast(str, self.content_asn1["subject_algorithm"]["algorithm"].native)

    @property
    def subject_algorithm(self) -> HashFunction:
        """Digest algorithm of identifying subjects in the list."""
        algorithm = self._subject_algorithm
        if algorithm == "microsoft_catalog_list_member":
            return hashlib.sha1
        elif algorithm == "microsoft_catalog_list_member_v2":
            return hashlib.sha256
        return _get_digest_algorithm(
            self.content_asn1["subject_algorithm"],
            location="CertificateTrustList.subjectAlgorithm",
        )

    @property
    def _is_catalog_member_algorithm(self) -> bool:
        return self._subject_algorithm in (
            "microsoft_catalog_list_member",
            "microsoft_catalog_list_member_v2",
        )

    def _iter_subjects_by_key(self, key: str) -> list[CertificateTrustSubject]:
        """Returns all subjects matching the provided lookup key, preserving catalog
        order. Used instead of a dictionary comprehension so that duplicate keys (e.g.
        two members with the same indirect digest) are not silently collapsed by a
        dictionary overwrite.
        """
        if self._is_catalog_member_algorithm:
            return [
                subject
                for subject in self.subjects
                if subject.indirect_data is not None
                and subject.indirect_data.digest.hex().lower() == key
            ]
        return [subject for subject in self.subjects if subject.identifier_str == key]

    # TODO: extensions??

    @property
    def subjects(self) -> Iterable[CertificateTrustSubject]:
        """A list of :class:`CertificateTrustSubject` s in this list."""
        return (
            CertificateTrustSubject(subject, self)
            for subject in self.content_asn1["trusted_subjects"]
        )

    def verify(self, *args: Any, **kwargs: Any) -> Iterable[list[Certificate]]:
        """Override to make sure that the TRUSTED_CERTIFICATE_STORE is set properly and
        that the proper exceptions are raised.
        """
        if "trusted_certificate_store" not in kwargs:
            from signify.authenticode import TRUSTED_CERTIFICATE_STORE

            kwargs["trusted_certificate_store"] = TRUSTED_CERTIFICATE_STORE

        try:
            return super().verify(*args, **kwargs)
        except InvalidDigestError as e:
            raise AuthenticodeInvalidDigestError(str(e))
        except CounterSignerError as e:
            raise AuthenticodeCounterSignerError(str(e))

    def verify_trust(self, chain: list[Certificate], *args: Any, **kwargs: Any) -> bool:
        """Checks whether the specified certificate is valid in the given conditions
        according to this Certificate Trust List.

        :param chain: The certificate chain to verify
        """

        # Find the subject belonging to this certificate
        subject = self.find_subject(chain[0])
        if not subject:
            raise CTLCertificateVerificationError(
                f"The root {chain[0]} is not in the certificate trust list"
            )
        return subject.verify_trust(chain, *args, **kwargs)

    def _lookup_key(
        self, subject: Certificate | signed_file.AuthenticodeFile | bytes
    ) -> str:
        """Calculates the lookup key (a lowercase hexadecimal string) for the provided
        certificate, file or raw digest, following the catalog's
        :attr:`subject_algorithm`.
        """
        if isinstance(subject, Certificate):
            if self.subject_algorithm == hashlib.sha1:
                return subject.sha1_fingerprint
            elif self.subject_algorithm == hashlib.sha256:
                return subject.sha256_fingerprint
            raise CertificateTrustListParseError(
                "The specified subject algorithm is not yet supported."
            )
        elif isinstance(subject, bytes):
            return subject.hex().lower()
        fingerprint = subject.get_fingerprint(self.subject_algorithm)
        return fingerprint.hex().lower()

    def find_subject(
        self, subject: Certificate | signed_file.AuthenticodeFile | bytes
    ) -> CertificateTrustSubject | None:
        """Finds the :class:`CertificateTrustSubject` belonging to the provided
        :class:`signify.x509.Certificate` or :class:`signed_file.AuthenticodeFile`.

        For catalogs, members are located by the digest in their
        :class:`~signify.authenticode.IndirectData`, never by the member's display
        name.

        This returns a single subject for backwards compatibility and returns
        :const:`None` when nothing matches. When multiple members match (an ambiguous
        catalog), the first is returned here; use :meth:`find_catalog_members` or
        :meth:`verify_file` to have such cases explicitly reported instead of silently
        resolved.

        :param subject: The certificate or file to look for.
        """
        matches = self._iter_subjects_by_key(self._lookup_key(subject))
        if not matches:
            return None
        return matches[0]

    def find_catalog_members(
        self, file: signed_file.AuthenticodeFile | bytes
    ) -> list[CertificateTrustSubject]:
        """Returns all catalog members whose indirect digest equals the fingerprint of
        the provided file (or a raw digest provided as :class:`bytes`).

        The file is hashed with the catalog's :attr:`subject_algorithm` (SHA-1 for
        catalog v1, SHA-256 for catalog v2), which is the algorithm that produces the
        member identifier. Members are only considered when they actually carry
        :class:`~signify.authenticode.IndirectData`; entries without indirect data can
        never prove a file's contents.

        A list (rather than a dictionary) is returned so that duplicate members are
        preserved. :meth:`verify_file` uses this to report ambiguity explicitly instead
        of letting a dictionary overwrite pick the winner.

        :raises CatalogNotACatalogError: if this list is not a file catalog.
        """
        if not self.is_catalog:
            raise CatalogNotACatalogError(
                "This Certificate Trust List is not a file catalog (its subject usage"
                f" is {self.subject_usage!r}, not containing 'microsoft_catalog_list')."
                " A regular certificate trust list cannot be used to prove a file."
            )
        return self._iter_subjects_by_key(self._lookup_key(file))

    def verify_file(
        self,
        file: signed_file.AuthenticodeFile,
        *,
        verify_catalog_signature: bool = True,
        verify_additional_hashes: bool = True,
        expected_hash: bytes | None = None,
        **kwargs: Any,
    ) -> CatalogVerificationResult:
        """Proves that the provided file is covered by this catalog.

        This is the explicit "use this catalog to prove this file" interface. It does
        *not* treat the mere presence of a same-named member as success. All of the
        following must hold:

        1. This object must actually be a file catalog (``microsoft_catalog_list``
           subject usage). A regular certificate trust list that merely shares the
           structure is rejected.
        2. The catalog's own signature must verify (unless
           ``verify_catalog_signature=False``).
        3. Exactly one member must match the file's contents. Membership is established
           by the indirect digest, never by the member's display name. If several
           members carry the same digest, an ambiguity is reported.
        4. The digest algorithm and the Authenticode file type recorded in the member's
           :class:`~signify.authenticode.IndirectData` must be interpreted together:
           the file is hashed with that exact algorithm and the resulting fingerprint
           must equal the member's digest.

        :param file: The file to prove.
        :param verify_catalog_signature: If :const:`True` (the default), verifies the
            catalog's own PKCS#7 signature before trusting its members.
        :param verify_additional_hashes: Forwarded to the file's indirect-data
            verification (e.g. PE page hashes), when applicable.
        :param expected_hash: A pre-calculated fingerprint of the file using the
            catalog's :attr:`subject_algorithm`. When omitted, the fingerprint is
            calculated from the file.
        :param kwargs: Additional keyword arguments forwarded to
            :meth:`CertificateTrustList.verify` when verifying the catalog signature.
        :return: A :class:`CatalogVerificationResult` identifying the member that was
            actually used and the matching file fingerprint.
        :raises CatalogNotACatalogError: if this is not a file catalog.
        :raises CatalogMemberNotFoundError: if no member matches the file.
        :raises CatalogAmbiguousMemberError: if multiple members match the file.
        :raises AuthenticodeInvalidDigestError: if the matched member's digest does not
            match the file's contents under the member's digest algorithm.
        """
        if not self.is_catalog:
            raise CatalogNotACatalogError(
                "This Certificate Trust List is not a file catalog (its subject usage"
                f" is {self.subject_usage!r}, not containing 'microsoft_catalog_list')."
                " A regular certificate trust list cannot be used to prove a file."
            )

        # 1. Verify the catalog's own signature before trusting any of its members.
        if verify_catalog_signature:
            self.verify(**kwargs)

        # 2. Locate members by the file fingerprint using the catalog's member
        # algorithm. This hashes the file with the catalog v1/v2 subject algorithm.
        if expected_hash is None:
            expected_hash = file.get_fingerprint(self.subject_algorithm)
        members = self.find_catalog_members(expected_hash)

        if not members:
            raise CatalogMemberNotFoundError(
                "The catalog does not contain a member whose indirect digest matches"
                f" the {self.subject_algorithm.__name__} fingerprint"
                f" {expected_hash.hex().lower()} of the provided file. A member with a"
                " matching display name is not sufficient."
            )
        if len(members) > 1:
            raise CatalogAmbiguousMemberError(
                f"The catalog contains {len(members)} members whose indirect digest"
                f" matches the file fingerprint {expected_hash.hex().lower()}. The"
                " matching member is ambiguous; refusing to pick one by dictionary"
                " ordering."
            )

        member = members[0]
        indirect_data = member.indirect_data
        # find_catalog_members only returns members with indirect data, but be explicit.
        if indirect_data is None:  # pragma: no cover - guarded by find_catalog_members
            raise CatalogMemberNotFoundError(
                "The matching catalog member does not contain indirect data and cannot"
                " prove the file's contents."
            )

        # 3. Interpret the digest algorithm and the file type together: hash the file
        # with the member's own digest algorithm and require an exact digest match.
        member_algorithm = indirect_data.digest_algorithm
        member_fingerprint = file.get_fingerprint(member_algorithm)
        file.verify_indirect_data(
            indirect_data,
            expected_hash=member_fingerprint,
            verify_additional_hashes=verify_additional_hashes,
        )

        return CatalogVerificationResult(
            catalog=self,
            member=member,
            fingerprint=member_fingerprint,
            digest_algorithm=member_algorithm,
            content_type=indirect_data.content_type,
        )

    def explain_verify_file(
        self, file: signed_file.AuthenticodeFile, **kwargs: Any
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        """Non-raising variant of :meth:`verify_file`. Returns the verification result
        and the exception (if any) instead of raising.
        """
        return AuthenticodeVerificationResult.call(self.verify_file, file, **kwargs)

    @classmethod
    def from_stl_file(cls, path: pathlib.Path = AUTHROOTSTL_PATH) -> Self:
        """Loads a :class:`CertificateTrustList` from a specified path."""

        with path.open("rb") as f:
            data = cms.ContentInfo.load(f.read())

        if data["content_type"].native != "signed_data":
            raise CertificateTrustListParseError(
                "ContentInfo does not contain SignedData"
            )

        signed_data = cls(data["content"])
        return signed_data


class CertificateTrustSubject:
    """A subject listed in a :class:`CertificateTrustList`. The structure in this object
    has mostly been reverse-engineered using Windows tooling such as ``certutil -dump``.
    We do not pretend to have a complete picture of all the edge-cases that are
    considered.

    .. warning::

       The interpretation of the various attributes and their implications has been
       reverse-engineered. Though we seem to have a fairly solid understanding, various
       edge-cases may not have been considered.

    """

    def __init__(self, asn1: asn1.ctl.TrustedSubject, parent: CertificateTrustList):
        self.asn1 = asn1
        self.parent = parent

    @property
    def identifier(self) -> bytes:
        return cast(bytes, self.asn1["subject_identifier"].native)

    @property
    def identifier_str(self) -> str:
        """Return :attr:`identifier` as a string. This is usually the hex encoding
        of the byte string, but in the case of ``microsoft_catalog_list``, this can be
        a UTF-16 encoded string if indirect_data is present.
        """
        if not self.indirect_data:
            return self.identifier.hex().lower()
        try:
            value = self.identifier.decode("utf-16").rstrip("\0")
            # Attempt to encode in latin-1. If this is not possible, we can assume that
            # this is not intended to be decoded.
            value.encode("latin-1")
            return value
        except (UnicodeDecodeError, UnicodeEncodeError):
            return self.identifier.hex().lower()

    @property
    def attributes(self) -> dict[str, Any]:
        """A dictionary mapping of attribute types to singular native values."""
        return {k: v.native[0] for k, v in self.attributes_asn1.items()}

    @property
    def attributes_asn1(self) -> dict[str, Any]:
        """A dictionary mapping of attribute types to ASN.1 values."""
        return {
            attr["type"].native: attr["values"]
            for attr in self.asn1["subject_attributes"]
        }

    @property
    def extended_key_usages(self) -> list[str] | None:
        """Defines the EKU's the certificate is valid for. It may be empty, which we
        take as 'all is acceptable'.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "list[str] | None", self.attributes.get("microsoft_ctl_enhkey_usage", None)
        )

    @property
    def friendly_name(self) -> str | None:
        """The friendly name of the certificate.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "str | None", self.attributes.get("microsoft_ctl_friendly_name", None)
        )

    @property
    def key_identifier(self) -> bytes:
        """The sha1 fingerprint of the certificate.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(bytes, self.attributes.get("microsoft_ctl_key_identifier", b""))

    @property
    def subject_name_md5(self) -> bytes:
        """The md5 of the subject name.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            bytes, self.attributes.get("microsoft_ctl_subject_name_md5_hash", b"")
        )

    @property
    def root_program_cert_policies(self) -> list[dict[str, Any]] | None:
        """The policies applicable to the root certificate.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "list[dict[str, Any]] | None",
            self.attributes.get("microsoft_ctl_root_program_cert_policies", None),
        )

    @property
    def auth_root_sha256(self) -> bytes:
        """The sha256 fingerprint of the certificate.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            bytes, self.attributes.get("microsoft_ctl_auth_root_sha256_hash", b"")
        )

    @property
    def disallowed_filetime(self) -> datetime.datetime | None:
        """The time since when a certificate has been disabled. Digital signatures with
        a timestamp prior to this date continue to be valid, but use cases after this
        date are prohibited. It may be used in conjunction with
        :attr:`disallowed_extended_key_usages` to define specific EKU's to be disabled.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "datetime.datetime | None",
            self.attributes.get("microsoft_ctl_disallowed_filetime", None),
        )

    @property
    def root_program_chain_policies(self) -> list[str] | None:
        """A list of EKU's probably used for EV certificates.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "list[str] | None",
            self.attributes.get("microsoft_ctl_root_program_chain_policies", None),
        )

    @property
    def disallowed_extended_key_usages(self) -> list[str] | None:
        """Defines the EKU's the certificate is not valid for. When used in combination
        with :attr:`disallowed_filetime`, the disabled EKU's are only disabled from
        that date onwards, otherwise, it means since the beginning of time.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "list[str] | None",
            self.attributes.get("microsoft_ctl_disallowed_enhkey_usage", None),
        )

    @property
    def not_before_filetime(self) -> datetime.datetime | None:
        """The time since when new certificates from this CA are not trusted.
        Certificates from prior the date will continue to validate. When used in
        conjunction with :attr:`not_before_extended_key_usages`, this only concerns
        certificates issued after this date for the defined EKU's.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "datetime.datetime | None",
            self.attributes.get("microsoft_ctl_not_before_filetime", None),
        )

    @property
    def not_before_extended_key_usages(self) -> list[str] | None:
        """Defines the EKU's for which the :attr:`not_before_filetime` is considered. If
        that attribute is not defined, we assume that it means since the beginning of
        time.

        Typically available for Certificate Trust Lists (i.e. non-catalog files).
        """
        return cast(
            "list[str] | None",
            self.attributes.get("microsoft_ctl_not_before_enhkey_usage", None),
        )

    @property
    def catalog_namevalue(self) -> dict[str, str | int] | None:
        """Return information about the CAT entry.

        Typically available for catalog files (i.e. not CTLs).
        """
        return cast(
            "dict[str, str | int] | None",
            self.attributes.get("microsoft_cat_namevalue", None),
        )

    @property
    def catalog_memberinfo(self) -> dict[str, str | int] | None:
        """Return information about the CAT entry.

        Typically available for catalog files (i.e. not CTLs).
        """
        return cast(
            "dict[str, str | int] | None",
            self.attributes.get("microsoft_cat_memberinfo", None),
        )

    @property
    def indirect_data(self) -> IndirectData | None:
        """Return the indirect data for this subject.

        Typically available for catalog files (i.e. not CTLs).
        """
        if "microsoft_spc_indirect_data_content" in self.attributes_asn1:
            from signify.authenticode.indirect_data import IndirectData

            return IndirectData(
                self.attributes_asn1["microsoft_spc_indirect_data_content"][0]
            )
        return None

    def verify_trust(
        self, chain: list[Certificate], context: VerificationContext
    ) -> bool:
        """Checks whether the specified certificate is valid in the given conditions
        according to this Certificate Trust List.

        :param chain: The certificate chain to verify.
        :param context: The context to verify with. Mainly the
            :attr:`VerificationContext.timestamp` and
            :attr:`VerificationContext.extended_key_usages` are used.
        """

        timestamp = context.timestamp
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        extended_key_usages = context.extended_key_usages
        if extended_key_usages is None:
            extended_key_usages = ()

        # Start by converting the list of provided extended_key_usages to a list of OIDs
        requested_extended_key_usages = set(extended_key_usages)

        # Now check each of the properties
        if self.extended_key_usages and (
            requested_extended_key_usages - set(self.extended_key_usages)
        ):
            raise CTLCertificateVerificationError(
                f"The root {self.friendly_name} lists its extended key usages, but"
                f" {requested_extended_key_usages - set(self.extended_key_usages)} are"
                " not present"
            )

        # The notBefore time does concern the validity of the certificate that is being
        # validated. It must have a notBefore of before the timestamp
        if self.not_before_filetime is not None:
            to_verify_timestamp = chain[-1].valid_from

            if to_verify_timestamp >= self.not_before_filetime:
                # If there is a notBefore time, and there is no NotBeforeEnhkeyUsage,
                # then the validity concerns the entire certificate.
                if self.not_before_extended_key_usages is None:
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} is disallowed for certificate"
                        f" issued after {self.not_before_filetime} (certificate is"
                        f" {to_verify_timestamp})"
                    )
                elif any(
                    eku in self.not_before_extended_key_usages
                    for eku in requested_extended_key_usages
                ):
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} disallows requested EKU's"
                        f" {requested_extended_key_usages} to certificates issued after"
                        f" {self.not_before_filetime} (certificate is"
                        f" {to_verify_timestamp})"
                    )
        elif self.not_before_extended_key_usages is not None and any(
            eku in self.not_before_extended_key_usages
            for eku in requested_extended_key_usages
        ):
            raise CTLCertificateVerificationError(
                f"The root {self.friendly_name} disallows requested EKU's"
                f" {requested_extended_key_usages}"
            )

        # The DisallowedFiletime time does concern the timestamp of the signature
        # being verified.
        if self.disallowed_filetime is not None:
            if timestamp >= self.disallowed_filetime:
                # If there is a DisallowedFiletime, and there is no
                # DisallowedEnhkeyUsage, then the validity concerns the entire
                # certificate.
                if self.disallowed_extended_key_usages is None:
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} is disallowed since "
                        f"{self.disallowed_filetime} (requested {timestamp})"
                    )
                elif any(
                    eku in self.disallowed_extended_key_usages
                    for eku in requested_extended_key_usages
                ):
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} is disallowed for EKU's"
                        f" {self.disallowed_extended_key_usages} since"
                        f" {self.disallowed_filetime} (requested"
                        f" {requested_extended_key_usages} at {timestamp})"
                    )
        elif self.disallowed_extended_key_usages is not None and any(
            eku in self.disallowed_extended_key_usages
            for eku in requested_extended_key_usages
        ):
            raise CTLCertificateVerificationError(
                f"The root {self.friendly_name} disallows requested EKU's"
                f" {requested_extended_key_usages}"
            )

        return True
