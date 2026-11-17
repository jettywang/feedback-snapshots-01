from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AuthenticationMode(str, Enum):
    """How SQLCipher page authentication is enforced while reading.

    The default ``OFF`` mode retains the historical behaviour of :class:`SQLCipher`.
    Authentication-aware callers should select either ``REPORT`` or ``STRICT`` explicitly.

    Attributes:
        OFF: Do not perform authentication and do not record any authentication results.
            The legacy ``verify_hmac`` keyword argument remains available on this mode.
        REPORT: Authenticate every page that is read and record the result. A page with an
            invalid HMAC is still decrypted and returned, but its report status is ``FAILED``.
        STRICT: Authenticate every page before returning its plaintext. A page with an invalid
            HMAC raises :class:`PageAuthenticationError` and no plaintext is returned.
    """

    OFF = "off"
    REPORT = "report"
    STRICT = "strict"


class AuthenticationStatus(str, Enum):
    """The authentication outcome for a single page."""

    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    NOT_COVERED = "not_covered"


@dataclass(frozen=True)
class PageAuthentication:
    """The authentication basis for one page that was actually read.

    This object intentionally only contains metadata about how a page was authenticated.
    It never contains the passphrase, derived keys, HMAC values or plaintext data.

    Attributes:
        page_number: The logical page number that was requested.
        status: The authentication outcome.
        algorithm: The page HMAC algorithm of the SQLCipher format, if any.
        page_number_binding: How the page number was bound into the HMAC input.
        plaintext_header_size: Number of leading page 1 bytes stored as a SQLCipher plaintext header.
        uncovered_prefix_size: Number of leading page 1 bytes excluded from the per-page HMAC. For the
            standard layout this is the 16-byte salt; with a plaintext header it is the larger header.
        detail: A short human readable explanation of the outcome.
    """

    page_number: int
    status: AuthenticationStatus
    algorithm: str | None = None
    page_number_binding: str = "uint32-le"
    plaintext_header_size: int = 0
    uncovered_prefix_size: int = 0
    detail: str = ""

    @property
    def authenticated(self) -> bool:
        """Whether the page was covered by an HMAC and that HMAC matched."""
        return self.status is AuthenticationStatus.AUTHENTICATED

    @property
    def covered(self) -> bool:
        """Whether the SQLCipher format defines an HMAC for this page."""
        return self.status is not AuthenticationStatus.NOT_COVERED

    @property
    def basis(self) -> str:
        """Describe the authentication basis without exposing any secret material."""
        if not self.covered:
            return "unavailable: the selected SQLCipher format defines no page HMAC"

        basis = f"HMAC-{self.algorithm} over the encrypted page, IV and {self.page_number_binding} page number"
        if self.page_number == 1 and self.uncovered_prefix_size:
            prefix = "plaintext header" if self.plaintext_header_size else "salt"
            basis += f"; the first {self.uncovered_prefix_size} bytes ({prefix}) are not covered"
        return basis


@dataclass(frozen=True)
class AuthenticationReport:
    """A snapshot of the authentication results for all pages read so far.

    The report is deliberately free of secrets: it contains page numbers, statuses and
    algorithm/version metadata only.

    Attributes:
        mode: The authentication mode that produced this report.
        format: The SQLCipher implementation class name.
        hmac_algorithm: The page HMAC algorithm, or ``None`` if the format has no HMAC.
        hmac_key_derivation: A description of how the HMAC key was derived, or ``None``.
        page_number_binding: How page numbers are encoded in the HMAC input.
        plaintext_header_size: Number of leading page 1 bytes excluded from encryption/HMAC.
        salt_source: Whether the salt came from the database file or was supplied by the caller.
        pages: Authentication results for pages that were actually read, ordered by page number.
    """

    mode: AuthenticationMode
    format: str
    hmac_algorithm: str | None
    hmac_key_derivation: str | None
    page_number_binding: str
    plaintext_header_size: int
    salt_source: str
    pages: tuple[PageAuthentication, ...] = ()

    @property
    def enabled(self) -> bool:
        """Whether an explicit authentication mode is active."""
        return self.mode is not AuthenticationMode.OFF

    @property
    def page_count(self) -> int:
        """The number of pages that were actually read."""
        return len(self.pages)

    @property
    def all_authenticated(self) -> bool:
        """Whether at least one page was read and every read page was authenticated."""
        return bool(self.pages) and all(page.authenticated for page in self.pages)

    @property
    def all_covered(self) -> bool:
        """Whether at least one page was read and every read page has an HMAC in the format."""
        return bool(self.pages) and all(page.covered for page in self.pages)

    @property
    def failed_pages(self) -> tuple[PageAuthentication, ...]:
        """Pages for which an HMAC existed but did not match."""
        return tuple(page for page in self.pages if page.status is AuthenticationStatus.FAILED)

    @property
    def not_covered_pages(self) -> tuple[PageAuthentication, ...]:
        """Pages for which the selected format defines no HMAC."""
        return tuple(page for page in self.pages if page.status is AuthenticationStatus.NOT_COVERED)

    @property
    def unauthenticated_pages(self) -> tuple[PageAuthentication, ...]:
        """All pages that are not authenticated, including failed and not covered pages."""
        return tuple(page for page in self.pages if not page.authenticated)

    def page(self, page_number: int) -> PageAuthentication | None:
        """Return the authentication result for a page, or ``None`` if it was not read."""
        for page in self.pages:
            if page.page_number == page_number:
                return page
        return None

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable, secret-free representation of this report."""
        return {
            "mode": self.mode.value,
            "format": self.format,
            "hmac_algorithm": self.hmac_algorithm,
            "hmac_key_derivation": self.hmac_key_derivation,
            "page_number_binding": self.page_number_binding,
            "plaintext_header_size": self.plaintext_header_size,
            "salt_source": self.salt_source,
            "page_count": self.page_count,
            "all_authenticated": self.all_authenticated,
            "all_covered": self.all_covered,
            "pages": [
                {
                    "page_number": page.page_number,
                    "status": page.status.value,
                    "basis": page.basis,
                    "detail": page.detail,
                }
                for page in self.pages
            ],
        }
