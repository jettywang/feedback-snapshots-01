from __future__ import annotations

import io
import json

import pytest
from dissect.database.sqlite3.encryption.sqlcipher import (
    AuthenticationMode,
    AuthenticationStatus,
    PageAuthenticationError,
    SQLCipher1,
    SQLCipher2,
    SQLCipher3,
    SQLCipher4,
)

from tests._util import absolute_path
from tests.sqlite3._sqlcipher_vector import KEY, PAGE_SIZE, build_vector, plaintext_pages

VECTOR_PASSPHRASE = KEY
ALL_PAGES = PAGE_SIZE * 4
SQLCIPHER_DATA = "_data/sqlite3/encryption/sqlcipher/"


def _open(data: bytes, authentication: AuthenticationMode) -> SQLCipher2:
    return SQLCipher2(io.BytesIO(data), VECTOR_PASSPHRASE, no_kdf=True, authentication=authentication)


def _read_all(sqlcipher: SQLCipher2) -> bytes:
    return sqlcipher.stream().read(ALL_PAGES)


def test_authenticated_normal_vector() -> None:
    """A pristine vector authenticates every page and preserves the decrypted plaintext."""
    db = _open(build_vector(), AuthenticationMode.REPORT)
    plaintext = _read_all(db)

    assert plaintext == b"".join(plaintext_pages())

    report = db.authentication_report()
    assert report.mode is AuthenticationMode.REPORT
    assert report.format == "SQLCipher2"
    assert report.hmac_algorithm == "sha1"
    assert report.page_number_binding == "uint32-le"
    assert report.page_count == 4
    assert report.all_authenticated is True
    assert report.all_covered is True
    assert report.failed_pages == ()
    assert report.not_covered_pages == ()

    page_one = db.page_authentication(1)
    assert page_one.status is AuthenticationStatus.AUTHENTICATED
    assert page_one.authenticated is True
    assert page_one.covered is True
    assert page_one.plaintext_header_size == 0
    assert page_one.uncovered_prefix_size == 16
    assert page_one.page_number_binding == "uint32-le"
    assert "HMAC-sha1" in page_one.basis


def test_page_swap_is_detected() -> None:
    """Swapping two encrypted page positions invalidates the page-number binding of both pages."""
    db = _open(build_vector(swap_pages=True), AuthenticationMode.REPORT)
    _read_all(db)

    report = db.authentication_report()
    assert report.all_authenticated is False
    assert [page.page_number for page in report.failed_pages] == [3, 4]
    assert db.page_authentication(1).authenticated is True
    assert db.page_authentication(2).authenticated is True
    assert db.page_authentication(3).status is AuthenticationStatus.FAILED
    assert db.page_authentication(4).status is AuthenticationStatus.FAILED


def test_single_byte_tamper_is_detected() -> None:
    """A one-byte ciphertext change fails authentication for exactly that page."""
    db = _open(build_vector(tamper_page=3), AuthenticationMode.REPORT)
    _read_all(db)

    report = db.authentication_report()
    assert [page.page_number for page in report.failed_pages] == [3]
    assert report.unauthenticated_pages == report.failed_pages
    assert db.page_authentication(1).authenticated is True
    assert db.page_authentication(2).authenticated is True
    assert db.page_authentication(3).status is AuthenticationStatus.FAILED
    assert db.page_authentication(4).authenticated is True


def test_random_and_sequential_reads_share_policy() -> None:
    """Both random and sequential reads go through the same authentication policy."""
    data = build_vector(tamper_page=3)

    sequential = _open(data, AuthenticationMode.REPORT)
    _read_all(sequential)
    sequential_report = sequential.authentication_report()

    random = _open(data, AuthenticationMode.REPORT)
    random.stream().readoffset(PAGE_SIZE * 2, PAGE_SIZE)
    random.stream().readoffset(0, PAGE_SIZE)
    random.stream().readoffset(PAGE_SIZE * 3, PAGE_SIZE)
    random.stream().readoffset(PAGE_SIZE, PAGE_SIZE)
    random_report = random.authentication_report()

    assert random_report.pages == sequential_report.pages
    assert random_report.all_authenticated is False
    assert [page.page_number for page in random_report.failed_pages] == [3]


def test_strict_refuses_plaintext_for_bad_page() -> None:
    """Strict mode raises before returning any plaintext for a failing page."""
    db = _open(build_vector(tamper_page=3), AuthenticationMode.STRICT)

    with pytest.raises(PageAuthenticationError) as exc_info:
        db.stream().readoffset(PAGE_SIZE * 2, 16)

    assert exc_info.value.page_number == 3
    assert exc_info.value.authentication is not None
    assert exc_info.value.authentication.status is AuthenticationStatus.FAILED
    assert db.page_authentication(3).status is AuthenticationStatus.FAILED


def test_strict_sequential_read_stops_before_bad_page() -> None:
    """A sequential strict read returns earlier pages but raises instead of returning the bad page."""
    db = _open(build_vector(tamper_page=3), AuthenticationMode.STRICT)
    stream = db.stream()

    assert stream.read(PAGE_SIZE * 2) == b"".join(plaintext_pages()[:2])

    with pytest.raises(PageAuthenticationError) as exc_info:
        stream.read(PAGE_SIZE)

    assert exc_info.value.page_number == 3


def test_legacy_verify_hmac_uses_strict_mode() -> None:
    """The historical verify_hmac switch keeps its semantics but is expressed as strict mode."""
    data = build_vector(tamper_page=2)

    db = SQLCipher2(io.BytesIO(data), VECTOR_PASSPHRASE, no_kdf=True, verify_hmac=True)
    with pytest.raises(PageAuthenticationError):
        db.stream().readoffset(PAGE_SIZE, 16)

    db = SQLCipher2(io.BytesIO(build_vector()), VECTOR_PASSPHRASE, no_kdf=True, verify_hmac=True)
    assert db.authentication is AuthenticationMode.STRICT
    assert db.authentication_report().all_authenticated is True


def test_off_mode_has_no_authentication_semantics() -> None:
    """The default mode does not perform or record authentication."""
    db = _open(build_vector(), AuthenticationMode.OFF)
    assert _read_all(db) == b"".join(plaintext_pages())

    report = db.authentication_report()
    assert report.mode is AuthenticationMode.OFF
    assert report.pages == ()
    assert report.all_authenticated is False


def test_format_without_hmac_reports_not_covered() -> None:
    """SQLCipher 1 has no page HMAC, so a valid decrypted header is not authentication."""
    path = absolute_path(SQLCIPHER_DATA + "aes256_hmac_none_kdf_4000.sqlite")
    db = SQLCipher1(path, "passphrase", authentication=AuthenticationMode.REPORT)
    assert db.stream().read(16) == b"SQLite format 3\x00"

    report = db.authentication_report()
    assert report.hmac_algorithm is None
    assert report.page_number_binding == "none"
    assert report.all_authenticated is False
    assert report.all_covered is False
    assert report.page(1).status is AuthenticationStatus.NOT_COVERED
    assert report.page(1).covered is False
    assert "no page HMAC" in report.page(1).basis

    with pytest.raises(ValueError, match="requires a SQLCipher format with a page HMAC"):
        SQLCipher1(path, "passphrase", authentication=AuthenticationMode.STRICT)


@pytest.mark.parametrize(
    ("cipher", "filename", "kwargs"),
    [
        pytest.param(SQLCipher4, "aes256_hmac_sha512_kdf_256000.sqlite", {}, id="v4"),
        pytest.param(SQLCipher3, "aes256_hmac_sha1_kdf_64000.sqlite", {}, id="v3"),
        pytest.param(SQLCipher2, "aes256_hmac_sha1_kdf_4000.sqlite", {}, id="v2"),
        pytest.param(
            SQLCipher4,
            "aes256_hmac_sha256_kdf_sha1_1337_page_8kb.sqlite",
            {"page_size": 8192, "hmac_algo": "sha256", "kdf_algo": "sha1", "kdf_iter": 1337},
            id="v4-custom",
        ),
        pytest.param(
            SQLCipher4,
            "aes256_hmac_sha512_kdf_256000_plain_header.sqlite",
            {"salt": bytes.fromhex("01" * 16)},
            id="v4-plaintext-header",
        ),
    ],
)
def test_real_vectors_authenticate(cipher: type, filename: str, kwargs: dict) -> None:
    """All SQLCipher versions with an HMAC authenticate every page they read."""
    db = cipher(
        absolute_path(SQLCIPHER_DATA + filename), "passphrase", authentication=AuthenticationMode.STRICT, **kwargs
    )

    report = db.authentication_report()
    assert report.enabled is True
    assert report.page_count >= 1
    assert report.all_authenticated is True
    assert report.hmac_algorithm is not None

    db.stream().read(16)
    db.stream().readoffset(db.cipher_page_size, 16)
    assert db.authentication_report().all_authenticated is True


def test_custom_hmac_algorithm_derives_correct_key() -> None:
    """A custom HMAC algorithm must not be confused with the KDF algorithm for key derivation."""
    path = absolute_path(SQLCIPHER_DATA + "aes256_hmac_sha256_kdf_sha1_1337_page_8kb.sqlite")
    db = SQLCipher4(
        path,
        "passphrase",
        page_size=8192,
        hmac_algo="sha256",
        kdf_algo="sha1",
        kdf_iter=1337,
        authentication=AuthenticationMode.REPORT,
    )
    db.stream().read(16)

    report = db.authentication_report()
    assert report.hmac_algorithm == "sha256"
    assert "PBKDF2-HMAC-sha1" in report.hmac_key_derivation
    assert db.page_authentication(1).authenticated is True


def test_plaintext_header_is_reported_as_uncovered_prefix() -> None:
    """A plaintext header is excluded from the HMAC, even though the remaining page authenticates."""
    path = absolute_path(SQLCIPHER_DATA + "aes256_hmac_sha512_kdf_256000_plain_header.sqlite")
    db = SQLCipher4(
        path,
        "passphrase",
        salt=bytes.fromhex("01" * 16),
        authentication=AuthenticationMode.REPORT,
    )

    page_one = db.page_authentication(1)
    assert page_one.status is AuthenticationStatus.AUTHENTICATED
    assert page_one.plaintext_header_size == 32
    assert page_one.uncovered_prefix_size == 32
    assert "plaintext header" in page_one.basis
    assert "not covered" in page_one.basis


def test_report_contains_no_secrets() -> None:
    """The report must not contain the passphrase, derived keys, HMAC values or plaintext."""
    db = _open(build_vector(), AuthenticationMode.REPORT)
    plaintext = _read_all(db)
    report = db.authentication_report()

    serialized = json.dumps(report.as_dict())
    assert KEY.hex() not in serialized
    assert db.key.hex() not in serialized
    assert db.hmac_key.hex() not in serialized
    assert plaintext[:16].hex() not in serialized
    assert "SQLite format 3" not in serialized

    hidden_attributes = {"passphrase", "key", "hmac_key", "salt", "cipher_fh"}
    assert not hidden_attributes & set(report.as_dict())

    for page in report.pages:
        assert not hidden_attributes & set(page.__dict__)


def test_report_only_contains_pages_that_were_read() -> None:
    """Authentication results are recorded for actually read pages, not the whole database."""
    db = _open(build_vector(), AuthenticationMode.REPORT)
    db.stream().readoffset(PAGE_SIZE * 2, PAGE_SIZE)

    # Initialization always reads page 1 for the SQLite header; the random read adds page 3.
    report = db.authentication_report()
    assert [page.page_number for page in report.pages] == [1, 3]
    assert report.page(2) is None

    with pytest.raises(KeyError):
        db.page_authentication(2)
