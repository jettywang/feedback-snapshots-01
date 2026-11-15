import io

import pytest

from signify.authenticode import AuthenticodeFile, DetectionResult
from signify.authenticode.signed_file import (
    AuthenticodeSignatureFile,
    CtlFile,
    FlatFile,
    SignedPEFile,
)
from signify.exceptions import (
    AuthenticodeNotSignedError,
    ParseError,
    SignedMsiParseError,
    SignedPEParseError,
    UnsupportedFileFormatError,
)
from signify.file_types import FailureStage, FileFormat
from tests._utils import data_path, open_test_data

MSI_MAGIC = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")


def _read(filename: str) -> bytes:
    return data_path(filename).read_bytes()


@pytest.mark.parametrize(
    ("filename", "expected_format", "expected_parser"),
    [
        ("SoftwareUpdate.exe", FileFormat.PE, SignedPEFile),
        ("cmake.msi", FileFormat.MSI, None),  # filled below for optional olefile
        ("oem89.cat", FileFormat.CTL, CtlFile),
        ("AppxSignature.p7x", FileFormat.P7X, AuthenticodeSignatureFile),
    ],
)
def test_detects_supported_formats(filename, expected_format, expected_parser):
    if expected_format == FileFormat.MSI:
        pytest.importorskip("olefile")
        from signify.authenticode.signed_file import SignedMsiFile

        expected_parser = SignedMsiFile

    with open_test_data(filename) as f:
        result = AuthenticodeFile.detect(f)
    assert isinstance(result, DetectionResult)
    assert result.file_format == expected_format
    assert result.stage is None
    assert result.error is None
    assert isinstance(result.signed_file, expected_parser)


def test_detection_does_not_close_or_consume_stream():
    with open_test_data("oem89.cat") as f:
        expected = f.read()
        f.seek(0)
        result = AuthenticodeFile.detect(f)
        assert not f.closed
        assert f.tell() == 0
        f.seek(0)
        assert f.read() == expected
    assert result.signed_file is not None


def test_unknown_format_is_unsupported():
    result = AuthenticodeFile.detect(io.BytesIO(b"just some text"))
    assert result.file_format == FileFormat.UNKNOWN
    assert result.stage == FailureStage.UNSUPPORTED_FORMAT
    assert isinstance(result.error, UnsupportedFileFormatError)
    assert result.signed_file is None


def test_unknown_format_with_flat_fallback_is_flat():
    result = AuthenticodeFile.detect(io.BytesIO(b"just some text"), allow_flat=True)
    assert result.file_format == FileFormat.FLAT
    assert result.stage is None
    assert isinstance(result.signed_file, FlatFile)


@pytest.mark.parametrize(
    ("prefix", "expected_format", "expected_error"),
    [
        (b"MZ", FileFormat.PE, SignedPEParseError),
        (MSI_MAGIC, FileFormat.MSI, SignedMsiParseError),
        (b"\x30", FileFormat.CTL, ParseError),
        (b"PKCX", FileFormat.P7X, ParseError),
    ],
)
def test_magic_only_truncations_are_malformed(prefix, expected_format, expected_error):
    if expected_format == FileFormat.MSI:
        pytest.importorskip("olefile")

    result = AuthenticodeFile.detect(io.BytesIO(prefix), allow_flat=True)
    # The recognized format must never be downgraded to an unsigned flat file.
    assert result.file_format == expected_format
    assert result.stage == FailureStage.MALFORMED_SIGNATURE
    assert isinstance(result.error, expected_error)
    assert result.signed_file is None
    assert result.error.requires_manual_inspection

    with pytest.raises(ParseError) as excinfo:
        AuthenticodeFile.from_stream(io.BytesIO(prefix), allow_flat=True)
    assert excinfo.value.file_format == expected_format
    assert excinfo.value.stage == FailureStage.MALFORMED_SIGNATURE


@pytest.mark.parametrize(
    ("filename", "prefix", "expected_format"),
    [
        # A PE body preceded by MSI magic is MSI, not PE and not flat.
        ("SoftwareUpdate.exe", MSI_MAGIC, FileFormat.MSI),
        # A CTL body preceded by PE magic is PE, not CTL.
        ("oem89.cat", b"MZ", FileFormat.PE),
        # A PE body preceded by P7X magic is P7X, not PE.
        ("SoftwareUpdate.exe", b"PKCX", FileFormat.P7X),
    ],
)
def test_foreign_prefix_wins_without_fallback(filename, prefix, expected_format):
    if expected_format == FileFormat.MSI:
        pytest.importorskip("olefile")

    body = _read(filename)
    result = AuthenticodeFile.detect(io.BytesIO(prefix + body), allow_flat=True)
    assert result.file_format == expected_format
    # The mismatched body is structural damage, not a signature to fall back on.
    assert result.stage in (
        FailureStage.MALFORMED_SIGNATURE,
        FailureStage.UNSUPPORTED_FORMAT,
    )
    assert result.signed_file is None


def test_pe_without_signature_is_unsigned_not_malformed():
    with open_test_data("SoftwareUpdate.exe") as f:
        data = f.read()

    # Zero the certificate table address/size in the PE optional header.
    patched = bytearray(data)
    pe_offset = int.from_bytes(patched[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    cert_entry = optional_header + 128
    patched[cert_entry : cert_entry + 8] = b"\x00" * 8

    result = AuthenticodeFile.detect(io.BytesIO(bytes(patched)))
    assert result.file_format == FileFormat.PE
    assert result.stage is None
    assert result.signed_file is not None
    status, error = result.signed_file.explain_verify()
    assert status.name == "NOT_SIGNED"
    assert isinstance(error, AuthenticodeNotSignedError)


def test_msi_without_signature_stream_is_unsigned():
    pytest.importorskip("olefile")

    with open_test_data("cmake_not_signed.msi") as f:
        result = AuthenticodeFile.detect(f)
    assert result.file_format == FileFormat.MSI
    assert result.stage is None
    assert result.signed_file is not None
    status, error = result.signed_file.explain_verify()
    assert status.name == "NOT_SIGNED"
    assert isinstance(error, AuthenticodeNotSignedError)


def test_unsigned_ctl_is_not_a_verification_failure():
    with open_test_data("catfiletest.cat") as f:
        result = AuthenticodeFile.detect(f)
    assert result.file_format == FileFormat.CTL
    assert result.stage is None
    status, error = result.signed_file.explain_verify()
    assert status.name == "NOT_SIGNED"
    assert isinstance(error, AuthenticodeNotSignedError)


def test_damaged_pe_certificate_table_is_malformed_not_unsigned():
    with open_test_data("SoftwareUpdate.exe") as f:
        data = bytearray(f.read())

    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    cert_entry = pe_offset + 24 + 128
    # Point the certificate table beyond the end of the file.
    data[cert_entry : cert_entry + 8] = (0xFFFFFF00).to_bytes(4, "little") * 2

    result = AuthenticodeFile.detect(io.BytesIO(bytes(data)))
    assert result.file_format == FileFormat.PE
    assert result.stage == FailureStage.MALFORMED_SIGNATURE
    assert isinstance(result.error, SignedPEParseError)


def test_error_messages_do_not_contain_file_content():
    marker = b"TOP-SECRET-PRIVATE-KEY-MATERIAL"

    # A damaged MSI whose bytes contain a sensitive-looking marker.
    result = AuthenticodeFile.detect(io.BytesIO(MSI_MAGIC + marker))
    assert result.error is not None
    assert marker.decode() not in str(result.error)
    assert marker.decode() not in repr(result.error)

    result = AuthenticodeFile.detect(io.BytesIO(b"PKCX" + marker))
    assert result.error is not None
    assert marker.decode() not in str(result.error)
    assert marker.decode() not in repr(result.error)
