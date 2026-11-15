"""Regression tests for MS-DOC table-stream selection and byte-range handling.

The fixtures are small synthetic files derived from
tests/inputs/rc4cryptoapi_password.doc by rewriting FIB flags, swapping the
two table streams, or truncating a stream at a known offset. They drive the
DOC97 entry point exactly like a real document.

The assertions are byte-level: they name the stream that was used and compare
the recovered bytes against the known-good output, or require a specific
ParseError. "Decryption did not raise" is never accepted as proof that the
right document was recovered.
"""

import io
import unittest
from os.path import dirname, join
from struct import unpack_from

import olefile

from msoffcrypto import OfficeFile, exceptions

DATA_DIR = join(dirname(__file__), "inputs")
OUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"
FIXTURE_OUTPUT = join(OUT_DIR, "rc4cryptoapi_password_plain.doc")


class _Decrypted:
    def __init__(self, officefile, data):
        self.officefile = officefile
        self.data = data

    def stream(self, name):
        return olefile.OleFileIO(io.BytesIO(self.data)).openstream(name).read()

    def names(self):
        ole = olefile.OleFileIO(io.BytesIO(self.data))
        return sorted(
            "/".join(entry)
            for entry in ole.listdir(streams=True, storages=False)
        )


def _decrypt(path):
    file_handle = open(path, "rb")
    officefile = OfficeFile(file_handle)
    officefile.load_key(password=PASSWORD)
    out = io.BytesIO()
    officefile.decrypt(out)
    decrypted = _Decrypted(officefile, out.getvalue())
    file_handle.close()
    return decrypted


def _expected_stream(name):
    ole = olefile.OleFileIO(FIXTURE_OUTPUT)
    try:
        return ole.openstream(name).read()
    finally:
        ole.close()


class TableStreamSelectionTest(unittest.TestCase):
    """fWhichTblStm is authoritative; the other stream is never substituted."""

    def test_declared_1table_is_used(self):
        """Byte-for-byte comparison against the known-good plaintext output."""
        result = _decrypt(join(DATA_DIR, "doc97_both_tables_declared_1.doc"))
        self.assertEqual(result.officefile.info.tablename, "1Table")
        self.assertEqual(result.officefile.info.fib.base.fWhichTblStm, 1)
        self.assertEqual(result.names(), ["1Table", "WordDocument"])
        for name in ("WordDocument", "1Table"):
            self.assertEqual(result.stream(name), _expected_stream(name), name)

    def test_identical_tables_follow_the_flag(self):
        """With identical bytes in both streams, only the flag decides the name."""
        expected = _expected_stream("1Table")
        for path, flag, chosen in (
            ("doc97_both_tables_identical.doc", 0, "0Table"),
            ("doc97_both_tables_identical_declared_1.doc", 1, "1Table"),
        ):
            with self.subTest(path=path):
                result = _decrypt(join(DATA_DIR, path))
                self.assertEqual(result.officefile.info.fib.base.fWhichTblStm, flag)
                self.assertEqual(result.officefile.info.tablename, chosen)
                self.assertEqual(result.stream(chosen), expected)

    def test_mismatched_flag_is_rejected_not_guessed(self):
        """The declared stream has no key header; the other must not be tried."""
        for path, declared in (
            ("doc97_both_tables_declared_0_real_is_1.doc", "0Table"),
            ("doc97_both_tables_declared_1_real_is_0.doc", "1Table"),
        ):
            with self.subTest(path=path):
                with self.assertRaises(exceptions.ParseError) as caught:
                    _decrypt(join(DATA_DIR, path))
                message = str(caught.exception)
                self.assertIn(declared, message)
                self.assertIn("Refusing to substitute", message)

    def test_table_with_only_the_key_header_is_rejected(self):
        """A table cut at lKey keeps the header but cannot hold the document."""
        with self.assertRaisesRegex(exceptions.ParseError, "table stream is truncated"):
            _decrypt(join(DATA_DIR, "doc97_table_truncated_at_lkey.doc"))


class FibFlagsTest(unittest.TestCase):
    """Other FibBase flags must not be misread as encryption signals."""

    def test_xor_flag_is_rejected(self):
        """fObfuscation=1 is XOR obfuscation; MS-DOC XOR is unimplemented."""
        with open(join(DATA_DIR, "doc97_xor_flag.doc"), "rb") as file_handle:
            officefile = OfficeFile(file_handle)
            self.assertEqual(officefile.info.fib.base.fObfuscation, 1)
            with self.assertRaisesRegex(exceptions.DecryptionError, "XOR"):
                officefile.load_key(password=PASSWORD)

    def test_unencrypted_input_is_not_decrypted(self):
        """fEncrypted=0 means there is no key header at all."""
        with open(join(DATA_DIR, "plain.doc"), "rb") as file_handle:
            officefile = OfficeFile(file_handle)
            self.assertEqual(officefile.info.fib.base.fEncrypted, 0)
            self.assertFalse(officefile.is_encrypted())
            with self.assertRaises(exceptions.DecryptionError):
                officefile.load_key(password=PASSWORD)


class StreamRangeTest(unittest.TestCase):
    """Truncation is detected from stream lengths, not from decryption luck."""

    def test_worddocument_shorter_than_fibbase(self):
        with self.assertRaisesRegex(exceptions.ParseError, "WordDocument stream is only"):
            _decrypt(join(DATA_DIR, "doc97_worddocument_truncated_fibbase.doc"))

    def test_worddocument_shorter_than_fib(self):
        with self.assertRaisesRegex(exceptions.ParseError, "truncated"):
            _decrypt(join(DATA_DIR, "doc97_worddocument_truncated_fib.doc"))

    def test_worddocument_shorter_than_piece_table(self):
        """The FIB fits, but the text a piece table addresses was cut away."""
        with self.assertRaisesRegex(
            exceptions.ParseError, "piece table addresses WordDocument byte"
        ):
            _decrypt(join(DATA_DIR, "doc97_worddocument_truncated_text.doc"))


class DataStreamTest(unittest.TestCase):
    """The optional Data stream is decrypted over its full length."""

    def test_data_stream_round_trip(self):
        result = _decrypt(join(DATA_DIR, "doc97_with_data_stream.doc"))
        self.assertTrue(result.officefile.ole.exists("Data"))
        self.assertEqual(result.stream("Data"), b"DOC97-DATA-PAYLOAD " * 200)
        for name in ("WordDocument", "1Table"):
            self.assertEqual(result.stream(name), _expected_stream(name), name)


if __name__ == "__main__":
    unittest.main()
