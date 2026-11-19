import hashlib
from unittest import mock

import pytest

import aiohttp

ssl = pytest.importorskip("ssl")


def test_fingerprint_sha256() -> None:
    sha256 = hashlib.sha256(b"12345678" * 64).digest()
    fp = aiohttp.Fingerprint(sha256)
    assert fp.fingerprint == sha256


def test_fingerprint_sha1() -> None:
    sha1 = hashlib.sha1(b"12345678" * 64).digest()
    with pytest.raises(ValueError):
        aiohttp.Fingerprint(sha1)


def test_fingerprint_md5() -> None:
    md5 = hashlib.md5(b"12345678" * 64).digest()
    with pytest.raises(ValueError):
        aiohttp.Fingerprint(md5)


def test_fingerprint_check_no_ssl() -> None:
    sha256 = hashlib.sha256(b"12345678" * 64).digest()
    fp = aiohttp.Fingerprint(sha256)
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    fp.check(transport)


def test_fingerprint_equality_by_digest() -> None:
    digest = hashlib.sha256(b"12345678" * 64).digest()
    fp1 = aiohttp.Fingerprint(digest)
    fp2 = aiohttp.Fingerprint(digest)
    other = aiohttp.Fingerprint(hashlib.sha256(b"other").digest())

    assert fp1 == fp2
    assert hash(fp1) == hash(fp2)
    assert fp1 != other
    assert fp1 != digest
    assert fp1 != object()


def test_fingerprint_usable_in_sets_and_mapping_keys() -> None:
    digest = hashlib.sha256(b"12345678" * 64).digest()
    assert {aiohttp.Fingerprint(digest), aiohttp.Fingerprint(digest)} == {
        aiohttp.Fingerprint(digest)
    }
