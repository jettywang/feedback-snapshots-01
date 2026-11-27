"""Streaming checksum helpers and SPDX-algorithm mapping.

Only algorithms that the local Python runtime can actually compute are
supported.  An SPDX algorithm that has no local implementation is reported as
*unsupported* so the caller can mark the corresponding reference edge as not
provable offline, instead of silently guessing.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

from spdx_tools.spdx.model import ChecksumAlgorithm

_READ_CHUNK = 1024 * 1024

# SPDX algorithm name -> (hashlib constructor name, optional digest size).
_HASHLIB_MAP: Dict[ChecksumAlgorithm, tuple[str, Optional[int]]] = {
    ChecksumAlgorithm.SHA1: ("sha1", None),
    ChecksumAlgorithm.SHA224: ("sha224", None),
    ChecksumAlgorithm.SHA256: ("sha256", None),
    ChecksumAlgorithm.SHA384: ("sha384", None),
    ChecksumAlgorithm.SHA512: ("sha512", None),
    ChecksumAlgorithm.SHA3_256: ("sha3_256", None),
    ChecksumAlgorithm.SHA3_384: ("sha3_384", None),
    ChecksumAlgorithm.SHA3_512: ("sha3_512", None),
    ChecksumAlgorithm.BLAKE2B_256: ("blake2b", 32),
    ChecksumAlgorithm.BLAKE2B_384: ("blake2b", 48),
    ChecksumAlgorithm.BLAKE2B_512: ("blake2b", 64),
    ChecksumAlgorithm.MD5: ("md5", None),
    ChecksumAlgorithm.MD4: ("md4", None),
}


@dataclass(frozen=True)
class Digest:
    algorithm: str
    value: str

    def as_spdx_pair(self) -> str:
        return f"{self.algorithm}:{self.value}"


def algorithm_available(algorithm: ChecksumAlgorithm) -> bool:
    """Return True when the SPDX algorithm can be computed locally."""
    mapping = _HASHLIB_MAP.get(algorithm)
    if mapping is None:
        return False
    constructor_name, _ = mapping
    return constructor_name in hashlib.algorithms_available


def new_hasher(algorithm: ChecksumAlgorithm):
    mapping = _HASHLIB_MAP.get(algorithm)
    if mapping is None or mapping[0] not in hashlib.algorithms_available:
        raise ValueError(f"checksum algorithm not available offline: {algorithm.name}")
    constructor_name, digest_size = mapping
    if digest_size is not None:
        return hashlib.new(constructor_name, digest_size=digest_size)
    return hashlib.new(constructor_name)


def hash_file(path, algorithm: ChecksumAlgorithm) -> str:
    """Return the lowercase hex digest of a file for the given algorithm."""
    hasher = new_hasher(algorithm)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_bytes(data: bytes, algorithm: ChecksumAlgorithm) -> str:
    hasher = new_hasher(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def digests_equal(claimed: str, actual: str) -> bool:
    return claimed.strip().lower() == actual.strip().lower()
