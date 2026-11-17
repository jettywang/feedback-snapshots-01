from __future__ import annotations

from dissect.apfs.apfs import APFS
from dissect.apfs.exception import (
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.apfs.seal import (
    ChainFailure,
    CheckedNode,
    HashChainReport,
    SealReport,
    SealStatus,
    compute_node_hash,
    verify_hash_chain,
    verify_volume_seal,
)

__all__ = [
    "APFS",
    "ChainFailure",
    "CheckedNode",
    "Error",
    "FileNotFoundError",
    "HashChainReport",
    "NotADirectoryError",
    "NotASymlinkError",
    "SealReport",
    "SealStatus",
    "compute_node_hash",
    "verify_hash_chain",
    "verify_volume_seal",
]
