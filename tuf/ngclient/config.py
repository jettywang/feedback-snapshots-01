# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for ``Updater`` class."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Flag, unique

from tuf.ngclient._internal.digest_policy import DigestPolicy


@unique
class EnvelopeType(Flag):
    """Configures deserialization and verification mode of TUF metadata.

    Args:
        METADATA: Traditional canonical JSON -based TUF Metadata.
        SIMPLE: Dead Simple Signing Envelope. (experimental)
    """

    METADATA = 1
    SIMPLE = 2


@dataclass
class UpdaterConfig:
    """Used to store ``Updater`` configuration.

    Args:
        max_root_rotations: Maximum number of root rotations.
        max_delegations: Maximum number of delegations.
        root_max_length: Maximum length of a root metadata file.
        timestamp_max_length: Maximum length of a timestamp metadata file.
        snapshot_max_length: Maximum length of a snapshot metadata file.
        targets_max_length: Maximum length of a targets metadata file.
        prefix_targets_with_hash: When `consistent snapshots
            <https://theupdateframework.github.io/specification/latest/#consistent-snapshots>`_
            are used, target download URLs are formed by prefixing the filename
            with a hash digest of file content by default. This can be
            overridden by setting ``prefix_targets_with_hash`` to ``False``.
        envelope_type: Configures deserialization and verification mode of TUF
            metadata. Per default, it is treated as traditional canonical JSON
            -based TUF Metadata.
        app_user_agent: Application user agent, e.g. "MyApp/1.0.0". This will be
            prefixed to ngclient user agent when the default fetcher is used.
        metadata_digest_policy: Policy for the digests in metadata
            descriptions (the ``MetaFile`` hashes in timestamp and snapshot).
            The default accepts every supported algorithm and, per the TUF
            specification, allows a description to omit hashes entirely.
        target_digest_policy: Policy for target file digests (the
            ``TargetFile`` hashes in targets metadata). Targets always carry
            at least one digest; the default accepts every supported
            algorithm. Both policies are applied to remote downloads and to
            the local cache, and a consistent-snapshot filename prefix is
            treated as a locator only, never as trusted content.
    """

    max_root_rotations: int = 256
    max_delegations: int = 32
    root_max_length: int = 512000  # bytes
    timestamp_max_length: int = 16384  # bytes
    snapshot_max_length: int = 2000000  # bytes
    targets_max_length: int = 5000000  # bytes
    prefix_targets_with_hash: bool = True
    envelope_type: EnvelopeType = EnvelopeType.METADATA
    app_user_agent: str | None = None
    metadata_digest_policy: DigestPolicy = field(
        default_factory=lambda: DigestPolicy(require_digest=False)
    )
    target_digest_policy: DigestPolicy = field(
        default_factory=lambda: DigestPolicy(require_digest=True)
    )
