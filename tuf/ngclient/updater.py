# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Client update workflow implementation.

The ``Updater`` class provides an implementation of the
`TUF client workflow
<https://theupdateframework.github.io/specification/latest/#detailed-client-workflow>`_.
``Updater`` provides an API to query available targets and to download them in a
secure manner: All downloaded files are verified by signed metadata.

High-level description of ``Updater`` functionality:
  * Initializing an ``Updater`` loads and validates the trusted local root
    metadata: This root metadata is used as the source of trust for all other
    metadata. Updater should always be initialized with the ``bootstrap``
    argument: pass ``bootstrap=None`` only to explicitly opt into using the
    cached root.json as the trust anchor.
  * ``refresh()`` can optionally be called to update and load all top-level
    metadata as described in the specification, using both locally cached
    metadata and metadata downloaded from the remote repository. If refresh is
    not done explicitly, it will happen automatically during the first target
    info lookup.
  * ``Updater`` can be used to download targets. For each target:

      * ``Updater.get_targetinfo()`` is first used to find information about a
        specific target. This will load new targets metadata as needed (from
        local cache or remote repository).
      * ``Updater.find_cached_target()`` can optionally be used to check if a
        target file is already locally cached.
      * ``Updater.download_target()`` downloads a target file and ensures it is
        verified correct by the metadata.

For applications that forward target information between components (for
example a download backend that receives target information from another
component that may have built it itself), ``Updater`` also provides a
trusted download permit API:

  * ``Updater.get_trusted_targetinfo()`` performs the same authenticated
    lookup as ``get_targetinfo()`` but returns a ``TrustedTarget`` permit
    instead of a plain ``TargetFile``.
  * ``Updater.find_cached_trusted_target()`` and
    ``Updater.download_trusted_target()`` only accept these permits: a permit
    is cryptographically bound to both the exact target description that was
    authenticated at lookup time and the ``Updater`` (trust context) that
    issued it. Fabricated, altered or foreign permits are refused before any
    network or cache access happens.

Note that applications using ``Updater`` should be 'single instance'
applications: running multiple instances that use the same cache directories at
the same time is not supported.

A simple example of using the Updater to implement a Python TUF client that
downloads target files is available in `examples/client
<https://github.com/theupdateframework/python-tuf/tree/develop/examples/client>`_.

Notes on how Updater uses HTTP by default:
  * urllib3 is the HTTP library
  * Typically all requests are retried by urllib3 three times (in cases where
    this seems useful)
  * Operating system certificate store is used for TLS, in other words
    ``certifi`` is not used as the certificate source
  * Proxy use can be configured with ``https_proxy`` and other similar
    environment variables

All of the HTTP decisions can be changed with ``fetcher`` argument:
Custom ``FetcherInterface`` implementations are possible. The alternative
``RequestsFetcher`` implementation is also provided (although deprecated).
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, cast
from urllib import parse

from tuf.api import exceptions
from tuf.api.metadata import Root, Snapshot, TargetFile, Targets, Timestamp
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType, UpdaterConfig
from tuf.ngclient.urllib3_fetcher import Urllib3Fetcher

if TYPE_CHECKING:
    from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)

# Token that only this module can pass to TrustedTarget(): this prevents
# application code from fabricating trusted download permits.
_PERMIT_CONSTRUCTION_TOKEN = object()


class TrustedTarget:
    """A trusted download permit for a specific target description.

    ``TrustedTarget`` instances can only be created by
    ``Updater.get_trusted_targetinfo()``: each permit is cryptographically
    bound to

    * the exact target description (path, length, hashes and any custom
      data) that the issuing ``Updater`` found and authenticated during the
      lookup, and
    * the trust context that produced it, that is the issuing ``Updater``
      instance itself.

    Unlike a plain ``TargetFile``, a ``TrustedTarget`` cannot be fabricated
    or repurposed by application code: ``Updater.download_trusted_target()``
    and ``Updater.find_cached_trusted_target()`` re-verify the permit before
    any download or cache access, and refuse permits whose description was
    altered, that were issued by another ``Updater`` (for example one
    connected to a different repository), or that were not issued by an
    ``Updater`` at all.

    The permit is an in-memory capability: it is not serializable and is
    only meaningful to the ``Updater`` that issued it.
    """

    __slots__ = ("_issuer", "_tag", "_targetinfo")

    def __init__(
        self,
        targetinfo: TargetFile,
        tag: bytes,
        issuer: Updater,
        *,
        _token: object | None = None,
    ):
        if _token is not _PERMIT_CONSTRUCTION_TOKEN:
            raise TypeError(
                "TrustedTarget cannot be constructed directly: "
                "use Updater.get_trusted_targetinfo()"
            )
        self._targetinfo = targetinfo
        self._tag = tag
        self._issuer = issuer

    @property
    def targetinfo(self) -> TargetFile:
        """Target description this permit authorizes.

        The description is informational: modifying it invalidates the
        permit and subsequent trusted downloads will be refused.
        """
        return self._targetinfo

    @property
    def issuer(self) -> Updater:
        """The ``Updater`` that issued this permit.

        Only the issuer can verify the permit: permits are bound to the
        trust context that created them.
        """
        return self._issuer

    def authenticate(self, expected_tag: bytes) -> TargetFile:
        """Return the bound target description if ``expected_tag`` matches.

        ``expected_tag`` is computed by the issuing ``Updater`` from its
        secret permit key: this is part of the permit verification
        machinery and application code should not need to call it.

        Raises:
            ValueError: The permit's target description was altered
        """
        if not hmac.compare_digest(self._tag, expected_tag):
            raise ValueError(
                "Permit target description was altered: refusing to use it"
            )
        return self._targetinfo

    def __repr__(self) -> str:
        return f"TrustedTarget({self._targetinfo.path!r})"


class Updater:
    """Creates a new ``Updater`` instance and loads trusted root metadata.

    Args:
        metadata_dir: Local metadata directory. Directory must be
            writable. If ``bootstrap`` is ``None``, this directory must contain
            a trusted root.json file.
        metadata_base_url: Base URL for all remote metadata downloads
        target_dir: Local targets directory. Directory must be writable. It
            will be used as the default target download directory by
            ``find_cached_target()`` and ``download_target()``
        target_base_url: ``Optional``; Default base URL for all remote target
            downloads. Can be individually set in ``download_target()``
        fetcher: ``Optional``; ``FetcherInterface`` implementation used to
            download both metadata and targets. Default is ``Urllib3Fetcher``
        config: ``Optional``; ``UpdaterConfig`` could be used to setup common
            configuration options.
        bootstrap: Initial root metadata bytes. This argument is required.
            Pass the embedded root metadata bytes for secure initialization.
            Pass ``None`` only if you explicitly want to use the cached
            root.json as the trust anchor (not recommended for most
            deployments).

    Raises:
        OSError: Local root.json cannot be read
        RepositoryError: Local root.json is invalid
    """

    def __init__(  # noqa: PLR0917
        self,
        metadata_dir: str,
        metadata_base_url: str,
        target_dir: str | None = None,
        target_base_url: str | None = None,
        fetcher: FetcherInterface | None = None,
        config: UpdaterConfig | None = None,
        *,
        bootstrap: bytes | None,
    ):
        self._dir = metadata_dir
        self._metadata_base_url = _ensure_trailing_slash(metadata_base_url)
        self.target_dir = target_dir
        if target_base_url is None:
            self._target_base_url = None
        else:
            self._target_base_url = _ensure_trailing_slash(target_base_url)

        self.config = config or UpdaterConfig()
        if fetcher is not None:
            self._fetcher = fetcher
        else:
            self._fetcher = Urllib3Fetcher(
                app_user_agent=self.config.app_user_agent
            )
        supported_envelopes = [EnvelopeType.METADATA, EnvelopeType.SIMPLE]
        if self.config.envelope_type not in supported_envelopes:
            raise ValueError(
                f"config: envelope_type must be one of {supported_envelopes}, "
                f"got '{self.config.envelope_type}'"
            )

        if bootstrap is None:
            # if no root was provided, use the cached non-versioned root.json
            bootstrap = self._load_local_metadata(Root.type)

        # Load the initial root, make sure it's cached
        self._trusted_set = TrustedMetadataSet(
            bootstrap, self.config.envelope_type
        )
        self._persist_root(self._trusted_set.root.version, bootstrap)
        self._update_root_symlink()

        # Secret used to authenticate the TrustedTarget permits issued by
        # this updater: permits from other trust contexts will not verify
        self._permit_key = secrets.token_bytes(32)

    def refresh(self) -> None:
        """Refresh top-level metadata.

        Downloads, verifies, and loads metadata for the top-level roles in the
        specified order (root -> timestamp -> snapshot -> targets) implementing
        all the checks required in the TUF client workflow.

        A ``refresh()`` can be done only once during the lifetime of an Updater.
        If ``refresh()`` has not been explicitly called before the first
        ``get_targetinfo()`` call, it will be done implicitly at that time.

        The metadata for delegated roles is not updated by ``refresh()``:
        that happens on demand during ``get_targetinfo()``. However, if the
        repository uses `consistent_snapshot
        <https://theupdateframework.github.io/specification/latest/#consistent-snapshots>`_,
        then all metadata downloaded by the Updater will use the same consistent
        repository state.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            DownloadError: Download of a metadata file failed in some way
        """

        self._load_root()
        self._load_timestamp()
        self._load_snapshot()
        self._load_targets(Targets.type, Root.type)

    def _generate_target_file_path(self, targetinfo: TargetFile) -> str:
        if self.target_dir is None:
            raise ValueError("target_dir must be set if filepath is not given")

        # Use URL encoded target path as filename
        filename = parse.quote(targetinfo.path, "")
        return os.path.join(self.target_dir, filename)

    def get_targetinfo(self, target_path: str) -> TargetFile | None:
        """Return ``TargetFile`` instance with information for ``target_path``.

        The return value can be used as an argument to
        ``download_target()`` and ``find_cached_target()``.

        If ``refresh()`` has not been called before calling
        ``get_targetinfo()``, the refresh will be done implicitly.

        As a side-effect this method downloads all the additional (delegated
        targets) metadata it needs to return the target information.

        Args:
            target_path: `path-relative-URL string
                <https://url.spec.whatwg.org/#path-relative-url-string>`_
                that uniquely identifies the target within the repository.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            DownloadError: Download of a metadata file failed in some way

        Returns:
            ``TargetFile`` instance or ``None``.
        """

        if Targets.type not in self._trusted_set:
            self.refresh()
        return self._preorder_depth_first_walk(target_path)

    def get_trusted_targetinfo(self, target_path: str) -> TrustedTarget | None:
        """Return a ``TrustedTarget`` download permit for ``target_path``.

        This performs the same authenticated lookup as ``get_targetinfo()``,
        but instead of a plain ``TargetFile`` returns a permit that
        ``download_trusted_target()`` and ``find_cached_trusted_target()``
        accept as proof that this exact target description was found and
        authenticated by this ``Updater``.

        Use this instead of ``get_targetinfo()`` whenever the target
        information crosses a trust boundary (for example when another
        component decides what gets downloaded): the permit guarantees that
        only targets this client actually looked up and authenticated can be
        downloaded or accepted from cache through the trusted API.

        Args:
            target_path: `path-relative-URL string
                <https://url.spec.whatwg.org/#path-relative-url-string>`_
                that uniquely identifies the target within the repository.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            DownloadError: Download of a metadata file failed in some way

        Returns:
            ``TrustedTarget`` permit or ``None`` if the target is not found.
        """

        targetinfo = self.get_targetinfo(target_path)
        if targetinfo is None:
            return None

        # Snapshot the description so that later changes to the object
        # returned by get_targetinfo() cannot affect the permit
        snapshot = copy.deepcopy(targetinfo)
        return TrustedTarget(
            snapshot,
            self._compute_permit_tag(snapshot),
            self,
            _token=_PERMIT_CONSTRUCTION_TOKEN,
        )

    def _compute_permit_tag(self, targetinfo: TargetFile) -> bytes:
        """Compute the authentication tag of a permit for ``targetinfo``."""
        canonical = json.dumps(
            {"path": targetinfo.path, "target": targetinfo.to_dict()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(self._permit_key, canonical, hashlib.sha256).digest()

    def _resolve_trusted_target(self, permit: TrustedTarget) -> TargetFile:
        """Verify ``permit`` and return the bound target description.

        Raises:
            TypeError: ``permit`` is not a ``TrustedTarget``
            ValueError: Permit was not issued by this ``Updater`` or its
                target description was altered
        """
        if not isinstance(permit, TrustedTarget):
            raise TypeError(
                "Expected a TrustedTarget permit issued by "
                "get_trusted_targetinfo(), got "
                f"'{type(permit).__name__}': plain TargetFile objects can "
                "only be used with download_target()/find_cached_target()"
            )
        if permit.issuer is not self:
            raise ValueError(
                "Permit was issued by a different Updater: trusted permits "
                "are bound to the trust context that created them"
            )
        return permit.authenticate(self._compute_permit_tag(permit.targetinfo))

    def find_cached_trusted_target(
        self,
        permit: TrustedTarget,
        filepath: str | None = None,
    ) -> str | None:
        """Check whether a local file is an up to date permitted target.

        Like ``find_cached_target()``, but only accepts a ``TrustedTarget``
        permit issued by this ``Updater``'s ``get_trusted_targetinfo()``:
        the permit is verified before the cache is consulted.

        Args:
            permit: ``TrustedTarget`` from ``get_trusted_targetinfo()``.
            filepath: Local path to file. If ``None``, a file path is
                generated based on ``target_dir`` constructor argument.

        Raises:
            TypeError: ``permit`` is not a ``TrustedTarget``
            ValueError: Incorrect arguments, or permit verification failed

        Returns:
            Local file path if the file is an up to date target file.
            ``None`` if file is not found or it is not up to date.
        """

        targetinfo = self._resolve_trusted_target(permit)
        return self.find_cached_target(targetinfo, filepath)

    def download_trusted_target(
        self,
        permit: TrustedTarget,
        filepath: str | None = None,
        target_base_url: str | None = None,
    ) -> str:
        """Download the target file authorized by ``permit``.

        Like ``download_target()``, but only accepts a ``TrustedTarget``
        permit issued by this ``Updater``'s ``get_trusted_targetinfo()``:
        the permit is verified before any download happens, so a component
        that can build or modify ``TargetFile`` objects cannot use this
        entry point to download or poison the cache with anything the
        client did not authenticate.

        Args:
            permit: ``TrustedTarget`` from ``get_trusted_targetinfo()``.
            filepath: Local path to download into. If ``None``, the file is
                downloaded into directory defined by ``target_dir`` constructor
                argument using a generated filename. If file already exists,
                it is overwritten.
            target_base_url: Base URL used to form the final target
                download URL. Default is the value provided in ``Updater()``

        Raises:
            TypeError: ``permit`` is not a ``TrustedTarget``
            ValueError: Invalid arguments, or permit verification failed
            DownloadError: Download of the target file failed in some way
            RepositoryError: Downloaded target failed to be verified in some way
            OSError: Failed to write target to file

        Returns:
            Local path to downloaded file
        """

        targetinfo = self._resolve_trusted_target(permit)
        return self.download_target(targetinfo, filepath, target_base_url)

    def find_cached_target(
        self,
        targetinfo: TargetFile,
        filepath: str | None = None,
    ) -> str | None:
        """Check whether a local file is an up to date target.

        .. note::
            This method accepts any ``TargetFile``: the caller is
            responsible for ensuring it comes from ``get_targetinfo()``.
            Use ``find_cached_trusted_target()`` if the target information
            crosses a trust boundary and this must be enforced.

        Args:
            targetinfo: ``TargetFile`` from ``get_targetinfo()``.
            filepath: Local path to file. If ``None``, a file path is
                generated based on ``target_dir`` constructor argument.

        Raises:
            ValueError: Incorrect arguments

        Returns:
            Local file path if the file is an up to date target file.
            ``None`` if file is not found or it is not up to date.
        """

        if filepath is None:
            filepath = self._generate_target_file_path(targetinfo)

        try:
            with open(filepath, "rb") as target_file:
                targetinfo.verify_length_and_hashes(target_file)
            return filepath
        except (OSError, exceptions.LengthOrHashMismatchError):
            return None

    def download_target(
        self,
        targetinfo: TargetFile,
        filepath: str | None = None,
        target_base_url: str | None = None,
    ) -> str:
        """Download the target file specified by ``targetinfo``.

        .. note::
            This method accepts any ``TargetFile``: the caller is
            responsible for ensuring it comes from ``get_targetinfo()``.
            Use ``download_trusted_target()`` if the target information
            crosses a trust boundary and this must be enforced.

        Args:
            targetinfo: ``TargetFile`` from ``get_targetinfo()``.
            filepath: Local path to download into. If ``None``, the file is
                downloaded into directory defined by ``target_dir`` constructor
                argument using a generated filename. If file already exists,
                it is overwritten.
            target_base_url: Base URL used to form the final target
                download URL. Default is the value provided in ``Updater()``

        Raises:
            ValueError: Invalid arguments
            DownloadError: Download of the target file failed in some way
            RepositoryError: Downloaded target failed to be verified in some way
            OSError: Failed to write target to file

        Returns:
            Local path to downloaded file
        """

        if filepath is None:
            filepath = self._generate_target_file_path(targetinfo)
        Path(filepath).parent.mkdir(exist_ok=True, parents=True)

        if target_base_url is None:
            if self._target_base_url is None:
                raise ValueError(
                    "target_base_url must be set in either "
                    "download_target() or constructor"
                )

            target_base_url = self._target_base_url
        else:
            target_base_url = _ensure_trailing_slash(target_base_url)

        target_filepath = targetinfo.path
        consistent_snapshot = self._trusted_set.root.consistent_snapshot
        if consistent_snapshot and self.config.prefix_targets_with_hash:
            hashes = list(targetinfo.hashes.values())
            dirname, sep, basename = target_filepath.rpartition("/")
            target_filepath = f"{dirname}{sep}{hashes[0]}.{basename}"
        full_url = f"{target_base_url}{target_filepath}"

        with self._fetcher.download_file(
            full_url, targetinfo.length
        ) as target_file:
            targetinfo.verify_length_and_hashes(target_file)

            target_file.seek(0)
            with open(filepath, "wb") as destination_file:
                shutil.copyfileobj(target_file, destination_file)

        logger.debug("Downloaded target %s", targetinfo.path)
        return filepath

    def _download_metadata(
        self, rolename: str, length: int, version: int | None = None
    ) -> bytes:
        """Download a metadata file and return it as bytes."""
        encoded_name = parse.quote(rolename, "")
        if version is None:
            url = f"{self._metadata_base_url}{encoded_name}.json"
        else:
            url = f"{self._metadata_base_url}{version}.{encoded_name}.json"
        return self._fetcher.download_bytes(url, length)

    def _load_local_metadata(self, rolename: str) -> bytes:
        encoded_name = parse.quote(rolename, "")
        with open(os.path.join(self._dir, f"{encoded_name}.json"), "rb") as f:
            return f.read()

    def _persist_metadata(self, rolename: str, data: bytes) -> None:
        """Write metadata to disk atomically to avoid data loss.

        Use a filename _not_ prefixed with version (e.g. "timestamp.json")
        . Encode the rolename to avoid issues with e.g. path separators
        """

        encoded_name = parse.quote(rolename, "")
        filename = os.path.join(self._dir, f"{encoded_name}.json")
        self._persist_file(filename, data)

    def _persist_root(self, version: int, data: bytes) -> None:
        """Write root metadata to disk atomically to avoid data loss.

        The metadata is stored with version prefix (e.g.
        "root_history/1.root.json").
        """
        rootdir = Path(self._dir, "root_history")
        rootdir.mkdir(exist_ok=True, parents=True)
        self._persist_file(str(rootdir / f"{version}.root.json"), data)

    def _persist_file(self, filename: str, data: bytes) -> None:
        """Write a file to disk atomically to avoid data loss."""
        temp_file_name = None

        try:
            with tempfile.NamedTemporaryFile(
                dir=self._dir, delete=False
            ) as temp_file:
                temp_file_name = temp_file.name
                temp_file.write(data)
            os.replace(temp_file.name, filename)
        except OSError as e:
            # remove tempfile if we managed to create one,
            # then let the exception happen
            if temp_file_name is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(temp_file_name)
            raise e

    def _update_root_symlink(self) -> None:
        """Symlink root.json to current trusted root version in root_history/"""
        linkname = os.path.join(self._dir, "root.json")
        version = self._trusted_set.root.version
        current = os.path.join("root_history", f"{version}.root.json")
        with contextlib.suppress(FileNotFoundError):
            os.remove(linkname)
        try:
            os.symlink(current, linkname)
        except OSError as e:
            if getattr(e, "winerror", None) == 1314:
                # Fallback for NTFS "required privilege is not held by client"
                os.link(os.path.join(self._dir, current), linkname)
            else:
                raise

    def _load_root(self) -> None:
        """Load root metadata.

        Sequentially load newer root metadata versions. First try to load from
        local cache and if that does not work, from the remote repository.

        If metadata is loaded from remote repository, store it in local cache.
        """

        # Update the root role
        lower_bound = self._trusted_set.root.version + 1
        upper_bound = lower_bound + self.config.max_root_rotations

        try:
            for next_version in range(lower_bound, upper_bound):
                # look for next_version in local cache
                try:
                    root_path = os.path.join(
                        self._dir, "root_history", f"{next_version}.root.json"
                    )
                    with open(root_path, "rb") as f:
                        self._trusted_set.update_root(f.read())
                    continue
                except (OSError, exceptions.RepositoryError) as e:
                    # this root did not exist locally or is invalid
                    logger.debug("Local root is not valid: %s", e)

                # next_version was not found locally, try remote
                try:
                    data = self._download_metadata(
                        Root.type,
                        self.config.root_max_length,
                        next_version,
                    )
                    self._trusted_set.update_root(data)
                    self._persist_root(next_version, data)

                except exceptions.DownloadHTTPError as exception:
                    if exception.status_code not in {403, 404}:
                        raise
                    # 404/403 means current root is newest available
                    break
        finally:
            # Make sure the non-versioned root.json links to current version
            self._update_root_symlink()

    def _load_timestamp(self) -> None:
        """Load local and remote timestamp metadata."""
        try:
            data = self._load_local_metadata(Timestamp.type)
            self._trusted_set.update_timestamp(data)
        except (OSError, exceptions.RepositoryError) as e:
            # Local timestamp does not exist or is invalid
            logger.debug("Local timestamp not valid as final: %s", e)

        # Load from remote (whether local load succeeded or not)
        data = self._download_metadata(
            Timestamp.type, self.config.timestamp_max_length
        )
        try:
            self._trusted_set.update_timestamp(data)
        except exceptions.EqualVersionNumberError:
            # If the new timestamp version is the same as current, discard the
            # new timestamp. This is normal and it shouldn't raise any error.
            return

        self._persist_metadata(Timestamp.type, data)

    def _load_snapshot(self) -> None:
        """Load local (and if needed remote) snapshot metadata."""
        try:
            data = self._load_local_metadata(Snapshot.type)
            self._trusted_set.update_snapshot(data, trusted=True)
            logger.debug("Local snapshot is valid: not downloading new one")
        except (OSError, exceptions.RepositoryError) as e:
            # Local snapshot does not exist or is invalid: update from remote
            logger.debug("Local snapshot not valid as final: %s", e)

            snapshot_meta = self._trusted_set.timestamp.snapshot_meta
            length = snapshot_meta.length or self.config.snapshot_max_length
            version = None
            if self._trusted_set.root.consistent_snapshot:
                version = snapshot_meta.version

            data = self._download_metadata(Snapshot.type, length, version)
            self._trusted_set.update_snapshot(data)
            self._persist_metadata(Snapshot.type, data)

    def _load_targets(self, role: str, parent_role: str) -> Targets:
        """Load local (and if needed remote) metadata for ``role``."""

        # Avoid loading 'role' more than once for the same parent_role
        if self._trusted_set.contains(role, parent_role):
            return cast("Targets", self._trusted_set[role])

        try:
            data = self._load_local_metadata(role)
            delegated_targets = self._trusted_set.update_delegated_targets(
                data, role, parent_role
            )
            logger.debug("Local %s is valid: not downloading new one", role)
            return delegated_targets
        except (OSError, exceptions.RepositoryError) as e:
            # Local 'role' does not exist or is invalid: update from remote
            logger.debug("Failed to load local %s: %s", role, e)

            snapshot = self._trusted_set.snapshot
            metainfo = snapshot.meta.get(f"{role}.json")
            if metainfo is None:
                raise exceptions.RepositoryError(
                    f"Role {role} was delegated but is not part of snapshot"
                ) from None

            length = metainfo.length or self.config.targets_max_length
            version = None
            if self._trusted_set.root.consistent_snapshot:
                version = metainfo.version

            data = self._download_metadata(role, length, version)
            delegated_targets = self._trusted_set.update_delegated_targets(
                data, role, parent_role
            )
            self._persist_metadata(role, data)

            return delegated_targets

    def _preorder_depth_first_walk(
        self, target_filepath: str
    ) -> TargetFile | None:
        """
        Interrogates the tree of target delegations in order of appearance
        (which implicitly order trustworthiness), and returns the matching
        target found in the most trusted role.
        """

        # List of delegations to be interrogated. A (role, parent role) pair
        # is needed to load and verify the delegated targets metadata.
        delegations_to_visit = [(Targets.type, Root.type)]
        visited_role_names: set[str] = set()

        # Preorder depth-first traversal of the graph of target delegations.
        while (
            len(visited_role_names) <= self.config.max_delegations
            and len(delegations_to_visit) > 0
        ):
            # Pop the role name from the top of the stack.
            role_name, parent_role = delegations_to_visit.pop(-1)

            # Skip any visited current role to prevent cycles.
            if role_name in visited_role_names:
                logger.debug("Skipping visited current role %s", role_name)
                continue

            # The metadata for 'role_name' must be downloaded/updated before
            # its targets, delegations, and child roles can be inspected.
            targets = self._load_targets(role_name, parent_role)

            target = targets.targets.get(target_filepath)

            if target is not None:
                logger.debug("Found target in current role %s", role_name)
                return target

            # After preorder check, add current role to set of visited roles.
            visited_role_names.add(role_name)

            if targets.delegations is not None:
                child_roles_to_visit = []
                # NOTE: This may be a slow operation if there are many
                # delegated roles.
                for (
                    child_name,
                    terminating,
                ) in targets.delegations.get_roles_for_target(target_filepath):
                    logger.debug("Adding child role %s", child_name)
                    child_roles_to_visit.append((child_name, role_name))
                    if terminating:
                        logger.debug("Not backtracking to other roles")
                        delegations_to_visit = []
                        break
                # Push 'child_roles_to_visit' in reverse order of appearance
                # onto 'delegations_to_visit'.  Roles are popped from the end of
                # the list.
                child_roles_to_visit.reverse()
                delegations_to_visit.extend(child_roles_to_visit)

        if len(delegations_to_visit) > 0:
            logger.debug(
                "%d roles left to visit, but allowed at most %d delegations",
                len(delegations_to_visit),
                self.config.max_delegations,
            )

        # If this point is reached then target is not found, return None
        return None


def _ensure_trailing_slash(url: str) -> str:
    """Return url guaranteed to end in a slash."""
    return url if url.endswith("/") else f"{url}/"
