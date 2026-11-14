# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Client-side digest (hash algorithm) acceptance policies.

A :class:`DigestPolicy` makes the decision "which hash algorithms are good
enough to trust" explicit and separate from the mechanical "does the
computed digest match the expected value" check.

The policy is applied to both content fetched from a remote repository and
content read from the local cache, so the two cannot disagree. A consistent
snapshot filename prefix is only used to locate a file: it never counts as a
trusted digest and is not involved in this decision.

Three distinct failure modes are reported with separate exceptions so that
callers can tell them apart:

* :class:`~tuf.api.exceptions.UnknownAlgorithmError`: the metadata names an
  algorithm this client cannot compute, so the digest cannot be checked.
* :class:`~tuf.api.exceptions.DisabledAlgorithmError`: every digest uses an
  algorithm the policy does not accept (typically a phased-out legacy
  algorithm appearing on its own).
* :class:`~tuf.api.exceptions.MissingDigestError`: the policy requires at
  least one digest but the metadata description has none.

A digest that *is* present and accepted but simply does not match the
observed content still raises
:class:`~tuf.api.exceptions.LengthOrHashMismatchError`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from tuf.api import exceptions
from tuf.api._payload import _get_digest, _hash_bytes, _hash_file

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)


class DigestPolicy:
    """Policy describing the hash algorithms accepted for a class of files.

    The same policy type is used for both metadata descriptions
    (``MetaFile``) and target files (``TargetFile``); the :class:`UpdaterConfig
    <tuf.ngclient.config.UpdaterConfig>` keeps one instance for each because
    the two have different requirements for *missing* digests.

    Args:
        accepted_algorithms: Hash algorithm names that are considered
            trustworthy. At least one digest must use one of these
            algorithms. If ``None``, every algorithm the client can compute
            is accepted (the compatibility default).
        require_digest: When ``True`` (target files), the metadata must
            contain at least one digest. When ``False`` (metadata
            descriptions), an omitted ``hashes`` field is allowed, matching
            the TUF specification which permits timestamp/snapshot
            descriptions to omit hashes.

    Algorithms are partitioned into three groups:

    * **accepted**: named in ``accepted_algorithms`` and supported locally.
      These digests are verified and at least one must be present.
    * **unknown**: not supported by this client's hash implementation. These
      always fail closed and raise
      :class:`~tuf.api.exceptions.UnknownAlgorithmError`.
    * **disabled / legacy**: supported locally but not in
      ``accepted_algorithms``. These digests are not trusted and do not
      satisfy the "at least one accepted digest" requirement, but their mere
      presence alongside an accepted digest is not an error.
    """

    def __init__(
        self,
        accepted_algorithms: Iterable[str] | None = None,
        require_digest: bool = True,
    ) -> None:
        self._accepted: frozenset[str] | None = (
            None
            if accepted_algorithms is None
            else frozenset(accepted_algorithms)
        )
        self.require_digest = require_digest

    @property
    def accepted_algorithms(self) -> frozenset[str] | None:
        """Accepted algorithm names, or ``None`` to accept all supported."""
        return self._accepted

    def _is_supported(self, algo: Any) -> bool:  # noqa: ANN401
        """Return whether the client can compute a digest for ``algo``."""
        if not isinstance(algo, str):
            return False
        try:
            _get_digest(algo)
        except (ValueError, TypeError):
            return False
        return True

    def _is_accepted(self, algo: Any) -> bool:  # noqa: ANN401
        # Unknown algorithms are handled separately in check_hashes().
        if not self._is_supported(algo):
            return False
        return self._accepted is None or algo in self._accepted

    def check_hashes(self, hashes: dict[str, str] | None) -> None:
        """Validate the *structure* of ``hashes`` against the policy.

        This does not need file content: it ensures the algorithm names in
        the metadata are known, that at least one accepted algorithm is
        present and, when required, that a digest exists at all.

        Raises:
            UnknownAlgorithmError: An algorithm the client cannot compute is
                present.
            DisabledAlgorithmError: No accepted algorithm is present.
            MissingDigestError: A digest is required but was omitted.
        """
        if not hashes:
            if self.require_digest:
                raise exceptions.MissingDigestError(
                    "No digest present but the digest policy requires one"
                )
            # Metadata descriptions are allowed to omit hashes entirely.
            return

        for algo in hashes:
            if not self._is_supported(algo):
                raise exceptions.UnknownAlgorithmError(
                    f"Digest uses unsupported algorithm '{algo}'"
                )

        accepted = [algo for algo in hashes if self._is_accepted(algo)]
        if not accepted:
            raise exceptions.DisabledAlgorithmError(
                "No digest uses an algorithm accepted by the digest policy "
                f"(available algorithms: {sorted(hashes)})"
            )

    def verify_hashes(
        self,
        data: bytes | Any,  # noqa: ANN401
        hashes: dict[str, str] | None,
    ) -> None:
        """Apply the policy and verify accepted digests of ``data``.

        First :meth:`check_hashes` enforces the structural policy, then every
        accepted digest is computed and compared. Multiple accepted digests
        must *all* match: a matching legacy digest can never rescue a
        mismatching modern one, because legacy digests are not even consulted
        for the trust decision.

        Raises:
            DigestPolicyError: The structural policy is not satisfied.
            LengthOrHashMismatchError: An accepted digest does not match.
        """
        self.check_hashes(hashes)
        if not hashes:
            return

        for algo, expected in hashes.items():
            if not self._is_accepted(algo):
                # Legacy digest: not trusted and not counted. It cannot make
                # verification pass on its own.
                logger.debug("Ignoring digest using non-accepted %s", algo)
                continue

            if isinstance(data, bytes):
                observed = _hash_bytes(data, algo)
            else:
                observed = _hash_file(data, algo)

            if observed != expected:
                raise exceptions.LengthOrHashMismatchError(
                    f"Observed {algo} hash {observed} does not match "
                    f"expected hash {expected}"
                )
