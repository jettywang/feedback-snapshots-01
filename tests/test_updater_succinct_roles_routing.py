# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Security model tests for succinct roles hash-bin routing.

Succinct roles (TAP 15) assign every target to a single, unique signing bin
based on the left-most bits of the SHA-256 digest of the target path's UTF-8
bytes. A target must only be authorized through the metadata of the bin it
actually routes to: a different bin, even one holding a fully valid signature,
the complete target file and the correct digest, must not be able to authorize
that target.

These tests pin down three independent views of the routing decision and check
that they always agree:

1. an independent reference router that recomputes the bin index from the
   raw SHA-256 bit string (no byte-alignment assumptions),
2. ``SuccinctRoles.get_role_for_target`` / ``is_delegated_role`` (the name
   recognition logic used during signature verification), and
3. the real ``Updater`` client, which must accept a target only through the
   routed bin and reject everything reachable through another bin.

The generated cases use a fixed, reducible seed so that any failing case can be
reproduced by shrinking :data:`SAMPLE_COUNT` or the generated path space.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from itertools import islice
from random import Random
from typing import TYPE_CHECKING
from urllib import parse

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import Metadata, SuccinctRoles, TargetFile
from tuf.ngclient import Updater

if TYPE_CHECKING:
    from collections.abc import Iterator

# Deterministic seed for the generated model. Reproduce any reported failure by
# re-running with the printed seed or by reducing SAMPLE_COUNT.
SEED = 20261114
# Number of generated (bit_length, prefix, path) combinations per seed. Keep
# small so a failure is cheap to reproduce.
SAMPLE_COUNT = 24
# bit_length values used for the simulated repositories: every value keeps the
# total number of bins small enough that a full in-memory repository is cheap.
# Non-byte-aligned values (not a multiple of 8) are deliberately included.
SMALL_BIT_LENGTHS = (1, 2, 3, 5, 7, 8)
# The largest legal bit_length: exercised through the API only, never by
# materializing the 2**32 bins.
MAX_BIT_LENGTH = 32

# ASCII and non-ASCII building blocks. Non-ASCII names stress the fact that the
# hash is taken over the UTF-8 encoding rather than the Python string.
_PATH_WORDS = (
    "target",
    "release",
    "bin",
    "a/b",
    "dir/file",
    "åäö",
    "目标",
    "パス",
    "émoji😀",
    "Ω/να",
)
_PREFIXES = ("bin", "delegated/targets", "ä", "")


def reference_bin_index(target_path: str, bit_length: int) -> int:
    """Independently compute the expected bin index.

    The reference builds the SHA-256 digest as an explicit bit string and takes
    the left-most ``bit_length`` bits, so it works for any bit length, including
    non-byte-aligned ones, without reusing the production shift arithmetic.
    """
    digest = hashlib.sha256(target_path.encode("utf-8")).digest()
    bit_string = "".join(f"{byte:08b}" for byte in digest)
    return int(bit_string[:bit_length], 2)


def reference_role_name(
    target_path: str, succinct_roles: SuccinctRoles
) -> str:
    """Independently compute the expected bin role name."""
    index = reference_bin_index(target_path, succinct_roles.bit_length)
    suffix = f"{index:0{succinct_roles.suffix_len}x}"
    return f"{succinct_roles.name_prefix}-{suffix}"


def find_path_for_index(
    succinct_roles: SuccinctRoles, wanted_index: int
) -> str:
    """Find a target path that routes to ``wanted_index`` by construction.

    The path space is searched locally instead of enumerating all bins, which
    matters for large ``bit_length`` configurations.
    """
    counter = 0
    while True:
        candidate = f"boundary-{counter}"
        if (
            reference_bin_index(candidate, succinct_roles.bit_length)
            == wanted_index
        ):
            return candidate
        counter += 1


def _generated_cases() -> Iterator[tuple[int, str, str]]:
    """Yield deterministic (bit_length, name_prefix, target_path) cases."""
    rng = Random(SEED)
    for _ in range(SAMPLE_COUNT):
        bit_length = rng.choice(SMALL_BIT_LENGTHS)
        prefix = rng.choice(_PREFIXES)
        words = rng.sample(_PATH_WORDS, k=rng.randint(1, 3))
        target_path = "/".join(words)
        yield bit_length, prefix, target_path


class TestSuccinctRolesRoutingModel(unittest.TestCase):
    """Pin the hash-bit routing model against an independent reference."""

    def test_seeded_routing_matches_reference(self) -> None:
        for case_number, (bit_length, prefix, path) in enumerate(
            _generated_cases()
        ):
            with self.subTest(
                seed=SEED,
                case=case_number,
                bit_length=bit_length,
                prefix=prefix,
                path=path,
            ):
                roles = SuccinctRoles([], 1, bit_length, prefix)

                # Reference router and production router must agree exactly.
                expected_name = reference_role_name(path, roles)
                self.assertEqual(roles.get_role_for_target(path), expected_name)

                expected_index = reference_bin_index(path, bit_length)
                self.assertGreaterEqual(expected_index, 0)
                self.assertLess(expected_index, roles.number_of_bins)

                # The recognized name must be a delegated bin and its hex
                # suffix must decode back to the reference index.
                self.assertTrue(roles.is_delegated_role(expected_name))
                suffix = expected_name[len(prefix) + 1 :]
                self.assertEqual(int(suffix, 16), expected_index)

    def test_non_byte_aligned_bit_length(self) -> None:
        # bit_length values that do not align to a byte boundary are where a
        # byte-wise router would silently disagree with the bit-string router.
        for bit_length in (1, 3, 5, 7, 9, 13):
            for path in ("foo", "åäö", "目标/路径"):
                with self.subTest(bit_length=bit_length, path=path):
                    roles = SuccinctRoles([], 1, bit_length, "bin")
                    self.assertEqual(
                        roles.get_role_for_target(path),
                        reference_role_name(path, roles),
                    )
                    index = reference_bin_index(path, bit_length)
                    self.assertLess(index, 2**bit_length)

    def test_routing_uses_utf8_bytes(self) -> None:
        # The same logical string must route from its UTF-8 encoding; encode
        # explicitly and confirm the digest the model relies on is the UTF-8
        # digest rather than some other representation.
        path = "目标/路径-émoji"
        roles = SuccinctRoles([], 1, 11, "bin")
        expected_index = int(
            "".join(
                f"{byte:08b}"
                for byte in hashlib.sha256(path.encode("utf-8")).digest()
            )[:11],
            2,
        )
        routed = roles.get_role_for_target(path)
        self.assertEqual(int(routed.split("-")[-1], 16), expected_index)
        # A different encoding of the same characters must not be mistaken for
        # the UTF-8 input.
        self.assertNotEqual(
            hashlib.sha256(path.encode("utf-8")).digest(),
            hashlib.sha256(path.encode("utf-16")).digest(),
        )

    def test_boundary_bin_names(self) -> None:
        roles = SuccinctRoles([], 1, 5, "bin")
        first_path = find_path_for_index(roles, 0)
        last_path = find_path_for_index(roles, roles.number_of_bins - 1)

        self.assertEqual(roles.get_role_for_target(first_path), "bin-00")
        self.assertEqual(roles.get_role_for_target(last_path), "bin-1f")
        # The very first and very last bin names are recognized, while names
        # one step outside the valid range are not.
        self.assertTrue(roles.is_delegated_role("bin-00"))
        self.assertTrue(roles.is_delegated_role("bin-1f"))
        self.assertFalse(roles.is_delegated_role("bin-20"))
        self.assertFalse(roles.is_delegated_role("bin-1g"))

    def test_name_prefix_is_part_of_identity(self) -> None:
        # Same hash, same bit length, but a different prefix yields a different
        # role name; the prefix cannot be substituted by an attacker.
        for prefix in ("bin", "delegated/targets"):
            roles = SuccinctRoles([], 1, 4, prefix)
            name = roles.get_role_for_target("prefixed-target")
            self.assertTrue(name.startswith(f"{prefix}-"))
            self.assertTrue(roles.is_delegated_role(name))
            # The same suffix under another prefix is not this configuration's
            # delegated role.
            suffix = name[len(prefix) + 1 :]
            self.assertFalse(roles.is_delegated_role(f"other-{suffix}"))

        # An empty prefix still produces the mandatory hyphen separator.
        empty = SuccinctRoles([], 1, 3, "")
        name = empty.get_role_for_target("x")
        self.assertTrue(name.startswith("-"))
        self.assertTrue(empty.is_delegated_role(name))

    def test_malformed_bin_names_are_not_delegated_roles(self) -> None:
        # Malformed names must never be recognized as bins, separately from
        # well-formed names that belong to a different bin.
        roles = SuccinctRoles([], 1, 5, "bin")
        malformed = (
            "foo",          # wrong prefix
            "bin",          # missing separator and suffix
            "bin-",         # empty suffix
            "bin-s",        # non-hex suffix
            "bin-0t",       # non-hex digit
            "bin-20",       # hex suffix but index out of range
            "bin-100",      # suffix too long
            "bin-0",        # suffix too short
            "BIN-00",       # prefix is case-sensitive
            "../bin-00",    # path traversal style name
        )
        for name in malformed:
            with self.subTest(name=name):
                self.assertFalse(roles.is_delegated_role(name))

    def test_well_formed_name_belonging_to_another_bin(self) -> None:
        # Unlike malformed names, this is a syntactically valid bin; it must be
        # recognized but must not be the bin the target routes to.
        roles = SuccinctRoles([], 1, 4, "bin")
        path = "some-target"
        routed_name = roles.get_role_for_target(path)
        routed_index = int(routed_name.split("-")[-1], 16)
        other_index = (routed_index + 1) % roles.number_of_bins
        other_name = f"bin-{other_index:0{roles.suffix_len}x}"

        self.assertTrue(roles.is_delegated_role(other_name))
        self.assertNotEqual(routed_name, other_name)
        self.assertEqual(
            reference_role_name(path, roles), routed_name
        )

    def test_maximum_legal_configuration_without_enumerating_bins(self) -> None:
        # bit_length 32 means 2**32 bins and must never be materialized here.
        roles = SuccinctRoles([], 1, MAX_BIT_LENGTH, "bin")
        self.assertEqual(roles.number_of_bins, 1 << MAX_BIT_LENGTH)
        self.assertEqual(roles.suffix_len, 8)

        # Inspect just a bounded slice of the lazy bin name iterator.
        head = list(islice(roles.get_roles(), 3))
        self.assertEqual(head, ["bin-00000000", "bin-00000001", "bin-00000002"])

        path = "max-config-target"
        expected = reference_role_name(path, roles)
        self.assertEqual(roles.get_role_for_target(path), expected)
        self.assertTrue(roles.is_delegated_role(expected))
        # The index stays within the full 32-bit range.
        index = reference_bin_index(path, MAX_BIT_LENGTH)
        self.assertLess(index, 1 << MAX_BIT_LENGTH)

        # Construction-time bounds are enforced.
        with self.assertRaises(ValueError):
            SuccinctRoles([], 1, 0, "bin")
        with self.assertRaises(ValueError):
            SuccinctRoles([], 1, MAX_BIT_LENGTH + 1, "bin")


class TestSuccinctRolesClientAuthorization(unittest.TestCase):
    """End-to-end checks that the client only accepts the routed bin."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_updater(self, sim: RepositorySimulator) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            sim,
            bootstrap=sim.signed_roots[0],
        )

    def _build_repo(
        self, bit_length: int, prefix: str
    ) -> tuple[RepositorySimulator, SuccinctRoles]:
        sim = RepositorySimulator()
        sim.add_succinct_roles("targets", bit_length, prefix)
        sim.update_snapshot()
        assert sim.targets.delegations is not None
        assert sim.targets.delegations.succinct_roles is not None
        return sim, sim.targets.delegations.succinct_roles

    def test_client_routing_matches_model_and_accepts_target(self) -> None:
        for case_number, (bit_length, prefix, path) in enumerate(
            _generated_cases()
        ):
            with self.subTest(
                seed=SEED,
                case=case_number,
                bit_length=bit_length,
                prefix=prefix,
                path=path,
            ):
                sim, roles = self._build_repo(bit_length, prefix)
                expected_bin = reference_role_name(path, roles)
                self.assertEqual(roles.get_role_for_target(path), expected_bin)

                # Publish the target only in its routed bin.
                content = f"content of {path}".encode("utf-8")
                sim.add_target(expected_bin, content, path)
                sim.update_snapshot()

                updater = self._init_updater(sim)
                updater.refresh()
                sim.fetch_tracker.metadata.clear()

                target_info = updater.get_targetinfo(path)
                self.assertIsNotNone(target_info)

                # Exactly one delegated bin was visited and it is the routed
                # bin: the client never enumerates the other bins. The fetch
                # tracker stores the URL-quoted role name.
                self.assertEqual(
                    sim.fetch_tracker.metadata,
                    [(parse.quote(expected_bin, safe=""), 1)],
                )

                # The client truly accepts the target: download succeeds and
                # the content hash/length verification passes.
                local_path = updater.download_target(target_info)
                with open(local_path, "rb") as handle:
                    self.assertEqual(handle.read(), content)
                self.assertEqual(
                    updater.find_cached_target(target_info), local_path
                )

    def test_wrong_bin_cannot_authorize_target(self) -> None:
        # The core security property: another bin holds a perfectly valid
        # signature, the full target and a correct digest, yet it must not be
        # able to authorize the target because the target does not route to it.
        sim, roles = self._build_repo(5, "bin")
        path = "protected/目标"
        routed_bin = reference_role_name(path, roles)
        routed_index = int(routed_bin.split("-")[-1], 16)
        wrong_index = (routed_index + 1) % roles.number_of_bins
        wrong_bin = f"bin-{wrong_index:0{roles.suffix_len}x}"
        self.assertNotEqual(routed_bin, wrong_bin)
        self.assertTrue(roles.is_delegated_role(wrong_bin))

        content = b"authentic target bytes"
        # The wrong bin gets the complete target with its *correct* digest.
        sim.add_target(wrong_bin, content, path)
        sim.update_snapshot()

        updater = self._init_updater(sim)
        updater.refresh()
        sim.fetch_tracker.metadata.clear()

        # The client visits only the routed bin and finds nothing there.
        self.assertIsNone(updater.get_targetinfo(path))
        self.assertEqual(
            sim.fetch_tracker.metadata,
            [(parse.quote(routed_bin, safe=""), 1)],
        )

        # The wrong bin is never fetched for this target, so its validly signed
        # copy cannot be used to authorize a download.
        wrong_bin_fetches = [
            name for name, _ in sim.fetch_tracker.metadata if name == wrong_bin
        ]
        self.assertEqual(wrong_bin_fetches, [])

    def test_correct_bin_accepts_even_when_wrong_bin_also_has_copy(self) -> None:
        # Defense in depth: publish the target in both the routed bin and a
        # different bin. The client must still select the routed bin only and
        # accept the target through it, never through the other bin.
        sim, roles = self._build_repo(4, "bin")
        path = "dual-published/émoji"
        routed_bin = reference_role_name(path, roles)
        routed_index = int(routed_bin.split("-")[-1], 16)
        other_index = (routed_index + 1) % roles.number_of_bins
        other_bin = f"bin-{other_index:0{roles.suffix_len}x}"

        content = b"same bytes in both bins"
        correct_target = TargetFile.from_data(path, content, ["sha256"])
        sim.add_target(routed_bin, content, path)
        sim.add_target(other_bin, content, path)
        sim.update_snapshot()

        updater = self._init_updater(sim)
        updater.refresh()
        sim.fetch_tracker.metadata.clear()

        target_info = updater.get_targetinfo(path)
        self.assertIsNotNone(target_info)
        self.assertEqual(target_info.to_dict(), correct_target.to_dict())
        self.assertEqual(
            sim.fetch_tracker.metadata,
            [(parse.quote(routed_bin, safe=""), 1)],
        )

        local_path = updater.download_target(target_info)
        with open(local_path, "rb") as handle:
            self.assertEqual(handle.read(), content)

    def test_malformed_bin_name_cannot_serve_target(self) -> None:
        # A repository that names a bin with a malformed identifier cannot get
        # the client to trust it: malformed names are not delegated roles and
        # are never part of the routing graph. This is distinct from a
        # well-formed name belonging to another bin, which the graph does know.
        sim, roles = self._build_repo(4, "bin")
        path = "malformed-name-target"
        routed_bin = reference_role_name(path, roles)
        malformed = "bin-gg"

        self.assertFalse(roles.is_delegated_role(malformed))
        # The simulator never created a bin (or signer) for that name.
        self.assertNotIn(malformed, sim.md_delegates)
        self.assertNotIn(malformed, sim.signers)

        updater = self._init_updater(sim)
        updater.refresh()
        sim.fetch_tracker.metadata.clear()

        # Routing only ever points at the routed bin, so the malformed name is
        # never requested and the missing target resolves to None.
        self.assertIsNone(updater.get_targetinfo(path))
        self.assertEqual(
            sim.fetch_tracker.metadata,
            [(parse.quote(routed_bin, safe=""), 1)],
        )
        self.assertNotIn(
            parse.quote(malformed, safe=""),
            [name for name, _ in sim.fetch_tracker.metadata],
        )

        # Even if malformed metadata reached the trusted set, loading it fails:
        # the snapshot has no entry for an unknown bin.
        with self.assertRaises(RepositoryError):
            updater._trusted_set.update_delegated_targets(
                b"{}", malformed, "targets"
            )

        # At the signature layer, the malformed name has no delegated role and
        # therefore no authorized key, so it can never be verified. Use a real
        # bin's signed bytes to show the rejection is purely the name.
        signed_bin_bytes = sim.fetch_metadata(routed_bin)
        signed_md = Metadata.from_bytes(signed_bin_bytes)
        with self.assertRaises(ValueError):
            sim.targets.verify_delegate(
                malformed, signed_md.signed_bytes, signed_md.signatures
            )
        # The same payload under the routed bin name verifies successfully.
        sim.targets.verify_delegate(
            routed_bin, signed_md.signed_bytes, signed_md.signatures
        )


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
