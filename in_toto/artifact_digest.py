# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Artifact digest configuration helpers.

A link records a mapping of artifact paths to digest dictionaries.  The digest
dictionary alone does not say whether a digest was computed over the raw file
bytes or over a defined textual normalization of those bytes.  This module
defines the explicit, signed ``artifact_digest_config`` descriptor that carries
that information.

Legacy links have no descriptor.  For those links the historical semantics
apply: digests are over raw bytes.  The absence of a descriptor is therefore
never interpreted as a particular normalization.

The canonical descriptor looks like::

    {
      "materials": {"sha256": "raw"},
      "products": {"sha256": "line-endings"}
    }

The descriptor is part of the signed link payload and is therefore covered by
link signatures.  Any explicitly named normalization that is not understood by
this implementation is rejected; it is never silently compared as raw bytes.
"""

import copy
import json
import os

from in_toto.exceptions import DigestConfigError

ARTIFACT_DIGEST_CONFIG_FIELD = "artifact_digest_config"
ARTIFACT_TYPES = ("materials", "products")

# Canonical normalization identifiers.
NORMALIZATION_RAW = "raw"
NORMALIZATION_LINE_ENDINGS = "line-endings"

# Normalization identifiers accepted in configuration input.  The canonical
# values are used when serializing links.
_RAW_ALIASES = {
    "raw",
    "raw-bytes",
    "bytes",
    "byte",
    "binary",
    "identity",
    "none",
    "as-is",
    "no-normalization",
    "no-normalize",
    "unnormalized",
    "original",
    "original-bytes",
}

_LINE_ENDING_ALIASES = {
    "line-endings",
    "line-ending",
    "lineendings",
    "lineending",
    "normalize-line-endings",
    "normalize-line-endings-normalization",
    "line-ending-normalization",
    "line-endings-normalization",
    "crlf-to-lf",
    "cr-to-lf",
    "lf",
    "text",
    "text-normalized",
    "normalized-text",
}

# Wildcard algorithm key, used when a config describes all digest algorithms.
ALL_ALGORITHMS = "*"


def _canonical_normalization(value):
    """Return canonical normalization identifier or raise."""
    if not isinstance(value, str):
        raise DigestConfigError(
            "artifact digest normalization must be a string"
        )

    normalized = value.strip().lower().replace("_", "-")
    if normalized in _RAW_ALIASES:
        return NORMALIZATION_RAW

    if normalized in _LINE_ENDING_ALIASES:
        return NORMALIZATION_LINE_ENDINGS

    raise DigestConfigError(f"unknown artifact digest normalization '{value}'")


def _check_algorithm(algorithm):
    if not isinstance(algorithm, str) or not algorithm:
        raise DigestConfigError(
            "artifact digest algorithm names must be non-empty strings"
        )


def _parse_side_config(value):
    """Parse one material/product side into an algorithm->normalization dict."""
    if isinstance(value, str):
        return {ALL_ALGORITHMS: _canonical_normalization(value)}

    if not isinstance(value, dict):
        raise DigestConfigError(
            "artifact digest config side must be a string or a dict"
        )

    parsed = {}
    for algorithm, normalization in value.items():
        _check_algorithm(algorithm)
        parsed[algorithm] = _canonical_normalization(normalization)

    return parsed


def parse_artifact_digest_config(config):
    """Validate and canonicalize an artifact digest configuration.

    ``None`` is passed through and denotes a legacy link, whose historical
    meaning is raw-byte digests.

    Accepted input shapes are intentionally small, but some convenient
    shorthands are supported:

    - a normalization string, e.g. ``"line-endings"``
    - ``{"normalization": "raw"}``
    - ``{"materials": "raw", "products": "line-endings"}``
    - ``{"materials": {"sha256": "raw"}, ...}``
    - ``{"sha256": "raw"}``

    The returned value is a fresh dictionary in the canonical per-side,
    per-algorithm form.
    """
    if config is None:
        return None

    if isinstance(config, str):
        normalization = _canonical_normalization(config)
        return {
            side: {ALL_ALGORITHMS: normalization} for side in ARTIFACT_TYPES
        }

    if not isinstance(config, dict):
        raise DigestConfigError(
            "artifact digest config must be a string, dict, or None"
        )

    has_sides = any(side in config for side in ARTIFACT_TYPES)
    if "normalization" in config:
        if has_sides:
            raise DigestConfigError(
                "artifact digest config cannot mix 'normalization' with"
                " per-side entries"
            )
        if set(config) != {"normalization"}:
            raise DigestConfigError(
                "artifact digest config with 'normalization' must not contain"
                " other entries"
            )
        normalization = _canonical_normalization(config["normalization"])
        return {
            side: {ALL_ALGORITHMS: normalization} for side in ARTIFACT_TYPES
        }

    if has_sides:
        unknown = set(config) - set(ARTIFACT_TYPES)
        if unknown:
            raise DigestConfigError(
                "unknown artifact digest config side(s): "
                + ", ".join(sorted(unknown))
            )
        return {
            side: _parse_side_config(value) for side, value in config.items()
        }

    # A bare algorithm->normalization mapping applies to both artifact sides.
    side_config = _parse_side_config(config)
    return {side: copy.deepcopy(side_config) for side in ARTIFACT_TYPES}


def build_config_from_hashes(
    materials,
    products,
    config=None,
    normalize_line_endings=False,
    sides=None,
):
    """Build an explicit config from recorded hashes and recording options.

    New metadata always records an explicit descriptor.  A legacy link is only
    produced by loading old metadata without a descriptor, never by this
    function.  ``config`` may set per-side normalizations; if absent, the
    ``normalize_line_endings`` flag determines them, with both sides raw when
    the flag is false.
    """
    parsed = parse_artifact_digest_config(config)

    if sides is None:
        sides = ARTIFACT_TYPES

    result = {}
    for side, hashes in (
        ("materials", materials),
        ("products", products),
    ):
        if side not in sides:
            continue

        if parsed is not None and side not in parsed:
            if hashes:
                raise DigestConfigError(
                    f"artifact digest config does not describe '{side}',"
                    " but artifacts were recorded for it"
                )
            # Sides absent from an explicit config and without artifacts (e.g.
            # products at record-start) are not described.
            continue

        normalization = recording_normalization(
            parsed, side, normalize_line_endings
        )
        algorithms = {
            algorithm
            for hash_dict in hashes.values()
            for algorithm in hash_dict
        }

        declared = {}
        if parsed is not None and side in parsed:
            declared = copy.deepcopy(parsed[side])

        if ALL_ALGORITHMS in declared:
            wildcard_normalization = declared.pop(ALL_ALGORITHMS)
            declared.update(
                {algorithm: wildcard_normalization for algorithm in algorithms}
            )

        if algorithms:
            declared.update(
                {
                    algorithm: declared.get(algorithm, normalization)
                    for algorithm in algorithms
                }
            )
            result[side] = declared
        elif declared:
            # Preserve explicit declarations for a side that has no recorded
            # artifacts yet, e.g. products in preliminary link metadata.
            result[side] = declared
        else:
            result[side] = {ALL_ALGORITHMS: normalization}

    return result


def explicit_side_config(link, side):
    """Return an explicit side config, mapping legacy raw semantics."""
    config = getattr(link, ARTIFACT_DIGEST_CONFIG_FIELD, None)
    if config is None:
        algorithms = {
            algorithm
            for hash_dict in getattr(link, side).values()
            for algorithm in hash_dict
        }
        if not algorithms:
            return {ALL_ALGORITHMS: NORMALIZATION_RAW}
        return {algorithm: NORMALIZATION_RAW for algorithm in algorithms}

    declared = copy.deepcopy(side_config(config, side))
    algorithms = {
        algorithm
        for hash_dict in getattr(link, side).values()
        for algorithm in hash_dict
    }
    if algorithms and ALL_ALGORITHMS in declared:
        normalization = declared.pop(ALL_ALGORITHMS)
        return {algorithm: normalization for algorithm in algorithms} | declared

    return declared


def recording_normalization(config, side, normalize_line_endings=False):
    """Return the normalization to use while recording one link side.

    If a config is passed, it is authoritative for sides it describes.  It must
    name exactly one normalization for such a side, because all artifacts of a
    side are recorded with the same hashing procedure.  Sides absent from an
    explicit config (e.g. products in preliminary links) fall back to the
    ``normalize_line_endings`` flag.
    """
    if not normalize_line_endings:
        fallback = NORMALIZATION_RAW
    else:
        fallback = NORMALIZATION_LINE_ENDINGS

    if config is None:
        return fallback

    parsed = parse_artifact_digest_config(config)
    if side not in parsed:
        return fallback
    side_config = parsed.get(side)
    if not side_config:
        raise DigestConfigError(
            f"artifact digest config does not describe '{side}'"
        )

    normalizations = set(side_config.values())
    if len(normalizations) != 1:
        raise DigestConfigError(
            f"artifact digest config for '{side}' must use a single"
            " normalization when recording"
        )

    normalization = next(iter(normalizations))

    if normalize_line_endings and normalization != NORMALIZATION_LINE_ENDINGS:
        raise DigestConfigError(
            f"artifact digest config for '{side}' declares"
            f" '{normalization}', but line ending normalization was requested"
        )

    return normalization


def side_config(config, side):
    """Return parsed per-algorithm config for a side, or None for legacy."""
    parsed = parse_artifact_digest_config(config)
    if parsed is None:
        return None

    value = parsed.get(side)
    if value is None:
        raise DigestConfigError(
            f"artifact digest config does not describe '{side}'"
        )

    return value


def effective_normalization(config, side, algorithm):
    """Return normalization for one side/algorithm, honoring legacy raw."""
    if config is None:
        return NORMALIZATION_RAW

    side_values = side_config(config, side)
    if algorithm in side_values:
        return side_values[algorithm]

    if ALL_ALGORITHMS in side_values:
        return side_values[ALL_ALGORITHMS]

    raise DigestConfigError(
        f"artifact digest config for '{side}' does not describe digest"
        f" algorithm '{algorithm}'"
    )


def effective_side_config(link, side):
    """Return effective per-algorithm normalization for a link side.

    Legacy links without a descriptor resolve to raw-byte semantics.
    """
    config = getattr(link, ARTIFACT_DIGEST_CONFIG_FIELD, None)
    artifacts = getattr(link, side)
    return {
        algorithm: effective_normalization(config, side, algorithm)
        for algorithm in artifacts
    }


def validate_link_config(link):
    """Raise if an explicit config does not describe recorded artifacts."""
    config = getattr(link, ARTIFACT_DIGEST_CONFIG_FIELD, None)
    if config is None:
        return

    # Re-parse to catch aliases or mutations after object construction.
    parsed = parse_artifact_digest_config(config)
    for side in ARTIFACT_TYPES:
        artifacts = getattr(link, side)
        if not artifacts:
            continue

        side_values = parsed.get(side)
        if side_values is None:
            raise DigestConfigError(
                f"artifact digest config does not describe '{side}'"
            )

        algorithms = {
            algorithm
            for hash_dict in artifacts.values()
            for algorithm in hash_dict
        }
        for algorithm in algorithms:
            effective_normalization(parsed, side, algorithm)


def hashes_match(
    hashes_a,
    config_a,
    side_a,
    hashes_b,
    config_b,
    side_b,
):
    """Return whether hashes denote the same content under their policies.

    A digest value is only meaningful together with the normalization that
    produced it.  Equal digest dictionaries under different policies therefore
    do not match, and unknown policies raise instead of defaulting to raw.
    """
    if hashes_a != hashes_b:
        return False

    for algorithm in hashes_a:
        normalization_a = effective_normalization(config_a, side_a, algorithm)
        normalization_b = effective_normalization(config_b, side_b, algorithm)
        if normalization_a != normalization_b:
            return False

    return True


def artifact_hashes_match(
    source_hashes,
    source_link,
    source_type,
    dest_hashes,
    dest_link,
    dest_type,
):
    """Return whether artifact hashes match under their link policies."""
    return hashes_match(
        source_hashes,
        getattr(source_link, ARTIFACT_DIGEST_CONFIG_FIELD, None),
        source_type,
        dest_hashes,
        getattr(dest_link, ARTIFACT_DIGEST_CONFIG_FIELD, None),
        dest_type,
    )


def side_policies_equal(config_a, side_a, hashes_a, config_b, side_b, hashes_b):
    """Compare effective digest policies for recorded algorithms of one side.

    Only algorithms present in the recorded hash dictionaries matter here; a
    declaration for an algorithm that was not recorded says nothing about the
    artifacts at hand.  For every recorded algorithm, an undeclared policy on an
    explicit link is an error, not an implicit raw default.
    """
    # Hash dictionaries were compared for equality before this helper is used,
    # so the algorithm sets are identical.
    algorithms = {
        algorithm for hash_dict in hashes_a.values() for algorithm in hash_dict
    }

    for algorithm in algorithms:
        normalization_a = effective_normalization(config_a, side_a, algorithm)
        normalization_b = effective_normalization(config_b, side_b, algorithm)
        if normalization_a != normalization_b:
            return False

    return True


def links_have_same_artifacts(link_a, link_b):
    """Compare materials and products including their digest policies."""
    config_a = getattr(link_a, ARTIFACT_DIGEST_CONFIG_FIELD, None)
    config_b = getattr(link_b, ARTIFACT_DIGEST_CONFIG_FIELD, None)

    for side in ARTIFACT_TYPES:
        hashes_a = getattr(link_a, side)
        hashes_b = getattr(link_b, side)
        if hashes_a != hashes_b:
            return False

        if not side_policies_equal(
            config_a, side, hashes_a, config_b, side, hashes_b
        ):
            return False

    return True


def config_for_summary(first_link, last_link):
    """Build a summary config from first-step materials and last-step products.

    If both contributing links are legacy links (no descriptor), the summary
    stays legacy.  Otherwise every side with artifacts gets an explicit policy,
    so a normalized side is never presented as raw in the summary.
    """
    first_config = getattr(first_link, ARTIFACT_DIGEST_CONFIG_FIELD, None)
    last_config = getattr(last_link, ARTIFACT_DIGEST_CONFIG_FIELD, None)

    if first_config is None and last_config is None:
        return None

    summary = {}
    if first_link.materials:
        summary["materials"] = explicit_side_config(first_link, "materials")

    if last_link.products:
        summary["products"] = explicit_side_config(last_link, "products")

    return summary or None


def parse_config_argument(value):
    """Parse a CLI config argument.

    Accepts a JSON string, a path to a JSON file, or a bare normalization
    name (e.g. ``raw`` or ``line-endings``).
    """
    if value is None:
        return None

    stripped = value.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise DigestConfigError(
                "artifact digest config is not valid JSON"
            ) from exc

        return parse_artifact_digest_config(data)

    if os.path.isfile(value):
        with open(value, encoding="utf-8") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError as exc:
                raise DigestConfigError(
                    "artifact digest config file is not valid JSON"
                ) from exc

        return parse_artifact_digest_config(data)

    return parse_artifact_digest_config(value)


def normalize_line_endings_bytes(data):
    """Return bytes with CRLF and lone CR normalized to LF."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
