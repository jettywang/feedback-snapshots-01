"""This module detects certain modifications in the beacon config and adapt it to the expected format for parsing.

Current seen and supported modifications:
    - Changes in the SettingsType enum values

Normalization never mutates the input :class:`BeaconConfigBlock`. Every decision is recorded on the
:class:`BeaconModifications` object:

    - the original and normalized config bytes (plus an input hash),
    - one :class:`TypeFieldChange` per setting type field, including the evidence it was based on,
    - observed type numbers that could not be confirmed (``unknown_types``), whose original bytes are retained,
    - explicit :class:`NormalizationConflict` entries when multiple normalizers contradict each other.

Evidence classes:

    - ``stock``: the setting index is a known :class:`BeaconSetting` and its stock type supports the mapping,
    - ``length``: only the value length heuristic supports the mapping,
    - ``unknown``: insufficient evidence; the observed type is left untouched.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import replace

from dissect.cobaltstrike.beacon import (
    BeaconConfigBlock,
    BeaconModifications,
    BeaconSetting,
    NormalizationConflict,
    Normalizer,
    SettingsType,
    STOCK_TYPE,
    TypeFieldChange,
)

logger = logging.getLogger(__name__)

NORMALIZER_NAME = "fix_settings_types"

# Candidate semantic type per value-length signature, used as a fallback when no stock setting is available.
_LENGTH_TO_STOCK_TYPE = {
    2: int(SettingsType.TYPE_SHORT),
    4: int(SettingsType.TYPE_INT),
}


def _iter_setting_headers(data: bytes) -> Iterator[tuple[int, int, int, int]]:
    """Yield ``(offset, index, observed_type, length)`` tuples for every packed setting in ``data``."""
    offset = 0
    while offset + 6 <= len(data):
        index, observed_type, length = struct.unpack(">HHH", data[offset : offset + 6])
        if index == 0:
            return
        yield offset, index, observed_type, length
        offset += 6 + length


def settings_type_modifications(config_block: BeaconConfigBlock) -> dict[int, int]:
    """Detect modifications to the SettingsType enum in the Beacon Configuration.

    Returns a mapping of *observed type number -> normalized stock type number*. Only mappings backed by
    sufficient evidence are returned; observed types that cannot be confirmed are intentionally absent and
    must keep their original bytes. An empty mapping means the stock enum values appear untouched.
    """
    inferred, unknown = infer_type_mapping(config_block)
    return inferred


def infer_type_mapping(config_block: BeaconConfigBlock) -> tuple[dict[int, int], dict[int, list[int]]]:
    """Infer the observed-type -> stock-type mapping and collect unconfirmable observed types.

    The primary evidence is the stock type of known :class:`BeaconSetting` indexes. The value-length
    heuristic (short == 2 bytes, int == 4 bytes, pointer > 4 bytes) only fills gaps for observed types
    that no known setting vouches for. Observed types without either kind of evidence are reported as
    unknown instead of being guessed.
    """
    # observed type -> set of stock types suggested by known settings, observed value lengths and indexes
    stock_votes: dict[int, set[int]] = defaultdict(set)
    length_votes: dict[int, set[int]] = defaultdict(set)
    type_indexes: dict[int, set[int]] = defaultdict(set)
    has_known_index: dict[int, bool] = defaultdict(bool)

    for _offset, index, observed_type, length in _iter_setting_headers(config_block.data):
        type_indexes[observed_type].add(index)
        if length in _LENGTH_TO_STOCK_TYPE:
            length_votes[observed_type].add(_LENGTH_TO_STOCK_TYPE[length])
        elif length > 4:
            length_votes[observed_type].add(int(SettingsType.TYPE_PTR))
        if index in BeaconSetting._value2member_map_:
            has_known_index[observed_type] = True
            setting = BeaconSetting(index)
            for stock_type in STOCK_TYPE.get(setting, set()):
                stock_votes[observed_type].add(int(stock_type))

    inferred: dict[int, int] = {}
    unknown: dict[int, list[int]] = {}

    for observed_type, indexes in type_indexes.items():
        stock_candidates = stock_votes.get(observed_type, set())
        length_candidates = length_votes.get(observed_type, set())

        if stock_candidates:
            # Known settings are the primary evidence. A single candidate is conclusive; otherwise the
            # value-length heuristic may break the tie, and failing that the type stays unconfirmed.
            if len(stock_candidates) == 1:
                candidates = stock_candidates
            elif len(length_candidates) == 1:
                candidates = length_candidates
            else:
                candidates = set()
        elif has_known_index.get(observed_type):
            # Known setting without a stock-type entry: the length heuristic is the only evidence.
            candidates = length_candidates if len(length_candidates) == 1 else set()
        else:
            # Observed only on unknown indexes: a length signature alone is not sufficient evidence.
            candidates = set()

        if len(candidates) == 1:
            inferred[observed_type] = next(iter(candidates))
        else:
            unknown[observed_type] = sorted(indexes)

    if not inferred:
        return {}, unknown

    # A stock enum needs no remapping: when the inferred mapping is the identity on the stock values,
    # treat the config as unmodified. Unknown observed types stay reported regardless.
    if all(observed == normalized for observed, normalized in inferred.items()):
        return {}, unknown
    return inferred, unknown


def _mapping_evidence(
    observed_type: int,
    indexes: set[int],
    normalized_type: int,
) -> tuple[str, str]:
    """Return ``(evidence, reason)`` explaining why ``observed_type`` maps to ``normalized_type``."""
    stock_indexes = []
    for index in sorted(indexes):
        if index not in BeaconSetting._value2member_map_:
            continue
        setting = BeaconSetting(index)
        if normalized_type in {int(stock_type) for stock_type in STOCK_TYPE.get(setting, set())}:
            stock_indexes.append(f"{setting.name}(idx={index})")
    if stock_indexes:
        return (
            "stock",
            f"known setting(s) {', '.join(stock_indexes)} declare stock type "
            f"{SettingsType(normalized_type).name}",
        )
    return (
        "length",
        f"no known setting declares observed type {observed_type}; value lengths are only consistent "
        f"with {SettingsType(normalized_type).name}",
    )


def fix_settings_types(
    config_block: BeaconConfigBlock,
    mods: BeaconModifications,
) -> tuple[BeaconConfigBlock, BeaconModifications]:
    """Normalize modified SettingsTypes in the ``BeaconConfigBlock`` and record every decision on ``mods``.

    Example hashes that have modified SettingsTypes:
        - a3a9d344b58d18a32780d8664bc0ba1018f0656e0d348e5d7d1c0166079bdab7
    """
    type_mapping, unknown = infer_type_mapping(config_block)

    # Record observed types that could not be confirmed. Their bytes are always retained.
    for observed_type, indexes in unknown.items():
        mods.unknown_types[observed_type] = indexes
        for offset, index, _typ, _length in _iter_setting_headers(config_block.data):
            if index not in indexes:
                continue
            mods.type_changes.append(
                TypeFieldChange(
                    offset=offset,
                    index=index,
                    original_type=observed_type,
                    proposed_type=None,
                    reason=(
                        f"insufficient evidence: observed type {observed_type} is neither backed by a known "
                        "setting nor by an unambiguous value length"
                    ),
                    normalizer=NORMALIZER_NAME,
                    evidence="unknown",
                )
            )

    if not type_mapping:
        if unknown:
            logger.debug("Unconfirmable SettingsTypes left untouched: %s", unknown)
        return config_block, mods

    logger.debug("Detected remapped SettingsTypes: %s; normalizing", type_mapping)
    if "remapped_types" not in mods.tags:
        mods.tags.append("remapped_types")
    mods.remapped_types.update(type_mapping)

    # Group indexes per observed type so the same evidence explanation is reused for every field.
    type_indexes: dict[int, set[int]] = defaultdict(set)
    for _offset, index, observed_type, _length in _iter_setting_headers(config_block.data):
        type_indexes[observed_type].add(index)

    buffer = bytearray(config_block.data)
    for offset, index, observed_type, _length in _iter_setting_headers(config_block.data):
        normalized_type = type_mapping.get(observed_type)
        if normalized_type is None:
            # Unknown observed type: retain the original bytes explicitly.
            continue

        evidence, reason = _mapping_evidence(observed_type, type_indexes[observed_type], normalized_type)
        applied = observed_type != normalized_type
        if applied:
            struct.pack_into(">H", buffer, offset + 2, normalized_type)
            setting_name = BeaconSetting(index).name if index in BeaconSetting._value2member_map_ else f"idx={index}"
            logger.debug(
                "Fixing %s: observed type %s -> normalized %s",
                setting_name,
                observed_type,
                SettingsType(normalized_type).name,
            )
        mods.type_changes.append(
            TypeFieldChange(
                offset=offset,
                index=index,
                original_type=observed_type,
                proposed_type=normalized_type,
                reason=reason,
                normalizer=NORMALIZER_NAME,
                evidence=evidence,
                applied=applied,
            )
        )

    block = replace(config_block, data=bytes(buffer))
    return block, mods


DEFAULT_NORMALIZERS: tuple[Normalizer, ...] = (fix_settings_types,)


def _reconcile_changes(
    original_data: bytes,
    candidate_data: bytes,
    mods: BeaconModifications,
) -> bytes:
    """Reconcile per-field proposals across normalizers and produce the final normalized block.

    When two normalizers propose a different normalized type for the same field, the conflict is recorded
    and the *original* bytes at that field are restored in the final block. Fields with a single consistent
    proposal keep their normalized value.
    """
    by_offset: dict[int, list[TypeFieldChange]] = defaultdict(list)
    for change in mods.type_changes:
        by_offset[change.offset].append(change)

    final = bytearray(candidate_data)
    for offset, changes in by_offset.items():
        proposals = {change.proposed_type for change in changes if change.proposed_type is not None}
        if len(proposals) <= 1:
            for change in changes:
                change.applied = change.is_change
            continue

        conflict = mods.conflicts[-1] if mods.conflicts and mods.conflicts[-1].offset == offset else None
        if conflict is None:
            conflict = NormalizationConflict(
                offset=offset,
                index=changes[0].index,
                original_type=changes[0].original_type,
            )
            mods.conflicts.append(conflict)
        for change in changes:
            if change.proposed_type is not None:
                conflict.proposals[change.normalizer] = change.proposed_type
            change.conflict = True
            change.applied = False
        # Restore the original type field bytes; no normalizer wins a contradiction.
        final[offset + 2 : offset + 4] = original_data[offset + 2 : offset + 4]

    return bytes(final)


def normalize_config_block(
    block: BeaconConfigBlock, *, normalizers: Sequence[Normalizer] | None = None
) -> tuple[BeaconConfigBlock, BeaconModifications]:
    """Run the normalizers against ``block`` so it can normalize a modified beacon config.

    The input block is never mutated. The returned :class:`BeaconModifications` holds the original and
    normalized bytes, the original input hash, per-field change records with their evidence, unconfirmed
    observed types and any contradictions between normalizers.

    Args:
        block: The BeaconConfigBlock to normalize.
        normalizers: A sequence of normalizer functions to apply. If None, the default normalizers will be used.

    Returns:
        A tuple of the normalized BeaconConfigBlock and a BeaconModifications object describing the decisions made.
    """
    original_data = block.data
    mods = BeaconModifications(
        original_data=original_data,
        original_sha256=hashlib.sha256(original_data).hexdigest(),
    )

    candidate = block
    pipeline = DEFAULT_NORMALIZERS if normalizers is None else normalizers
    for fn in pipeline:
        candidate, mods = fn(candidate, mods)

    mods.normalized_data = _reconcile_changes(original_data, candidate.data, mods)
    if not mods.tags and not mods.type_changes and not mods.conflicts:
        mods.normalized_data = original_data

    normalized_block = replace(block, data=mods.normalized_data)
    return normalized_block, mods
