"""
This module is responsible for finding and recovering Beacon Guardrails configuration from Cobalt Strike payloads.
Guardrails is an additional layer of protection to the beacon config by using environmental keying (`T1480`_).

.. note::
    Beacon Guardrails was introduced in Cobalt Strike 4.8:

    - https://www.cobaltstrike.com/blog/cobalt-strike-4-8-system-call-me-maybe

    Other research on Beacon Guardrails:

    - https://itea.org/journals/volume-45-3/cobalt-strike-cyber-assessment-challenge/

    .. _T1480: https://attack.mitre.org/techniques/T1480/
"""

from __future__ import annotations

import collections
import functools
import hashlib
import io
import json
import logging
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cobaltstrike.utils import catch_sigpipe, grouper, retain_file_offset, u32be, xor
from dissect.cstruct import cstruct

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

log = logging.getLogger(__name__)

C_GUARDRAILS_DEF = """
enum GuardOption: uint16 {
    GUARD_USER = 5,
    GUARD_COMPUTER = 6,
    GUARD_DOMAIN = 7,
    GUARD_LOCAL_IP = 8,
    GUARD_PAYLOAD_CHECKSUM = 9,
};

enum SettingsType: uint16 {
    TYPE_NONE = 0,
    TYPE_SHORT = 1,
    TYPE_INT = 2,
    TYPE_PTR = 3,
};

struct GuardrailSetting {
    GuardOption option;         // uint16
    SettingsType type;          // uint16
    uint16 length;              // uint16
    char value[length];
};
"""

BEACON_CONFIG_PATCH_SIZES = (
    0x1800,  # V2, since CS 4.9
    0x1000,  # V1
)
GUARD_PATCH_SIZE = 2048

GUARD_CONFIG_STARTS = [
    b"\x00\x05\x00\x01\x00\x02",  # GUARD_USER
    b"\x00\x06\x00\x01\x00\x02",  # GUARD_COMPUTER
    b"\x00\x07\x00\x01\x00\x02",  # GUARD_DOMAIN
    b"\x00\x08\x00\x02\x00\x04",  # GUARD_LOCAL_IP
]

c_guardrails = cstruct(endian=">").load(C_GUARDRAILS_DEF)
GuardrailSetting = c_guardrails.GuardrailSetting
GuardOption = c_guardrails.GuardOption


@dataclass
class GuardrailMetadata:
    """Class for holding Guardrail related data"""

    beacon_config_offset: int
    """ Offset of the beacon configuration in the payload """
    guard_config_offset: int
    """ Offset of the guardrail configuration in the payload """
    masked_beacon_config: bytes
    """ Masked raw beacon configuration """
    masked_guard_config: bytes
    """ Masked raw guardrail configuration """
    beacon_xor_key: bytes
    """ Single byte XOR key used to mask the beacon configuration. (0x2e by default unless modified beacon) """
    guardrail_xor_key: bytes
    """ Single byte XOR key used to unmask the guardrail configuration (0x8a by default unless modified beacon) """
    unmasked_guard_config: bytes
    """ Unmasked guardrail configuration """
    checksum: int
    """ Extracted payload checksum from guardrail configuration. This is used to validate the beacon configuration """
    payload_xor_key: bytes | None
    """ XOR key used to unmask the guarded beacon configuration. This is the environmental key """
    unmasked_beacon_config: bytes
    """ Unmasked beacon configuration """
    settings: list[GuardrailSetting]
    """ List of guardrail settings """


def iter_guardrail_configs(fh: BinaryIO, xorkey: bytes = b"\x8a") -> Iterator[GuardrailMetadata]:
    xorred_guardconfig_starts = [xor(x, xorkey) for x in GUARD_CONFIG_STARTS]
    size = len(xorred_guardconfig_starts[0])
    offset = 0
    while True:
        fh.seek(offset)
        block = fh.read(size * 2)
        if not block:
            break
        a, b = block[:size], block[size:]
        if xor(a[::-1], b) in xorred_guardconfig_starts:
            log.info("Found guardrail config at offset: %u in %r", offset, fh)
            guard_config_offset = offset + 6
            for patch_size in BEACON_CONFIG_PATCH_SIZES:
                beacon_config_offset = guard_config_offset - patch_size
                fh.seek(beacon_config_offset)
                masked_beacon_config = fh.read(patch_size)
                masked_guard_config = fh.read(GUARD_PATCH_SIZE)
                unmasked_guard_config = xor(xor(masked_guard_config, masked_beacon_config[::-1]), xorkey)

                fh_guard = io.BufferedReader(io.BytesIO(unmasked_guard_config))
                checksum = 0
                settings: list[GuardrailSetting] = []
                while True:
                    if fh_guard.peek(2)[:2] == b"\x00\x00":
                        break
                    setting = GuardrailSetting(fh_guard)
                    settings.append(setting)
                    log.debug(setting)
                    if setting.option == GuardOption.GUARD_PAYLOAD_CHECKSUM:
                        checksum = u32be(setting.value)
                        log.debug("%s = 0x%08x", setting.option.name, checksum)

                yield GuardrailMetadata(
                    beacon_config_offset=beacon_config_offset,
                    guard_config_offset=guard_config_offset,
                    checksum=checksum,
                    masked_guard_config=masked_guard_config,
                    masked_beacon_config=masked_beacon_config,
                    unmasked_guard_config=unmasked_guard_config,
                    guardrail_xor_key=xorkey,
                    beacon_xor_key=b"\x2e",  # we currently only support the XOR default key
                    payload_xor_key=None,
                    unmasked_beacon_config=None,
                    settings=settings,
                )
        offset += 1


def find_xor_key_candidates(fh: BinaryIO) -> Iterator[bytes]:
    for keylen in range(2, 257):
        fh.seek(0)
        counter = collections.Counter()
        for chunk in iter(functools.partial(fh.read, io.DEFAULT_BUFFER_SIZE), b""):
            grams = grouper(chunk, n=keylen, fillvalue=0)
            counter.update(bytes(gram) for gram in grams)

        first_count = 0
        for key, count in counter.most_common(2):
            if count >= first_count:
                first_count = count
                yield key
            else:
                break


def payload_checksum(data: bytes) -> int:
    n = 0
    for i in range(len(data)):
        n = (n + (data[i] & 0xFF) * (i % 3 + 1)) % 99999999
    return n


def iter_guardrail_configs_with_beacon(fh: BinaryIO) -> Iterator[GuardrailMetadata]:
    for grconfig in iter_guardrail_configs(fh):
        # Unmask the beacon config, static single byte xor key should be 0x2E unless modified beacon
        # The beacon config is still masked with the environmental key
        grconfig.beacon_xor_key = b"\x2e"  # we currently only support the XOR default key
        guarded_config = xor(grconfig.masked_beacon_config, grconfig.beacon_xor_key)

        for xorkey in find_xor_key_candidates(io.BytesIO(guarded_config)):
            unguarded = xor(guarded_config, xorkey)

            checksum = payload_checksum(unguarded) + 1
            log.debug("payload checksum: 0x%08x for xorkey: %r", checksum, xorkey)

            if grconfig.checksum == checksum:
                log.info("Found guardrail payload xorkey: %r", xorkey)
                grconfig.payload_xor_key = xorkey
                grconfig.unmasked_beacon_config = unguarded
                yield grconfig
                break
        else:
            # No valid xor key found, so not able to unmask the beacon config
            log.debug(
                "Unable to find valid xorkey for guardrail at offset %u (patch_size 0x%x, checksum 0x%08x)",
                grconfig.guard_config_offset,
                len(grconfig.masked_beacon_config),
                grconfig.checksum,
            )


class CandidateStatus(str, Enum):
    """Outcome of correlating one Guardrails candidate with a Beacon configuration."""

    CONFIRMED = "confirmed"
    """The guardrail checksum was recomputed from the raw interval with the recovered payload key."""

    CHECKSUM_MISMATCH = "checksum_mismatch"
    """Settings parsed, but no discovered payload key reproduces the declared checksum."""

    NO_CHECKSUM = "no_checksum"
    """The guardrail block parsed but does not declare a GUARD_PAYLOAD_CHECKSUM setting."""

    PARSE_ERROR = "parse_error"
    """The guardrail block could not be parsed into settings."""

    MISSING_INTERVAL = "missing_interval"
    """The patch interval needed for recomputation is not present in the file."""

    TRUNCATED_ADJACENT_BLOCK = "truncated_adjacent_block"
    """The Beacon patch is present but the adjacent guardrail patch reads past end-of-file."""


@dataclass
class GuardrailCandidate:
    """A single Guardrails candidate and the evidence collected for it.

    A candidate is a (guard config offset, patch size) pair. Multiple candidates can
    point at the same guardrail block with different patch sizes; the patch size
    determines which raw bytes are treated as the guarded Beacon configuration.
    """

    guard_config_offset: int
    """Offset of the Guardrails configuration (start of its settings) in the payload."""
    guard_config_signature_offset: int
    """Offset where the reversed/masked Guardrails signature matched."""
    patch_size: int
    """Size of the Beacon configuration patch that this candidate pairs with."""
    beacon_config_offset: int
    """Derived offset of the Beacon configuration patch, ``guard_config_offset - patch_size``."""
    guardrail_xor_key: bytes
    """Single byte XOR key used to unmask the guardrail configuration."""
    beacon_xor_key: bytes
    """Single byte XOR key used to unmask the static Beacon configuration mask."""
    checksum: int
    """Declared checksum from GUARD_PAYLOAD_CHECKSUM, ``0`` if not present."""
    settings: list[GuardrailSetting] = field(default_factory=list)
    """Parsed guardrail settings, empty on parse errors."""
    masked_beacon_config: bytes = b""
    """Raw masked Beacon configuration read from the derived interval."""
    masked_guard_config: bytes = b""
    """Raw masked guardrail configuration read after the Beacon interval."""
    unmasked_guard_config: bytes = b""
    """Guardrail configuration after unmasking."""
    interval_available: bool = False
    """Whether the full Beacon patch interval exists in the payload."""
    masked_guard_config_truncated: bool = False
    """Whether the adjacent guardrail patch extends past end-of-file."""
    payload_xor_key: bytes | None = None
    """Recovered environmental payload XOR key, if the checksum validated."""
    payload_xor_key_ambiguous: bool = False
    """Whether multiple distinct plaintexts reproduce the declared checksum."""
    unmasked_beacon_config: bytes | None = None
    """Recovered Beacon configuration for a confirmed candidate."""
    payload_checksum: int | None = None
    """Checksum recomputed from ``unmasked_beacon_config``, if computed."""
    status: CandidateStatus = CandidateStatus.PARSE_ERROR
    """Correlation outcome for this candidate."""
    discovery_status: CandidateStatus | None = field(default=None, repr=False)
    """Status assigned during parsing, used to make correlation re-runnable."""
    evidence: list[str] = field(default_factory=list)
    """Human readable notes collected during analysis."""
    discovery_evidence: list[str] = field(default_factory=list, repr=False)
    """Evidence collected during parsing, preserved across repeated correlation runs."""

    def __post_init__(self) -> None:
        if self.discovery_status is None:
            self.discovery_status = self.status
        if not self.discovery_evidence:
            self.discovery_evidence = list(self.evidence)

    @property
    def candidate_id(self) -> str:
        """Stable identifier independent of discovery order."""
        return f"guard@0x{self.guard_config_offset:x}/patch@0x{self.patch_size:x}"

    def settings_summary(self) -> list[dict[str, Any]]:
        """Return the parsed guardrail settings as JSON-friendly dictionaries."""
        return [_setting_to_dict(setting) for setting in self.settings]

    def decode_preview(self, limit: int = 32) -> dict[str, Any]:
        """Return a small preview of the decoding material for this candidate."""
        return {
            "masked_beacon_config": _hex_preview(self.masked_beacon_config, limit),
            "masked_guard_config": _hex_preview(self.masked_guard_config, limit),
            "unmasked_guard_config": _hex_preview(self.unmasked_guard_config, limit),
            "unmasked_beacon_config": _hex_preview(self.unmasked_beacon_config, limit),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the candidate."""
        return {
            "candidate_id": self.candidate_id,
            "status": self.status.value,
            "guard_config_offset": self.guard_config_offset,
            "guard_config_signature_offset": self.guard_config_signature_offset,
            "beacon_config_offset": self.beacon_config_offset,
            "patch_size": self.patch_size,
            "guardrail_xor_key": self.guardrail_xor_key.hex(),
            "beacon_xor_key": self.beacon_xor_key.hex(),
            "declared_checksum": self.checksum,
            "recomputed_checksum": self.payload_checksum,
            "payload_xor_key": self.payload_xor_key.hex() if self.payload_xor_key is not None else None,
            "payload_xor_key_ambiguous": self.payload_xor_key_ambiguous,
            "interval_available": self.interval_available,
            "masked_guard_config_truncated": self.masked_guard_config_truncated,
            "masked_beacon_config_sha256": _sha256(self.masked_beacon_config),
            "masked_guard_config_sha256": _sha256(self.masked_guard_config),
            "unmasked_guard_config_sha256": _sha256(self.unmasked_guard_config),
            "unmasked_beacon_config_sha256": _sha256(self.unmasked_beacon_config),
            "decode_preview": self.decode_preview(),
            "settings": self.settings_summary(),
            "evidence": list(self.evidence),
        }


@dataclass
class GuardrailsDiagnostic:
    """Order-independent correlation report for all Guardrails candidates in one payload."""

    source: str | None
    candidates: list[GuardrailCandidate]
    """Candidates sorted by a deterministic key, not discovery order."""
    confirmed: list[str] = field(default_factory=list)
    """Candidate IDs that were confirmed by checksum recomputation."""
    ambiguous: bool = False
    """``True`` when the evidence does not identify a single association."""
    association_ambiguous: bool = False
    """``True`` when more than one distinct interval is confirmed."""
    notes: list[str] = field(default_factory=list)
    """Report-level caveats and sample-declaration notes."""

    @property
    def status(self) -> str:
        """A single summary status for the whole report."""
        if self.association_ambiguous:
            return "ambiguous"
        if self.confirmed:
            return "confirmed"
        if self.candidates:
            return "unresolved"
        return "no_association"

    def resolved_candidate(self) -> GuardrailCandidate | None:
        """Return the confirmed candidate only when the association is unambiguous."""
        if self.association_ambiguous or len(self.confirmed) != 1:
            return None
        return next((c for c in self.candidates if c.candidate_id == self.confirmed[0]), None)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the report."""
        return {
            "source": self.source,
            "status": self.status,
            "confirmed": list(self.confirmed),
            "ambiguous": self.ambiguous,
            "association_ambiguous": self.association_ambiguous,
            "resolved_candidate_id": self.resolved_candidate().candidate_id
            if self.resolved_candidate() is not None
            else None,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "notes": list(self.notes),
        }


def _sha256(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _hex_preview(data: bytes | None, limit: int = 32) -> str | None:
    if data is None:
        return None
    if len(data) <= limit:
        return data.hex()
    return f"{data[:limit].hex()}... ({len(data)} bytes)"


def _setting_to_dict(setting: GuardrailSetting) -> dict[str, Any]:
    option = setting.option
    return {
        "option": getattr(option, "name", None) or f"UNKNOWN_{int(option)}",
        "option_value": int(option),
        "type": getattr(setting.type, "name", None) or f"UNKNOWN_{int(setting.type)}",
        "type_value": int(setting.type),
        "length": setting.length,
        "value": bytes(setting.value).hex(),
    }


def _read_setting_value(setting: GuardrailSetting) -> bytes:
    try:
        return bytes(setting.value)
    except TypeError:
        return bytes(setting.value or b"")


def parse_guardrail_settings(data: bytes) -> tuple[list[GuardrailSetting], str | None]:
    """Best-effort parse of unmasked guardrail settings.

    Returns the parsed settings and an error message if parsing stopped early.
    A zero-length buffer or an immediate ``00 00`` terminator yields no settings and no error.
    """
    settings: list[GuardrailSetting] = []
    fh_guard = io.BufferedReader(io.BytesIO(data))
    try:
        while True:
            if fh_guard.peek(2)[:2] == b"\x00\x00":
                break
            setting = GuardrailSetting(fh_guard)
            settings.append(setting)
    except (EOFError, ValueError, TypeError) as e:
        return settings, f"{type(e).__name__}: {e}"
    return settings, None


def _declared_checksum(settings: Sequence[GuardrailSetting]) -> int:
    for setting in settings:
        if setting.option == GuardOption.GUARD_PAYLOAD_CHECKSUM:
            value = _read_setting_value(setting)
            if len(value) < 4:
                log.debug("Truncated GUARD_PAYLOAD_CHECKSUM value (%d bytes)", len(value))
            return u32be(value)
    return 0


def recompute_guardrail_checksum(
    masked_beacon_config: bytes,
    payload_xor_key: bytes,
    beacon_xor_key: bytes = b"\x2e",
) -> tuple[bytes, int]:
    """Recompute the guarded Beacon configuration and its checksum from the raw interval.

    This is the inverse of the masking scheme: the raw interval is first unmasked with
    the static Beacon XOR key, then with the environmental payload XOR key. The resulting
    buffer is passed through :func:`payload_checksum` (with the ``+ 1`` used by Beacon).

    Args:
        masked_beacon_config: raw patch bytes read from the payload
        payload_xor_key: environmental payload XOR key
        beacon_xor_key: static Beacon configuration XOR key

    Returns:
        A ``(unmasked_beacon_config, checksum)`` tuple.
    """
    guarded_config = xor(masked_beacon_config, beacon_xor_key)
    unmasked = xor(guarded_config, payload_xor_key)
    return unmasked, payload_checksum(unmasked) + 1


def _candidate_sort_key(candidate: GuardrailCandidate) -> tuple:
    return (
        candidate.guard_config_offset,
        candidate.beacon_config_offset,
        candidate.patch_size,
        candidate.checksum,
        candidate.guardrail_xor_key,
        candidate.beacon_xor_key,
    )


def _collect_candidates(
    fh: BinaryIO,
    xorkey: bytes = b"\x8a",
) -> list[GuardrailCandidate]:
    """Enumerate all (guard offset, patch size) candidates without associating them."""
    candidates: list[GuardrailCandidate] = []
    xorred_starts = [xor(start, xorkey) for start in GUARD_CONFIG_STARTS]
    size = len(GUARD_CONFIG_STARTS[0])

    with retain_file_offset(fh):
        fh.seek(0, io.SEEK_END)
        file_size = fh.tell()

        offset = 0
        while offset + size * 2 <= file_size:
            fh.seek(offset)
            block = fh.read(size * 2)
            if len(block) < size * 2:
                break
            a, b = block[:size], block[size:]
            if xor(a[::-1], b) not in xorred_starts:
                offset += 1
                continue

            guard_config_offset = offset + 6
            for patch_size in BEACON_CONFIG_PATCH_SIZES:
                beacon_config_offset = guard_config_offset - patch_size
                interval_available = beacon_config_offset >= 0 and beacon_config_offset + patch_size <= file_size
                masked_beacon_config = b""
                masked_guard_config = b""
                unmasked_guard_config = b""
                settings: list[GuardrailSetting] = []
                evidence: list[str] = []
                parse_error = None
                masked_guard_config_truncated = False

                if interval_available:
                    fh.seek(beacon_config_offset)
                    masked_beacon_config = fh.read(patch_size)
                    gh_end = fh.tell() + GUARD_PATCH_SIZE
                    masked_guard_config_truncated = gh_end > file_size
                    masked_guard_config = fh.read(GUARD_PATCH_SIZE)

                    if masked_guard_config_truncated:
                        evidence.append(
                            f"adjacent guardrail patch truncated: read {len(masked_guard_config)} of "
                            f"{GUARD_PATCH_SIZE} bytes"
                        )

                    unmasked_guard_config = xor(xor(masked_guard_config, masked_beacon_config[::-1]), xorkey)
                    settings, parse_error = parse_guardrail_settings(unmasked_guard_config)
                else:
                    evidence.append(
                        f"patch interval [0x{beacon_config_offset:x}, 0x{beacon_config_offset + patch_size:x}) "
                        f"is outside the payload (size 0x{file_size:x})"
                    )

                checksum = _declared_checksum(settings) if settings else 0
                if not interval_available:
                    status = CandidateStatus.MISSING_INTERVAL
                elif parse_error:
                    status = CandidateStatus.PARSE_ERROR
                    evidence.append(f"guardrail settings parse stopped: {parse_error}")
                elif masked_guard_config_truncated:
                    status = CandidateStatus.TRUNCATED_ADJACENT_BLOCK
                elif checksum == 0:
                    status = CandidateStatus.NO_CHECKSUM
                    evidence.append("no GUARD_PAYLOAD_CHECKSUM setting present")
                else:
                    status = CandidateStatus.CHECKSUM_MISMATCH

                candidates.append(
                    GuardrailCandidate(
                        guard_config_offset=guard_config_offset,
                        guard_config_signature_offset=offset,
                        patch_size=patch_size,
                        beacon_config_offset=beacon_config_offset,
                        guardrail_xor_key=xorkey,
                        beacon_xor_key=b"\x2e",
                        checksum=checksum,
                        settings=settings,
                        masked_beacon_config=masked_beacon_config,
                        masked_guard_config=masked_guard_config,
                        unmasked_guard_config=unmasked_guard_config,
                        interval_available=interval_available,
                        masked_guard_config_truncated=masked_guard_config_truncated,
                        status=status,
                        evidence=evidence,
                        discovery_status=status,
                        discovery_evidence=list(evidence),
                    )
                )
            offset += 1

    return candidates


def _payload_key_candidates(masked_beacon_config: bytes, beacon_xor_key: bytes) -> Iterator[bytes]:
    if not masked_beacon_config:
        return
    guarded_config = xor(masked_beacon_config, beacon_xor_key)
    yield from find_xor_key_candidates(io.BytesIO(guarded_config))


def _equivalent_payload_key(keys: Iterable[bytes]) -> bytes:
    """Return the shortest, lexicographically smallest key from an equivalent group."""
    return min(keys, key=lambda key: (len(key), key))


def correlate_guardrail_candidates(
    candidates: Iterable[GuardrailCandidate],
    payload_keys: dict[str, Iterable[bytes]] | None = None,
) -> GuardrailsDiagnostic:
    """Associate Guardrails candidates with Beacon configurations, independent of input order.

    For every candidate that declares a checksum and has a complete patch interval, the
    payload XOR key candidates are replayed against the raw interval. A candidate is
    ``confirmed`` only if a key reproduces the declared checksum exactly. If multiple keys
    reproduce it, the candidates remain confirmed but the report is marked ambiguous
    because the environmental key cannot be uniquely determined.

    ``payload_keys`` optionally supplies pre-computed key candidates keyed by
    :attr:`GuardrailCandidate.candidate_id`. When absent, keys are derived from the
    candidate bytes. Passing pre-computed keys is useful for re-running the analysis
    from a stored report without re-reading the payload.

    Args:
        candidates: Guardrails candidates to correlate
        payload_keys: optional mapping of candidate ID to payload XOR key candidates

    Returns:
        A :class:`GuardrailsDiagnostic` with candidates in a deterministic order.
    """
    ordered = sorted(candidates, key=_candidate_sort_key)
    payload_keys = payload_keys or {}

    for candidate in ordered:
        # Reset derived fields so repeated correlation runs are idempotent.
        candidate.status = candidate.discovery_status or CandidateStatus.PARSE_ERROR
        candidate.evidence = list(candidate.discovery_evidence)
        candidate.payload_xor_key = None
        candidate.payload_xor_key_ambiguous = False
        candidate.unmasked_beacon_config = None
        candidate.payload_checksum = None

        if candidate.status in (
            CandidateStatus.PARSE_ERROR,
            CandidateStatus.MISSING_INTERVAL,
        ):
            continue
        if candidate.status == CandidateStatus.TRUNCATED_ADJACENT_BLOCK:
            # The Beacon interval is complete, so its checksum can still be evaluated. It is
            # reported as an observation only, never promoted to a confirmed association.
            candidate.evidence.append("adjacent guardrail patch is truncated; not treated as a confirmed association")
            continue
        if candidate.status == CandidateStatus.NO_CHECKSUM:
            candidate.evidence.append("cannot validate a candidate without a declared checksum")
            continue
        if not candidate.masked_beacon_config:
            candidate.status = CandidateStatus.MISSING_INTERVAL
            continue

        keys = payload_keys.get(candidate.candidate_id)
        if keys is None:
            keys = _payload_key_candidates(candidate.masked_beacon_config, candidate.beacon_xor_key)
        keys = list(keys)

        if not keys:
            candidate.status = CandidateStatus.CHECKSUM_MISMATCH
            candidate.evidence.append("no payload key candidates were generated")
            continue

        # Group matching keys by the plaintext they produce. Repeating a short key yields
        # identical plaintext, so it is the same evidence rather than a separate key.
        matches: dict[str, list[bytes]] = {}
        for key in keys:
            unmasked, checksum = recompute_guardrail_checksum(
                candidate.masked_beacon_config, key, candidate.beacon_xor_key
            )
            if checksum == candidate.checksum:
                matches.setdefault(_sha256(unmasked), []).append(key)
        if not matches:
            # Record a deterministic reference checksum so the mismatch is explainable
            # without depending on which key candidate happened to be tried first.
            reference_key = _equivalent_payload_key(keys)
            _, reference_checksum = recompute_guardrail_checksum(
                candidate.masked_beacon_config, reference_key, candidate.beacon_xor_key
            )
            candidate.payload_checksum = reference_checksum
            candidate.status = CandidateStatus.CHECKSUM_MISMATCH
            candidate.evidence.append(
                f"no payload key reproduced declared checksum 0x{candidate.checksum:08x}; "
                f"reference checksum 0x{reference_checksum:08x} under key {reference_key!r}"
            )
            continue

        # Canonical key: pick the group whose shortest key is smallest by (length, bytes),
        # then the shortest key in that group. This is purely a recording choice and keeps
        # the result independent of key enumeration order. A key shorter than the patch
        # repeats, so only its prefix is meaningful; longer repeats share the same plaintext.
        plaintext_sha, matching_keys = min(
            matches.items(),
            key=lambda item: (_equivalent_payload_key(item[1]), item[0]),
        )
        canonical_key = _equivalent_payload_key(matching_keys)
        unmasked, _ = recompute_guardrail_checksum(
            candidate.masked_beacon_config, canonical_key, candidate.beacon_xor_key
        )

        candidate.status = CandidateStatus.CONFIRMED
        candidate.payload_xor_key = canonical_key
        candidate.payload_checksum = candidate.checksum
        candidate.unmasked_beacon_config = unmasked
        candidate.payload_xor_key_ambiguous = len(matches) > 1
        candidate.evidence.append(
            f"recomputed checksum 0x{candidate.checksum:08x} from raw interval with payload key "
            f"{canonical_key!r} ({len(matching_keys)} equivalent key(s), plaintext sha256 {plaintext_sha[:16]})"
        )
        if candidate.payload_xor_key_ambiguous:
            candidate.evidence.append(
                "multiple distinct plaintexts reproduce the declared checksum; the payload key is ambiguous"
            )

    confirmed = [c for c in ordered if c.status == CandidateStatus.CONFIRMED]
    confirmed_ids = [c.candidate_id for c in confirmed]

    # Ambiguity is a property of the evidence, not of enumeration order: if more than one
    # distinct interval confirms, we cannot say which one is the live Beacon configuration.
    ambiguous_intervals = {(c.guard_config_offset, c.beacon_config_offset, c.patch_size) for c in confirmed}
    association_ambiguous = len(ambiguous_intervals) > 1
    ambiguous = association_ambiguous or any(c.payload_xor_key_ambiguous for c in confirmed)

    notes = [
        (
            "Guardrail options are sample-declared only; this report does not assert that a victim host "
            "satisfies them."
        ),
    ]

    if not ordered:
        notes.append("no Guardrails signature match was found")
    elif not confirmed_ids:
        notes.append(f"none of {len(ordered)} candidate(s) could be associated with a Beacon configuration")
    elif association_ambiguous:
        notes.append("multiple distinct intervals reproduce a checksum; association is ambiguous")
    elif any(c.payload_xor_key_ambiguous for c in confirmed):
        notes.append("the declared checksum does not uniquely determine the payload XOR key")
    elif len(confirmed) > 1:
        notes.append("multiple candidates confirm the same interval with different patch sizes")

    if any(c.status == CandidateStatus.CHECKSUM_MISMATCH for c in ordered):
        notes.append("at least one candidate did not reproduce its declared checksum")
    if any(c.status == CandidateStatus.MISSING_INTERVAL for c in ordered):
        notes.append("at least one candidate's patch interval lies outside the payload")
    if any(c.status == CandidateStatus.TRUNCATED_ADJACENT_BLOCK for c in ordered):
        notes.append("at least one candidate has a truncated adjacent guardrail block")

    return GuardrailsDiagnostic(
        source=None,
        candidates=ordered,
        confirmed=confirmed_ids,
        ambiguous=ambiguous,
        association_ambiguous=association_ambiguous,
        notes=notes,
    )


def diagnose_guardrails(
    fh: BinaryIO,
    source: str | None = None,
    xorkey: bytes = b"\x8a",
    payload_keys: Sequence[bytes] | None = None,
) -> GuardrailsDiagnostic:
    """Run a full, order-independent Guardrails association diagnostic over ``fh``.

    Args:
        fh: file-like object containing the payload
        source: optional source label included in the report
        xorkey: single byte XOR key used to unmask the guardrail configuration
        payload_keys: optional explicit payload XOR keys to use instead of deriving candidates

    Returns:
        A :class:`GuardrailsDiagnostic`.
    """
    try:
        if not fh.seekable():
            fh = io.BytesIO(fh.read())
    except AttributeError:
        fh = io.BytesIO(fh.read())

    candidates = _collect_candidates(fh, xorkey=xorkey)
    explicit = None
    if payload_keys:
        explicit = {candidate.candidate_id: list(payload_keys) for candidate in candidates}
    report = correlate_guardrail_candidates(candidates, payload_keys=explicit)
    report.source = source
    return report


def format_report(report: GuardrailsDiagnostic) -> str:
    """Render a :class:`GuardrailsDiagnostic` as a human readable text report."""
    lines: list[str] = []
    lines.append(f"source: {report.source or '<memory>'}")
    lines.append(f"status: {report.status}")
    lines.append(f"confirmed: {', '.join(report.confirmed) if report.confirmed else '<none>'}")
    lines.append(f"ambiguous: {str(report.ambiguous).lower()}")
    lines.append(f"association_ambiguous: {str(report.association_ambiguous).lower()}")
    resolved = report.resolved_candidate()
    lines.append(f"resolved: {resolved.candidate_id if resolved is not None else '<none>'}")
    lines.append("")

    for candidate in report.candidates:
        lines.append(f"[{'*' if candidate.status == CandidateStatus.CONFIRMED else ' '}] {candidate.candidate_id}")
        lines.append(f"    status: {candidate.status.value}")
        lines.append(f"    guard_config_offset: 0x{candidate.guard_config_offset:x}")
        lines.append(f"    guard_config_signature_offset: 0x{candidate.guard_config_signature_offset:x}")
        lines.append(f"    beacon_config_offset: 0x{candidate.beacon_config_offset:x}")
        lines.append(f"    patch_size: 0x{candidate.patch_size:x}")
        lines.append(f"    guardrail_xor_key: {candidate.guardrail_xor_key.hex()}")
        lines.append(f"    beacon_xor_key: {candidate.beacon_xor_key.hex()}")
        lines.append(f"    declared_checksum: 0x{candidate.checksum:08x}")
        if candidate.payload_checksum is not None:
            lines.append(f"    recomputed_checksum: 0x{candidate.payload_checksum:08x}")
        payload_key = candidate.payload_xor_key.hex() if candidate.payload_xor_key is not None else "<none>"
        lines.append(f"    payload_xor_key: {payload_key}")
        lines.append(f"    interval_available: {str(candidate.interval_available).lower()}")
        lines.append(f"    masked_beacon_config_sha256: {_sha256(candidate.masked_beacon_config) or '<none>'}")
        lines.append(f"    unmasked_beacon_config_sha256: {_sha256(candidate.unmasked_beacon_config) or '<none>'}")
        lines.append("    settings:")
        if candidate.settings:
            for setting in candidate.settings_summary():
                lines.append("        - {option} type={type} length={length} value={value}".format(**setting))
        else:
            lines.append("        <none>")
        if candidate.evidence:
            lines.append("    evidence:")
            for note in candidate.evidence:
                lines.append(f"        - {note}")
        lines.append("")

    if report.notes:
        lines.append("notes:")
        for note in report.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines).rstrip() + "\n"


def _parse_key_value(value: str) -> bytes:
    """Parse a hex string, ``0x`` prefix, or plain string into bytes."""
    stripped = value.strip()
    if stripped.lower().startswith("0x"):
        return bytes.fromhex(stripped[2:])
    try:
        return bytes.fromhex(stripped)
    except ValueError:
        return stripped.encode()


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="beacon-guardrails",
        description="Correlate Guardrails candidates with Beacon configurations in a payload.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", metavar="FILE", nargs="+", help="payload file(s) to analyze, use '-' for stdin")
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format",
    )
    parser.add_argument(
        "--guardrail-xorkey",
        default="0x8a",
        help="XOR key used to unmask the guardrail configuration",
    )
    parser.add_argument(
        "--payload-xorkey",
        action="append",
        default=None,
        help="known environmental payload XOR key(s) to consider (repeatable); default: derive candidates",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="exit non-zero if any input has no unambiguous confirmed association",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbosity level (-v for INFO, -vv for DEBUG)",
    )
    return parser


def _diagnose_path(
    path: str,
    guardrail_xorkey: bytes,
    explicit_payload_keys: Sequence[bytes] | None,
) -> GuardrailsDiagnostic:
    if path in ("-", "/dev/stdin"):
        return diagnose_guardrails(
            io.BytesIO(sys.stdin.buffer.read()),
            source="<stdin>",
            xorkey=guardrail_xorkey,
            payload_keys=explicit_payload_keys,
        )
    with open(path, "rb") as fh:
        return diagnose_guardrails(fh, source=path, xorkey=guardrail_xorkey, payload_keys=explicit_payload_keys)


@catch_sigpipe
def main() -> int:
    """Entrypoint for ``beacon-guardrails``."""
    parser = build_parser()
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    guardrail_xorkey = _parse_key_value(args.guardrail_xorkey)
    if len(guardrail_xorkey) != 1:
        parser.error("--guardrail-xorkey must be a single byte")

    explicit_keys = None
    if args.payload_xorkey:
        explicit_keys = [_parse_key_value(key) for key in args.payload_xorkey]

    failed = False
    for path in args.input:
        try:
            report = _diagnose_path(path, guardrail_xorkey, explicit_keys)
        except (OSError, ValueError) as e:
            logging.error("failed to analyze %s: %s", path, e)
            failed = True
            continue

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            sys.stdout.write(format_report(report))

        if report.resolved_candidate() is None:
            failed = True

    return 1 if failed and args.fail_on_error else 0


if __name__ == "__main__":
    sys.exit(main())
