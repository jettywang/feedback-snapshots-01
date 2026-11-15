from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

VALUE_MAP = "valueMap"
BIT_MAP = "bitMap"


def _width_mask(width: int) -> int:
    """Return a mask covering ``width`` bits, or ``0`` when the width is unknown."""
    return (1 << width) - 1 if width > 0 else 0


def normalize_value(value: int, width: int) -> int:
    """Normalize a parsed field value to the unsigned bit pattern of its field width.

    Manifest map values are unsigned, while the underlying template field can be a signed
    integer (for example ``int8``).  A parsed ``-1`` in an 8-bit field therefore has to be
    interpreted as ``0xFF`` without losing the original ``-1`` elsewhere in the result.
    """
    if width <= 0:
        return value
    return value & _width_mask(width)


@dataclass(frozen=True, slots=True)
class MapEntry:
    """A single ``<map>`` entry from a manifest.

    ``name`` is the resolved resource string (or a literal message when the manifest does not
    use ``$(string...)``).  ``identifier`` is the resource string identifier, which is kept even
    when the provider's string table does not contain the referenced text.
    """

    value: int
    name: str | None = None
    identifier: str | None = None

    @property
    def label(self) -> str:
        """A displayable label, falling back to the preserved identifier or value."""
        if self.name is not None:
            return self.name
        if self.identifier is not None:
            return self.identifier
        return f"0x{self.value:x}"

    @property
    def resource(self) -> str | None:
        """Alias for :attr:`identifier`."""
        return self.identifier

    def as_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "name": self.name,
            "identifier": self.identifier,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class MapReference:
    """The provider-local identity of a map definition."""

    name: str
    kind: str | None
    provider_guid: UUID | None = None
    provider_name: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "provider_guid": str(self.provider_guid) if self.provider_guid is not None else None,
            "provider_name": self.provider_name,
        }


@dataclass(frozen=True, slots=True)
class MappedValue:
    """The interpreted result for one mapped template field.

    The original parsed value is always kept in :attr:`raw_value`; :attr:`value` is the same
    value normalized to the unsigned width of the field.  For bitmaps, ``matched_mask`` and
    ``unknown_mask`` partition the normalized value and can be used to recompute exactly which
    bits were explained and which were not.
    """

    field: str
    raw_value: int
    value: int
    width: int
    map: MapReference | None
    kind: str | None
    entries: tuple[MapEntry, ...] = ()
    matched_mask: int = 0
    unknown_mask: int = 0
    unknown_bits: tuple[int, ...] = ()
    signed: bool | None = None

    @property
    def raw(self) -> int:
        """Alias for :attr:`raw_value`."""
        return self.raw_value

    @property
    def mapping(self) -> MapReference | None:
        """Alias for :attr:`map`."""
        return self.map

    @property
    def map_name(self) -> str | None:
        return self.map.name if self.map is not None else None

    @property
    def map_kind(self) -> str | None:
        return self.kind

    @property
    def provider_guid(self) -> UUID | None:
        return self.map.provider_guid if self.map is not None else None

    @property
    def provider_name(self) -> str | None:
        return self.map.provider_name if self.map is not None else None

    @property
    def matched(self) -> bool:
        """Whether at least one map entry matched the value."""
        return bool(self.entries)

    @property
    def resolved(self) -> bool:
        """Alias for :attr:`matched`."""
        return self.matched

    @property
    def complete(self) -> bool:
        """Whether every set bit (or the exact value) was explained."""
        if self.map is not None and self.map.kind is None:
            # The definition itself was unavailable; nothing can be claimed as explained.
            return False
        if self.kind == BIT_MAP:
            return self.unknown_mask == 0
        return self.matched

    @property
    def known_mask(self) -> int:
        """Alias for :attr:`matched_mask`."""
        return self.matched_mask

    @property
    def known_bits(self) -> tuple[int, ...]:
        """Bit positions that were explained by a bitmap entry."""
        if self.matched_mask <= 0:
            return ()
        return tuple(bit for bit in range(self.matched_mask.bit_length()) if self.matched_mask & (1 << bit))

    @property
    def unknown(self) -> int:
        """Alias for :attr:`unknown_mask`."""
        return self.unknown_mask

    @property
    def explained(self) -> int:
        """Alias for :attr:`matched_mask`."""
        return self.matched_mask

    @property
    def recomputed(self) -> int:
        """Recombine the explained and unknown bits of a bitmap value.

        ``recomputed == value`` proves that no interpreted bit was lost.  For exact
        ``valueMap`` matches there is no bit partition, so the normalized value is returned.
        """
        if self.kind == BIT_MAP:
            return self.matched_mask | self.unknown_mask
        return self.value

    @property
    def name(self) -> str | None:
        """The first displayable label, or ``None`` when nothing matched."""
        return self.labels[0] if self.labels else None

    @property
    def names(self) -> tuple[str, ...]:
        """All resolved names, skipping entries whose resource string was missing."""
        return tuple(entry.name for entry in self.entries if entry.name is not None)

    @property
    def identifiers(self) -> tuple[str, ...]:
        """All preserved resource identifiers, including unresolved ones."""
        return tuple(entry.identifier for entry in self.entries if entry.identifier is not None)

    @property
    def labels(self) -> tuple[str, ...]:
        """All displayable labels, including identifier fallbacks for missing strings."""
        return tuple(entry.label for entry in self.entries)

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation for backend display."""
        return {
            "field": self.field,
            "raw_value": self.raw_value,
            "value": self.value,
            "width": self.width,
            "signed": self.signed,
            "kind": self.kind,
            "map": self.map.as_dict() if self.map is not None else None,
            "matched": self.matched,
            "complete": self.complete,
            "entries": [entry.as_dict() for entry in self.entries],
            "names": list(self.names),
            "identifiers": list(self.identifiers),
            "labels": list(self.labels),
            "matched_mask": self.matched_mask,
            "known_bits": list(self.known_bits),
            "unknown_mask": self.unknown_mask,
            "unknown_bits": list(self.unknown_bits),
            "recomputed": self.recomputed,
        }


@dataclass(frozen=True, slots=True)
class MapDefinition:
    """A provider-local ``valueMap`` or ``bitMap`` definition."""

    name: str
    kind: str | None
    entries: tuple[MapEntry, ...]
    provider_guid: UUID | None = None
    provider_name: str | None = None

    def __post_init__(self) -> None:
        # Accept the terse ``value``/``bit`` spellings as well as the manifest names.
        if self.kind is not None:
            kind = {"value": VALUE_MAP, "bit": BIT_MAP}.get(self.kind, self.kind)
            if kind not in (VALUE_MAP, BIT_MAP):
                raise ValueError(f"unknown map kind: {self.kind!r}")
            object.__setattr__(self, "kind", kind)

    @classmethod
    def missing(
        cls,
        name: str,
        provider_guid: UUID | None = None,
        provider_name: str | None = None,
    ) -> MapDefinition:
        """Create a placeholder for a referenced map whose definition is unavailable.

        The identity is preserved so a backend can still show which map the manifest intended
        to use, without inventing any label or numeric interpretation.
        """
        return cls(name, None, (), provider_guid, provider_name)

    @property
    def is_value_map(self) -> bool:
        """Whether this map is an exact-match ``valueMap``."""
        return self.kind == VALUE_MAP

    @property
    def is_bit_map(self) -> bool:
        """Whether this map is a per-bit ``bitMap``."""
        return self.kind == BIT_MAP

    @property
    def reference(self) -> MapReference:
        return MapReference(
            name=self.name,
            kind=self.kind,
            provider_guid=self.provider_guid,
            provider_name=self.provider_name,
        )

    def lookup(self, value: int) -> tuple[MapEntry, ...]:
        """Return all entries for an exact value, preserving aliases."""
        return tuple(entry for entry in self.entries if entry.value == value)

    def resolve(self, raw_value: int, width: int = 0, field: str = "", signed: bool | None = None) -> MappedValue:
        """Interpret ``raw_value`` according to this map's kind and the field width."""
        value = normalize_value(raw_value, width)

        if self.kind == BIT_MAP:
            entries, matched_mask, unknown_mask = self._resolve_bits(value, width)
            # A negative value without a known field width has no meaningful bit positions, so
            # only the mask itself is reported in that case.
            unknown_bits = (
                tuple(bit for bit in range(unknown_mask.bit_length()) if unknown_mask & (1 << bit))
                if unknown_mask > 0
                else ()
            )
        else:
            entries = self._resolve_exact(value, width)
            matched_mask = value if entries else 0
            unknown_mask = 0
            unknown_bits = ()

        return MappedValue(
            field=field,
            raw_value=raw_value,
            value=value,
            width=width,
            map=self.reference,
            kind=self.kind,
            entries=entries,
            matched_mask=matched_mask,
            unknown_mask=unknown_mask,
            unknown_bits=unknown_bits,
            signed=signed,
        )

    def _resolve_exact(self, value: int, width: int) -> tuple[MapEntry, ...]:
        """Return all exact-match entries for a value, preserving duplicate aliases."""
        return tuple(entry for entry in self.entries if normalize_value(entry.value, width) == value)

    def _resolve_bits(self, value: int, width: int) -> tuple[tuple[MapEntry, ...], int, int]:
        """Resolve a bitmap value by requiring every bit of an entry to be present.

        An entry with value ``0`` is a named zero/default state and only applies when the field
        value is zero.  For non-zero values each defined bit combination is OR-ed into the
        matched mask, so one known label never hides the remaining unknown bits.
        """
        if value == 0:
            entries = tuple(entry for entry in self.entries if entry.value == 0)
            return entries, 0, 0

        entries = tuple(entry for entry in self.entries if entry.value and (value & entry.value) == entry.value)
        matched_mask = 0
        for entry in entries:
            matched_mask |= entry.value

        mask = _width_mask(width)
        if width > 0:
            matched_mask &= mask
            unknown_mask = value & ~matched_mask & mask
        else:
            unknown_mask = value & ~matched_mask

        return entries, matched_mask, unknown_mask
