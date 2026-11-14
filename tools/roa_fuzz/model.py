"""Pure value types for ROAs, EE resources and routing announcements.

These types carry no authorization logic and do not import the checker, so
they can be shared by the fuzzer, the independent oracle and the adapter
without any component computing expected results for another.
"""

AFI_IPV4 = 1
AFI_IPV6 = 2
SUPPORTED_AFIS = (AFI_IPV4, AFI_IPV6)

AFI_BITS = {AFI_IPV4: 32, AFI_IPV6: 128}
AFI_BYTES = {AFI_IPV4: 4, AFI_IPV6: 16}


class Prefix:
    """An IP prefix identified by AFI, integer address and prefix length.

    The address always holds the full-width integer; bits beyond
    ``length`` are stored zeroed (canonical network order) for values that
    are meant to be prefixes, but the codec round-trips arbitrary input so
    that the fuzzer can feed non-canonical bit strings to the checker.
    """

    __slots__ = ("afi", "address", "length")

    def __init__(self, afi, address, length):
        self.afi = int(afi)
        self.address = int(address)
        self.length = int(length)

    @property
    def max_bit_length(self):
        return AFI_BITS[self.afi]

    def network_address(self):
        """The address with host bits masked off."""
        if self.length == 0:
            return 0
        shift = AFI_BITS[self.afi] - self.length
        return (self.address >> shift) << shift

    def is_canonical(self):
        return self.address == self.network_address() and 0 <= self.length <= AFI_BITS[self.afi]

    def contains(self, other):
        if self.afi != other.afi:
            return False
        if other.length < self.length:
            return False
        if self.length == 0:
            return True
        shift = AFI_BITS[self.afi] - self.length
        return (other.address >> shift) == (self.network_address() >> shift)

    def to_dict(self):
        return {"afi": self.afi, "address": self.address, "length": self.length}

    @classmethod
    def from_dict(cls, data):
        return cls(data["afi"], data["address"], data["length"])

    def __eq__(self, other):
        if not isinstance(other, Prefix):
            return NotImplemented
        return (self.afi, self.address, self.length) == (other.afi, other.address, other.length)

    def __hash__(self):
        return hash((self.afi, self.address, self.length))

    def __repr__(self):
        return "Prefix(afi=%d, address=%d, length=%d)" % (self.afi, self.address, self.length)


class RoaPrefix:
    """One ROAIPAddress entry; ``max_length is None`` means the OPTIONAL
    maxLength was absent, which is semantically distinct from any value."""

    __slots__ = ("prefix", "max_length")

    def __init__(self, prefix, max_length=None):
        self.prefix = prefix
        self.max_length = None if max_length is None else int(max_length)

    @property
    def has_max_length(self):
        return self.max_length is not None

    def to_dict(self):
        data = {"prefix": self.prefix.to_dict()}
        if self.max_length is not None:
            data["max_length"] = self.max_length
        return data

    @classmethod
    def from_dict(cls, data):
        return cls(Prefix.from_dict(data["prefix"]), data.get("max_length"))

    def __repr__(self):
        return "RoaPrefix(%r, max_length=%r)" % (self.prefix, self.max_length)


class RoaObject:
    """In-memory representation of a RouteOriginAttestation eContent."""

    __slots__ = ("version", "as_id", "blocks")

    def __init__(self, as_id, blocks, version=0):
        self.version = int(version)
        self.as_id = int(as_id)
        # Mapping of AFI -> list of RoaPrefix; ordering is preserved.
        self.blocks = dict(blocks)

    def iter_prefixes(self):
        for afi in self.blocks:
            for entry in self.blocks[afi]:
                yield afi, entry

    def to_dict(self):
        return {
            "version": self.version,
            "as_id": self.as_id,
            "blocks": {
                str(afi): [entry.to_dict() for entry in entries]
                for afi, entries in self.blocks.items()
            },
        }

    @classmethod
    def from_dict(cls, data):
        blocks = {
            int(afi): [RoaPrefix.from_dict(item) for item in entries]
            for afi, entries in data["blocks"].items()
        }
        return cls(data["as_id"], blocks, data.get("version", 0))

    def __repr__(self):
        return "RoaObject(version=%r, as_id=%r, blocks=%r)" % (self.version, self.as_id, self.blocks)


class EEResources:
    """Authenticated IP resources from an EE certificate's RFC 3779 extension.

    Each AFI maps to a list of inclusive (min, max) full-width integer
    ranges, or ``None`` when the AFI uses the ``inherit`` choice.
    """

    __slots__ = ("ranges",)

    def __init__(self, ranges=None):
        self.ranges = ranges if ranges is not None else {}

    def set_inherit(self, afi):
        self.ranges[afi] = None

    def add_range(self, afi, minimum, maximum):
        self.ranges.setdefault(afi, []).append((int(minimum), int(maximum)))

    def add_prefix(self, prefix):
        minimum = prefix.network_address()
        size = 1 << (AFI_BITS[prefix.afi] - prefix.length)
        self.add_range(prefix.afi, minimum, minimum + size - 1)

    def to_dict(self):
        out = {}
        for afi, value in self.ranges.items():
            out[str(afi)] = None if value is None else [
                {"min": lo, "max": hi} for lo, hi in value
            ]
        return out

    @classmethod
    def from_dict(cls, data):
        obj = cls()
        for afi, value in data.items():
            afi = int(afi)
            if value is None:
                obj.set_inherit(afi)
            else:
                for item in value:
                    obj.add_range(afi, item["min"], item["max"])
        return obj

    def __repr__(self):
        return "EEResources(%r)" % (self.ranges,)


class Route:
    """A concrete route announcement: origin AS plus an announced prefix."""

    __slots__ = ("origin_as", "prefix")

    def __init__(self, origin_as, prefix):
        self.origin_as = int(origin_as)
        self.prefix = prefix

    def to_dict(self):
        return {"origin_as": self.origin_as, "prefix": self.prefix.to_dict()}

    @classmethod
    def from_dict(cls, data):
        return cls(data["origin_as"], Prefix.from_dict(data["prefix"]))

    def __repr__(self):
        return "Route(origin_as=%r, prefix=%r)" % (self.origin_as, self.prefix)
