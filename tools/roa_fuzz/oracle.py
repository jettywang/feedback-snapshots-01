"""Independent reference expectations built only on the standard library.

The oracle never imports the adapter or the pyasn1 codec.  It re-derives
every decision from the RFC text using :mod:`ipaddress`, so the test
suite has an expectation source that cannot accidentally share a bug with
the code under test.
"""

import ipaddress

from .model import AFI_BITS, AFI_IPV4, SUPPORTED_AFIS


def _network(prefix):
    cls = ipaddress.IPv4Network if prefix.afi == AFI_IPV4 else ipaddress.IPv6Network
    return cls((prefix.address, prefix.length), strict=False)


class ReferenceOracle:
    """Stateless RFC expectations used as the fuzzing test oracle."""

    # --- Layer 1: structural / semantic well-formedness of the ROA -------
    def is_structurally_valid_roa(self, roa):
        if roa.version != 0:
            return False
        if not 0 <= roa.as_id <= (1 << 32) - 1:
            return False
        if not roa.blocks:
            return False
        for afi, entries in roa.blocks.items():
            if afi not in SUPPORTED_AFIS:
                return False
            if not entries:
                return False
            width = AFI_BITS[afi]
            for entry in entries:
                prefix = entry.prefix
                if prefix.afi != afi:
                    return False
                if not 0 <= prefix.length <= width:
                    return False
                if entry.has_max_length:
                    if not prefix.length <= entry.max_length <= width:
                        return False
        return True

    # --- Layer 2: ROA resources vs. authenticated EE resources -----------
    def ee_contains_prefix(self, ee_resources, prefix):
        value = ee_resources.ranges.get(prefix.afi)
        if value is None:
            return False
        network = _network(prefix)
        first = int(network.network_address)
        last = int(network.broadcast_address)
        return any(minimum <= first and last <= maximum for minimum, maximum in value)

    def is_resource_valid(self, roa, ee_resources):
        if not self.is_structurally_valid_roa(roa):
            return False
        for _afi, entry in roa.iter_prefixes():
            if not self.ee_contains_prefix(ee_resources, entry.prefix):
                return False
        return True

    # --- Layer 3: does one concrete route match an authorization? --------
    def is_route_authorized(self, roa, ee_resources, route):
        if not self.is_resource_valid(roa, ee_resources):
            return False
        # AS 0 is the RFC 6483 negative attestation: it authorizes nothing.
        if roa.as_id == 0:
            return False
        if route.origin_as != roa.as_id:
            return False
        announced = _network(route.prefix)
        for _afi, entry in roa.iter_prefixes():
            roa_network = _network(entry.prefix)
            if not roa_network.supernet_of(announced):
                continue
            # Absent maxLength -> exact prefix only (RFC 6482 section 3.3).
            effective_max = entry.max_length if entry.has_max_length else entry.prefix.length
            if route.prefix.length <= effective_max:
                return True
        return False
