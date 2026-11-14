"""DER encoding/decoding glue around the RFC 6482 pyasn1 structures.

This module is deliberately limited to (de)serialization.  It does not
decide whether resources are valid or whether a route is authorized.
"""

from pyasn1.codec.der.decoder import decode as _der_decode
from pyasn1.codec.der.encoder import encode as _der_encode
from pyasn1.error import PyAsn1Error

from pyasn1_modules import rfc6482

from .model import AFI_BITS, RoaObject, RoaPrefix, Prefix


class StructuralError(ValueError):
    """Raised when bytes cannot be decoded as a well-formed ROA eContent."""


def _bits_to_prefix(afi, bit_string):
    # asBinary() cannot distinguish the zero-length BIT STRING (a /0 prefix)
    # because pyasn1 renders that as '0'; asOctets() is empty only for /0,
    # so detect that case explicitly and otherwise read the significant bits.
    octets = bit_string.asOctets()
    if not octets:
        return Prefix(afi, 0, 0)
    bits = bit_string.asBinary()
    length = len(bits)
    value = int(bits, 2)
    # RFC 3779 stores prefix bits starting at the MSB of the full address,
    # so shift the recovered bits back up to their full-width position.
    value <<= AFI_BITS[afi] - length
    return Prefix(afi, value, length)


def _prefix_to_bit_string(prefix):
    length = prefix.length
    if length == 0:
        return rfc6482.IPAddress("")
    width = AFI_BITS[prefix.afi]
    if length < 0 or length > width:
        raise StructuralError("prefix length %d out of range for AFI %d" % (length, prefix.afi))
    full_width = format(prefix.network_address(), "0%db" % width)
    return rfc6482.IPAddress.fromBinaryString(full_width[:length])


def encode_roa(roa):
    """Serialize a RoaObject to DER; raise StructuralError on bad input."""
    try:
        addr_blocks = rfc6482.RouteOriginAttestation()
        addr_blocks["version"] = roa.version
        addr_blocks["asID"] = roa.as_id

        blocks = []
        for afi, entries in roa.blocks.items():
            family = rfc6482.ROAIPAddressFamily()
            family["addressFamily"] = bytes([0, afi & 0xFF])
            addresses = []
            for entry in entries:
                roa_address = rfc6482.ROAIPAddress()
                roa_address["address"] = _prefix_to_bit_string(entry.prefix)
                if entry.has_max_length:
                    roa_address["maxLength"] = entry.max_length
                addresses.append(roa_address)
            family["addresses"].setComponents(*addresses)
            blocks.append(family)

        addr_blocks["ipAddrBlocks"].setComponents(*blocks)
        return _der_encode(addr_blocks)
    except PyAsn1Error as exc:
        raise StructuralError("could not encode ROA: %s" % exc) from exc


def decode_roa(der_bytes):
    """Decode DER into a RoaObject or raise StructuralError.

    Only structural well-formedness is checked here; semantic constraints
    (AFI support, maxLength bounds, EE containment, route authorization)
    are the responsibility of the adapter.
    """
    try:
        parsed, rest = _der_decode(der_bytes, asn1Spec=rfc6482.RouteOriginAttestation())
    except PyAsn1Error as exc:
        raise StructuralError("could not decode ROA: %s" % exc) from exc
    if rest:
        raise StructuralError("trailing %d bytes after ROA eContent" % len(rest))

    try:
        as_id = int(parsed["asID"])
        blocks = {}
        for family in parsed["ipAddrBlocks"]:
            afi_octets = bytes(family["addressFamily"])
            if len(afi_octets) != 2 or afi_octets[0] != 0:
                raise StructuralError("unsupported non-IANA addressFamily %r" % afi_octets)
            afi = afi_octets[1]
            entries = []
            for roa_address in family["addresses"]:
                prefix = _bits_to_prefix(afi, roa_address["address"])
                max_length_field = roa_address["maxLength"]
                max_length = int(max_length_field) if max_length_field.hasValue() else None
                entries.append(RoaPrefix(prefix, max_length))
            blocks.setdefault(afi, []).extend(entries)
        return RoaObject(as_id, blocks, version=int(parsed["version"]))
    except PyAsn1Error as exc:
        raise StructuralError("malformed ROA component: %s" % exc) from exc
