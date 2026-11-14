"""Semantic fuzzing and a bounded local authorization adapter for RPKI ROAs.

The package separates three questions that are easy to conflate:

1. Is the ROA byte string a structurally valid DER encoding of the
   RFC 6482 RouteOriginAttestation?
2. Are the resources carried by the ROA contained in the authenticated
   IP resources of its end-entity (EE) certificate?
3. Does one specific route (AFI, prefix, origin AS) match an authorization?

An answer of "yes" to (1) says nothing about (2) or (3).  In particular a
decodable ROA never implies that a route is authorized.
"""

from .model import (
    AFI_IPV4,
    AFI_IPV6,
    EEResources,
    Prefix,
    RoaObject,
    RoaPrefix,
    Route,
)
from .asn1_codec import decode_roa, encode_roa, StructuralError
from .adapter import AuthorizationVerdict, LocalRoaAdapter, StructuralVerdict
from .oracle import ReferenceOracle

__all__ = [
    "AFI_IPV4",
    "AFI_IPV6",
    "EEResources",
    "Prefix",
    "RoaObject",
    "RoaPrefix",
    "Route",
    "decode_roa",
    "encode_roa",
    "StructuralError",
    "AuthorizationVerdict",
    "LocalRoaAdapter",
    "StructuralVerdict",
    "ReferenceOracle",
]
