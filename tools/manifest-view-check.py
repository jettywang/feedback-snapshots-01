#!/usr/bin/env python
#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
# Offline RPKI manifest view check (RFC 6486).
#
"""Demonstrate two interleaved repository syncs.

Each half of the directory is individually legitimate: every file present
hashes to the value on some manifest.  Neither complete manifest generation
covers the merged directory, so no consumable view is produced and the gaps
are reported per manifest.  No network or filesystem discovery is involved;
all inputs come from the in-memory mapping below.
"""
import hashlib
import json
import sys

from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc4055
from pyasn1_modules import rfc6486
from pyasn1_modules import rfc6486_manifest_view


CHECKED_AT = '20261115000000Z'

# The CRL keeps its published file name across generations even though its
# content changes; that is normal for a publication point.
FILES = {
    'authority.cer': b'authority EE certificate',
    'object-1.cer': b'signed object, generation one',
    'object-2.cer': b'signed object, generation two',
    'crl.cer': b'CRL, generation one',
    'crl.next.cer': b'CRL, generation two',
}


def bitstring(content):
    return univ.BitString.fromOctetString(
        hashlib.sha256(content).digest())


def manifest(number, files):
    value = rfc6486.Manifest()
    value['manifestNumber'] = number
    value['thisUpdate'] = '20261114000000Z'
    value['nextUpdate'] = '20261121000000Z'
    value['fileHashAlg'] = rfc4055.id_sha256

    file_list = value['fileList'].clone()
    file_list.clear()
    for name, content in files:
        entry = file_list.componentType.clone()
        entry['file'] = name
        entry['hash'] = bitstring(content)
        file_list.append(entry)
    value['fileList'] = file_list
    return der_encoder(value)


# The hash of 'crl.cer' differs between the two generations.
GEN_ONE = manifest(1, [
    ('authority.cer', FILES['authority.cer']),
    ('object-1.cer', FILES['object-1.cer']),
    ('crl.cer', FILES['crl.cer']),
])
GEN_TWO = manifest(2, [
    ('authority.cer', FILES['authority.cer']),
    ('object-2.cer', FILES['object-2.cer']),
    ('crl.cer', FILES['crl.next.cer']),
])

# The interrupted sync: the CRL content is from generation two while the
# signed-object side is still from generation one.  Every individual file
# is genuine; the merged directory is not any complete generation.
INTERLEAVED = {
    'authority.cer': FILES['authority.cer'],
    'object-1.cer': FILES['object-1.cer'],
    'object-2.cer': FILES['object-2.cer'],
    'crl.cer': FILES['crl.next.cer'],
}


def dump(label, result):
    print('%s: %s' % (label, result.state))
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    print()


def main():
    if len(sys.argv) != 1:
        print('Usage:\n$ %s' % sys.argv[0], file=sys.stderr)
        return 2

    one = rfc6486_manifest_view.evaluate(
        GEN_ONE, INTERLEAVED, checked_at=CHECKED_AT)
    two = rfc6486_manifest_view.evaluate(
        GEN_TWO, INTERLEAVED, checked_at=CHECKED_AT)

    complete_one = rfc6486_manifest_view.evaluate(
        GEN_ONE,
        {'authority.cer': FILES['authority.cer'],
         'object-1.cer': FILES['object-1.cer'],
         'crl.cer': FILES['crl.cer']},
        checked_at=CHECKED_AT)
    complete_two = rfc6486_manifest_view.evaluate(
        GEN_TWO,
        {'authority.cer': FILES['authority.cer'],
         'object-2.cer': FILES['object-2.cer'],
         'crl.cer': FILES['crl.next.cer']},
        checked_at=CHECKED_AT)

    dump('interleaved under manifest 1', one)
    dump('interleaved under manifest 2', two)
    dump('complete generation 1 alone', complete_one)
    dump('complete generation 2 alone', complete_two)

    generation = rfc6486_manifest_view.evaluate_generation(
        [GEN_ONE, GEN_TWO], INTERLEAVED, checked_at=CHECKED_AT)
    dump('interleaved generation', generation)

    # Success means the unusual result was observed: the interleaved
    # directory is rejected while both halves are independently complete.
    ok = (one.state == 'rejected' and two.state == 'rejected'
          and complete_one.state == 'verified'
          and complete_two.state == 'verified'
          and generation.state == 'rejected'
          and generation.current_number == 2
          and generation.gaps == {
              1: {'missing': [], 'extra': ['object-2.cer']},
              2: {'missing': [], 'extra': ['object-1.cer']},
          })
    if not ok:
        print('demo premise not met', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
