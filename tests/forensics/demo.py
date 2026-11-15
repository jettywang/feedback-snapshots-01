#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Runnable demonstration of the forensic dual-schema workflow.

Run from the repository root with::

    PYTHONPATH=. python -m tests.forensics.demo

It prints, for each divergence mechanism and for the semantic-equivalence
control, the exact bytes involved and the structured conclusion a reviewer
can act on.  Nothing here is imported by the test suite; it is documentation
that executes.
"""
import json

from pyasn1.codec.der import encoder
from pyasn1.forensics import ForensicExporter
from pyasn1.forensics import compare
from pyasn1.forensics import semantic_equivalence
from tests.forensics import fixtures as fx


def _banner(title):
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def _summarize(report):
    print('  findings: %d (divergent=%s)' % (
        report['findingCount'], report['divergent']))
    for finding in report['findings']:
        print('  - %-28s evidence=%s' % (
            finding['kind'], finding['evidenceSource']))
        print('      %s' % finding['reason'])


def main():
    _banner('1. Implicit tagging: INTEGER permission vs BOOLEAN admin')
    print('  shared DER: %s' % fx.IMPLICIT_WIRE.hex())
    exporter = ForensicExporter(fx.IMPLICIT_WIRE)
    left = exporter.interpret('integer-permission', fx.IntegerPermission())
    right = exporter.interpret('boolean-admin', fx.BooleanAdmin())
    _summarize(compare(left, right, raw_root=exporter.raw_root,
                       re_encoder=encoder.encode,
                       substrate=fx.IMPLICIT_WIRE))

    _banner('2. Same display text, different type: INTEGER vs ENUMERATED')
    print('  shared DER: %s (content 0x07 renders as "7" under both)'
          % fx.IMPLICIT_WIRE.hex())
    enum_right = exporter.interpret('enumerated-clearance',
                                    fx.EnumeratedClearance())
    _summarize(compare(left, enum_right, raw_root=exporter.raw_root,
                       re_encoder=encoder.encode,
                       substrate=fx.IMPLICIT_WIRE))

    _banner('3. DEFAULT handling: omitted version is never an on-wire TLV')
    print('  shared DER: %s' % fx.DEFAULT_WIRE.hex())
    default_exporter = ForensicExporter(fx.DEFAULT_WIRE)
    dz = default_exporter.interpret('default-0', fx.VersionDefaultZero())
    dt = default_exporter.interpret('default-3', fx.VersionDefaultThree())
    do = default_exporter.interpret('optional', fx.VersionOptional())
    _summarize(compare(dz, dt, raw_root=default_exporter.raw_root,
                       re_encoder=encoder.encode, substrate=fx.DEFAULT_WIRE))
    _summarize(compare(dz, do, raw_root=default_exporter.raw_root,
                       re_encoder=encoder.encode, substrate=fx.DEFAULT_WIRE))

    _banner('4. Open/ANY typing: known type-id vs untyped ANY')
    print('  shared DER: %s' % fx.ENVELOPE_DETAILED_WIRE.hex())
    open_exporter = ForensicExporter(fx.ENVELOPE_DETAILED_WIRE)
    known = open_exporter.interpret('detailed', fx.EnvelopeDetailed())
    untyped = open_exporter.interpret('untyped', fx.EnvelopeUntyped())
    _summarize(compare(known, untyped, raw_root=open_exporter.raw_root,
                       re_encoder=encoder.encode,
                       substrate=fx.ENVELOPE_DETAILED_WIRE))

    _banner('5. Control: equal permissions, different construction')
    print('  SEQUENCE DER: %s' % fx.CONTROL_SEQUENCE_WIRE.hex())
    print('  SET      DER: %s' % fx.CONTROL_SET_WIRE.hex())
    seq_exporter = ForensicExporter(fx.CONTROL_SEQUENCE_WIRE)
    set_exporter = ForensicExporter(fx.CONTROL_SET_WIRE)
    seq = seq_exporter.interpret('sequence-record', fx.PermissionRecord())
    aset = set_exporter.interpret('set-record', fx.PermissionRecordSet())
    equivalence = semantic_equivalence(
        seq, aset, left_raw_root=seq_exporter.raw_root,
        right_raw_root=set_exporter.raw_root)
    print('  semantically equivalent: %s' %
          equivalence['semanticallyEquivalent'])
    print('  construction differs:    %s (root tags %s vs %s)' % (
        equivalence['construction']['constructionDiffers'],
        equivalence['construction']['leftRootTag']['tagNumber'],
        equivalence['construction']['rightRootTag']['tagNumber']))
    print('  changed permission values: %s' % equivalence['changedValues'])

    _banner('Structured export sample (raw evidence + one interpretation)')
    sample = ForensicExporter(fx.IMPLICIT_WIRE).export(
        (('integer-permission', fx.IntegerPermission()),))
    print(json.dumps(sample, indent=2, sort_keys=True)[:1200])


if __name__ == '__main__':
    main()
