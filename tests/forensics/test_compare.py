#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase
from tests.forensics import fixtures as fx

from pyasn1.codec.der import encoder
from pyasn1.forensics import ENCODING_RECONSTRUCTION
from pyasn1.forensics import ORIGINAL_EVIDENCE
from pyasn1.forensics import UNDETERMINED
from pyasn1.forensics import ForensicExporter
from pyasn1.forensics import compare
from pyasn1.forensics import semantic_equivalence
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class CompareTestCase(BaseTestCase):

    def _report(self, wire, left_schema, right_schema,
                left_name='left', right_name='right'):
        exporter = ForensicExporter(wire)
        left = exporter.interpret(left_name, left_schema)
        right = exporter.interpret(right_name, right_schema)
        return compare(left, right, raw_root=exporter.raw_root,
                       re_encoder=encoder.encode, substrate=wire), exporter

    def test_implicit_tag_integer_vs_boolean_divergence(self):
        report, _ = self._report(
            fx.IMPLICIT_WIRE, fx.IntegerPermission(), fx.BooleanAdmin(),
            'integer', 'boolean')
        kinds = [f['kind'] for f in report['findings']]
        assert 'schema-meaning-divergence' in kinds
        finding = next(f for f in report['findings']
                       if f['kind'] == 'schema-meaning-divergence')
        assert finding['left']['schemaType'] == 'Integer'
        assert finding['right']['schemaType'] == 'Boolean'
        # Same raw TLV anchors both sides; the bytes are identical.
        assert finding['left']['rawPath'] == '0'
        assert finding['right']['rawPath'] == '0'
        assert finding['left']['rawTlvHex'] == \
            finding['right']['rawTlvHex'] == '810107'
        # Boolean DER cannot re-encode 0x07 canonically; reconstruction
        # exposes that the meaning, not the bytes, is the dispute.
        assert report['reconstruction']['boolean'][
            'matchesSubstrate'] is False

    def test_same_display_text_does_not_merge_fields(self):
        # INTEGER 7 and ENUMERATED 7 render identically but differ in type.
        report, _ = self._report(
            fx.IMPLICIT_WIRE, fx.IntegerPermission(),
            fx.EnumeratedClearance(), 'integer', 'enumerated')
        finding = next(f for f in report['findings']
                       if f['kind'] == 'schema-meaning-divergence')
        assert finding['detail']['sameDisplayText'] is True
        assert finding['left']['schemaType'] != \
            finding['right']['schemaType']
        assert report['divergent'] is True
        # Both re-encode to the identical substrate: pure schema-assigned
        # meaning, supported by encoding reconstruction.
        assert finding['evidenceSource'] == ENCODING_RECONSTRUCTION
        for entry in report['reconstruction'].values():
            assert entry['matchesSubstrate'] is True

    def test_default_value_divergence_is_encoding_reconstruction(self):
        report, _ = self._report(
            fx.DEFAULT_WIRE, fx.VersionDefaultZero(),
            fx.VersionDefaultThree(), 'default-0', 'default-3')
        finding = next(f for f in report['findings']
                       if f['kind'] == 'default-value-divergence')
        assert finding['evidenceSource'] == ENCODING_RECONSTRUCTION
        assert finding['left']['presence'] == 'default-injected'
        assert finding['right']['presence'] == 'default-injected'
        # Neither side has the field on the wire: no raw path is claimed.
        assert finding['left']['rawPath'] is None
        assert finding['right']['rawPath'] is None

    def test_default_vs_optional_presence_divergence(self):
        report, _ = self._report(
            fx.DEFAULT_WIRE, fx.VersionDefaultZero(),
            fx.VersionOptional(), 'default', 'optional')
        finding = next(f for f in report['findings']
                       if f['kind'] == 'presence-divergence')
        assert finding['left']['presence'] == 'default-injected'
        assert finding['right']['presence'] == 'absent-optional'
        assert finding['evidenceSource'] == ORIGINAL_EVIDENCE

    def test_open_type_known_vs_unknown_is_undetermined(self):
        report, _ = self._report(
            fx.ENVELOPE_DETAILED_WIRE, fx.EnvelopeDetailed(),
            fx.EnvelopeUntyped(), 'known', 'untyped')
        kinds = [f['kind'] for f in report['findings']]
        assert 'open-type-undetermined' in kinds
        finding = next(f for f in report['findings']
                       if f['kind'] == 'open-type-undetermined')
        assert finding['evidenceSource'] == UNDETERMINED
        # The unresolved side keeps the ANY verbatim and does not guess.
        unresolved = finding['right']
        assert unresolved['unresolvedAny'] is True
        assert unresolved['rawTlvHex'] == fx.RIGHTS_CONTENT.hex()
        # Nested children of the resolved side are not double-counted as
        # missing fields on the unresolved side.
        assert 'field-only-on-one-side' not in kinds

    def test_two_different_open_type_mappings_diverge(self):
        report, _ = self._report(
            fx.ENVELOPE_DETAILED_WIRE, fx.EnvelopeDetailed(),
            fx.EnvelopeCompact(), 'detailed', 'compact')
        # The compact schema does not know OID 1.2.3.4, so its content stays
        # untyped while the detailed side resolves it.
        assert any(f['kind'] == 'open-type-undetermined'
                   for f in report['findings'])

    def test_decode_failure_is_captured_not_raised(self):
        class RequiresTwoFields(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        exporter = ForensicExporter(fx.IMPLICIT_WIRE)
        good = exporter.interpret('ok', fx.IntegerPermission())
        bad = exporter.interpret('broken', RequiresTwoFields())
        report = compare(good, bad, raw_root=exporter.raw_root)
        assert any(f['kind'] == 'decode-failure'
                   for f in report['findings'])
        assert bad.decode_error is not None


class SemanticEquivalenceTestCase(BaseTestCase):

    def test_equivalent_values_different_construction(self):
        seq_exp = ForensicExporter(fx.CONTROL_SEQUENCE_WIRE)
        set_exp = ForensicExporter(fx.CONTROL_SET_WIRE)
        seq = seq_exp.interpret('seq', fx.PermissionRecord())
        aset = set_exp.interpret('set', fx.PermissionRecordSet())
        result = semantic_equivalence(
            seq, aset, left_raw_root=seq_exp.raw_root,
            right_raw_root=set_exp.raw_root)
        assert result['semanticallyEquivalent'] is True
        assert result['changedValues'] == []
        # Construction genuinely differs (SEQUENCE tag 16 vs SET tag 17).
        assert result['construction']['constructionDiffers'] is True
        assert result['construction']['leftRootTag']['tagNumber'] == 16
        assert result['construction']['rightRootTag']['tagNumber'] == 17

    def test_permission_change_is_detected(self):
        # Build a second record with an elevated write permission.
        elevated = fx.PermissionRecord()
        elevated.setComponentByName('read', 1)
        elevated.setComponentByName('write', 1)
        elevated_wire = encoder.encode(elevated)

        original = ForensicExporter(fx.CONTROL_SEQUENCE_WIRE).interpret(
            'orig', fx.PermissionRecord())
        changed = ForensicExporter(elevated_wire).interpret(
            'elevated', fx.PermissionRecord())
        result = semantic_equivalence(original, changed)
        assert result['semanticallyEquivalent'] is False
        paths = [c['path'] for c in result['changedValues']]
        assert 'write' in paths

    def test_internal_typeid_difference_is_not_a_value_change(self):
        # Same field path and scalar value reached through two pyasn1
        # subclasses with distinct typeId must still compare as equal values.
        class BaseInteger(univ.Integer):
            pass

        class OtherInteger(univ.Integer):
            typeId = univ.Integer.getTypeId() + 1000

        class MsgA(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('perm', BaseInteger()))

        class MsgB(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('perm', OtherInteger()))

        msg_a = MsgA()
        msg_a.setComponentByName('perm', 5)
        wire = encoder.encode(msg_a)

        left = ForensicExporter(wire).interpret('a', MsgA())
        right = ForensicExporter(wire).interpret('b', MsgB())
        result = semantic_equivalence(left, right)
        assert result['semanticallyEquivalent'] is True
        assert result['changedValues'] == []


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
