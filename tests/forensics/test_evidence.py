#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import hashlib
import json
import sys
import unittest

from tests.base import BaseTestCase
from tests.forensics import fixtures as fx

from pyasn1.codec.der import encoder
from pyasn1.forensics import DEFAULT_INJECTED
from pyasn1.forensics import ABSENT_OPTIONAL
from pyasn1.forensics import OPEN_UNRESOLVED
from pyasn1.forensics import PRESENT
from pyasn1.forensics import ForensicExporter
from pyasn1.forensics import find_field
from pyasn1.forensics import iter_fields
from pyasn1.forensics import redact
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class EvidenceTestCase(BaseTestCase):

    def test_omitted_default_is_not_on_wire(self):
        exporter = ForensicExporter(fx.DEFAULT_WIRE)
        interpretation = exporter.interpret(
            'default-zero', fx.VersionDefaultZero())
        version = find_field(interpretation.fields, 'version')
        permissions = find_field(interpretation.fields, 'permissions')
        assert version.presence == DEFAULT_INJECTED
        assert version.raw_path is None
        assert version.raw_hex is None
        assert version.default_value['value'] == 0
        assert permissions.presence == PRESENT
        assert permissions.raw_path == '0'
        assert permissions.raw_hex == '810107'

    def test_optional_absence_distinguished_from_default(self):
        exporter = ForensicExporter(fx.DEFAULT_WIRE)
        interpretation = exporter.interpret(
            'optional', fx.VersionOptional())
        version = find_field(interpretation.fields, 'version')
        assert version.presence == ABSENT_OPTIONAL
        assert version.default_value is None
        assert version.raw_path is None

    def test_different_defaults_recorded_per_schema(self):
        exporter = ForensicExporter(fx.DEFAULT_WIRE)
        zero = exporter.interpret('z', fx.VersionDefaultZero())
        three = exporter.interpret('t', fx.VersionDefaultThree())
        assert find_field(zero.fields, 'version').default_value['value'] == 0
        assert find_field(three.fields, 'version').default_value['value'] == 3

    def test_full_integer_and_octet_precision(self):
        big = fx.BIG_INTEGER
        octets = fx.FULL_OCTETS

        class Precise(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('big', univ.Integer()),
                namedtype.NamedType('blob', univ.OctetString()))

        msg = Precise()
        msg.setComponentByName('big', big)
        msg.setComponentByName('blob', octets)
        wire = encoder.encode(msg)

        interpretation = ForensicExporter(wire).interpret('p', Precise())
        big_field = find_field(interpretation.fields, 'big')
        blob_field = find_field(interpretation.fields, 'blob')
        assert big_field.value.value == big
        assert blob_field.value.value == octets.hex()
        assert blob_field.value.detail['lengthOctets'] == 256

    def test_choice_branch_recorded(self):
        class Choice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'read', univ.Integer().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, 0, 1))),
                namedtype.NamedType(
                    'write', univ.Integer().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, 0, 2))))

        wire = bytes.fromhex('820101')
        interpretation = ForensicExporter(wire).interpret('c', Choice())
        selected = [f for f in iter_fields(interpretation.fields)
                    if f.presence == PRESENT]
        assert len(selected) == 1
        assert selected[0].choice_branch == 'write'
        assert selected[0].name == 'write'

    def test_unknown_open_type_kept_as_raw_any(self):
        exporter = ForensicExporter(fx.ENVELOPE_UNKNOWN_WIRE)
        interpretation = exporter.interpret(
            'untyped', fx.EnvelopeUntyped())
        content = find_field(interpretation.fields, 'content')
        assert content.presence == OPEN_UNRESOLVED
        assert content.unresolved is True
        assert content.schema_type == 'Any'
        assert content.raw_hex == fx.RIGHTS_CONTENT.hex()
        assert content.value.kind == 'any-raw'

    def test_known_open_type_resolves_and_keeps_children(self):
        exporter = ForensicExporter(fx.ENVELOPE_DETAILED_WIRE)
        interpretation = exporter.interpret(
            'detailed', fx.EnvelopeDetailed())
        content = find_field(interpretation.fields, 'content')
        assert content.unresolved is False
        assert content.schema_type == 'RightsDetailed'
        child_names = sorted(c.name for c in content.children)
        assert child_names == ['read', 'write']

    def test_tag_class_and_category_captured(self):
        exporter = ForensicExporter(fx.IMPLICIT_WIRE)
        interpretation = exporter.interpret(
            'int', fx.IntegerPermission())
        field = find_field(interpretation.fields, 'readPermission')
        assert field.tag_category == 'implicit'
        assigned = field.tag.to_dict()[0]
        assert assigned['tagClass'] == 'context'
        assert assigned['tagNumber'] == 1
        assert assigned['format'] == 'primitive'

    def test_redaction_preserves_length_and_digest_only(self):
        exporter = ForensicExporter(fx.ENVELOPE_DETAILED_WIRE)
        interpretation = exporter.interpret(
            'detailed', fx.EnvelopeDetailed())
        original = find_field(interpretation.fields, 'content.read')
        original_value = original.value.to_dict()

        redacted = redact(
            interpretation, ('content.read',),
            raw_index={n.path: n for n in _walk(exporter.raw_root)})
        redacted_field = redacted['fields'][1]['children'][0]
        value = redacted_field['value']
        assert value['value'] == 'REDACTED'
        assert value['lengthOctets'] == 1
        assert value['sha256'] == hashlib.sha256(b'\x01').hexdigest()
        # The in-memory interpretation and its value are untouched.
        assert original.value.to_dict() == original_value
        assert exporter.substrate == fx.ENVELOPE_DETAILED_WIRE

    def test_export_is_json_serializable_plain_data(self):
        exporter = ForensicExporter(fx.ENVELOPE_DETAILED_WIRE)
        export = exporter.export(
            (('detailed', fx.EnvelopeDetailed()),
             ('untyped', fx.EnvelopeUntyped())),
            sensitive_paths=('typeId',))
        encoded = json.dumps(export)
        assert 'substrateHex' in encoded
        assert len(export['interpretations']) == 2

    def test_export_redacts_without_mutating_objects(self):
        exporter = ForensicExporter(fx.ENVELOPE_DETAILED_WIRE)
        export = exporter.export(
            (('detailed', fx.EnvelopeDetailed()),),
            sensitive_paths=('typeId',))
        redacted_type = export['interpretations'][0]['fields'][0]
        assert redacted_type['value']['value'] == 'REDACTED'
        # A second, non-redacted export still exposes the full value.
        clean = exporter.export(
            (('detailed', fx.EnvelopeDetailed()),))
        assert clean['interpretations'][0]['fields'][0]['value'][
            'value'] == '1.2.3.4'

    def test_integer_redaction_digests_content_octets(self):
        exporter = ForensicExporter(fx.IMPLICIT_WIRE)
        export = exporter.export(
            (('p', fx.IntegerPermission()),),
            sensitive_paths=('readPermission',))
        value = export['interpretations'][0]['fields'][0]['value']
        assert value['value'] == 'REDACTED'
        assert value['lengthOctets'] == 1
        assert value['sha256'] == hashlib.sha256(b'\x07').hexdigest()
        assert value['contentTlvLength'] == 3

    def test_redacting_absent_and_unknown_paths_is_safe(self):
        exporter = ForensicExporter(fx.DEFAULT_WIRE)
        # An absent DEFAULT has no value to redact; nothing is fabricated.
        export = exporter.export(
            (('d', fx.VersionDefaultZero()),),
            sensitive_paths=('version', 'permissions', 'no.such.path'))
        interpretation = export['interpretations'][0]
        by_name = {f['fieldName']: f for f in interpretation['fields']}
        assert by_name['version']['value'] is None
        assert by_name['version']['presence'] == 'default-injected'
        assert by_name['permissions']['value']['value'] == 'REDACTED'
        assert interpretation['redactedPaths'] == [
            'no.such.path', 'permissions', 'version']


def _walk(node):
    nodes = [node]
    for child in node.children:
        nodes.extend(_walk(child))
    return nodes


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
