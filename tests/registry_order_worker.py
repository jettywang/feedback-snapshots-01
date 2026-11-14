"""Subprocess worker for the open-type import-order differential test.

It runs in a fresh interpreter so that module import order is fully under
test control.  It imports the requested modules in the given order, then
reports a JSON snapshot describing how the three real open-type
registries resolve a fixed set of DER fixtures.

Snapshot schema (one JSON object on stdout):
  status            "ok" or "import-error" (never treated as a finding)
  import_error      [module, exception-type, message] when status != ok
  order             the import order actually applied
  registries        per family: per OID -> resolved schema fingerprint +
                    source module, or null for an unregistered OID
  decode            per fixture: decoded leaf class name, whether the raw
                    bytes survived, and DER re-encode equality
  coverage          registry relationships exercised by this order
"""

import importlib
import json
import sys

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc5280
from pyasn1_modules import rfc5652
from pyasn1_modules.guarded_registry import schema_fingerprint


FAMILIES = {
    'cmsContentTypesMap': rfc5652.cmsContentTypesMap,
    'cmsAttributesMap': rfc5652.cmsAttributesMap,
    'certificateExtensionsMap': rfc5280.certificateExtensionsMap,
}

UNKNOWN_OID = univ.ObjectIdentifier('1.3.6.1.4.1.99999.42.1')
RAW_PAYLOAD = b'\x00\x01\x02raw-must-survive'


def _encode_fixtures():
    """Build fixed DER blobs once; identical in every process."""
    fixtures = {}

    data = univ.OctetString(b'order-independent-content')
    content_info = rfc5652.ContentInfo()
    content_info['contentType'] = rfc5652.id_data
    content_info['content'] = univ.Any(der_encoder.encode(data))
    fixtures['cms_content'] = der_encoder.encode(content_info)

    raw_value = univ.OctetString(RAW_PAYLOAD)
    unknown_attr = rfc5652.Attribute()
    unknown_attr['attrType'] = UNKNOWN_OID
    unknown_attr['attrValues'][0] = univ.Any(der_encoder.encode(raw_value))
    fixtures['cms_attribute_unknown'] = der_encoder.encode(unknown_attr)

    basic_constraints = rfc5280.BasicConstraints()
    basic_constraints['cA'] = True
    extension = rfc5280.Extension()
    extension['extnID'] = univ.ObjectIdentifier('2.5.29.19')
    extension['critical'] = True
    extension['extnValue'] = univ.OctetString(
        der_encoder.encode(basic_constraints))
    fixtures['cert_extension'] = der_encoder.encode(extension)

    return fixtures


def _resolve(reg_map, oid):
    spec = reg_map.get(oid)
    if spec is None:
        return None
    return {
        'fingerprint': list(schema_fingerprint(spec)),
        'type': type(spec).__name__,
        'source': type(spec).__module__,
    }


def _snapshot_registry(reg_map):
    return {str(oid): _resolve(reg_map, oid) for oid in reg_map}


def _decode_fixtures(fixtures):
    result = {}

    content_info, _ = der_decoder.decode(
        fixtures['cms_content'],
        asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
    content = content_info['content']
    result['cms_content'] = {
        'leaf_type': type(content).__name__,
        'roundtrip': der_encoder.encode(content_info)
        == fixtures['cms_content'],
    }

    attr, _ = der_decoder.decode(
        fixtures['cms_attribute_unknown'],
        asn1Spec=rfc5652.Attribute(), decodeOpenTypes=True)
    value = attr['attrValues'][0]
    result['cms_attribute_unknown'] = {
        'leaf_type': type(value).__name__,
        'raw_preserved': value.asOctets()
        == der_encoder.encode(univ.OctetString(RAW_PAYLOAD)),
        'registered': UNKNOWN_OID in rfc5652.cmsAttributesMap,
        'roundtrip': der_encoder.encode(attr)
        == fixtures['cms_attribute_unknown'],
    }

    extension, _ = der_decoder.decode(
        fixtures['cert_extension'], asn1Spec=rfc5280.Extension())
    extn_id = extension['extnID']
    spec = rfc5280.certificateExtensionsMap.get(extn_id)
    if spec is None:
        inner_type = None
        inner_roundtrip = False
    else:
        inner, _ = der_decoder.decode(extension['extnValue'], asn1Spec=spec)
        inner_type = type(inner).__name__
        inner_roundtrip = der_encoder.encode(inner) == bytes(
            extension['extnValue'])
    result['cert_extension'] = {
        'leaf_type': inner_type,
        'roundtrip': inner_roundtrip
        and der_encoder.encode(extension) == fixtures['cert_extension'],
    }
    return result


def main(order):
    fixtures = _encode_fixtures()
    for module_name in order:
        importlib.import_module('pyasn1_modules.%s' % module_name)

    registries = {
        family: _snapshot_registry(reg_map)
        for family, reg_map in FAMILIES.items()
    }
    coverage = {
        family: sorted(registries[family]) for family in FAMILIES
    }
    return {
        'status': 'ok',
        'order': list(order),
        'registries': registries,
        'decode': _decode_fixtures(fixtures),
        'coverage': coverage,
    }


if __name__ == '__main__':
    requested = sys.argv[1:]
    try:
        payload = main(requested)
    except Exception as exc:  # import/parse failures are data, not findings
        payload = {
            'status': 'import-error',
            'order': requested,
            'import_error': [
                getattr(exc, '__module__', 'builtins'),
                type(exc).__name__,
                str(exc),
            ],
        }
    json.dump(payload, sys.stdout, sort_keys=True)
