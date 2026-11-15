#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Run explicit schemas against one substrate and redact sensitive paths.

The orchestration here never mutates the caller's schema objects or decoded
values.  Each schema is decoded onto a fresh ``asn1Spec`` instance and the
structured result is a separate tree of plain evidence objects, so redaction
only touches the exported copy.
"""
import hashlib

from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.error import PyAsn1Error

from pyasn1.forensics import evidence as _evidence
from pyasn1.forensics.raw import ForensicError
from pyasn1.forensics.raw import walk_tlv

__all__ = [
    'ForensicError', 'ForensicExporter', 'redact', 'iter_fields',
    'find_field', 'REDACTED',
]

#: Value substituted for a redacted field; length and digest are retained.
REDACTED = 'REDACTED'


def iter_fields(fields):
    """Yield every :class:`FieldEvidence` in pre-order, including nested."""
    for field in fields:
        yield field
        if field.children:
            for nested in iter_fields(field.children):
                yield nested


def find_field(fields, path):
    """Look up a field by dotted path within an evidence field tree."""
    for field in iter_fields(fields):
        if field.path == path:
            return field
    return None


def _normalize_paths(sensitive_paths):
    normalized = set()
    for path in sensitive_paths or ():
        normalized.add(path.lstrip('.'))
    return frozenset(normalized)


def _index_raw_nodes(node, index=None):
    if index is None:
        index = {}
    index[node.path] = node
    for child in node.children:
        _index_raw_nodes(child, index)
    return index


def _redact_value(field, raw_index):
    """Return a redacted value dict that preserves length and a digest.

    The digest is computed over the *content* octets of the transmitted TLV
    (the sensitive value itself, excluding identifier and length octets) so it
    is a property of the original bytes rather than of any schema-assigned
    Python value.  Fields that were never on the wire have no content to hash.
    """
    raw_node = raw_index.get(field.raw_path) if field.raw_path else None
    if raw_node is not None:
        content = raw_node.content_octets
        digest_hex = hashlib.sha256(content).hexdigest()
        content_length = len(content)
        tlv_length = len(raw_node.tlv_octets)
    else:
        digest_hex = None
        content_length = None
        tlv_length = None

    length = None
    if field.value is not None:
        length = field.value.detail.get('lengthOctets')
    if length is None:
        length = content_length

    return {
        'kind': 'redacted',
        'value': REDACTED,
        'lengthOctets': length,
        'contentTlvLength': tlv_length,
        'sha256': digest_hex,
        'pythonType': field.schema_type,
    }


def redact(interpretation, sensitive_paths, raw_index=None):
    """Return a deep-copied, redacted :class:`Interpretation`.

    Fields whose dotted path is in *sensitive_paths* keep their tag, presence
    and raw content length plus a SHA-256 digest, but their value is replaced.
    The original *interpretation* and every decoded ASN.1 object are left
    untouched.
    """
    targets = _normalize_paths(sensitive_paths)

    def clone_field(field):
        value = field.value
        if field.path in targets and value is not None:
            value_dict = _redact_value(field, raw_index or {})
        elif value is not None:
            value_dict = value.to_dict()
        else:
            value_dict = None
        return {
            'path': field.path,
            'fieldName': field.name,
            'schemaType': field.schema_type,
            'presence': field.presence,
            'tagCategory': field.tag_category,
            'assignedTag': list(field.tag.to_dict()),
            'choiceBranch': field.choice_branch,
            'openType': dict(field.open_type) if field.open_type else None,
            'unresolvedAny': field.unresolved,
            'rawPath': field.raw_path,
            'rawTlvHex': field.raw_hex,
            'value': value_dict,
            'defaultValue': field.default_value,
            'children': [clone_field(child) for child in field.children],
        }

    cloned_fields = [clone_field(field) for field in interpretation.fields]
    return {
        'schemaName': interpretation.schema_name,
        'rootRawPath': interpretation.root_raw_path,
        'decodeError': interpretation.decode_error,
        'fields': cloned_fields,
        'redactedPaths': sorted(targets),
    }


class ForensicExporter(object):
    """Produce schema-neutral evidence and per-schema interpretations.

    Parameters
    ----------
    substrate: :class:`bytes`
        The DER (or BER) bytes under examination.
    decoder: optional
        A pyasn1 decoder module exposing ``decode(substrate, asn1Spec=...,
        decodeOpenTypes=...)``.  Defaults to the DER decoder.
    """

    def __init__(self, substrate, decoder=None):
        if not isinstance(substrate, (bytes, bytearray)):
            raise ForensicError(
                'Substrate must be bytes, got %s' % type(substrate).__name__)
        self._substrate = bytes(substrate)
        self._decoder = decoder or _der_decoder
        self._raw_root = walk_tlv(self._substrate)

    @property
    def substrate(self):
        return self._substrate

    @property
    def raw_root(self):
        return self._raw_root

    def raw_evidence(self):
        """Return the schema-neutral TLV tree as plain data."""
        return self._raw_root.to_dict()

    def interpret(self, schema_name, asn1_spec):
        """Decode with one explicit schema and build its field evidence.

        A decode failure is captured rather than raised: the returned
        interpretation records the error alongside the still-valid raw
        evidence, so one bad schema never hides the others.
        """
        try:
            decoded, tail = self._decoder.decode(
                self._substrate, asn1Spec=asn1_spec, decodeOpenTypes=True)
        except PyAsn1Error as exc:
            return _evidence.build_interpretation(
                schema_name, None, self._raw_root, decode_error=str(exc))
        if tail:
            return _evidence.build_interpretation(
                schema_name, None, self._raw_root,
                decode_error='%d trailing byte(s) after decoded TLV'
                % len(tail))
        return _evidence.build_interpretation(
            schema_name, decoded, self._raw_root)

    def export(self, schemas, sensitive_paths=None):
        """Build the full structured export for two or more named schemas.

        *schemas* is an iterable of ``(name, asn1Spec)`` pairs.  The raw
        evidence is emitted once; each interpretation is independent.  When
        *sensitive_paths* is given, the exported interpretation values are
        redacted while the in-memory interpretations stay intact.
        """
        interpretations = []
        raw_index = _index_raw_nodes(self._raw_root)
        for name, spec in schemas:
            interpretation = self.interpret(name, spec)
            if sensitive_paths:
                interpretations.append(
                    redact(interpretation, sensitive_paths, raw_index))
            else:
                interpretations.append(interpretation.to_dict())
        return {
            'substrateHex': self._substrate.hex(),
            'substrateLength': len(self._substrate),
            'raw': self.raw_evidence(),
            'interpretations': interpretations,
        }
