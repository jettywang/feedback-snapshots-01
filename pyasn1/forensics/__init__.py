#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Structured forensic export and dual-schema comparison for ASN.1 messages.

This subpackage helps a reviewer decide whether two parsers disagree because
of what the *bytes* say or because of the *meaning a schema assigns* to them.

* :mod:`pyasn1.forensics.raw` dissects the substrate into schema-neutral TLVs.
* :mod:`pyasn1.forensics.evidence` records one schema-driven interpretation
  with field paths, tag class/number, CHOICE branch, presence and full values.
* :mod:`pyasn1.forensics.interpret` runs explicit schemas and redacts
  caller-designated sensitive paths without mutating the original objects.
* :mod:`pyasn1.forensics.compare` compares two interpretations on the raw
  evidence, never merging fields just because their display text matches.

Nothing here adds a runtime dependency and the package is import-safe on
Python 3.8+.
"""
from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder

from pyasn1.forensics.compare import ENCODING_RECONSTRUCTION
from pyasn1.forensics.compare import ORIGINAL_EVIDENCE
from pyasn1.forensics.compare import UNDETERMINED
from pyasn1.forensics.compare import compare
from pyasn1.forensics.compare import semantic_equivalence
from pyasn1.forensics.evidence import ABSENT_OPTIONAL
from pyasn1.forensics.evidence import DEFAULT_INJECTED
from pyasn1.forensics.evidence import OPEN_UNRESOLVED
from pyasn1.forensics.evidence import PRESENT
from pyasn1.forensics.interpret import ForensicExporter
from pyasn1.forensics.interpret import find_field
from pyasn1.forensics.interpret import iter_fields
from pyasn1.forensics.interpret import redact
from pyasn1.forensics.raw import ForensicError
from pyasn1.forensics.raw import RawNode
from pyasn1.forensics.raw import walk_tlv

__all__ = [
    'ForensicError', 'RawNode', 'walk_tlv', 'ForensicExporter',
    'compare', 'semantic_equivalence', 'redact', 'iter_fields',
    'find_field', 'forensic_report',
    'PRESENT', 'ABSENT_OPTIONAL', 'DEFAULT_INJECTED', 'OPEN_UNRESOLVED',
    'ORIGINAL_EVIDENCE', 'ENCODING_RECONSTRUCTION', 'UNDETERMINED',
]


def forensic_report(substrate, left_schema, right_schema,
                    left_name='left', right_name='right',
                    sensitive_paths=None, decoder=None, encoder=None):
    """Run the full dual-schema forensic workflow in one call.

    Parameters
    ----------
    substrate: :class:`bytes`
        DER/BER bytes under examination.
    left_schema, right_schema:
        Explicit pyasn1 schema instances (``asn1Spec`` objects).
    left_name, right_name: :class:`str`
        Labels used in the report to identify each schema.
    sensitive_paths: optional iterable of :class:`str`
        Dotted field paths whose values are redacted in the exported copy.
    decoder, encoder: optional
        pyasn1 codec modules; default to the DER codec.

    Returns
    -------
    :class:`dict`
        Keys ``export`` (raw evidence plus both interpretations, redacted as
        requested) and ``comparison`` (the divergence report with evidence
        provenance and whole-tree encoding reconstruction).
    """
    decoder = decoder or _der_decoder
    encoder = encoder or _der_encoder
    exporter = ForensicExporter(substrate, decoder=decoder)

    left = exporter.interpret(left_name, left_schema)
    right = exporter.interpret(right_name, right_schema)

    comparison = compare(
        left, right, raw_root=exporter.raw_root,
        re_encoder=getattr(encoder, 'encode', None), substrate=substrate)

    export = exporter.export(
        ((left_name, left_schema), (right_name, right_schema)),
        sensitive_paths=sensitive_paths)

    return {'export': export, 'comparison': comparison}
