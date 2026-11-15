#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Compare two schema-driven interpretations of the same substrate.

The comparison is anchored on the *transmitted TLVs* (their ``rawPath``), not
on rendered text.  Two fields that pretty-print identically are never merged:
a difference in pyasn1 type, tag category, CHOICE branch or presence is a
genuine divergence even when their display strings coincide.  Omitted DEFAULT
components are reported as schema-injected rather than confused with bytes
that were really transmitted.
"""
from pyasn1.forensics.interpret import iter_fields

__all__ = [
    'compare', 'ORIGINAL_EVIDENCE', 'ENCODING_RECONSTRUCTION',
    'UNDETERMINED',
]

#: Divergence is decided solely by bytes that are present in the substrate.
ORIGINAL_EVIDENCE = 'original-evidence'
#: Both interpretations re-encode to the substrate; difference is schema meaning.
ENCODING_RECONSTRUCTION = 'encoding-reconstruction'
#: An open/ANY field cannot be resolved from the supplied schemas.
UNDETERMINED = 'undetermined'

# Presence states that describe a field with no TLV on the wire.
_ABSENT_STATES = frozenset(('absent-optional', 'default-injected'))


def _index_by_raw_path(fields):
    index = {}
    for field in iter_fields(fields):
        if field.raw_path is not None:
            index.setdefault(field.raw_path, []).append(field)
    return index


def _index_by_path(fields):
    return {field.path: field for field in iter_fields(fields)}


def _absent_fields(fields):
    return [field for field in iter_fields(fields)
            if field.presence in _ABSENT_STATES]


def _assigned_identity(field):
    """Schema-assigned identity, deliberately excluding display text."""
    return (
        field.schema_type,
        field.tag_category,
        tuple(tuple(sorted(tag.items())) for tag in field.tag.to_dict()),
        field.choice_branch,
        field.unresolved,
    )


def _value_identity(field):
    if field.value is None:
        return None
    data = field.value.to_dict()
    # Compare the structured value, not prettyPrint text.
    return (data.get('kind'), data.get('value'))


def _pair_summary(field):
    if field is None:
        return None
    return {
        'path': field.path,
        'fieldName': field.name,
        'schemaType': field.schema_type,
        'tagCategory': field.tag_category,
        'assignedTag': field.tag.to_dict(),
        'presence': field.presence,
        'choiceBranch': field.choice_branch,
        'unresolvedAny': field.unresolved,
        'value': field.value.to_dict() if field.value is not None else None,
        'defaultValue': field.default_value,
        'rawPath': field.raw_path,
        'rawTlvHex': field.raw_hex,
    }


def _make_finding(kind, reason, evidence, left, right, detail=None):
    finding = {
        'kind': kind,
        'reason': reason,
        'evidenceSource': evidence,
        'left': _pair_summary(left),
        'right': _pair_summary(right),
    }
    if detail:
        finding['detail'] = detail
    return finding


def _unresolved_raw_paths(fields):
    """Raw paths of ANY fields a schema left unresolved, with their subtrees.

    Nested TLVs inside an unresolved ANY are not claimed by that schema, so a
    peer that *does* resolve them must not be reported as owning extra fields.
    """
    unresolved = set()
    for field in iter_fields(fields):
        if field.unresolved and field.raw_path is not None:
            unresolved.add(field.raw_path)
    return unresolved


def _is_beneath(path, roots):
    """True when *path* is a strict descendant of any unresolved root."""
    return any(path.startswith(root + '.') for root in roots)


def compare(left, right, raw_root=None, re_encoder=None, substrate=None):
    """Compare two :class:`Interpretation` objects over one substrate.

    Returns a structured report.  Every finding names the schema on each side,
    the shared raw TLV (or its absence), and which kind of evidence supports
    the conclusion: original bytes, an encoding reconstruction, or an
    undetermined open type.

    When *re_encoder* and *substrate* are supplied, each successful
    interpretation is re-encoded and checked against the original bytes.  Both
    schemas reconstructing the identical substrate proves that a meaning
    divergence is assigned by the schema rather than carried by the bytes.
    """
    findings = []
    left_name, right_name = left.schema_name, right.schema_name

    if left.decode_error or right.decode_error:
        for side in (left, right):
            if side.decode_error:
                findings.append({
                    'kind': 'decode-failure',
                    'reason': 'Schema %r rejected the substrate'
                    % side.schema_name,
                    'evidenceSource': UNDETERMINED,
                    'failingSchema': side.schema_name,
                    'error': side.decode_error,
                })
        return _report(left_name, right_name, findings, raw_root)

    left_raw = _index_by_raw_path(left.fields)
    right_raw = _index_by_raw_path(right.fields)
    left_unresolved = _unresolved_raw_paths(left.fields)
    right_unresolved = _unresolved_raw_paths(right.fields)
    shared_raw_paths = sorted(set(left_raw) | set(right_raw))

    for raw_path in shared_raw_paths:
        # TLVs inside an unresolved ANY are covered by the open-type finding;
        # do not double-count their nested structure as missing fields.
        if _is_beneath(raw_path, left_unresolved) or \
                _is_beneath(raw_path, right_unresolved):
            continue
        left_fields = left_raw.get(raw_path, [])
        right_fields = right_raw.get(raw_path, [])
        left_field = left_fields[0] if left_fields else None
        right_field = right_fields[0] if right_fields else None
        findings.extend(_compare_present(
            raw_path, left_field, right_field))

    findings.extend(_compare_absent(left.fields, right.fields))
    reconstruction = _reconstruction(left, right, re_encoder, substrate)
    _apply_reconstruction(findings, reconstruction)
    return _report(left_name, right_name, findings, raw_root,
                   reconstruction)


def _reconstruction(left, right, re_encoder, substrate):
    if re_encoder is None or substrate is None:
        return None
    result = {}
    for interpretation in (left, right):
        if interpretation.decoded is None:
            result[interpretation.schema_name] = None
            continue
        try:
            encoded = re_encoder(interpretation.decoded)
            result[interpretation.schema_name] = {
                'matchesSubstrate': bytes(encoded) == bytes(substrate),
                'encodedHex': bytes(encoded).hex(),
            }
        except Exception as exc:
            result[interpretation.schema_name] = {
                'matchesSubstrate': False,
                'error': str(exc),
            }
    return result


def _apply_reconstruction(findings, reconstruction):
    if not reconstruction:
        return
    both_match = all(
        entry and entry.get('matchesSubstrate')
        for entry in reconstruction.values())
    for finding in findings:
        if finding['kind'] == 'schema-meaning-divergence' and \
                finding['evidenceSource'] == ORIGINAL_EVIDENCE:
            finding['reconstruction'] = reconstruction
            if both_match:
                finding['evidenceSource'] = ENCODING_RECONSTRUCTION
                finding['reason'] += '; both schemas re-encode to the ' \
                    'identical substrate, so the divergence is schema-assigned'
        elif finding['kind'] == 'schema-meaning-divergence':
            finding['reconstruction'] = reconstruction


def _compare_present(raw_path, left, right):
    findings = []
    if left is None or right is None:
        present = left or right
        findings.append(_make_finding(
            'field-only-on-one-side',
            'Raw TLV %s is claimed by only one schema' % raw_path,
            ORIGINAL_EVIDENCE, left, right))
        return findings

    if _assigned_identity(left) != _assigned_identity(right):
        same_text = _display_text(left) == _display_text(right)
        reason = 'Schema-assigned type/tag/branch differs for TLV %s' % \
            raw_path
        if same_text:
            reason += ' even though rendered text is identical'
        open_split = left.unresolved or right.unresolved
        findings.append(_make_finding(
            'schema-meaning-divergence', reason,
            UNDETERMINED if open_split else ORIGINAL_EVIDENCE,
            left, right, {'sameDisplayText': same_text}))
    elif _value_identity(left) != _value_identity(right):
        findings.append(_make_finding(
            'value-divergence',
            'Structured value differs for TLV %s' % raw_path,
            ORIGINAL_EVIDENCE, left, right))

    if left.unresolved or right.unresolved:
        unresolved_side = left if left.unresolved else right
        resolved_side = right if left.unresolved else left
        findings.append(_make_finding(
            'open-type-undetermined',
            'ANY/open type at TLV %s is left untyped by one schema but '
            'resolved to %r by the other; the untyped side keeps the raw '
            'TLV and never guesses its inner meaning'
            % (raw_path, resolved_side.schema_type),
            UNDETERMINED, left, right,
            {'unresolvedSchema': _schema_name(left, right, unresolved_side),
             'resolvedSchema': _schema_name(left, right, resolved_side)}))
    return findings


def _schema_name(left, right, field):
    # Field evidence does not carry its owning schema; the caller labels the
    # sides through the report, so return a positional marker here.
    return 'left' if field is left else 'right'


def _compare_absent(left_fields, right_fields):
    findings = []
    left_absent = {f.path: f for f in _absent_fields(left_fields)}
    right_absent = {f.path: f for f in _absent_fields(right_fields)}
    left_all = _index_by_path(left_fields)
    right_all = _index_by_path(right_fields)

    for path in sorted(set(left_absent) | set(right_absent)):
        left_field = left_all.get(path)
        right_field = right_all.get(path)
        left_is_absent = path in left_absent
        right_is_absent = path in right_absent
        if left_is_absent and right_is_absent:
            if left_field.presence != right_field.presence:
                # One schema injects a DEFAULT, the other declares OPTIONAL:
                # neither has a TLV, but the effective value treatment differs.
                findings.append(_make_finding(
                    'presence-divergence',
                    'Field %r is absent from the wire in both schemas but is '
                    '%r under one and %r under the other; an omitted '
                    'DEFAULT/OPTIONAL is not an on-wire TLV'
                    % (path, left_field.presence, right_field.presence),
                    ORIGINAL_EVIDENCE, left_field, right_field))
            elif (left_field.default_value or None) != \
                    (right_field.default_value or None):
                findings.append(_make_finding(
                    'default-value-divergence',
                    'Field %r is absent from the wire in both schemas but '
                    'the injected defaults differ' % path,
                    ENCODING_RECONSTRUCTION, left_field, right_field))
            continue
        findings.append(_make_finding(
            'presence-divergence',
            'Field %r is %s on one side but %s on the other; an omitted '
            'DEFAULT/OPTIONAL is not an on-wire TLV'
            % (path,
               left_field.presence if left_field else 'missing',
               right_field.presence if right_field else 'missing'),
            ORIGINAL_EVIDENCE, left_field, right_field))
    return findings


def _display_text(field):
    if field.value is None:
        return None
    return field.value.to_dict().get('value')


def _report(left_name, right_name, findings, raw_root, reconstruction=None):
    return {
        'leftSchema': left_name,
        'rightSchema': right_name,
        'rawRootPath': raw_root.path if raw_root is not None else None,
        'findingCount': len(findings),
        'divergent': bool(findings),
        'reconstruction': reconstruction,
        'findings': findings,
        'findingKinds': [f['kind'] for f in findings],
    }


def _present_value_map(fields):
    """Map logical field path -> structured value for present scalar leaves.

    Only on-wire scalar values participate: construction (container class,
    implicit/explicit wrapping, internal pyasn1 ``typeId``) is deliberately
    excluded, so two semantically equal messages built differently compare
    equal here.
    """
    values = {}
    for field in iter_fields(fields):
        if field.value is None or field.presence in _ABSENT_STATES or \
                field.unresolved:
            continue
        values[field.path] = _value_identity(field)
    return values


def semantic_equivalence(left, right, value_paths=None, left_raw_root=None,
                         right_raw_root=None):
    """Compare decoded *meaning* independently of object construction.

    Returns a report that separates value-level agreement from structural
    construction differences.  Two messages that carry identical scalar
    values through different containers, tag wrapping or pyasn1 subclasses
    (different internal ``typeId``) are reported as semantically equivalent,
    so an internal ``typeId`` difference is never mistaken for a permission
    change.

    Parameters
    ----------
    left, right: :class:`Interpretation`
        Interpretations, potentially of different (but value-equivalent)
        substrates.
    value_paths: optional iterable of :class:`str`
        If given, restrict the value comparison to these dotted paths (e.g.
        the permission-bearing fields).  Otherwise every scalar leaf is used.
    left_raw_root, right_raw_root: optional :class:`RawNode`
        Root TLVs used to surface container-level construction differences
        (e.g. SEQUENCE tag 16 versus SET tag 17).
    """
    left_values = _present_value_map(left.fields)
    right_values = _present_value_map(right.fields)

    if value_paths is not None:
        wanted = frozenset(value_paths)
        left_values = {p: v for p, v in left_values.items() if p in wanted}
        right_values = {p: v for p, v in right_values.items() if p in wanted}

    changed = []
    for path in sorted(set(left_values) & set(right_values)):
        if left_values[path] != right_values[path]:
            changed.append({
                'path': path,
                'leftValue': left_values[path],
                'rightValue': right_values[path],
            })
    only_left = sorted(set(left_values) - set(right_values))
    only_right = sorted(set(right_values) - set(left_values))

    construction = {
        'leftRootType': _root_type(left),
        'rightRootType': _root_type(right),
        'leftRootTag': _root_tag(left_raw_root),
        'rightRootTag': _root_tag(right_raw_root),
        'constructionDiffers': _construction_signature(
            left, left_raw_root) != _construction_signature(
                right, right_raw_root),
    }
    equivalent = not changed and not only_left and not only_right
    return {
        'semanticallyEquivalent': equivalent,
        'valuePathsCompared': sorted(set(left_values) | set(right_values)),
        'changedValues': changed,
        'onlyOnLeft': only_left,
        'onlyOnRight': only_right,
        'construction': construction,
        'note': 'Compares decoded scalar values, not container class, tag '
                'wrapping or internal typeId; a typeId difference alone is '
                'not a permission change.',
    }


def _root_type(interpretation):
    if not interpretation.fields:
        return None
    return interpretation.fields[0].schema_type


def _root_tag(raw_root):
    if raw_root is None:
        return None
    return {
        'tagClass': raw_root.tag_class_name,
        'tagNumber': raw_root.tag_number,
        'constructed': raw_root.constructed,
    }


def _construction_signature(interpretation, raw_root=None):
    signature = [('__root__', _root_tag(raw_root))]
    for field in iter_fields(interpretation.fields):
        signature.append((
            field.path,
            field.schema_type,
            field.tag_category,
            tuple(tag['tagNumber'] for tag in field.tag.to_dict()),
        ))
    return tuple(signature)
