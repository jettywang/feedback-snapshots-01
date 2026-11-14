#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""RFC 7508 SecureHeaderFields verification for archived messages.

The archive backend is assumed to have already verified the S/MIME
signature.  This module compares the SecureHeaderFields signed
attribute (id-aa-secureHeaderFieldsIdentifier) against the raw
headers of the archived message and reports which displayed header
fields are actually authenticated, which were legitimately changed
in transit, and which cannot be confirmed.

Analysis is strictly read-only: the archived message is never
modified.
"""

import argparse
import base64
import binascii
import json
import re
import sys

from dataclasses import dataclass
from dataclasses import field

from pyasn1.codec.der.decoder import decode as der_decoder

from pyasn1_modules import pem
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc7508

ALGORITHM_SIMPLE = 0
ALGORITHM_RELAXED = 1

ALGORITHM_NAMES = {
    ALGORITHM_SIMPLE: 'simple',
    ALGORITHM_RELAXED: 'relaxed',
}

STATUS_NAMES = {
    0: 'duplicated',
    1: 'deleted',
    2: 'modified',
}

CONFIRMED = 'confirmed'
RESTORED = 'restored'
ABSENT_AS_EXPECTED = 'absent-as-expected'
EXPECTED_DIFFERENCE = 'expected-difference'
CHANGED = 'changed'
MISSING = 'missing'
UNEXPECTED_VALUE = 'unexpected-value'
UNCONFIRMED = 'unconfirmed'

FAILURE_OUTCOMES = frozenset((CHANGED, MISSING, UNEXPECTED_VALUE))
DOCUMENTED_DIFFERENCE_OUTCOMES = frozenset(
    (EXPECTED_DIFFERENCE, ABSENT_AS_EXPECTED))

VERDICT_VALID = 'valid'
VERDICT_VALID_WITH_DIFFERENCES = 'valid-with-documented-differences'
VERDICT_INVALID = 'invalid-headers'
VERDICT_UNCONFIRMED = 'unconfirmed'

DEFAULT_MANDATORY = (
    'from', 'sender', 'reply-to', 'to', 'cc',
    'subject', 'date', 'message-id',
)

_MAX_ALIGN_GROUP = 8


def canon_simple_value(value):
    """RFC 6376 3.4.1 "simple": the value is used exactly as is."""
    return value


def canon_relaxed_value(value):
    """RFC 6376 3.4.2 "relaxed": unfold, compress WSP, trim WSP."""
    value = re.sub(r'\r?\n(?=[ \t])', '', value)
    value = re.sub(r'[ \t]+', ' ', value)
    return value.strip(' \t')


CANON_VALUE = {
    ALGORITHM_SIMPLE: canon_simple_value,
    ALGORITHM_RELAXED: canon_relaxed_value,
}


@dataclass
class SecuredEntry:
    name: str
    value: str
    status: str
    position: int


@dataclass
class EntryResult:
    entry: SecuredEntry
    outcome: str
    received_value: str = None
    detail: str = ''


@dataclass
class VerificationReport:
    algorithm: str
    entries: list = field(default_factory=list)
    extra_headers: list = field(default_factory=list)
    unsecured_displayed: list = field(default_factory=list)
    verdict: str = VERDICT_UNCONFIRMED

    def to_dict(self):
        return {
            'algorithm': self.algorithm,
            'verdict': self.verdict,
            'entries': [
                {
                    'position': r.entry.position,
                    'name': r.entry.name,
                    'status': r.entry.status,
                    'secured_value': r.entry.value,
                    'received_value': r.received_value,
                    'outcome': r.outcome,
                    'detail': r.detail,
                }
                for r in self.entries
            ],
            'extra_headers': [
                {'name': n, 'value': v} for n, v in self.extra_headers
            ],
            'unsecured_displayed': self.unsecured_displayed,
        }


def split_head_body(data):
    idx = data.find(b'\r\n\r\n')
    if idx >= 0:
        return data[:idx], data[idx + 4:]
    idx = data.find(b'\n\n')
    if idx >= 0:
        return data[:idx], data[idx + 2:]
    return data, b''


def parse_headers(data):
    """Parse raw message headers, preserving order, duplicates, folding."""
    head, _ = split_head_body(data)
    text = head.decode('utf-8', 'surrogateescape')
    eol = '\r\n' if '\r\n' in text else '\n'
    headers = []
    for raw_line in text.split(eol):
        if not raw_line:
            continue
        if raw_line[0] in ' \t':
            if headers:
                name, value = headers[-1]
                headers[-1] = (name, value + eol + raw_line)
            continue
        name, sep, value = raw_line.partition(':')
        if not sep:
            continue
        headers.append((name.strip(), value))
    return headers


def _best_matchings(secured_vals, received_vals):
    best_score = [-1]
    best_pairs = []

    def rec(i, j, score, pairs):
        if i == len(secured_vals) or j == len(received_vals):
            if score > best_score[0]:
                best_score[0] = score
                del best_pairs[:]
                best_pairs.append(dict(pairs))
            elif score == best_score[0]:
                best_pairs.append(dict(pairs))
            return
        rec(i + 1, j, score, pairs)
        rec(i, j + 1, score, pairs)
        pairs[i] = j
        rec(i + 1, j + 1,
            score + (1 if secured_vals[i] == received_vals[j] else 0),
            pairs)
        del pairs[i]

    rec(0, 0, 0, {})
    return best_pairs


def _align(group, received_group, canon_value):
    """Pair secured entries with received headers of the same name.

    Returns (aligned, extras) where aligned maps each secured index to
    (received_index_or_None, ambiguous).  Order is preserved; when the
    counts differ, value-based monotone alignment is used and any
    correspondence that cannot be established uniquely is reported as
    ambiguous instead of being guessed.
    """
    m, n = len(group), len(received_group)
    if m == n:
        return {i: (i, False) for i in range(m)}, set()
    if n == 0:
        return {i: (None, False) for i in range(m)}, set()
    if max(m, n) > _MAX_ALIGN_GROUP:
        return {i: (None, True) for i in range(m)}, set()

    secured_vals = [canon_value(e.value) for e in group]
    received_vals = [canon_value(v) for _, v in received_group]
    matchings = _best_matchings(secured_vals, received_vals)

    aligned = {}
    used = set()
    for i in range(m):
        values = set()
        for matching in matchings:
            j = matching.get(i)
            values.add(None if j is None else received_vals[j])
        if len(values) > 1:
            aligned[i] = (None, True)
        else:
            j = matchings[0].get(i)
            aligned[i] = (j, False)
            if j is not None:
                used.add(j)

    if any(amb for _, amb in aligned.values()):
        return aligned, set()

    extras = set(range(n)) - used
    return aligned, extras


def _classify(status, secured_val, received_val):
    if status is None:
        return UNCONFIRMED
    if received_val is None:
        if status == 'deleted':
            return ABSENT_AS_EXPECTED
        return MISSING
    if secured_val == received_val:
        return CONFIRMED if status == 'duplicated' else RESTORED
    if status == 'modified':
        return EXPECTED_DIFFERENCE
    if status == 'deleted':
        return UNEXPECTED_VALUE
    return CHANGED


def verify_secure_headers(secured_entries, algorithm, received_headers,
                          mandatory=DEFAULT_MANDATORY, shared_policy=True):
    canon_value = CANON_VALUE.get(algorithm)
    report = VerificationReport(
        algorithm=ALGORITHM_NAMES.get(algorithm, 'unknown'))

    secured_by_name = {}
    for entry in secured_entries:
        secured_by_name.setdefault(entry.name.lower(), []).append(entry)

    received_by_name = {}
    for name, value in received_headers:
        received_by_name.setdefault(name.lower(), []).append((name, value))

    for lname in secured_by_name:
        group = secured_by_name[lname]
        received_group = received_by_name.get(lname, [])

        if canon_value is None:
            for entry in group:
                report.entries.append(EntryResult(
                    entry, UNCONFIRMED,
                    detail='unknown canonicalization algorithm'))
            continue

        aligned, extras = _align(group, received_group, canon_value)

        for idx, entry in enumerate(group):
            ridx, ambiguous = aligned[idx]
            if ambiguous:
                report.entries.append(EntryResult(
                    entry, UNCONFIRMED,
                    detail='ambiguous correspondence among duplicated '
                           'headers'))
                continue
            if entry.status is None:
                report.entries.append(EntryResult(
                    entry, UNCONFIRMED,
                    detail='unknown field-Status value'))
                continue
            received_val = None
            raw_received = None
            if ridx is not None:
                raw_received = received_group[ridx][1]
                received_val = canon_value(raw_received)
            outcome = _classify(
                entry.status, canon_value(entry.value), received_val)
            report.entries.append(EntryResult(
                entry, outcome, received_value=raw_received))

        if shared_policy:
            for ridx in sorted(extras):
                report.extra_headers.append(received_group[ridx])

    mandatory = {n.lower() for n in mandatory}
    report.unsecured_displayed = sorted(
        n for n in received_by_name
        if n in mandatory and n not in secured_by_name)

    outcomes = [r.outcome for r in report.entries]
    if (any(o in FAILURE_OUTCOMES for o in outcomes)
            or report.extra_headers):
        report.verdict = VERDICT_INVALID
    elif any(o == UNCONFIRMED for o in outcomes):
        report.verdict = VERDICT_UNCONFIRMED
    elif any(o in DOCUMENTED_DIFFERENCE_OUTCOMES for o in outcomes):
        report.verdict = VERDICT_VALID_WITH_DIFFERENCES
    else:
        report.verdict = VERDICT_VALID

    return report


def entries_from_attribute(shf):
    algorithm = int(shf['canonAlgorithm'])
    entries = []
    for pos, hf in enumerate(shf['secHeaderFields']):
        entries.append(SecuredEntry(
            name=str(hf['field-Name']),
            value=str(hf['field-Value']),
            status=STATUS_NAMES.get(int(hf['field-Status'])),
            position=pos))
    return algorithm, entries


def _read_der(path):
    with open(path, 'rb') as f:
        data = f.read()
    try:
        return pem.readBase64fromText(data.decode('ascii'))
    except Exception:
        pass
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return data


def load_attribute_file(path):
    substrate = _read_der(path)
    shf, rest = der_decoder(substrate, asn1Spec=rfc7508.SecureHeaderFields())
    if rest:
        raise ValueError('trailing data after SecureHeaderFields')
    return shf


def extract_attribute_from_cms(path):
    substrate = _read_der(path)
    content_info, _ = der_decoder(substrate, asn1Spec=rfc5652.ContentInfo())
    if content_info['contentType'] != rfc5652.id_signedData:
        raise ValueError('CMS content is not SignedData')
    signed_data, _ = der_decoder(
        content_info['content'], asn1Spec=rfc5652.SignedData())
    for signer_info in signed_data['signerInfos']:
        for attr in signer_info['signedAttrs']:
            if attr['attrType'] == rfc7508.id_aa_secureHeaderFieldsIdentifier:
                shf, _ = der_decoder(
                    attr['attrValues'][0],
                    asn1Spec=rfc7508.SecureHeaderFields())
                return shf
    raise ValueError('no SecureHeaderFields attribute in signedAttrs')


_OUTCOME_MARKS = {
    CONFIRMED: 'OK',
    RESTORED: 'OK',
    ABSENT_AS_EXPECTED: 'OK',
    EXPECTED_DIFFERENCE: '~~',
    CHANGED: '!!',
    MISSING: '!!',
    UNEXPECTED_VALUE: '!!',
    UNCONFIRMED: '??',
}


def format_report(report, source=''):
    lines = []
    lines.append('SecureHeaderFields verification report')
    if source:
        lines.append('  message: %s' % source)
    lines.append('  canonicalization: %s' % report.algorithm)
    for r in report.entries:
        mark = _OUTCOME_MARKS.get(r.outcome, '??')
        lines.append('  [%s] #%d %s (status: %s): %s' % (
            mark, r.entry.position, r.entry.name,
            r.entry.status or 'unknown', r.outcome))
        lines.append('       secured : %r' % r.entry.value)
        if r.received_value is not None:
            lines.append('       received: %r' % r.received_value)
        if r.detail:
            lines.append('       detail  : %s' % r.detail)
    for name, value in report.extra_headers:
        lines.append('  [!!] extra header with secured name: '
                     '%s: %s' % (name, value.strip()))
    if report.unsecured_displayed:
        lines.append('  [??] displayed but NOT secured: %s'
                     % ', '.join(report.unsecured_displayed))
    lines.append('  verdict: %s' % report.verdict)
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Compare a verified RFC 7508 SecureHeaderFields '
                    'attribute against the raw headers of an archived '
                    'message (read-only).')
    parser.add_argument('message', help='archived message file (.eml)')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        '--attribute',
        help='DER-encoded SecureHeaderFields (PEM/base64/raw)')
    source.add_argument(
        '--cms',
        help='CMS ContentInfo (PEM/DER) whose signature was already '
             'verified; the attribute is extracted from signedAttrs')
    parser.add_argument(
        '--mandatory', default=','.join(DEFAULT_MANDATORY),
        help='comma-separated header names the UI displays and the '
             'policy requires to be secured')
    parser.add_argument(
        '--no-shared-policy', action='store_true',
        help='skip the added-header check (RFC 7508 4.5.2 step 6)')
    parser.add_argument('--json', action='store_true',
                        help='emit JSON instead of text')
    args = parser.parse_args(argv)

    if args.attribute:
        shf = load_attribute_file(args.attribute)
    else:
        shf = extract_attribute_from_cms(args.cms)

    algorithm, entries = entries_from_attribute(shf)

    with open(args.message, 'rb') as f:
        received_headers = parse_headers(f.read())

    mandatory = [n.strip() for n in args.mandatory.split(',') if n.strip()]
    report = verify_secure_headers(
        entries, algorithm, received_headers, mandatory=mandatory,
        shared_policy=not args.no_shared_policy)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report, source=args.message))

    if report.verdict == VERDICT_INVALID:
        return 1
    if report.verdict == VERDICT_UNCONFIRMED:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
