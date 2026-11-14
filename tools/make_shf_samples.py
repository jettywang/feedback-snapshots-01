#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Generate the RFC 7508 SecureHeaderFields sample set.

Each sample consists of an archived (received) message ``NN-name.eml``
and the DER-encoded SecureHeaderFields attribute ``NN-name.shf.b64``
that a verified S/MIME signature carried for it.  The attribute is
built from the *original* headers, exactly as the signing MUA would
have produced it (RFC 7508 4.5.1).  Samples are deterministic and are
used by tests/test_secure_header_verify.py and by the investigator
report in tools/shf_samples/REPORT.md.
"""

import base64
import os

from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import rfc7508

import secure_header_verify as shv

CRLF = '\r\n'

BODY = 'Please see the attached report.' + CRLF

STATUS_BY_NAME = {
    'x-confidential-note': 'modified',
    'x-internal-tag': 'deleted',
}


def build_attribute(original_head, algorithm=shv.ALGORITHM_RELAXED):
    canon = shv.CANON_VALUE[algorithm]
    headers = shv.parse_headers(original_head.encode('utf-8'))
    shf = rfc7508.SecureHeaderFields()
    shf['canonAlgorithm'] = algorithm
    fields = rfc7508.HeaderFields()
    for idx, (name, value) in enumerate(headers):
        hf = rfc7508.HeaderField()
        hf['field-Name'] = name
        hf['field-Value'] = canon(value)
        status = STATUS_BY_NAME.get(name.lower(), 'duplicated')
        if status != 'duplicated':
            hf['field-Status'] = status
        fields[idx] = hf
    shf['secHeaderFields'] = fields
    return der_encoder(shf)


def message(head):
    return head + CRLF + BODY


SAMPLES = {}


SAMPLES['01-duplicate-from'] = dict(
    original=(
        'From: alice@example.com' + CRLF +
        'From: bob@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Q2 planning' + CRLF +
        'Date: Sat, 14 Nov 2026 10:00:00 +0000' + CRLF +
        'Message-ID: <m1@example.com>' + CRLF
    ),
    received=(
        'From: alice@example.com' + CRLF +
        'From: bob@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Q2 planning' + CRLF +
        'Date: Sat, 14 Nov 2026 10:00:00 +0000' + CRLF +
        'Message-ID: <m1@example.com>' + CRLF
    ),
)


SAMPLES['02-folded-subject'] = dict(
    original=(
        'From: alice@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Quarterly results and' + CRLF +
        ' roadmap discussion' + CRLF +
        'Date: Sat, 14 Nov 2026 10:05:00 +0000' + CRLF +
        'Message-ID: <m2@example.com>' + CRLF
    ),
    received=(
        'From: alice@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Quarterly' + CRLF +
        '\tresults  and   roadmap' + CRLF +
        ' discussion' + CRLF +
        'Date: Sat, 14 Nov 2026 10:05:00 +0000' + CRLF +
        'Message-ID: <m2@example.com>' + CRLF
    ),
)


SAMPLES['03-relay-modified'] = dict(
    original=(
        'From: alice@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Launch plan' + CRLF +
        'Date: Sat, 14 Nov 2026 10:10:00 +0000' + CRLF +
        'Message-ID: <m3@example.com>' + CRLF +
        'X-Confidential-Note: Project NIGHTINGALE budget' + CRLF +
        'X-Internal-Tag: secret-42' + CRLF
    ),
    received=(
        'Received: from mx1.example.com by archive.example.com;' + CRLF +
        ' Sat, 14 Nov 2026 10:12:03 +0000' + CRLF +
        'Received: from mail.example.com by mx1.example.com;' + CRLF +
        ' Sat, 14 Nov 2026 10:11:58 +0000' + CRLF +
        'From: alice@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Launch' + CRLF +
        '  plan' + CRLF +
        'Date: Sat, 14 Nov 2026 10:10:00 +0000' + CRLF +
        'Message-ID: <m3@example.com>' + CRLF +
        'X-Spam-Score: 0.1' + CRLF +
        'X-Confidential-Note: *** replaced by DCA ***' + CRLF
    ),
)


SAMPLES['04-attacker-inserted'] = dict(
    original=(
        'From: alice@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Subject: Wire transfer details' + CRLF +
        'Date: Sat, 14 Nov 2026 10:15:00 +0000' + CRLF +
        'Message-ID: <m4@example.com>' + CRLF
    ),
    received=(
        'From: "CEO" <ceo@example.com>' + CRLF +
        'From: alice@example.com' + CRLF +
        'To: carol@example.com' + CRLF +
        'Reply-To: attacker@evil.example' + CRLF +
        'Subject: Wire transfer details' + CRLF +
        'Date: Sat, 14 Nov 2026 10:15:00 +0000' + CRLF +
        'Message-ID: <m4@example.com>' + CRLF
    ),
)


def write_samples(outdir):
    os.makedirs(outdir, exist_ok=True)
    written = []
    for name, spec in sorted(SAMPLES.items()):
        eml_path = os.path.join(outdir, name + '.eml')
        attr_path = os.path.join(outdir, name + '.shf.b64')
        with open(eml_path, 'w', encoding='utf-8', newline='') as f:
            f.write(message(spec['received']))
        der = build_attribute(spec['original'])
        with open(attr_path, 'w', encoding='ascii') as f:
            f.write(base64.encodebytes(der).decode('ascii'))
        written.append((eml_path, attr_path))
    return written


if __name__ == '__main__':
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'shf_samples')
    for eml_path, attr_path in write_samples(outdir):
        print('wrote %s' % eml_path)
        print('wrote %s' % attr_path)
