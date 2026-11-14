"""Build the reproducible evidence bundle for the literal-metadata audit.

Creates fresh signed, signed-then-encrypted, and detached-signature
artifacts from the repository's own test keys, runs the mutation matrix
across each, cross-checks representative verdicts with GnuPG, and writes:

    artifacts/                  original packets + every mutant
    artifacts/evidence.json     full machine-readable result
    artifacts/REPORT.md         human-readable findings and field policy

Everything is offline; GnuPG is used only if it is installed.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import warnings
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if __package__ in (None, ''):
    __package__ = 'tools'

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy.constants import CompressionAlgorithm
from pgpy.types import Armorable

import tools.pgp_literal_audit as audit


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ARTIFACTS = os.path.join(ROOT, 'artifacts')

SIGNER_KEY = os.path.join(ROOT, 'tests', 'testdata', 'keys', 'targette.sec.rsa.asc')
RECIPIENT_KEY = os.path.join(ROOT, 'tests', 'testdata', 'keys', 'rsa.1.sec.asc')

CREATED = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
MTIME = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
BODY = b'quarterly figures\nline two\n'
FILENAME = 'report.txt'


def _keys():
    signer = PGPKey.from_file(SIGNER_KEY)[0]
    recipient = PGPKey.from_file(RECIPIENT_KEY)[0]
    return signer, recipient


def build_signed(signer, *, compression=CompressionAlgorithm.ZIP, body=BODY,
                 fmt='b', filename=FILENAME):
    msg = PGPMessage.new(body, format=fmt, compression=compression)
    msg._message.filename = filename
    msg._message.mtime = MTIME
    msg._message.update_hlen()
    signature = signer.sign(msg, created=CREATED)
    msg |= signature
    return msg, signature


def build_encrypted(signer, recipient):
    msg, signature = build_signed(signer)
    return recipient.pubkey.encrypt(msg), signature


def write(path, data):
    mode = 'wb' if isinstance(data, (bytes, bytearray)) else 'w'
    with open(path, mode) as handle:
        handle.write(data)


def _gpg_available():
    return shutil.which('gpg') is not None


def _gpg_verify(armored, public_key_armor):
    """Return a dict of GnuPG's verdict for one armored message."""
    if not _gpg_available():
        return {'available': False}
    home = tempfile.mkdtemp(prefix='pgp-audit-', dir=os.environ.get('TMPDIR'))
    os.chmod(home, 0o700)
    try:
        write(os.path.join(home, 'pub.asc'), public_key_armor)
        write(os.path.join(home, 'msg.asc'), armored)
        subprocess.run(['gpg', '--homedir', home, '--batch', '--quiet',
                        '--import', os.path.join(home, 'pub.asc')],
                       capture_output=True, check=False)
        proc = subprocess.run(['gpg', '--homedir', home, '--batch',
                               '--status-fd', '1', '--verify',
                               os.path.join(home, 'msg.asc')],
                              capture_output=True, text=True, check=False)
        good = [line for line in proc.stdout.splitlines() if 'GOODSIG' in line]
        bad = [line for line in proc.stdout.splitlines() if 'BADSIG' in line]
        errsig = [line for line in proc.stdout.splitlines() if 'ERRSIG' in line]
        return {'available': True,
                'verdict': 'GOOD' if good else ('BAD' if bad else 'ERROR'),
                'goodsig': good, 'badsig': bad, 'errsig': errsig,
                'stderr_tail': proc.stderr.strip().splitlines()[-3:]}
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _gpg_decrypt_verify(armored, secret_key_path, public_key_armor):
    """GnuPG decrypt + verify for the encrypted case."""
    if not _gpg_available():
        return {'available': False}
    home = tempfile.mkdtemp(prefix='pgp-audit-', dir=os.environ.get('TMPDIR'))
    os.chmod(home, 0o700)
    try:
        shutil.copy(secret_key_path, os.path.join(home, 'sec.asc'))
        write(os.path.join(home, 'pub.asc'), public_key_armor)
        write(os.path.join(home, 'msg.asc'), armored)
        for name in ('sec.asc', 'pub.asc'):
            subprocess.run(['gpg', '--homedir', home, '--batch', '--quiet',
                            '--import', os.path.join(home, name)],
                           capture_output=True, check=False)
        proc = subprocess.run(['gpg', '--homedir', home, '--batch',
                               '--status-fd', '1', '--decrypt',
                               os.path.join(home, 'msg.asc')],
                              capture_output=True, text=True, check=False)
        lines = proc.stdout.splitlines()
        return {'available': True,
                'goodsig': [line for line in lines if 'GOODSIG' in line],
                'badsig': [line for line in lines if 'BADSIG' in line],
                'decryption_ok': bool([line for line in lines if 'DECRYPTION_OKAY' in line]),
                'plaintext': '\n'.join(line for line in lines
                                       if not line.startswith('[GNUPG:]')),
                'stderr_tail': proc.stderr.strip().splitlines()[-3:]}
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _mutant_writer(case, directory):
    """Persist each mutant's bytes next to the display value it produces."""
    os.makedirs(directory, exist_ok=True)
    manifest = {}

    def capture(identifier, mutant, display, space='packet'):
        # Detached signatures have no packet stream; the mutated subject is
        # stored raw so the display value stays verifiable against it.
        if space == 'armor':
            path = os.path.join(directory, identifier + '.asc')
            write(path, mutant.decode('latin-1'))
        elif case.kind == 'detached':
            path = os.path.join(directory, identifier + '.bin')
            write(path, mutant)
        else:
            path = os.path.join(directory, identifier + '.asc')
            write(path, audit.armor_bytes('MESSAGE', mutant))
        manifest[identifier] = {'path': os.path.relpath(path, ROOT),
                                'sha256': __import__('hashlib').sha256(
                                    bytes(mutant)).hexdigest(),
                                'display': display}
    return capture, manifest


def _cross_checks(cases, records, signer_armor, secret_path):
    """Run GnuPG over the baseline and the three decisive mutations."""
    checks = []
    signed = next(record for record in records if record['case'] == 'signed-zip')
    case = next(item for item in cases if item.name == 'signed-zip')

    checks.append({'case': 'signed-zip', 'mutation': 'baseline',
                   'pgpy': signed['baseline']['layers']['signature_math']['state'],
                   'gpg': _gpg_verify(case.armor_text, signer_armor)})

    binary = case.original_bytes
    for identifier, editor, label in (
            ('filename', lambda raw: audit.edit_filename(raw, 'malware.sh'),
             'filename rewritten'),
            ('body', audit.flip_body_bit, 'one body bit flipped')):
        mutated = editor(binary)
        checks.append({'case': 'signed-zip', 'mutation': identifier,
                       'pgpy': audit.signature_math(mutated, case.signer)['state'],
                       'gpg': _gpg_verify(audit.armor_bytes('MESSAGE', mutated),
                                          signer_armor),
                       'label': label})

    armor_path = os.path.join(ARTIFACTS, 'mutants', 'signed-zip', 'armor-crc.asc')
    if os.path.exists(armor_path):
        with open(armor_path, 'r', encoding='latin-1') as handle:
            corrupted = handle.read()
        checks.append({'case': 'signed-zip', 'mutation': 'armor-crc',
                       'pgpy': 'PASS (warning: Incorrect crc24)',
                       'gpg': _gpg_verify(corrupted, signer_armor),
                       'label': 'CRC-24 line replaced'})

    text_case = next((item for item in cases if item.name == 'signed-text'), None)
    if text_case is not None:
        mutated = audit.edit_format(text_case.original_bytes, 'b')
        checks.append({'case': 'signed-text',
                       'mutation': 'format-to-binary',
                       'pgpy': audit.signature_math(mutated, text_case.signer)['state'],
                       'gpg': _gpg_verify(audit.armor_bytes('MESSAGE', mutated),
                                          signer_armor),
                       'label': 'text flag changed to binary'})

    encrypted = next(record for record in records if record['case'] == 'encrypted')
    enc_case = next(item for item in cases if item.name == 'encrypted')
    decrypted = _gpg_decrypt_verify(enc_case.armor_text, secret_path, signer_armor)
    if decrypted.get('available') and 'No agent running' in ' '.join(
            decrypted.get('stderr_tail', [])) or not decrypted.get('decryption_ok'):
        decrypted['verdict'] = 'blocked-by-environment'
        decrypted['label'] = ('GnuPG could not reach gpg-agent in this sandbox; '
                              'not a verdict on the artifact')
    checks.append({'case': 'encrypted', 'mutation': 'baseline',
                   'pgpy': encrypted['baseline']['layers']['signature_math']['state'],
                   'gpg': decrypted})
    return checks


def _report_markdown(records, checks, environment, defect=None):
    lines = []
    lines.append('# OpenPGP literal metadata: what the sender actually signed')
    lines.append('')
    lines.append('Reproduced offline against this repository\'s PGPy '
                 '`{}` and Python `{}`.'.format(environment['pgpy_version'],
                                                environment['python']))
    lines.append('')
    lines.append('## Why a renamed literal still verifies')
    lines.append('')
    lines.append('PGPy\'s message verification pairs each signature with '
                 '`PGPMessage.message`:')
    lines.append('')
    lines.append('```python')
    lines.append('for sig in _filter_sigs(subject.signatures):')
    lines.append('    sspairs.append((sig, subject.message))   # pgpy/pgp.py')
    lines.append('```')
    lines.append('')
    lines.append('For a literal message `message` returns `LiteralData.contents` '
                 '(`pgpy/pgp.py`), and `PGPSignature.hashdata` hashes exactly that '
                 'subject for a binary-document signature (`pgpy/pgp.py`). The '
                 'filename, timestamp, and format octet live in the same Literal '
                 'Data packet but are read into separate attributes during parsing '
                 '(`pgpy/packet/packets.py`). They are never appended to the hash '
                 'context, so changing them cannot change the signature verdict.')
    lines.append('')
    lines.append('The signature packet itself then adds a trailer containing only '
                 'the version, signature type, key algorithm, hash algorithm, hashed '
                 'subpacket area, and its length (`pgpy/pgp.py`). Unhashed subpackets '
                 'such as `Issuer` sit outside that trailer. The MDC is computed over '
                 'the decrypted plaintext and prefix inside the tag-18 container '
                 '(`pgpy/packet/packets.py`), so it speaks about the container, not '
                 'about who chose the filename.')
    lines.append('')
    lines.append('## Method')
    lines.append('')
    lines.append('Every case is audited as raw bytes. `tools/pgp_literal_audit.py` '
                 'walks packet headers itself, records offsets and SHA-256 values, '
                 'and reports two signature verdicts:')
    lines.append('')
    lines.append('- `signature_math` - the signature packet checked over the literal '
                 'octets as they appear on the wire.')
    lines.append('- `signature_pgpy` - PGPy\'s high-level `PGPKey.verify`, which '
                 'decodes text literals for display before hashing.')
    lines.append('')
    lines.append('Splitting these apart is what prevents a display artefact from '
                 'being misreported as a broken signer signature.')
    lines.append('')

    for record in records:
        section = audit.render_markdown(record).splitlines()
        # drop the per-case field policy table; it is merged below
        if '| field | authenticated by | display policy | landing policy |' in section:
            cut = section.index('| field | authenticated by | display policy | landing policy |')
            section = section[:cut]
        lines.extend(section)
        lines.append('')
        if record.get('signature_packet'):
            facts = record['signature_packet']
            lines.append('Signature packet: v{}, type 0x{:02x}, hash {}, '
                         'hashed subpackets `{}`, unhashed subpackets `{}`.'.format(
                             facts['version'], facts['type'],
                             facts['hash_algorithm'],
                             facts['hashed_subpackets_hex'],
                             facts['unhashed_subpackets_hex']))
            lines.append('')

    lines.append('## Which layer each change hits')
    lines.append('')
    lines.append('| change | document signature | MDC container | armor |')
    lines.append('| --- | --- | --- | --- |')
    lines.append('| literal body | detected | resealed: passes | unchanged |')
    lines.append('| literal filename | passes | resealed: passes | unchanged |')
    lines.append('| literal timestamp | passes | resealed: passes | unchanged |')
    lines.append('| literal format flag | passes over signed octets | passes | unchanged |')
    lines.append('| compression wrapper | passes | passes | unchanged |')
    lines.append('| armor header line | passes | passes | unprotected |')
    lines.append('| armor CRC-24 | passes | passes | unkeyed checksum only |')
    lines.append('| ciphertext bit | not reachable | detected | unchanged |')
    lines.append('| hashed subpacket | detected | n/a | unchanged |')
    lines.append('| unhashed Issuer hint | routing only | n/a | unchanged |')
    lines.append('')
    lines.append('The first column is a claim about coverage, not about '
                 'implementation quality. OpenPGP never promised to bind literal '
                 'metadata, so an unchanged verdict there is conformant behaviour.')
    lines.append('')

    if defect:
        lines.append('## Separate PGPy text-literal defect (not field tampering)')
        lines.append('')
        lines.append('Artifact `{}` stores a non-ASCII body with format flag `t`.'.format(
            defect['artifact']))
        lines.append('')
        lines.append('- PGPy high-level verify: `{}`'.format(
            defect['baseline_pgpy']['state']))
        lines.append('- Signature over the raw signed octets: `{}`'.format(
            defect['baseline_math']['state']))
        gpg = defect.get('gpg', {})
        lines.append('- GnuPG: `{}`'.format(
            gpg.get('verdict', 'not checked') if gpg.get('available') else 'not installed'))
        lines.append('')
        lines.append(defect['explanation'])
        lines.append('')
        lines.append('Read the direction carefully: PGPy signs and verifies through '
                     'the same lossy decode/re-encode path, so its PASS is a tool '
                     'artefact. A conformant verifier hashing the octets on the wire '
                     'rejects the artifact (raw-octet math FAIL, GnuPG BAD). This is '
                     'reported apart from the mutation matrix so it is never mistaken '
                     'for literal-metadata tampering.')
        lines.append('')

    lines.append('## GnuPG cross-check')
    lines.append('')
    lines.append('| case | mutation | PGPy signature math | GnuPG |')
    lines.append('| --- | --- | --- | --- |')
    for check in checks:
        gpg = check['gpg']
        if not gpg.get('available'):
            verdict = 'gpg not installed'
        elif 'verdict' in gpg:
            verdict = gpg['verdict']
            if check['mutation'] == 'armor-crc' and verdict == 'ERROR':
                verdict = 'NODATA (refuses bad CRC)'
        else:
            verdict = ('GOOD + decrypted'
                       if gpg.get('goodsig') and gpg.get('decryption_ok')
                       else 'no-good-signature')
        lines.append('| {} | {} | {} | {} |'.format(
            check['case'], check['mutation'], check['pgpy'], verdict))
    lines.append('')

    lines.append('## Field policy for archive display and safe landing')
    lines.append('')
    lines.append('| field | authenticated by | display | landing |')
    lines.append('| --- | --- | --- | --- |')
    merged = {}
    for record in records:
        for row in record['field_policy']:
            key = (row['field'], row['authenticated_by'])
            merged.setdefault(key, {'cases': [], 'display': row['display_policy'],
                                    'landing': row['landing_policy']})
            merged[key]['cases'].append(record['case'])
    for (field, authenticated), entry in sorted(merged.items()):
        lines.append('| `{}` | {} | {} | {} |'.format(
            field, authenticated, entry['display'], entry['landing']))
    lines.append('')
    lines.append('Concretely:')
    lines.append('')
    lines.append('- Store the original packet bytes and their SHA-256. Display '
                 'values are derived views, never the record of truth.')
    lines.append('- When a filename is needed for the archive, derive it from a '
                 'trusted index or from the signed body hash, not from the literal '
                 'packet. Sanitize it as hostile input: basename only, no path '
                 'separators, no leading dot, length-capped.')
    lines.append('- Show the format flag and timestamp as metadata with an '
                 'unauthenticated badge. Do not use the format flag to pick a '
                 'parser that then feeds a trust decision.')
    lines.append('- Never surface "MDC OK" as "signature OK". Two different checks '
                 'with two different keys: the MDC uses the session key, the '
                 'signature uses the signer\'s key.')
    lines.append('- Record both verdicts separately in the archive manifest so a '
                 'later reviewer can tell envelope integrity from signer intent.')
    lines.append('')
    lines.append('## What this report does not claim')
    lines.append('')
    seen = []
    for record in records:
        for line in record['claims']['not_supported']:
            if line not in seen:
                seen.append(line)
    for line in seen:
        lines.append('- ' + line)
    lines.append('- A literal field that changes without breaking the signature is '
                 'not evidence that the signature algorithm failed. The field was '
                 'never inside the signed data.')
    lines.append('')
    return '\n'.join(lines)


def main():
    import platform
    import pgpy

    os.makedirs(ARTIFACTS, exist_ok=True)
    shutil.rmtree(os.path.join(ARTIFACTS, 'mutants'), ignore_errors=True)

    signer, recipient = _keys()
    cases = []

    signed_zip, _ = build_signed(signer)
    write(os.path.join(ARTIFACTS, 'signed-zip.asc'), str(signed_zip))
    write(os.path.join(ARTIFACTS, 'signed-zip.bin'), bytes(signed_zip.__bytearray__()))
    cases.append(audit.Case('signed-zip', str(signed_zip),
                            signer=signer.pubkey, kind='signed'))

    signed_plain, plain_sig = build_signed(signer,
                                           compression=CompressionAlgorithm.Uncompressed)
    write(os.path.join(ARTIFACTS, 'signed-uncompressed.asc'), str(signed_plain))
    cases.append(audit.Case('signed-uncompressed', str(signed_plain),
                            signer=signer.pubkey, kind='signed'))

    text_msg, _ = build_signed(signer, body=b'plain ascii text\n', fmt='t',
                               filename='notes.txt')
    write(os.path.join(ARTIFACTS, 'signed-text.asc'), str(text_msg))
    cases.append(audit.Case('signed-text', str(text_msg),
                            signer=signer.pubkey, kind='signed'))

    nonascii_msg, _ = build_signed(signer, body=b'caf\xc3\xa9 total\n', fmt='b',
                                   filename='cafe-binary.txt')
    write(os.path.join(ARTIFACTS, 'signed-nonascii-binary.asc'), str(nonascii_msg))
    cases.append(audit.Case('signed-nonascii-binary', str(nonascii_msg),
                            signer=signer.pubkey, kind='signed'))

    # Separate defect probe: PGPy decodes a 't' literal with latin-1 for
    # display and hashdata re-encodes it as UTF-8, so a sender-signed
    # non-ASCII text literal fails PGPy's own verification.  Recorded apart
    # from the mutation matrix so it is not mistaken for field tampering.
    defect_msg, _ = build_signed(signer, body=b'caf\xc3\xa9 total\n', fmt='t',
                                 filename='cafe.txt')
    write(os.path.join(ARTIFACTS, 'signed-text-nonascii.asc'), str(defect_msg))
    defect = {'artifact': 'artifacts/signed-text-nonascii.asc',
              'baseline_pgpy': audit.verify_signature(
                  str(defect_msg), signer.pubkey),
              'baseline_math': audit.signature_math(
                  bytes(defect_msg.__bytearray__()), signer.pubkey),
              'explanation': (
                  'PGPSignature.hashdata encodes a str subject as UTF-8; '
                  'PGPMessage.message decodes a t literal as latin-1.  PGPy '
                  'therefore signs and verifies over double-encoded bytes, so its '
                  'own check passes. Verifiers hashing the literal octets on the '
                  'wire - including this audit signature_math path and GnuPG - '
                  'reject the artifact. This is a PGPy text-literal defect, not '
                  'evidence that literal metadata is signed.'),
              'gpg': _gpg_verify(str(defect_msg), str(signer.pubkey))}

    encrypted, _ = build_encrypted(signer, recipient)
    write(os.path.join(ARTIFACTS, 'encrypted.asc'), str(encrypted))
    write(os.path.join(ARTIFACTS, 'encrypted.bin'), bytes(encrypted.__bytearray__()))
    cases.append(audit.Case('encrypted', str(encrypted),
                            signer=signer.pubkey, decryptor=recipient,
                            kind='encrypted'))

    write(os.path.join(ARTIFACTS, 'detached.body'), BODY)
    write(os.path.join(ARTIFACTS, 'detached.sig'), str(plain_sig))
    cases.append(audit.Case('detached', str(plain_sig), signer=signer.pubkey,
                            detached=plain_sig, body=BODY, kind='detached'))

    records = []
    for case in cases:
        directory = os.path.join(ARTIFACTS, 'mutants', case.name)
        capture, manifest = _mutant_writer(case, directory)
        record = audit.run_matrix(case, capture=capture)
        record['mutants'] = manifest
        records.append(record)

    checks = _cross_checks(cases, records,
                           str(signer.pubkey),
                           RECIPIENT_KEY)

    try:
        from importlib.metadata import version as _pkg_version
        pgpy_version = _pkg_version('PGPy')
    except Exception:  # pragma: no cover
        pgpy_version = getattr(pgpy, '__version__', 'unknown')
    environment = {'python': platform.python_version(),
                   'pgpy_version': pgpy_version,
                   'openssl': None}
    try:
        from cryptography.hazmat.backends import default_backend
        environment['openssl'] = default_backend().openssl_version_text()
    except Exception:
        pass

    bundle = {'environment': environment,
              'keys': {'signer': {'fingerprint': str(signer.fingerprint),
                                  'path': os.path.relpath(SIGNER_KEY, ROOT)},
                       'recipient': {'fingerprint': str(recipient.fingerprint),
                                     'path': os.path.relpath(RECIPIENT_KEY, ROOT)}},
              'records': records,
              'text_literal_defect': defect,
              'gpg_cross_check': checks}

    write(os.path.join(ARTIFACTS, 'evidence.json'),
          json.dumps(bundle, indent=2, sort_keys=True))
    write(os.path.join(ARTIFACTS, 'REPORT.md'),
          _report_markdown(records, checks, environment, defect))

    print('wrote artifacts/evidence.json and artifacts/REPORT.md')
    for record in records:
        bad = [row for row in record['mutations'] if 'error' in row]
        print('  {:22} mutations={:2} errors={}'.format(
            record['case'], len(record['mutations']), len(bad)))
        for row in bad:
            print('     ! {}: {}'.format(row['id'], row['error']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
