""" Tests for the offline literal-metadata authentication audit tool.

These exercise the invariants that make the audit trustworthy:

* the original bytes survive untouched;
* a filename, timestamp, or format change never flips the signature math;
* a body change always does;
* armor and compression framing are not signed;
* an MDC verdict is reported separately from the signature verdict.
"""

import warnings
from datetime import datetime, timezone

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy.constants import CompressionAlgorithm

from tools import pgp_literal_audit as audit


SEC = 'tests/testdata/keys/targette.sec.rsa.asc'
REC = 'tests/testdata/keys/rsa.1.sec.asc'
CREATED = datetime(2020, 1, 1, tzinfo=timezone.utc)
MTIME = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.fixture(scope='module')
def signer():
    return PGPKey.from_file(SEC)[0]


@pytest.fixture(scope='module')
def recipient():
    return PGPKey.from_file(REC)[0]


@pytest.fixture(scope='module')
def signed(signer):
    msg = PGPMessage.new(b'quarterly figures\n', format='b',
                         compression=CompressionAlgorithm.ZIP)
    msg._message.filename = 'report.txt'
    msg._message.mtime = MTIME
    msg._message.update_hlen()
    msg |= signer.sign(msg, created=CREATED)
    return str(msg)


@pytest.fixture(scope='module')
def signed_case(signer, signed):
    return audit.Case('signed', signed, signer=signer.pubkey, kind='signed')


@pytest.fixture(scope='module')
def encrypted(signer, recipient):
    msg = PGPMessage.new(b'quarterly figures\n', format='b',
                         compression=CompressionAlgorithm.ZIP)
    msg._message.filename = 'report.txt'
    msg._message.mtime = MTIME
    msg._message.update_hlen()
    msg |= signer.sign(msg, created=CREATED)
    return str(recipient.pubkey.encrypt(msg))


def _run(case):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return audit.run_matrix(case)


def _mutation(record, identifier):
    return next(row for row in record['mutations'] if row['id'] == identifier)


def test_original_bytes_survive_audit(signed_case, signed):
    record = _run(signed_case)
    binary = audit.Armorable.ascii_unarmor(signed)['body']
    assert record['original']['binary_sha256'] == \
        __import__('hashlib').sha256(bytes(binary)).hexdigest()
    assert record['original']['payload_sha256'] == \
        __import__('hashlib').sha256(signed.encode('latin-1')).hexdigest()


def test_packet_map_records_offsets(signed_case):
    record = _run(signed_case)
    tags = _all_tags(record['packets'])
    assert {11, 2}.issubset(tags)
    literal = _find_node(record['packets'], 11)
    assert literal['literal']['filename'] == 'report.txt'
    assert literal['offset'] > 0


def _all_tags(nodes):
    tags = set()
    for node in nodes:
        tags.add(node['tag'])
        tags |= _all_tags(node.get('children', []))
    return tags


def _find_node(nodes, tag):
    for node in nodes:
        if node['tag'] == tag:
            return node
        found = _find_node(node.get('children', []), tag)
        if found:
            return found
    return None


def test_metadata_changes_do_not_break_signature(signed_case):
    record = _run(signed_case)
    for identifier in ('filename-same-length', 'filename-shortened',
                       'mtime-zeroed', 'format-to-t', 'format-to-u'):
        row = _mutation(record, identifier)
        assert row['result']['signature_math'] == audit.PASS
        assert row['verdict'] == 'undetected-by-any-layer'


def test_body_change_breaks_signature(signed_case):
    record = _run(signed_case)
    row = _mutation(record, 'body-bitflip')
    assert row['result']['signature_math'] == audit.FAIL
    assert row['verdict'] == 'detected-by-document-signature'


def test_compression_wrapper_is_not_signed(signed_case):
    record = _run(signed_case)
    for identifier in ('compression-uncompressed', 'compression-zlib'):
        row = _mutation(record, identifier)
        assert row['result']['signature_math'] == audit.PASS
        assert row['framing_changed'] is True


def test_hashed_subpacket_is_detected(signed_case):
    record = _run(signed_case)
    row = _mutation(record, 'signature-hashed-subpacket')
    assert row['result']['signature_math'] == audit.FAIL


def test_unhashed_issuer_is_routing_only(signed_case):
    record = _run(signed_case)
    row = _mutation(record, 'signature-unhashed-subpacket')
    assert row['result']['signature_math'] == audit.PASS
    assert row['verdict'] == 'only-routing-affected'


def test_armor_does_not_affect_signature(signed_case):
    record = _run(signed_case)
    for identifier in ('armor-header', 'armor-crc'):
        row = _mutation(record, identifier)
        assert row['result']['signature_math'] == audit.PASS


def test_encrypted_layers_are_separate(signer, recipient, encrypted):
    case = audit.Case('encrypted', encrypted, signer=signer.pubkey,
                      decryptor=recipient, kind='encrypted')
    record = _run(case)
    assert record['baseline']['layers']['mdc']['state'] == audit.PASS
    assert record['baseline']['layers']['signature_math']['state'] == audit.PASS

    filename = _mutation(record, 'filename-same-length')
    assert filename['result']['signature_math'] == audit.PASS
    assert filename['result']['mdc'] == audit.PASS

    body = _mutation(record, 'body-bitflip')
    assert body['result']['signature_math'] == audit.FAIL
    assert body['result']['mdc'] == audit.PASS

    ciphertext = _mutation(record, 'ciphertext-bitflip')
    assert ciphertext['result']['mdc'] == audit.FAIL
    assert ciphertext['result']['signature_math'] == audit.UNREACHABLE


def test_mdc_is_not_reported_as_sender_authentication(encrypted, signer, recipient):
    case = audit.Case('encrypted', encrypted, signer=signer.pubkey,
                      decryptor=recipient, kind='encrypted')
    record = _run(case)
    row = next(item for item in record['field_policy']
               if item['field'] == 'literal.filename')
    assert 'signature' not in row['authenticated_by']


def test_text_literal_pgpy_divergence_is_flagged(signer):
    """A non-ASCII binary literal relabelled as 't' must not be blamed on the signer."""
    msg = PGPMessage.new(b'caf\xc3\xa9\n', format='b',
                         compression=CompressionAlgorithm.Uncompressed)
    msg._message.filename = 'cafe.txt'
    msg._message.mtime = MTIME
    msg._message.update_hlen()
    msg |= signer.sign(msg, created=CREATED)
    case = audit.Case('nonascii', str(msg), signer=signer.pubkey, kind='signed')
    record = _run(case)
    row = _mutation(record, 'format-to-t')
    assert row['result']['signature_math'] == audit.PASS
    assert row['result']['signature'] == audit.FAIL
    assert row['verdict'] == 'display-artifact-only'


def test_detached_subject_change_is_detected(signer, signed):
    sig = signer.sign(PGPMessage.new(b'detached body\n'), created=CREATED)
    case = audit.Case('detached', str(sig), signer=signer.pubkey,
                      detached=sig, body=b'detached body\n', kind='detached')
    record = _run(case)
    row = _mutation(record, 'detached-subject')
    assert row['result']['signature_math'] == audit.FAIL


def test_capture_receives_mutant_and_display(signed_case):
    captured = {}

    def capture(identifier, mutant, display, space='packet'):
        captured[identifier] = (bytes(mutant), dict(display), space)

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        audit.run_matrix(signed_case, capture=capture)

    assert 'filename-same-length' in captured
    mutant, display, space = captured['filename-same-length']
    assert space == 'packet'
    assert display['filename'] == 'malware.sh'
    assert display['format'] == 'b'
    # the mutant must be a distinct byte stream, not the original
    assert mutant != signed_case.original_bytes


def test_armor_mutants_are_captured_in_envelope_space(signed_case):
    captured = {}

    def capture(identifier, mutant, display, space='packet'):
        captured[identifier] = (bytes(mutant), space)

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        audit.run_matrix(signed_case, capture=capture)

    assert captured['armor-header'][1] == 'armor'
    assert b'Comment: interposed by a relay' in captured['armor-header'][0]
    assert captured['armor-crc'][1] == 'armor'
