"""Offline audit of which OpenPGP layer authenticates each displayed field.

The question is narrow:

    for every value a viewer would show, which layer - if any - would
    change its verdict if that value were altered?

Three things are kept strictly apart:

``original``
    The exact bytes audited.  They are never rewritten; the report carries
    their SHA-256 and a packet map with byte offsets.

``display``
    The value PGPy's parser derives from those bytes for presentation.

``evidence``
    The measured verdict of every layer that could have covered the field.

Two signature verdicts are reported, because PGPy has two:

``signature``
    ``PGPKey.verify(PGPMessage)``.  This follows PGPy's own message
    decoding, which turns a 't' literal into text and re-encodes it as
    UTF-8 before hashing.  For non-ASCII text that can differ from the
    octets the sender actually signed.

``signature_math``
    The same signature packet checked over the literal octets exactly as
    they appear on the wire, bypassing PGPy's display decoding.  This is
    the ground truth for "did the sender sign these bytes".

A field is only called sender-authenticated when mutating it flips
``signature_math``.  An MDC pass is reported as integrity of the
decryption container, never as the sender authenticating a filename.

``tools/make_evidence.py`` drives the full reproducible experiment.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import warnings
from datetime import datetime, timezone

if __package__ in (None, ''):
    # allow `python tools/pgp_literal_audit.py` without installing the package
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import hashes as crypto_hashes

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.packet import Packet
from pgpy.packet.packets import PKESessionKeyV3
from pgpy.symenc import _decrypt
from pgpy.symenc import _encrypt
from pgpy.types import Armorable


__all__ = ['PASS', 'FAIL', 'ABSENT', 'REJECTED', 'UNREACHABLE',
           'Node', 'Case', 'walk_packets', 'split_packets', 'inner_of',
           'literal_view', 'verify_signature', 'signature_math',
           'open_mdc', 'run_matrix', 'audit_file', 'render_markdown', 'main']


PASS = 'PASS'
FAIL = 'FAIL'
ABSENT = 'NOT-PRESENT'
REJECTED = 'REJECTED'
UNREACHABLE = 'NOT-REACHABLE'


# ---------------------------------------------------------------------------
# byte-level packet walking
# ---------------------------------------------------------------------------

_TAG_NAMES = {1: 'PKESessionKey', 2: 'Signature', 3: 'SKESessionKey',
              4: 'OnePassSignature', 5: 'SecretKey', 6: 'PublicKey',
              7: 'SecretSubkey', 8: 'CompressedData',
              9: 'SymmetricallyEncryptedData', 10: 'Marker', 11: 'LiteralData',
              12: 'Trust', 13: 'UserID', 14: 'PublicSubkey', 17: 'UserAttribute',
              18: 'SymEncryptedIntegrityProtectedData',
              19: 'ModificationDetectionCode'}


class Node(object):
    """One packet, addressed within the buffer it was found in."""

    def __init__(self, tag, header, body, offset):
        self.tag = tag
        self.header = header
        self.body = body
        self.offset = offset

    @property
    def name(self):
        return _TAG_NAMES.get(self.tag, 'Unknown{:d}'.format(self.tag))

    def view(self):
        out = {'tag': self.tag, 'name': self.name, 'offset': self.offset,
               'header_hex': self.header.hex(),
               'header_length': len(self.header),
               'body_length': len(self.body),
               'body_sha256': hashlib.sha256(self.body).hexdigest()}
        if self.tag == 11:
            literal = literal_view(self.body)
            literal.pop('contents')
            out['literal'] = literal
        if self.tag == 8 and self.body:
            out['compression'] = CompressionAlgorithm(self.body[0]).name
        inner = inner_of(self)
        if inner:
            out['children'] = [child.view() for child in walk_packets(inner)]
        return out


def _read_header(data, offset):
    start = offset
    first = data[offset]
    if not first & 0x80:
        raise ValueError('not an OpenPGP packet at offset {:d}'.format(start))
    offset += 1
    if first & 0x40:
        tag = first & 0x3f
        l0 = data[offset]
        offset += 1
        if l0 < 192:
            length = l0
        elif l0 < 224:
            length = ((l0 - 192) << 8) + data[offset] + 192
            offset += 1
        elif l0 == 255:
            length = int.from_bytes(data[offset:offset + 4], 'big')
            offset += 4
        else:
            raise ValueError('partial body lengths are not supported')
    else:
        tag = (first >> 2) & 0x0f
        ltype = first & 0x03
        if ltype == 0:
            length = data[offset]
            offset += 1
        elif ltype == 1:
            length = int.from_bytes(data[offset:offset + 2], 'big')
            offset += 2
        elif ltype == 2:
            length = int.from_bytes(data[offset:offset + 4], 'big')
            offset += 4
        else:
            length = len(data) - offset
    return tag, bytes(data[start:offset]), offset, length


def walk_packets(data):
    """Packet tree for ``data``.  Nothing is re-serialized."""
    nodes = []
    offset = 0
    while offset < len(data):
        tag, header, body_start, length = _read_header(data, offset)
        body = bytes(data[body_start:body_start + length])
        nodes.append(Node(tag, header, body, offset))
        offset = body_start + length
    return nodes


def split_packets(data):
    """Flat list of (node, raw_slice) for a buffer without compression wrappers."""
    out = []
    offset = 0
    while offset < len(data):
        tag, header, body_start, length = _read_header(data, offset)
        end = body_start + length
        out.append((Node(tag, header, bytes(data[body_start:end]), offset),
                    bytes(data[offset:end])))
        offset = end
    return out


def inner_of(node):
    """Decompress a CompressedData node on demand; never mutate the node."""
    if node.tag != 8 or not node.body:
        return None
    try:
        return CompressionAlgorithm(node.body[0]).decompress(node.body[1:])
    except Exception:
        return None


def encode_header(tag, length):
    """Emit a new-format packet header with the shortest length encoding."""
    first = bytes([0xC0 | tag])
    if length < 192:
        return first + bytes([length])
    if length < 8384:
        value = length - 192
        return first + bytes([(value >> 8) + 192, value & 0xFF])
    return first + b'\xFF' + length.to_bytes(4, 'big')


def packet_bytes(tag, body):
    return encode_header(tag, len(body)) + body


def diff_ranges(before, after):
    """Byte-level difference summary between the original and the mutant."""
    if before == after:
        return []
    prefix = 0
    shortest = min(len(before), len(after))
    while prefix < shortest and before[prefix] == after[prefix]:
        prefix += 1
    suffix_b, suffix_a = len(before), len(after)
    while suffix_b > prefix and suffix_a > prefix \
            and before[suffix_b - 1] == after[suffix_a - 1]:
        suffix_b -= 1
        suffix_a -= 1
    ranges = [{'space': 'original', 'offset': prefix,
               'length': suffix_b - prefix,
               'hex': before[prefix:suffix_b][:32].hex()}]
    ranges.append({'space': 'mutant', 'offset': prefix,
                   'length': max(0, suffix_a - prefix),
                   'hex': after[prefix:suffix_a][:32].hex()})
    return ranges


# ---------------------------------------------------------------------------
# literal packet view
# ---------------------------------------------------------------------------

def literal_view(body):
    fmt = chr(body[0]) if body else ''
    fnl = body[1] if len(body) > 1 else 0
    filename = body[2:2 + fnl].decode('latin-1', 'replace')
    mtime = int.from_bytes(body[2 + fnl:6 + fnl], 'big') if len(body) >= 6 + fnl else 0
    contents = body[6 + fnl:]
    return {'format': fmt,
            'filename': filename,
            'mtime': mtime,
            'mtime_iso': (datetime.fromtimestamp(mtime, timezone.utc).isoformat()
                          if mtime else '0 (no time)'),
            'contents_length': len(contents),
            'contents_sha256': hashlib.sha256(contents).hexdigest(),
            'contents': contents}


# ---------------------------------------------------------------------------
# verification primitives, one layer at a time
# ---------------------------------------------------------------------------

def _as_message(payload):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        msg = PGPMessage()
        msg.parse(payload)
    return msg


def verify_signature(payload, signer, detached=None, contents=None):
    """Verdict of PGPy's high-level document-signature check."""
    if detached is not None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                sv = signer.verify(contents, detached)
            return {'state': PASS if bool(sv) else FAIL,
                    'detail': _verification_detail(sv)}
        except Exception as exc:
            return {'state': FAIL, 'detail': '{}: {}'.format(type(exc).__name__, exc)}

    try:
        msg = _as_message(payload)
    except Exception as exc:
        return {'state': REJECTED,
                'detail': '{}: {}'.format(type(exc).__name__, exc)}
    if not msg.signatures:
        return {'state': ABSENT, 'detail': 'no signature packet in this composition'}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sv = signer.verify(msg)
        return {'state': PASS if bool(sv) else FAIL,
                'detail': _verification_detail(sv)}
    except Exception as exc:
        return {'state': FAIL, 'detail': '{}: {}'.format(type(exc).__name__, exc)}


def _verification_detail(sv):
    return [{'signer': str(entry.signature.signer),
             'signature_type': entry.signature.type.name,
             'hash_algorithm': entry.signature.hash_algorithm.name,
             'issues': int(entry.issues),
             'issue_names': [flag.name for flag in type(entry.issues)
                             if flag.value and entry.issues & flag.value]}
            for entry in sv._subjects]


def signature_math(raw, signer, contents=None, detached=None):
    """Verify the signature packet over literal octets as they appear on the wire.

    PGPy's high-level path hashes ``PGPMessage.message``.  For a 't' literal
    that value is text decoded as latin-1 and re-encoded as UTF-8 by
    ``PGPSignature.hashdata``.  That is a display choice, not the signed
    octets.  This helper builds the PGPSignature straight from the packet
    and hashes the raw literal contents instead.
    """
    try:
        if detached is not None:
            sig = detached
        else:
            sig = _signature_object(raw)
        if contents is None:
            contents = literal_view(find_literal(raw)['node'].body)['contents']
        digest = sig.hashdata(contents)
        ok = signer._key.verify(digest, sig.__sig__,
                                getattr(crypto_hashes, sig.hash_algorithm.name)())
    except Exception as exc:
        return {'state': FAIL, 'detail': '{}: {}'.format(type(exc).__name__, exc)}
    return {'state': PASS if ok else FAIL,
            'detail': {'hash_algorithm': sig.hash_algorithm.name,
                       'signed_octets_sha256': hashlib.sha256(contents).hexdigest()}}


def _signature_object(raw):
    body = find_signature(raw)['node'].body
    packet = Packet(bytearray(packet_bytes(2, body)))
    sig = PGPSignature()
    sig |= packet
    return sig


def _secret_for(decryptor, keyid):
    if str(decryptor.fingerprint.keyid).upper() == str(keyid).upper():
        return decryptor._key
    for sub in decryptor.subkeys.values():
        if str(sub.fingerprint.keyid).upper() == str(keyid).upper():
            return sub._key
    raise KeyError('no secret key for recipient {}'.format(keyid))


def open_mdc(payload, decryptor):
    """Decrypt a tag-18 container and judge the MDC on its own.

    Returns the plaintext, the MDC verdict, the inner packets with the MDC
    packet removed, and the session material needed to seal a new container.
    The random prefix is kept verbatim so a re-seal is comparable.
    """
    result = {'state': ABSENT, 'detail': 'not an encrypted message',
              'plaintext': None, 'inner': None, 'session': None}
    try:
        msg = _as_message(payload)
    except Exception as exc:
        result.update(state=REJECTED,
                      detail='{}: {}'.format(type(exc).__name__, exc))
        return result
    if not msg.is_encrypted:
        return result

    pkesk = next((key for key in msg._sessionkeys
                  if isinstance(key, PKESessionKeyV3)), None)
    if pkesk is None:
        result.update(state=REJECTED, detail='no public-key session key')
        return result

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            symalg, sessionkey = pkesk.decrypt_sk(
                _secret_for(decryptor, pkesk.encrypter))
        container = next(node for node in walk_packets(bytes(msg.__bytearray__()))
                         if node.tag == 18)
        plaintext = _decrypt(bytes(container.body[1:]), sessionkey, symalg)
        expected = b'\xd3\x14' + hashlib.sha1(bytes(plaintext[:-20])).digest()
        ok = bytes(plaintext[-22:]) == expected
        block = symalg.block_size // 8
        result.update(state=PASS if ok else FAIL,
                      detail='SHA-1 modification detection packet',
                      plaintext=bytes(plaintext),
                      inner=_strip_mdc(bytes(plaintext[block + 2:])) if ok else None,
                      session={'algorithm': symalg.name, 'key': sessionkey,
                               'block_size': block,
                               'prefix': bytes(plaintext[:block + 2])})
        return result
    except Exception as exc:
        result.update(state=FAIL,
                      detail='{}: {}'.format(type(exc).__name__, exc))
        return result


def _strip_mdc(inner):
    """Remove the trailing tag-19 packet from decrypted plaintext."""
    parts = split_packets(inner)
    if parts and parts[-1][0].tag == 19:
        return b''.join(chunk for _, chunk in parts[:-1])
    return inner


def rewrap_mdc(session, inner_packets):
    """Seal packet bytes under the recovered session key with a valid MDC.

    Models a gateway or archive tool that legitimately holds the session
    key, not an attacker who only has the recorded ciphertext.
    """
    alg = session['algorithm']
    if isinstance(alg, str):
        alg = SymmetricKeyAlgorithm[alg]
    body = session['prefix'] + inner_packets
    digest = hashlib.sha1(body + b'\xd3\x14').digest()
    sealed = _encrypt(body + b'\xd3\x14' + digest, session['key'], alg)
    return packet_bytes(18, b'\x01' + bytes(sealed))


def stale_seal(session, edited_packets, old_mdc_packet):
    """Re-seal with the session key but reuse the old MDC packet verbatim.

    Models a careless re-encryptor that skipped the modification check.
    """
    alg = session['algorithm']
    if isinstance(alg, str):
        alg = SymmetricKeyAlgorithm[alg]
    body = session['prefix'] + edited_packets + old_mdc_packet
    sealed = _encrypt(body, session['key'], alg)
    return packet_bytes(18, b'\x01' + bytes(sealed))


def armor_bytes(magic, data):
    payload = base64.b64encode(data).decode('latin-1')
    payload = '\n'.join(payload[i:i + 64] for i in range(0, len(payload), 64))
    crc = base64.b64encode(Armorable.crc24(data).to_bytes(3, 'big')).decode('latin-1')
    return ('-----BEGIN PGP {magic}-----\n\n{payload}\n={crc}\n'
            '-----END PGP {magic}-----\n').format(
                magic=magic, payload=payload, crc=crc)


# ---------------------------------------------------------------------------
# editing the packet stream
# ---------------------------------------------------------------------------

def _replace_index(parts, index, new_packet):
    return b''.join(chunk if i != index else new_packet
                    for i, (_, chunk) in enumerate(parts))


def find_literal(raw):
    """Locate the literal packet anywhere in the message structure."""
    outer = split_packets(raw)
    for index, (node, _) in enumerate(outer):
        if node.tag == 11:
            return {'outer_index': index, 'inner_index': None, 'node': node,
                    'parts': outer, 'compression': None,
                    'outer_parts': outer, 'outer_node': node}
        inner = inner_of(node)
        if inner:
            inner_parts = split_packets(inner)
            for j, (candidate, _) in enumerate(inner_parts):
                if candidate.tag == 11:
                    return {'outer_index': index, 'inner_index': j,
                            'node': candidate, 'parts': inner_parts,
                            'compression': node.body[0],
                            'outer_parts': outer, 'outer_node': node}
    raise ValueError('no Literal Data packet found')


def replace_literal(raw, new_body):
    """Swap the literal packet body, preserving every other packet verbatim."""
    located = find_literal(raw)
    replacement = packet_bytes(11, new_body)
    if located['inner_index'] is None:
        return _replace_index(located['parts'], located['outer_index'], replacement)
    rebuilt = _replace_index(located['parts'], located['inner_index'], replacement)
    calg = located['compression']
    wrapper = bytes([calg]) + CompressionAlgorithm(calg).compress(rebuilt)
    return _replace_index(located['outer_parts'], located['outer_index'],
                          packet_bytes(8, wrapper))


def edit_filename(raw, name):
    body = find_literal(raw)['node'].body
    fnl = body[1]
    encoded = name.encode('latin-1')
    if len(encoded) > 255:
        raise ValueError('filename exceeds the one-octet length field')
    return replace_literal(raw, bytes([body[0], len(encoded)]) + encoded + body[2 + fnl:])


def edit_mtime(raw, value=0):
    body = find_literal(raw)['node'].body
    fnl = body[1]
    return replace_literal(
        raw, body[:2 + fnl] + int(value).to_bytes(4, 'big') + body[6 + fnl:])


def edit_format(raw, fmt):
    body = find_literal(raw)['node'].body
    return replace_literal(raw, bytes([ord(fmt)]) + body[1:])


def flip_body_bit(raw):
    body = bytearray(find_literal(raw)['node'].body)
    body[6 + body[1]] ^= 0x01
    return replace_literal(raw, bytes(body))


def replace_compression(raw, calg):
    """Rewrite the compression wrapper only; inner packets stay byte-identical."""
    parts = split_packets(raw)
    for index, (node, _) in enumerate(parts):
        inner = inner_of(node)
        if not inner:
            continue
        if calg is CompressionAlgorithm.Uncompressed:
            return _replace_index(parts, index, inner)
        wrapper = bytes([calg]) + calg.compress(inner)
        return _replace_index(parts, index, packet_bytes(8, wrapper))
    raise ValueError('no compression wrapper present')


def find_signature(raw):
    for index, (node, _) in enumerate(split_packets(raw)):
        if node.tag == 2:
            return {'index': index, 'node': node,
                    'parts': split_packets(raw), 'compressed': False}
        inner = inner_of(node)
        if inner:
            inner_parts = split_packets(inner)
            for j, (candidate, _) in enumerate(inner_parts):
                if candidate.tag == 2:
                    return {'index': j, 'node': candidate, 'parts': inner_parts,
                            'compressed': True, 'outer_index': index,
                            'calg': node.body[0],
                            'outer_parts': split_packets(raw)}
    raise ValueError('no Signature packet found')


def replace_signature(raw, new_body):
    located = find_signature(raw)
    replacement = packet_bytes(2, new_body)
    if not located['compressed']:
        return _replace_index(located['parts'], located['index'], replacement)
    rebuilt = _replace_index(located['parts'], located['index'], replacement)
    wrapper = bytes([located['calg']]) + \
        CompressionAlgorithm(located['calg']).compress(rebuilt)
    return _replace_index(located['outer_parts'], located['outer_index'],
                          packet_bytes(8, wrapper))


def _signature_areas(body):
    hlen = int.from_bytes(body[4:6], 'big')
    uhlen = int.from_bytes(body[6 + hlen:8 + hlen], 'big')
    return 6, 6 + hlen, 8 + hlen, 8 + hlen + uhlen


def signature_areas(raw):
    body = find_signature(raw)['node'].body
    return body, _signature_areas(body)


def edit_hashed_creation_time(raw):
    body, (hstart, hend, _, _) = signature_areas(raw)
    area = bytearray(body[hstart:hend])
    if area[1] != 0x02:
        raise ValueError('first hashed subpacket is 0x{:02x}, not CreationTime'
                         .format(area[1]))
    area[2:6] = (0).to_bytes(4, 'big')
    return replace_signature(raw, body[:hstart] + bytes(area) + body[hend:])


def edit_unhashed_issuer(raw):
    body, (_, _, ustart, uend) = signature_areas(raw)
    area = bytearray(body[ustart:uend])
    index = area.index(0x10)
    area[index + 1:index + 9] = b'\x00' * 8
    return replace_signature(raw, body[:ustart] + bytes(area) + body[uend:])


def edit_hash2(raw):
    body, (_, _, _, uend) = signature_areas(raw)
    out = bytearray(body)
    out[uend] ^= 0xFF
    out[uend + 1] ^= 0xFF
    return replace_signature(raw, bytes(out))


def signature_facts(raw):
    body, (_, _, ustart, uend) = signature_areas(raw)
    hlen = int.from_bytes(body[4:6], 'big')
    return {'version': body[0],
            'type': body[1],
            'public_key_algorithm': body[2],
            'hash_algorithm': body[3],
            'hashed_subpackets_hex': body[6:6 + hlen].hex(),
            'unhashed_subpackets_hex': body[ustart:uend].hex(),
            'hash2': body[uend:uend + 2].hex().upper(),
            'unhashed_issuer': _scan_issuer(body[ustart:uend])}


def _scan_issuer(area):
    offset = 0
    while offset < len(area):
        length = area[offset]
        if length == 0:
            break
        if length == 255:
            size = int.from_bytes(area[offset + 1:offset + 5], 'big')
            start = offset + 5
        elif length < 192:
            size = length
            start = offset + 1
        else:
            size = ((length - 192) << 8) + area[offset + 1] + 192
            start = offset + 2
        if area[start] == 0x10 and size == 9:
            return area[start + 1:start + 9].hex().upper()
        offset = start + size
    return None


# ---------------------------------------------------------------------------
# layer evaluation
# ---------------------------------------------------------------------------

class Case(object):
    """One message plus the verification context it needs."""

    def __init__(self, name, payload, *, signer=None, decryptor=None,
                 detached=None, body=None, kind='signed'):
        self.name = name
        self.payload = payload
        self.signer = signer
        self.decryptor = decryptor
        self.detached = detached
        self.body = body
        self.kind = kind

    @property
    def original_bytes(self):
        if isinstance(self.payload, str):
            return bytes(Armorable.ascii_unarmor(self.payload)['body'])
        return bytes(self.payload)

    @property
    def payload_bytes(self):
        if isinstance(self.payload, str):
            return self.payload.encode('latin-1')
        return bytes(self.payload)

    @property
    def armor_text(self):
        if isinstance(self.payload, str):
            return self.payload
        return armor_bytes('MESSAGE', self.payload)


def _inner_reference(case, payload):
    """Return (binary_reference, armored_reference, decrypted_inner_or_None)."""
    if isinstance(payload, str):
        binary = bytes(Armorable.ascii_unarmor(payload)['body'])
        armored = payload
    else:
        binary = bytes(payload)
        armored = armor_bytes('MESSAGE', binary)

    if case.kind != 'encrypted':
        return binary, armored, None
    opened = open_mdc(armored, case.decryptor)
    return binary, armored, opened


def layers(case, payload=None):
    """Evaluate each layer in the space where it actually lives.

    For an encrypted message the MDC is judged on the container, and the
    document signature only on the decrypted inner packets - and only if
    the MDC passed.  That ordering mirrors a real client.
    """
    payload = case.armor_text if payload is None else payload
    binary, armored, opened = _inner_reference(case, payload)

    if case.kind == 'detached':
        contents = case.body if case.body is not None else b''
        if case.body is None:
            return {'signature': {'state': REJECTED,
                                  'detail': 'detached case has no subject bytes'},
                    'signature_math': {'state': REJECTED,
                                       'detail': 'detached case has no subject bytes'},
                    'mdc': {'state': ABSENT, 'detail': 'no encryption container'}}
        return {'signature': verify_signature(None, case.signer,
                                              detached=case.detached,
                                              contents=contents),
                'signature_math': signature_math(None, case.signer,
                                                 contents=contents,
                                                 detached=case.detached),
                'mdc': {'state': ABSENT, 'detail': 'no encryption container'}}

    if case.kind != 'encrypted':
        return {'signature': verify_signature(armored, case.signer),
                'signature_math': signature_math(binary, case.signer),
                'mdc': {'state': ABSENT, 'detail': 'no encryption container'}}

    if opened['state'] != PASS or not opened['inner']:
        return {'signature': {'state': UNREACHABLE,
                              'detail': 'inner packets unavailable; MDC did not pass'},
                'signature_math': {'state': UNREACHABLE,
                                   'detail': 'no authenticated plaintext'},
                'mdc': {'state': opened['state'], 'detail': opened['detail']}}
    return {'signature': verify_signature(armor_bytes('MESSAGE', opened['inner']),
                                          case.signer),
            'signature_math': signature_math(opened['inner'], case.signer),
            'mdc': {'state': PASS, 'detail': opened['detail']}}


def display_of(case, payload=None):
    """What a viewer would show, derived through PGPy from these bytes."""
    payload = case.armor_text if payload is None else payload
    binary, armored, opened = _inner_reference(case, payload)

    if case.kind == 'encrypted':
        if not opened['inner']:
            return {'error': 'MDC failed; no plaintext is shown',
                    'mdc': opened['state']}
        reference = opened['inner']
    else:
        reference = binary

    if case.kind == 'detached':
        contents = case.body if case.body is not None else b''
        return {'format': '(none: detached signature)',
                'filename': None, 'mtime': None, 'mtime_iso': None,
                'body_sha256': hashlib.sha256(bytes(contents)).hexdigest(),
                'body_text': (bytes(contents).decode('utf-8', 'replace')
                              if isinstance(contents, (bytes, bytearray)) else contents),
                'body_bytes_hex': bytes(contents)[:64].hex()}

    view = literal_view(find_literal(reference)['node'].body)
    try:
        msg = _as_message(armor_bytes('MESSAGE', reference))
        filename = msg.filename
        format_hint = getattr(msg._message, 'format', None)
    except Exception as exc:
        # PGPy decodes the literal filename as UTF-8 unconditionally; a
        # latin-1 name raises before any packet is exposed.  Fall back to
        # the raw packet view and record why the display path failed.
        return _render_literal(view, display_error='{}: {}'.format(
            type(exc).__name__, exc))
    return _render_literal(view, filename=filename, format_hint=format_hint)


def _render_literal(view, filename=None, format_hint=None, display_error=None):
    contents = bytes(view['contents'])
    fmt = format_hint or view['format']
    if fmt == 'u':
        text = contents.decode('utf-8', 'replace')
    elif fmt == 't':
        text = contents.decode('latin-1')
    else:
        text = None
    out = {'format': fmt,
            'filename': view['filename'] if filename is None else filename,
            'mtime': view['mtime'],
            'mtime_iso': view['mtime_iso'],
            'body_sha256': hashlib.sha256(contents).hexdigest(),
            'body_text': text,
            'body_bytes_hex': contents[:64].hex()}
    if display_error:
        out['display_error'] = display_error
    return out


# ---------------------------------------------------------------------------
# the mutation matrix
# ---------------------------------------------------------------------------

def _edit_space(case, binary, editor, rewrap):
    """Apply ``editor`` in the space a sender's bytes live in.

    Signed-only: edit the packet stream directly.
    Encrypted: decrypt, edit the sealed plaintext, then either re-seal under
    the recovered session key or leave the old container stale.
    """
    if case.kind != 'encrypted':
        return editor(binary), 'packet stream'

    opened = open_mdc(armor_bytes('MESSAGE', binary), case.decryptor)
    if not opened['inner']:
        raise RuntimeError('cannot edit: MDC did not open')
    edited = editor(opened['inner'])
    if not rewrap:
        return binary, 'sealed plaintext edited but container left stale'
    others = b''.join(chunk for node, chunk in split_packets(binary)
                      if node.tag != 18)
    return others + rewrap_mdc(opened['session'], edited), 'container resealed'


def _verdict(signature_math_state, mdc_state, pgpy_state=None, baseline_ok=True):
    if not baseline_ok:
        return 'baseline-signature-invalid'
    if signature_math_state == REJECTED and pgpy_state == REJECTED:
        return 'baseline-signature-invalid'
    if signature_math_state == FAIL:
        return 'detected-by-document-signature'
    if mdc_state == FAIL:
        return 'detected-by-mdc-integrity'
    if signature_math_state == UNREACHABLE:
        return 'not-evaluable'
    if signature_math_state == PASS and pgpy_state == FAIL:
        return 'display-artifact-only'
    if signature_math_state == PASS:
        return 'undetected-by-any-layer'
    if signature_math_state == REJECTED:
        return 'rejected-during-parse'
    return 'no-signature-present'


def _attribution(field, outcome, baseline_ok=True):
    if not baseline_ok:
        return ('the untouched artifact already fails signature verification; '
                'this mutation is not attributable to the field')
    math_state = outcome['signature_math']['state']
    mdc_state = outcome['mdc']['state']
    if math_state == FAIL:
        if field.startswith('signature.'):
            return ('{} lives in the hashed region of the Signature packet, so the '
                    'signature trailer no longer matches'.format(field))
        return ('sender document signature covers {}; changing it breaks the '
                'signature over the literal octets'.format(field))
    if math_state == UNREACHABLE:
        return 'MDC blocked access to the inner packets; signature not reached'
    if mdc_state == FAIL:
        return ('MDC integrity rejects the container; that is tamper evidence, '
                'not sender authentication of {}'.format(field))
    if math_state == PASS:
        return ('neither the document signature nor the MDC binds {}; the change '
                'is invisible to both'.format(field))
    return 'no document signature present'


def _row(identifier, field, stimulus, before, after, outcome, display_after,
         *, framing_changed, note, attribution=None, verdict=None,
         baseline_ok=True):
    return {'id': identifier,
            'field': field,
            'stimulus': stimulus,
            'original_packet_sha256': hashlib.sha256(before).hexdigest(),
            'mutant_packet_sha256': hashlib.sha256(after).hexdigest(),
            'byte_diff': diff_ranges(before, after),
            'framing_changed': framing_changed,
            'edit_note': note,
            'result': {'signature': outcome['signature']['state'],
                       'signature_math': outcome['signature_math']['state'],
                       'mdc': outcome['mdc']['state'],
                       'signature_detail': outcome['signature'].get('detail'),
                       'signature_math_detail': outcome['signature_math'].get('detail'),
                       'mdc_detail': outcome['mdc'].get('detail')},
            'display_after': display_after,
            'attribution': attribution or _attribution(field, outcome, baseline_ok),
            'verdict': verdict or _verdict(outcome['signature_math']['state'],
                                           outcome['mdc']['state'],
                                           outcome['signature']['state'],
                                           baseline_ok)}


def _evaluate(case, after):
    armored = armor_bytes('MESSAGE', after)
    outcome = layers(case, armored)
    display = display_of(case, armored)
    return outcome, display


def run_matrix(case, capture=None):
    """Run every mutation.  ``capture(identifier, mutant_bytes, display)`` is
    called for each row that produces parseable bytes, so a caller can persist
    the reassembled artifact next to its verdict."""
    binary = case.original_bytes
    baseline_outcome = layers(case)
    baseline_ok = baseline_outcome['signature_math']['state'] == PASS
    reference = binary
    if case.kind == 'encrypted':
        opened = open_mdc(case.armor_text, case.decryptor)
        if opened['inner']:
            reference = opened['inner']

    record = {'case': case.name,
              'kind': case.kind,
              'original': {'binary_sha256': hashlib.sha256(binary).hexdigest(),
                           'binary_length': len(binary),
                           'payload_sha256': hashlib.sha256(case.payload_bytes).hexdigest()},
              'packets': [node.view() for node in walk_packets(binary)],
              'signature_packet': (signature_facts(reference)
                                   if any(node.tag == 2
                                          for node in walk_packets(reference))
                                   else None),
              'baseline': {'layers': baseline_outcome,
                           'display': display_of(case),
                           'signature_valid': baseline_ok},
              'mutations': []}

    if case.kind == 'encrypted':
        record['mdc_container'] = {
            'state': opened['state'],
            'detail': opened['detail'],
            'session_algorithm': (opened['session'] or {}).get('algorithm'),
            'inner_packets': ([node.view() for node in walk_packets(opened['inner'])]
                              if opened['inner'] else [])}

    if case.kind == 'detached':
        literal = {'format': '', 'filename': '', 'mtime': 0, 'mtime_iso': '',
                   'contents': bytes(case.body or b''), 'contents_sha256': '',
                   'contents_length': len(case.body or b'')}
    else:
        literal = literal_view(find_literal(reference)['node'].body)
    rewrap = case.kind == 'encrypted'

    def emit(row, mutant_bytes=None, display=None, space='packet'):
        if capture is not None and mutant_bytes is not None:
            capture(row['id'], mutant_bytes, display, space)
        record['mutations'].append(row)

    def add(identifier, field, stimulus, editor, *, attribution=None,
            verdict=None, framing_changed=False, postprocess=None):
        try:
            if case.kind == 'detached':
                before = bytes(case.body or b'')
                after = editor(before)
                outcome = {'signature': verify_signature(
                               None, case.signer, detached=case.detached,
                               contents=after),
                           'signature_math': signature_math(
                               None, case.signer, contents=after,
                               detached=case.detached),
                           'mdc': {'state': ABSENT,
                                   'detail': 'no encryption container'}}
                display = display_of(case)
                emit(_row(
                    identifier, field, stimulus, before, after, outcome, display,
                    framing_changed=framing_changed,
                    note='detached subject edited',
                    attribution=attribution, verdict=verdict,
                    baseline_ok=baseline_ok), after, display)
                return
            after = editor(reference) if case.kind == 'encrypted' else editor(binary)
            if case.kind == 'encrypted':
                others = b''.join(chunk for node, chunk in split_packets(binary)
                                  if node.tag != 18)
                opened = open_mdc(case.armor_text, case.decryptor)
                after = others + rewrap_mdc(opened['session'], after)
                note = 'sealed plaintext edited, container resealed with recovered session key'
            else:
                note = 'packet stream edited in place'
            if postprocess is not None:
                after = postprocess(after)
            outcome, display = _evaluate(case, after)
        except Exception as exc:
            record['mutations'].append({'id': identifier, 'field': field,
                                        'error': '{}: {}'.format(type(exc).__name__, exc)})
            return
        emit(_row(
            identifier, field, stimulus, binary, after, outcome, display,
            framing_changed=framing_changed, note=note,
            attribution=attribution, verdict=verdict, baseline_ok=baseline_ok),
             after, display)

    if case.kind == 'detached':
        add('detached-subject', 'detached.subject',
            'flip one bit in the subject presented for verification',
            lambda body: bytes([body[0] ^ 0x01]) + bytes(body[1:]),
            attribution=('detached signature verifies over supplied bytes; the '
                         'literal packet never existed in this composition'),
            verdict=None)
    else:
        add('filename-same-length', 'literal.filename',
            'rewrite the filename bytes in place',
            lambda raw: edit_filename(raw, 'malware.sh'))
        add('filename-shortened', 'literal.filename',
            'shorten the filename and re-encode the one-octet length',
            lambda raw: edit_filename(raw, 'x.sh'), framing_changed=True)
        add('mtime-zeroed', 'literal.mtime',
            'replace the four-octet timestamp with zero',
            lambda raw: edit_mtime(raw, 0))
        for target_format in ('b', 't', 'u'):
            if literal['format'] == target_format:
                continue
            add('format-to-' + target_format, 'literal.format',
                'change only the one-octet format indicator to {!r}'.format(target_format),
                lambda raw, chosen=target_format: edit_format(raw, chosen),
                attribution=('format is outside the signed octets; the raw signed bytes '
                             'still verify, but a decoder may re-encode what it displays'),
                verdict=None)
        add('body-bitflip', 'literal.contents',
            'flip one bit in the literal data',
            flip_body_bit)

    if any(node.tag == 8 for node in walk_packets(reference)):
        for calg in (CompressionAlgorithm.Uncompressed,
                     CompressionAlgorithm.ZLIB):
            add('compression-' + calg.name.lower(), 'framing.compression',
                'replace the compression wrapper, inner packets untouched',
                lambda raw, chosen=calg: replace_compression(raw, chosen),
                attribution=('outer framing only; the document signature covers '
                             'literal data, not the wrapper'),
                framing_changed=True)

    if case.kind == 'signed':
        add('signature-hashed-subpacket', 'signature.hashed-subpacket',
            'zero the hashed CreationTime subpacket',
            edit_hashed_creation_time)

        before = binary
        try:
            after = edit_unhashed_issuer(binary)
            outcome, display = _evaluate(case, after)
            emit(_row(
                'signature-unhashed-subpacket', 'signature.unhashed-subpacket',
                'zero the unhashed Issuer key id', before, after, outcome, display,
                framing_changed=True, baseline_ok=baseline_ok,
                note='advisory key id only; hashed area untouched',
                attribution=('advisory routing hint outside the signed hash; the '
                             'signature math over the literal octets still verifies'),
                verdict=('only-routing-affected'
                         if outcome['signature_math']['state'] == PASS
                         and baseline_ok else 'signature-failed')),
                 after, display)
        except Exception as exc:
            record['mutations'].append({
                'id': 'signature-unhashed-subpacket',
                'error': '{}: {}'.format(type(exc).__name__, exc)})

        add('signature-hash2', 'signature.hash2',
            'flip the two-octet signed-hash prefix', edit_hash2,
            attribution=('quick check only; the signature math is unaffected'))

    if isinstance(case.payload, str):
        _armor_cases(case, record, emit)

    if case.kind == 'encrypted':
        _encrypted_only_cases(case, binary, record, emit)

    record['layer_table'] = layer_table(record)
    record['field_policy'] = field_policy(record)
    record['claims'] = claims(record)
    return record


def _armor_cases(case, record, emit=None):
    armored = case.payload
    original = armored.encode('latin-1')

    inserted = list(armored.splitlines())
    inserted.insert(1, 'Comment: interposed by a relay')
    new_armor = '\n'.join(inserted) + '\n'
    mutants = [('armor-header', 'armor.headers',
                'insert a Comment: header line in the armor envelope',
                new_armor, 'cleartext envelope line; base64 body unchanged',
                'envelope metadata; armor headers are not hashed by the signature'),
               ('armor-crc', 'armor.crc24',
                'replace the radix-64 checksum line',
                _corrupt_crc(armored), 'CRC-24 is an unkeyed transmission check',
                'unkeyed checksum: detects accidental corruption, trivially recomputed')]

    for identifier, field, stimulus, mutant, note, attribution in mutants:
        binary_mutant = bytes(Armorable.ascii_unarmor(mutant)['body']) \
            if _crc_valid(mutant) is not None else None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                outcome = layers(case, mutant)
            display = display_of(case, mutant)
        except Exception as exc:
            record['mutations'].append({'id': identifier, 'field': field,
                                        'error': '{}: {}'.format(type(exc).__name__, exc)})
            continue
        row = {
            'id': identifier, 'field': field, 'stimulus': stimulus,
            'original_packet_sha256': hashlib.sha256(original).hexdigest(),
            'mutant_packet_sha256': hashlib.sha256(mutant.encode('latin-1')).hexdigest(),
            'byte_diff': diff_ranges(original, mutant.encode('latin-1')),
            'framing_changed': False,
            'edit_note': note,
            'result': {'signature': outcome['signature']['state'],
                       'signature_math': outcome['signature_math']['state'],
                       'mdc': outcome['mdc']['state'],
                       'mdc_detail': outcome['mdc'].get('detail')},
            'display_after': display,
            'attribution': attribution,
            'verdict': ('checksum-warning-only'
                        if identifier == 'armor-crc'
                        and outcome['signature_math']['state'] == PASS
                        else _verdict(outcome['signature_math']['state'],
                                      outcome['mdc']['state']))}
        if identifier == 'armor-crc':
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                Armorable.ascii_unarmor(mutant)
            row['result']['crc_warnings'] = [str(item.message) for item in caught]
        if emit is not None:
            emit(row, mutant.encode('latin-1'), display, 'armor')
        else:
            record['mutations'].append(row)


def _crc_valid(armored):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return Armorable.ascii_unarmor(armored)['crc'] is not None
    except Exception:
        return None


def _corrupt_crc(armored):
    lines = armored.splitlines()
    for index, line in enumerate(lines):
        if line.startswith('=') and len(line) >= 5:
            lines[index] = '=' + ('AAAA' if line[1:] != 'AAAA' else 'BBBB')
            break
    return '\n'.join(lines) + '\n'


def _encrypted_only_cases(case, binary, record, emit=None):
    container = next(node for node in walk_packets(binary) if node.tag == 18)
    tampered = bytearray(binary)
    target = container.offset + len(container.header) + 1 + 32
    if target < len(tampered):
        tampered[target] ^= 0x01
    tampered = bytes(tampered)
    outcome, display = _evaluate(case, tampered)
    record['mutations'].append({
        'id': 'ciphertext-bitflip', 'field': 'container.ciphertext',
        'stimulus': 'flip one ciphertext bit without the session key',
        'original_packet_sha256': hashlib.sha256(binary).hexdigest(),
        'mutant_packet_sha256': hashlib.sha256(tampered).hexdigest(),
        'byte_diff': diff_ranges(binary, tampered),
        'framing_changed': False,
        'edit_note': 'no reseal possible without the session key',
        'result': {'signature': outcome['signature']['state'],
                   'signature_math': outcome['signature_math']['state'],
                   'mdc': outcome['mdc']['state'],
                   'mdc_detail': outcome['mdc'].get('detail')},
        'display_after': display,
        'attribution': 'MDC integrity covers the container ciphertext',
        'verdict': _verdict(outcome['signature_math']['state'],
                            outcome['mdc']['state'])})

    opened = open_mdc(case.armor_text, case.decryptor)
    if not opened['inner']:
        return
    old_mdc = opened['plaintext'][-22:]
    edited = edit_filename(opened['inner'], 'malware.sh')
    others = b''.join(chunk for node, chunk in split_packets(binary)
                      if node.tag != 18)
    stale = others + stale_seal(opened['session'], edited, old_mdc)
    outcome, display = _evaluate(case, stale)
    record['mutations'].append({
        'id': 'filename-stale-mdc', 'field': 'literal.filename',
        'stimulus': 'rewrite the filename, reseal the ciphertext, reuse the old MDC packet',
        'original_packet_sha256': hashlib.sha256(binary).hexdigest(),
        'mutant_packet_sha256': hashlib.sha256(stale).hexdigest(),
        'byte_diff': diff_ranges(binary, stale),
        'framing_changed': False,
        'edit_note': 'models a re-encryptor with the session key that skipped the MDC',
        'result': {'signature': outcome['signature']['state'],
                   'signature_math': outcome['signature_math']['state'],
                   'mdc': outcome['mdc']['state'],
                   'mdc_detail': outcome['mdc'].get('detail')},
        'display_after': display,
        'attribution': ('MDC rejects a stale container: integrity of the envelope, '
                        'not sender authentication'),
        'verdict': _verdict(outcome['signature_math']['state'],
                            outcome['mdc']['state'])})


# ---------------------------------------------------------------------------
# policy derived from measurements
# ---------------------------------------------------------------------------

def _rows(record):
    return [row for row in record['mutations'] if 'result' in row]


def layer_table(record):
    table = []
    for row in record['mutations']:
        if 'error' in row:
            table.append({'id': row['id'], 'field': row.get('field'),
                          'error': row['error']})
            continue
        table.append({'id': row['id'], 'field': row['field'],
                      'signature_math': row['result']['signature_math'],
                      'signature_pgpy': row['result']['signature'],
                      'mdc': row['result']['mdc'],
                      'verdict': row['verdict']})
    return table


def field_policy(record):
    baseline_ok = record['baseline'].get('signature_valid', True)
    grouped = {}
    for row in _rows(record):
        field = row['field']
        if not field.startswith('literal.'):
            continue
        entry = grouped.setdefault(field, {'signature_math': set(),
                                           'signature_pgpy': set(),
                                           'mdc': set(), 'mutations': []})
        entry['signature_math'].add(row['result']['signature_math'])
        entry['signature_pgpy'].add(row['result']['signature'])
        entry['mdc'].add(row['result']['mdc'])
        entry['mutations'].append(row['id'])

    table = []
    for field in sorted(grouped):
        entry = grouped[field]
        if FAIL in entry['signature_math'] and baseline_ok:
            authenticated = 'sender document signature'
            display = 'may be shown as authenticated; bind it to the original packet hash'
            landing = 'write the literal body (or its hash) as the canonical artefact'
        elif FAIL in entry['mdc']:
            authenticated = 'none (the MDC covers only the container)'
            display = ('untrusted hint; a resealed container passes the MDC, so an '
                       'MDC failure means tamper, not signer intent')
            landing = ('store beside the signed body with an explicit '
                       'unauthenticated label; never derived from the literal packet')
        elif not baseline_ok:
            authenticated = 'not established (baseline signature invalid)'
            display = ('untrusted hint; the artifact fails verification before any '
                       'field question arises')
            landing = ('quarantine the artifact; do not archive it as signed')
        else:
            authenticated = 'none'
            display = ('untrusted hint; never use as a path, a filename, or a '
                       'trust input; show the packet hash instead')
            landing = ('discard, or store next to the signed packet hash with an '
                       'explicit unauthenticated label')
        table.append({'field': field,
                      'observed_signature_math': sorted(entry['signature_math']),
                      'observed_signature_pgpy': sorted(entry['signature_pgpy']),
                      'observed_mdc': sorted(entry['mdc']),
                      'authenticated_by': authenticated,
                      'display_policy': display,
                      'landing_policy': landing,
                      'mutations': entry['mutations']})
    return table


def claims(record):
    policy = {row['field']: row['authenticated_by'] for row in record['field_policy']}
    return {
        'supported': [
            'The literal body is covered by the document signature; flipping one bit '
            'breaks the signature over the literal octets.',
            'In the encrypted case the same body signature still verifies after the '
            'MDC container is opened and resealed.',
            'Armor headers, the armor CRC, and the compression wrapper are outside '
            'the signed data: replacing them leaves the signature verdict unchanged.',
        ],
        'not_supported': [
            ('MDC integrity is not sender authentication of '
             'literal.filename.' if 'none' in policy.get('literal.filename', '') else
             'Do not describe the MDC as authenticating a filename.'),
            'Do not describe a literal filename, timestamp, or format flag as signed.',
            'Do not call the signature algorithm broken when a field it never covered '
            'is changed; check signature_math before making that claim.',
        ],
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_markdown(record):
    lines = ['## {}'.format(record['case']), '']
    original = record['original']
    lines.append('Original bytes: {} bytes, sha256 `{}`.'.format(
        original['binary_length'], original['binary_sha256']))
    lines.append('')
    lines.append('| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |')
    lines.append('| --- | --- | --- | --- | --- | --- | --- |')
    for row in record['mutations']:
        if 'error' in row:
            lines.append('| `{}` | `{}` | error | | | {} | |'.format(
                row['id'], row.get('field'), row['error']))
            continue
        lines.append('| `{}` | `{}` | {} | {} | {} | {} | {} |'.format(
            row['id'], row['field'], row['result']['signature_math'],
            row['result']['signature'], row['result']['mdc'], row['verdict'],
            row['attribution'].replace('|', '/')))
    lines.append('')
    lines.append('| field | authenticated by | display policy | landing policy |')
    lines.append('| --- | --- | --- | --- |')
    for row in record['field_policy']:
        lines.append('| `{}` | {} | {} | {} |'.format(
            row['field'], row['authenticated_by'],
            row['display_policy'], row['landing_policy']))
    lines.append('')
    return '\n'.join(lines)


def audit_file(path, signer_path=None, decryptor_path=None, kind=None):
    with open(path, 'rb') as handle:
        payload = handle.read()
    if b'-----BEGIN PGP' in payload:
        payload = payload.decode('latin-1')
    signer = PGPKey.from_file(signer_path)[0] if signer_path else None
    decryptor = PGPKey.from_file(decryptor_path)[0] if decryptor_path else None
    kind = kind or ('encrypted' if decryptor is not None else 'signed')
    record = run_matrix(Case(os.path.basename(path), payload,
                             signer=signer, decryptor=decryptor, kind=kind))
    record['artifact'] = os.path.basename(path)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('message')
    parser.add_argument('--signer', help='public key used to verify')
    parser.add_argument('--decryptor', help='secret key used to open an MDC container')
    parser.add_argument('--kind', choices=['signed', 'encrypted', 'detached'])
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    record = audit_file(args.message, args.signer, args.decryptor, args.kind)
    print(json.dumps(record, indent=2, sort_keys=True) if args.json
          else render_markdown(record))
    return 0


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
