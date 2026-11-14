# -*- coding: utf-8 -*-
"""
Structured fuzz tests for Noise PSK pattern modifiers.

Covers, for every base handshake pattern supported by this repository
(N, K, X, NN, KN, NK, KK, NX, KX, XN, IN, XK, IK, XX, IX):

* protocol name parsing of a bounded corpus of legal and illegal modifier
  combinations (psk0, message-end positions, multi-PSK, duplicated positions,
  negative indexes, out-of-range indexes, malformed modifiers),
* token insertion positions, checked against an independently derived
  reference model of Noise spec rev 34 section 9.3,
* the actual PSK consumption order during the handshake, observed by spying
  on SymmetricState.mix_key_and_hash and on the ephemeral-key MixKey calls
  (not only on the parser output),
* consistency of legal combinations with the public cacophony / snow
  multi-PSK test vectors,
* rejection of illegal combinations before any PSK is consumed, and
* preservation of the caller-provided PSK list (the handshake must not
  drain the list object handed to NoiseConnection.set_psks).

Findings kept from fuzzing
--------------------------
Minimal failing protocol name: ``Noise_NNpsk-1_25519_ChaChaPoly_SHA256``

State trace (current, buggy behaviour)::

    NoiseConnection.from_name(b'Noise_NNpsk-1_25519_ChaChaPoly_SHA256')
      -> UnpackedName.from_protocol_name: pattern='NN', pattern_modifiers=['psk-1']
      -> Pattern.apply_pattern_modifiers(['psk-1'])
           int('-1') == -1; bounds check (-1 // 2 = -1) > 2 is False  -> passes
           index != 0 -> self.tokens[-2].append(TOKEN_PSK)            # negative index wrap-around
      -> pattern.tokens == [['e', 'psk'], ['e', 'ee']]                 # silently identical to NNpsk1
      -> pattern.psk_count == 1, is_psk_handshake == True
    start_handshake() + write_message()
      -> SymmetricState.mix_key_and_hash(psks.pop(0))                  # a real PSK is consumed

Expected behaviour: rejected with ValueError before any PSK is consumed.
See TestMinimalFailingCase below (xfail until fixed).

Secondary finding: out-of-range indexes that are "near" the message count
(e.g. psk3/psk4/psk5 on a 2-message pattern such as NN, psk2/psk3 on a
1-message pattern such as N) raise a bare IndexError instead of a clean
ValueError, because the bounds check uses ``index // 2 > len(tokens)``
instead of ``index > len(tokens)``. Also ``psk-0`` is accepted as an alias
of ``psk0``. See TestOutOfRangeIndexError.
"""
import json
import os
import random

import pytest

from noise.backends.default import noise_backend
from noise.connection import Keypair, NoiseConnection
from noise.constants import TOKEN_E, TOKEN_PSK, TOKEN_S
from noise.exceptions import NoiseProtocolNameError, NoisePSKError
from noise.state import SymmetricState

DH = b'25519'
CIPHER = b'ChaChaPoly'
HASH = b'SHA256'

BASE_PATTERN_NAMES = ['N', 'K', 'X', 'NN', 'KN', 'NK', 'KK', 'NX', 'KX', 'XN', 'IN', 'XK', 'IK', 'XX', 'IX']

# Fixed 25519 private keys so ephemeral public keys (and therefore the
# ephemeral MixKey inputs) are known in advance.
INIT_STATIC_PRIV = b'\x01' * 32
RESP_STATIC_PRIV = b'\x02' * 32
INIT_EPH_PRIV = b'\x03' * 32
RESP_EPH_PRIV = b'\x04' * 32

# Distinct, recognisable PSKs so consumption order can be verified.
PSKS = [bytes([0xA0 + i]) * 32 for i in range(8)]


# ---------------------------------------------------------------------------
# Reference model (independent derivation of spec rev 34 section 9.3)
# ---------------------------------------------------------------------------

def base_tokens(pattern_name):
    """Unmodified token sequence of a base pattern, straight from its class."""
    pattern = noise_backend.patterns[pattern_name]()
    return [list(message) for message in pattern.tokens]


def reference_apply_modifiers(pattern_name, modifiers):
    """
    Independently derived token sequence after applying psk modifiers:
    psk0 inserts TOKEN_PSK at the beginning of the first message,
    pskN (N >= 1) appends TOKEN_PSK at the end of message N.
    Raises ValueError for anything outside that rule.
    """
    tokens = base_tokens(pattern_name)
    for modifier in modifiers:
        if not modifier.startswith('psk'):
            raise ValueError('Unknown pattern modifier {}'.format(modifier))
        digits = modifier[3:]
        if not digits.isdigit():
            raise ValueError('Improper psk modifier {}'.format(modifier))
        index = int(digits)
        if index > len(tokens):
            raise ValueError('Modifier {} cannot be applied - pattern has not enough messages'.format(modifier))
        if index == 0:
            tokens[0].insert(0, TOKEN_PSK)
        else:
            tokens[index - 1].append(TOKEN_PSK)
    return tokens


def protocol_name(pattern_name, modifiers):
    suffix = '+'.join(modifiers)
    return b'_'.join([b'Noise', (pattern_name + suffix).encode(), DH, CIPHER, HASH])


# ---------------------------------------------------------------------------
# Bounded corpus of legal modifier combinations
# ---------------------------------------------------------------------------

def legal_modifier_combos():
    combos = []
    for name in BASE_PATTERN_NAMES:
        message_count = len(base_tokens(name))
        positions = list(range(message_count + 1))  # 0..message_count
        for position in positions:  # single psk, incl. psk0 and last-message position
            combos.append((name, ('psk{}'.format(position),)))
        for first in positions:  # all pairs, incl. duplicated positions (psk0+psk0, psk2+psk2, ...)
            for second in positions:
                combos.append((name, ('psk{}'.format(first), 'psk{}'.format(second))))
        if message_count >= 2:  # multi-PSK triple as used by the snow-multipsk vectors (e.g. NXpsk0+psk1+psk2)
            combos.append((name, ('psk0', 'psk1', 'psk2')))
        if message_count == 3:  # quad as used by the snow-multipsk vectors (XXpsk0+psk1+psk2+psk3)
            combos.append((name, ('psk0', 'psk1', 'psk2', 'psk3')))
    return combos


LEGAL_COMBOS = legal_modifier_combos()


def combo_id(combo):
    return '{}-{}'.format(combo[0], '+'.join(combo[1]))


# ---------------------------------------------------------------------------
# Handshake driver and SymmetricState spy
# ---------------------------------------------------------------------------

@pytest.fixture
def mix_trace(monkeypatch):
    """Records every mix_key_and_hash / mix_key call as (state_id, method, ikm)."""
    events = []
    original_mkah = SymmetricState.mix_key_and_hash
    original_mk = SymmetricState.mix_key

    def mkah(self, ikm):
        events.append((id(self), 'mix_key_and_hash', bytes(ikm)))
        return original_mkah(self, ikm)

    def mk(self, ikm):
        events.append((id(self), 'mix_key', bytes(ikm)))
        return original_mk(self, ikm)

    monkeypatch.setattr(SymmetricState, 'mix_key_and_hash', mkah)
    monkeypatch.setattr(SymmetricState, 'mix_key', mk)
    return events


def build_connection(name, initiator, psks):
    conn = NoiseConnection.from_name(name)
    conn.set_psks(psks=list(psks))
    conn.set_keypair_from_private_bytes(Keypair.STATIC, INIT_STATIC_PRIV if initiator else RESP_STATIC_PRIV)
    conn.set_keypair_from_private_bytes(Keypair.EPHEMERAL, INIT_EPH_PRIV if initiator else RESP_EPH_PRIV)
    if initiator:
        conn.set_as_initiator()
    else:
        conn.set_as_responder()
    return conn


def make_pair(name, psks):
    init = build_connection(name, True, psks)
    resp = build_connection(name, False, psks)
    init.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, resp.noise_protocol.keypairs['s'].public_bytes)
    resp.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, init.noise_protocol.keypairs['s'].public_bytes)
    return init, resp


def drive_handshake(init, resp):
    turns = 0
    while not (init.handshake_finished and resp.handshake_finished):
        resp.read_message(init.write_message(b''))
        if init.handshake_finished and resp.handshake_finished:
            break
        init.read_message(resp.write_message(b''))
        turns += 1
        assert turns < 10, 'handshake did not terminate'


def expected_side_events(tokens, writes_even_messages, own_e_pub, peer_e_pub, psks):
    """
    Expected (method, ikm) sequence for one party. ikm is None for DH-token
    MixKey calls (wildcard); ephemeral and PSK inputs are checked exactly.
    """
    events = []
    psk_iter = iter(psks)
    for index, message in enumerate(tokens):
        writing = (index % 2 == 0) == writes_even_messages
        for token in message:
            if token == TOKEN_E:
                events.append(('mix_key', own_e_pub if writing else peer_e_pub))
            elif token == TOKEN_PSK:
                events.append(('mix_key_and_hash', next(psk_iter)))
            elif token != TOKEN_S:  # ee / es / se / ss
                events.append(('mix_key', None))
    return events


def assert_events_match(actual, expected):
    assert len(actual) == len(expected), 'event count mismatch: {} vs {}'.format(actual, expected)
    for (actual_method, actual_ikm), (expected_method, expected_ikm) in zip(actual, expected):
        assert actual_method == expected_method
        if expected_ikm is not None:
            assert actual_ikm == expected_ikm


# ---------------------------------------------------------------------------
# Legal combinations: parse + token positions + observed handshake PSK order
# ---------------------------------------------------------------------------

@pytest.mark.filterwarnings('ignore:One of ephemeral keypairs')
class TestLegalCombinations(object):
    @pytest.mark.parametrize('pattern_name,modifiers', LEGAL_COMBOS, ids=map(combo_id, LEGAL_COMBOS))
    def test_tokens_match_reference_model(self, pattern_name, modifiers):
        conn = NoiseConnection.from_name(protocol_name(pattern_name, modifiers))
        protocol = conn.noise_protocol
        assert protocol.is_psk_handshake
        assert protocol.pattern.psk_count == len(modifiers)
        assert protocol.pattern.tokens == reference_apply_modifiers(pattern_name, modifiers)

    @pytest.mark.parametrize('pattern_name,modifiers', LEGAL_COMBOS, ids=map(combo_id, LEGAL_COMBOS))
    def test_handshake_psk_order_and_ephemeral_mix_key(self, pattern_name, modifiers, mix_trace):
        name = protocol_name(pattern_name, modifiers)
        psks = PSKS[:len(modifiers)]
        init, resp = make_pair(name, psks)
        init_e_pub = init.noise_protocol.keypairs['e'].public_bytes
        resp_e_pub = resp.noise_protocol.keypairs['e'].public_bytes
        init.start_handshake()
        resp.start_handshake()
        init_state_id = id(init.noise_protocol.symmetric_state)
        resp_state_id = id(resp.noise_protocol.symmetric_state)

        drive_handshake(init, resp)

        tokens = reference_apply_modifiers(pattern_name, modifiers)
        init_events = [(method, ikm) for sid, method, ikm in mix_trace if sid == init_state_id]
        resp_events = [(method, ikm) for sid, method, ikm in mix_trace if sid == resp_state_id]
        assert_events_match(init_events, expected_side_events(tokens, True, init_e_pub, resp_e_pub, psks))
        assert_events_match(resp_events, expected_side_events(tokens, False, resp_e_pub, init_e_pub, psks))

        # PSKs are consumed through mix_key_and_hash in exactly the provided order, on both sides
        assert [ikm for method, ikm in init_events if method == 'mix_key_and_hash'] == psks
        assert [ikm for method, ikm in resp_events if method == 'mix_key_and_hash'] == psks
        # Every 'e' token triggered the PSK-handshake ephemeral MixKey with the ephemeral public key
        e_count = sum(message.count(TOKEN_E) for message in tokens)
        ephemeral_mix_keys = [ikm for method, ikm in init_events
                              if method == 'mix_key' and ikm in (init_e_pub, resp_e_pub)]
        assert len(ephemeral_mix_keys) == e_count

    def test_caller_psk_list_is_not_drained(self):
        caller_psks = [PSKS[0], PSKS[1]]
        init, resp = make_pair(protocol_name('NN', ('psk0', 'psk2')), caller_psks)
        init.start_handshake()
        resp.start_handshake()
        drive_handshake(init, resp)
        assert caller_psks == [PSKS[0], PSKS[1]]

    def test_wrong_psk_count_rejected_before_consuming_any_psk(self):
        conn = NoiseConnection.from_name(protocol_name('NN', ('psk0', 'psk2')))
        conn.set_psks(psks=[PSKS[0]])
        conn.set_as_initiator()
        with pytest.raises(NoisePSKError):
            conn.start_handshake()
        assert conn.noise_protocol.psks == [PSKS[0]]  # nothing popped


# ---------------------------------------------------------------------------
# Illegal combinations: must be rejected before any PSK is consumed
# ---------------------------------------------------------------------------

class TestIllegalCombinations(object):
    @pytest.mark.parametrize('suffix', ['psk', 'psk1x', 'pskA', 'psk999', 'foo', 'PSK1'])
    @pytest.mark.parametrize('pattern_name', BASE_PATTERN_NAMES)
    def test_malformed_modifier_rejected(self, pattern_name, suffix):
        with pytest.raises((ValueError, NoiseProtocolNameError)):
            NoiseConnection.from_name(protocol_name(pattern_name, (suffix,)))

    @pytest.mark.parametrize('suffix', ['psk0+', '+psk0', 'psk0++psk1', 'psk+psk0'])
    def test_empty_modifier_rejected(self, suffix):
        with pytest.raises((ValueError, NoiseProtocolNameError)):
            NoiseConnection.from_name(protocol_name('NN', (suffix,)))

    def test_fallback_modifier_not_implemented(self):
        with pytest.raises(NotImplementedError):
            NoiseConnection.from_name(protocol_name('NN', ('fallback',)))

    def test_far_out_of_range_rejected_cleanly(self):
        # index // 2 > message_count triggers the intended ValueError path
        with pytest.raises(ValueError):
            NoiseConnection.from_name(protocol_name('NN', ('psk6',)))


class TestMinimalFailingCase(object):
    """
    Kept minimal failing protocol name found by the fuzzer:
    b'Noise_NNpsk-1_25519_ChaChaPoly_SHA256' - a negative psk index is
    silently accepted and, through Python's negative list indexing, lands on
    the first message (identical state trajectory to legitimate NNpsk1),
    consuming a real PSK. See module docstring for the full state trace.
    """

    MINIMAL_FAILING_NAME = b'Noise_NNpsk-1_25519_ChaChaPoly_SHA256'

    @pytest.mark.xfail(reason='negative psk index accepted via tokens[-2] wrap-around', strict=True)
    def test_negative_index_rejected(self):
        with pytest.raises(ValueError):
            NoiseConnection.from_name(self.MINIMAL_FAILING_NAME)

    def test_negative_index_state_trace_documents_bug(self):
        # Pins the current (buggy) state trajectory so a fix flips this test.
        conn = NoiseConnection.from_name(self.MINIMAL_FAILING_NAME)
        assert conn.noise_protocol.pattern.tokens == [[TOKEN_E, TOKEN_PSK], [TOKEN_E, 'ee']]
        assert conn.noise_protocol.pattern.psk_count == 1

    @pytest.mark.xfail(reason='psk-0 accepted as alias of psk0', strict=True)
    def test_negative_zero_rejected(self):
        with pytest.raises(ValueError):
            NoiseConnection.from_name(b'Noise_NNpsk-0_25519_ChaChaPoly_SHA256')


class TestOutOfRangeIndexError(object):
    """Near out-of-range indexes raise a bare IndexError instead of ValueError."""

    @pytest.mark.xfail(reason='bounds check uses index // 2 > len(tokens)', strict=True)
    @pytest.mark.parametrize('suffix', ['psk3', 'psk4', 'psk5'])
    def test_near_out_of_range_raises_value_error(self, suffix):
        with pytest.raises(ValueError):
            NoiseConnection.from_name(protocol_name('NN', (suffix,)))

    def test_near_out_of_range_currently_index_error(self):
        # Pins the current (buggy) behaviour so a fix flips this test.
        with pytest.raises(IndexError):
            NoiseConnection.from_name(protocol_name('NN', ('psk3',)))


# ---------------------------------------------------------------------------
# Seeded structured fuzz round
# ---------------------------------------------------------------------------

# Known-bug zone pinned by the tests above: negative indexes and indexes in
# message_count < index <= 2 * message_count + 1 are excluded here on purpose.
FUZZ_ALPHABET = ['psk0', 'psk1', 'psk2', 'psk3', 'psk', 'psk1x', 'psk999', 'foo', '', 'fallback', 'PSK1']


def in_known_bug_zone(pattern_name, modifiers):
    message_count = len(base_tokens(pattern_name))
    for modifier in modifiers:
        if modifier.startswith('psk') and modifier[3:].isdigit():
            index = int(modifier[3:])
            if message_count < index <= 2 * message_count + 1:
                return True
    return False


class TestSeededFuzz(object):
    @pytest.mark.parametrize('seed', range(120))
    def test_random_modifier_strings(self, seed):
        rng = random.Random(3407 + seed)
        pattern_name = rng.choice(BASE_PATTERN_NAMES)
        modifiers = tuple(rng.choice(FUZZ_ALPHABET) for _ in range(rng.randint(1, 3)))
        if not '+'.join(modifiers):
            pytest.skip('degenerated to a modifier-less protocol name')
        if in_known_bug_zone(pattern_name, modifiers):
            pytest.skip('known-bug zone, pinned by dedicated tests')
        try:
            expected = reference_apply_modifiers(pattern_name, modifiers)
        except ValueError:
            with pytest.raises((ValueError, NoiseProtocolNameError, NotImplementedError)):
                NoiseConnection.from_name(protocol_name(pattern_name, modifiers))
        else:
            conn = NoiseConnection.from_name(protocol_name(pattern_name, modifiers))
            assert conn.noise_protocol.pattern.tokens == expected
            assert conn.noise_protocol.pattern.psk_count == len(modifiers)


# ---------------------------------------------------------------------------
# Consistency with public test vectors
# ---------------------------------------------------------------------------

def load_vectors(filename):
    path = os.path.join(os.path.dirname(__file__), 'vectors', filename)
    with open(path) as fd:
        return json.load(fd)


def hexed(value):
    return bytes.fromhex(value) if value else None


def run_vector(vector):
    init = NoiseConnection.from_name(vector['protocol_name'].encode())
    resp = NoiseConnection.from_name(vector['protocol_name'].encode())
    for conn, prefix in ((init, 'init'), (resp, 'resp')):
        prologue = hexed(vector.get(prefix + '_prologue'))
        if prologue:
            conn.set_prologue(prologue)
        conn.set_psks(psks=[bytes.fromhex(p) for p in vector[prefix + '_psks']])
        static = hexed(vector.get(prefix + '_static'))
        if static:
            conn.set_keypair_from_private_bytes(Keypair.STATIC, static)
        ephemeral = hexed(vector.get(prefix + '_ephemeral'))
        if ephemeral:
            conn.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral)
        remote_static = hexed(vector.get(prefix + '_remote_static'))
        if remote_static:
            conn.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static)
    init.set_as_initiator()
    resp.set_as_responder()
    init.start_handshake()
    resp.start_handshake()

    conns = (init, resp)
    one_way = init.noise_protocol.pattern.one_way
    for turn, message in enumerate(vector['messages']):
        payload = bytes.fromhex(message['payload'])
        ciphertext = bytes.fromhex(message['ciphertext'])
        if not init.handshake_finished:
            sender, receiver = conns[turn % 2], conns[(turn + 1) % 2]
            assert bytes(sender.write_message(payload)) == ciphertext
            assert bytes(receiver.read_message(ciphertext)) == payload
        else:
            if one_way or turn % 2 == 0:
                sender, receiver = init, resp
            else:
                sender, receiver = resp, init
            assert sender.encrypt(payload) == ciphertext
            assert receiver.decrypt(ciphertext) == payload
    assert init.handshake_finished and resp.handshake_finished
    if vector.get('handshake_hash'):
        assert init.get_handshake_hash() == resp.get_handshake_hash() == bytes.fromhex(vector['handshake_hash'])


@pytest.mark.filterwarnings('ignore:One of ephemeral keypairs')
class TestPublicVectorConsistency(object):
    def test_vector_modifiers_covered_by_legal_corpus(self):
        vector_names = {v['protocol_name'] for v in load_vectors('snow-multipsk.txt')}
        vector_names.update(v['protocol_name'] for v in load_vectors('cacophony.txt') if 'psk' in v['protocol_name'])
        generated_pairs = {(p, m) for p, m in LEGAL_COMBOS}
        missing = set()
        for name in vector_names:
            pattern_part = name.split('_')[1]
            for pattern_name in sorted(BASE_PATTERN_NAMES, key=len, reverse=True):
                if pattern_part.startswith(pattern_name):
                    modifiers = tuple(pattern_part[len(pattern_name):].split('+'))
                    break
            if (pattern_name, modifiers) not in generated_pairs:
                missing.add(name)
        assert not missing, 'vector modifiers missing from legal corpus: {}'.format(sorted(missing))

    @pytest.mark.parametrize('vector', [
        v for v in load_vectors('snow-multipsk.txt')
        if v['protocol_name'].endswith('_25519_ChaChaPoly_SHA256')
    ], ids=lambda v: v['protocol_name'])
    def test_snow_multipsk_vectors(self, vector):
        run_vector(vector)

    @pytest.mark.parametrize('vector', [
        v for v in load_vectors('cacophony.txt')
        if v['protocol_name'] in ('Noise_Npsk0_25519_ChaChaPoly_SHA256',
                                  'Noise_Kpsk0_25519_ChaChaPoly_SHA256',
                                  'Noise_Xpsk1_25519_ChaChaPoly_SHA256')
    ], ids=lambda v: v['protocol_name'])
    def test_cacophony_one_way_psk_vectors(self, vector):
        run_vector(vector)
