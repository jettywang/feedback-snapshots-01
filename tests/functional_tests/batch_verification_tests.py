from __future__ import unicode_literals

import hmac as hmac_module

import pytest
from nacl.exceptions import CryptoError

from pymacaroons import Macaroon, SignatureCache, Verifier
from pymacaroons.exceptions import (
    MacaroonInvalidSignatureException,
    MacaroonUnmetCaveatException,
)
from pymacaroons.serializers import BinarySerializer

ROOT_KEY = 'batch root key'
IDENTIFIER = 'batch-token-id'
TP_LOCATION = 'https://auth.example.com'
TP_KEY = 'third party key'
TP_KEY_ID = 'tp caveat 1'
TP_NONCE = b'\x01' * 24
DISCHARGE_CAVEAT = 'discharge = ok'

PREFIX_CAVEATS = ['level{0} = ok'.format(i) for i in range(12)]
BRANCH_A = 'branch = A'
BRANCH_B = 'branch = B'  # differs from BRANCH_A by exactly one byte


def mint_token(branch, request_id, third_party=True):
    '''A token with a long shared caveat prefix (including a third-party
    caveat minted with a fixed nonce so the prefix bytes are identical
    across the batch), then a one-byte-different branch caveat, then a
    per-request unique caveat.'''
    m = Macaroon(
        location='https://service.example.com',
        identifier=IDENTIFIER,
        key=ROOT_KEY,
    )
    for index, predicate in enumerate(PREFIX_CAVEATS):
        m.add_first_party_caveat(predicate)
        if third_party and index == 5:
            m.add_third_party_caveat(
                TP_LOCATION, TP_KEY, TP_KEY_ID, nonce=TP_NONCE
            )
    m.add_first_party_caveat(branch)
    m.add_first_party_caveat('req = {0}'.format(request_id))
    return m


def mint_discharge():
    discharge = Macaroon(
        location=TP_LOCATION, identifier=TP_KEY_ID, key=TP_KEY
    )
    discharge.add_first_party_caveat(DISCHARGE_CAVEAT)
    return discharge


def bound_discharge(root):
    return root.prepare_for_request(mint_discharge())


def all_predicates(token):
    predicates = [c.caveat_id for c in token.first_party_caveats()]
    predicates.append(DISCHARGE_CAVEAT)
    return predicates


def tamper_hex(signature):
    prefix = 'ff' if not signature.startswith('ff') else '00'
    return prefix + signature[2:]


def make_verifier(token, cache, log, satisfied=None, discharge='bound'):
    if discharge == 'bound':
        discharges = [bound_discharge(token)]
    elif discharge == 'unrelated':
        # a discharge macaroon for some other identifier, so the
        # required one is simply absent
        discharges = [Macaroon(
            location=TP_LOCATION, identifier='unrelated', key=TP_KEY
        )]
    else:
        discharges = None
    verifier = Verifier(
        discharge_macaroons=discharges,
        signature_cache=cache,
    )
    for predicate in (satisfied if satisfied is not None
                      else all_predicates(token)):
        verifier.satisfy_exact(predicate)

    def general(predicate):
        log.append(predicate)
        return False

    verifier.satisfy_general(general)
    return verifier


@pytest.fixture
def hmac_counter(monkeypatch):
    counter = {'count': 0}
    real_new = hmac_module.new

    def counting_new(*args, **kwargs):
        counter['count'] += 1
        return real_new(*args, **kwargs)

    monkeypatch.setattr(hmac_module, 'new', counting_new)
    return counter


def outcome_of(func):
    try:
        return func()
    except Exception as exc:
        return type(exc)


class TestBatchVerification(object):

    def test_shared_prefix_hmac_reduction_and_cache_bounds(
            self, hmac_counter):
        request_count = 8
        tokens = [
            mint_token(BRANCH_A if i % 2 == 0 else BRANCH_B, i)
            for i in range(request_count)
        ]

        # Baseline: each token verified independently, no cache.
        sequential_costs = []
        for token in tokens:
            verifier = make_verifier(token, None, [])
            start = hmac_counter['count']
            assert verifier.verify(token, ROOT_KEY) is True
            sequential_costs.append(hmac_counter['count'] - start)
        assert len(set(sequential_costs)) == 1
        sequential_total = sum(sequential_costs)

        # Cached: every request gets its own verifier (its own
        # predicates, callbacks and discharge macaroons) but all share
        # one bounded signature cache.
        cache = SignatureCache(maxsize=1024, ttl=300.0)
        cached_costs = []
        for token in tokens:
            verifier = make_verifier(token, cache, [])
            start = hmac_counter['count']
            assert verifier.verify(token, ROOT_KEY) is True
            cached_costs.append(hmac_counter['count'] - start)

        # Cold-cache first request costs exactly the same as
        # sequential. Every later request only pays for its non-shared
        # suffix; the first request to see the second branch pays one
        # extra HMAC to extend the cache.
        assert cached_costs[0] == sequential_costs[0]
        steady_residual = cached_costs[2]
        assert all(cost == steady_residual for cost in cached_costs[2:])
        assert cached_costs[1] == steady_residual + 1
        assert 0 < steady_residual < sequential_costs[0]

        saved = sequential_total - sum(cached_costs)
        assert saved == (request_count - 1) * (
            sequential_costs[0] - steady_residual
        ) - 1

        # Worst-case cache size: one entry per distinct
        # (key, identifier, prefix) chain state:
        #   1 initial signature
        #   12 shared first-party prefixes
        #   1 shared third-party prefix
        #   2 one-byte-different branches
        #   8 unique per-request caveats
        #   2 discharge macaroon chain states (shared caveat key)
        expected_entries = 1 + 12 + 1 + 2 + request_count + 2
        assert len(cache) == expected_entries
        assert len(cache) <= cache.maxsize

        print('\nbatch of {0}: HMACs sequential={1}, cached={2}, '
              'saved={3}; worst cache size={4} entries'.format(
                  request_count, sequential_total, sum(cached_costs),
                  saved, len(cache)))

    def test_mixed_batch_decisions_and_callbacks_match_sequential(self):
        def build_requests():
            tokens = [
                mint_token(BRANCH_A, 0),   # valid
                mint_token(BRANCH_B, 1),   # valid
                mint_token(BRANCH_A, 2),   # unmet caveat
                mint_token(BRANCH_B, 3),   # tampered caveat id
                mint_token(BRANCH_A, 4),   # discharge missing
                mint_token(BRANCH_B, 5),   # valid
                mint_token(BRANCH_A, 6),   # tampered signature
            ]
            # caller mutates one byte of a prefix caveat after minting
            tokens[3].caveats[0].caveat_id = 'levelX = ok'
            # caller tampers with the token signature
            tokens[6].signature = tamper_hex(tokens[6].signature)
            policies = [all_predicates(t) for t in tokens]
            policies[2] = [
                p for p in policies[2] if p != 'level3 = ok'
            ]
            return tokens, policies

        def run(cache):
            tokens, policies = build_requests()
            outcomes, logs = [], []
            for index, token in enumerate(tokens):
                log = []
                verifier = make_verifier(
                    token, cache, log,
                    satisfied=policies[index],
                    discharge='unrelated' if index == 4 else 'bound',
                )
                outcomes.append(outcome_of(
                    lambda: verifier.verify(token, ROOT_KEY)
                ))
                logs.append(log)
            return outcomes, logs

        sequential_outcomes, sequential_logs = run(None)

        # Warm the cache with valid traffic first, so the mixed batch
        # runs entirely against a hot cache.
        cache = SignatureCache(maxsize=1024, ttl=300.0)
        warm = mint_token(BRANCH_A, 99)
        make_verifier(warm, cache, []).verify(warm, ROOT_KEY)
        cached_outcomes, cached_logs = run(cache)

        # Note: when the signature chain diverges before the
        # third-party caveat, the existing library behavior is a
        # CryptoError from failing to decrypt the caveat key; the cache
        # must reproduce these decisions exactly.
        expected = [
            True,
            True,
            CryptoError,                         # unmet caveat
            CryptoError,                         # tampered caveat id
            MacaroonUnmetCaveatException,        # discharge missing
            True,
            MacaroonInvalidSignatureException,   # tampered signature
        ]
        assert sequential_outcomes == expected
        # Per-item decisions are identical with and without the cache,
        # even for items after a failure (the batch is not interrupted)
        # and even on a hot cache (no stale auth conclusions).
        assert cached_outcomes == sequential_outcomes
        # Every request still runs its own caveat checks: the exact
        # callback invocation record is identical.
        assert cached_logs == sequential_logs
        assert all(len(log) > 0 for log in cached_logs)

    def test_verify_batch_returns_per_item_results(self, hmac_counter):
        tokens = [mint_token(BRANCH_A, i, third_party=False)
                  for i in range(4)]
        tokens[2].signature = tamper_hex(tokens[2].signature)

        def run(cache):
            verifier = Verifier(signature_cache=cache)
            for i in (0, 1, 3):
                for predicate in all_predicates(tokens[i])[:-1]:
                    verifier.satisfy_exact(predicate)
            return [
                type(r) if isinstance(r, Exception) else r
                for r in verifier.verify_batch(tokens, ROOT_KEY)
            ]

        sequential = run(None)
        cached = run(SignatureCache(maxsize=64, ttl=60.0))
        expected = [True, True, MacaroonInvalidSignatureException, True]
        # a failing item neither interrupts the batch nor changes the
        # per-item decisions when the cache is enabled
        assert sequential == expected
        assert cached == expected

    def test_mutation_after_success_does_not_reuse_cached_conclusion(self):
        cache = SignatureCache(maxsize=64, ttl=300.0)
        token = mint_token(BRANCH_A, 0)
        make_verifier(token, cache, []).verify(token, ROOT_KEY)

        # Same token, one caveat byte modified by the caller afterwards.
        token.caveats[7].caveat_id = 'level7 = NO'
        with pytest.raises(MacaroonInvalidSignatureException):
            make_verifier(token, cache, []).verify(token, ROOT_KEY)

        # Same token, signature modified by the caller afterwards.
        token = mint_token(BRANCH_A, 0)
        token.signature = tamper_hex(token.signature)
        with pytest.raises(MacaroonInvalidSignatureException):
            make_verifier(token, cache, []).verify(token, ROOT_KEY)

        # Serialized token with one signature byte flipped also fails
        # against the hot cache.
        token = mint_token(BRANCH_A, 0)
        serializer = BinarySerializer()
        raw = bytearray(serializer.serialize_raw(token))
        # last byte is a trailing newline; flip the final signature byte
        raw[-2] ^= 0x01
        tampered = serializer.deserialize_raw(bytes(raw))
        with pytest.raises(MacaroonInvalidSignatureException):
            make_verifier(tampered, cache, []).verify(tampered, ROOT_KEY)

    def test_consumed_discharge_is_never_cached(self):
        cache = SignatureCache(maxsize=64, ttl=300.0)
        token = mint_token(BRANCH_A, 0)

        verifier = Verifier(
            discharge_macaroons=[bound_discharge(token)],
            signature_cache=cache,
        )
        for predicate in all_predicates(token):
            verifier.satisfy_exact(predicate)
        assert verifier.verify(token, ROOT_KEY) is True

        # The discharge was consumed by the first verification; a second
        # verification of the same token with the same verifier must
        # still fail even though every signature is cached.
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(token, ROOT_KEY)


class TestSignatureCache(object):

    def test_capacity_evicts_least_recently_used(self):
        cache = SignatureCache(maxsize=2, ttl=300.0)
        cache.put('a', b'1')
        cache.put('b', b'2')
        assert cache.get('a') == b'1'  # refresh recency
        cache.put('c', b'3')
        assert cache.get('b') is None
        assert cache.get('a') == b'1'
        assert cache.get('c') == b'3'
        assert len(cache) == 2

    def test_ttl_expires_entries(self):
        now = [1000.0]
        cache = SignatureCache(maxsize=8, ttl=10.0, clock=lambda: now[0])
        cache.put('a', b'1')
        now[0] += 5.0
        assert cache.get('a') == b'1'
        now[0] += 10.0
        assert cache.get('a') is None
        assert len(cache) == 0

    def test_rejects_invalid_bounds(self):
        with pytest.raises(ValueError):
            SignatureCache(maxsize=0)
        with pytest.raises(ValueError):
            SignatureCache(ttl=0)
