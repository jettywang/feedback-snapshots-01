import binascii

try:
    # py2.7.7+ and py3.3+ have native comparison support
    from hmac import compare_digest as constant_time_compare
except ImportError:
    from pymacaroons.utils import equals as constant_time_compare

from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.exceptions import MacaroonInvalidSignatureException
from pymacaroons.caveat_delegates import (
    FirstPartyCaveatVerifierDelegate,
    ThirdPartyCaveatVerifierDelegate,
)
from pymacaroons.utils import (
    convert_to_bytes,
    convert_to_string,
    generate_derived_key,
    hmac_digest
)


class Verifier(object):

    def __init__(self, discharge_macaroons=None, signature_cache=None):
        self.predicates = []
        self.callbacks = [self.verify_exact]
        self.calculated_signature = None
        # Optional SignatureCache shared across verify() calls. Only
        # intermediate HMAC chain state is cached; every caveat check,
        # discharge consumption, and final signature comparison still
        # runs per request.
        self.signature_cache = signature_cache
        self.first_party_caveat_verifier_delegate = (
            FirstPartyCaveatVerifierDelegate()
        )
        self.third_party_caveat_verifier_delegate = (
            ThirdPartyCaveatVerifierDelegate(
                discharge_macaroons=discharge_macaroons
            )
        )

    def satisfy_exact(self, predicate):
        if predicate is None:
            raise TypeError('Predicate cannot be none.')
        self.predicates.append(convert_to_string(predicate))

    def satisfy_general(self, func):
        if not hasattr(func, '__call__'):
            raise TypeError('General caveat verifiers must be callable.')
        self.callbacks.append(func)

    def verify_exact(self, predicate):
        return predicate in self.predicates

    def verify(self, macaroon, key):
        key = generate_derived_key(convert_to_bytes(key))
        return self.verify_discharge(
            macaroon,
            macaroon,
            key,
        )

    def verify_batch(self, macaroons, key):
        '''Verify a batch of macaroons, returning one result per item.

        Each item is verified independently: every caveat check runs and
        the final signature is compared for every macaroon. When the
        verifier was given a signature_cache, intermediate signature
        chain state shared between macaroons (e.g. a long common caveat
        prefix) is computed only once.

        :return: a list with True for each verified macaroon, or the
        raised exception for each macaroon that failed verification.
        '''
        results = []
        for macaroon in macaroons:
            try:
                results.append(self.verify(macaroon, key))
            except Exception as exc:
                results.append(exc)
        return results

    def verify_discharge(self, root, discharge, key):
        cache_prefix = None
        calculated_signature = None
        if self.signature_cache is not None:
            cache_prefix = (key, discharge.identifier_bytes)
            calculated_signature = self.signature_cache.get(cache_prefix)
        if calculated_signature is None:
            calculated_signature = hmac_digest(
                key, discharge.identifier_bytes
            )
            if self.signature_cache is not None:
                self.signature_cache.put(cache_prefix, calculated_signature)

        calculated_signature = self._verify_caveats(
            root, discharge, calculated_signature,
            cache_prefix=cache_prefix,
        )

        if root != discharge:
            calculated_signature = binascii.unhexlify(
                HashSignaturesBinder(root).bind_signature(
                    binascii.hexlify(calculated_signature)
                )
            )

        if not self._signatures_match(
                discharge.signature_bytes,
                binascii.hexlify(calculated_signature)):
            raise MacaroonInvalidSignatureException('Signatures do not match')

        return True

    def _verify_caveats(self, root, macaroon, signature, cache_prefix=None):
        for caveat in macaroon.caveats:
            if self._caveat_met(root,
                                caveat,
                                macaroon,
                                signature):
                if cache_prefix is not None:
                    cache_prefix = cache_prefix + (
                        self._caveat_cache_contribution(caveat),
                    )
                    cached_signature = self.signature_cache.get(cache_prefix)
                    if cached_signature is not None:
                        signature = cached_signature
                        continue
                signature = self._update_signature(caveat, signature)
                if cache_prefix is not None:
                    self.signature_cache.put(cache_prefix, signature)
        return signature

    def _caveat_cache_contribution(self, caveat):
        # The exact signing input of this caveat, so that a cache key is
        # fully determined by (root key, identifier, caveat prefix) and
        # changes whenever the caller tampers with any caveat bytes.
        if caveat.first_party():
            return (b'fp', caveat.caveat_id_bytes)
        return (
            b'tp',
            caveat._verification_key_id,
            caveat._caveat_id,
        )

    def _caveat_met(self, root, caveat, macaroon, signature):
        if caveat.first_party():
            return (
                self
                .first_party_caveat_verifier_delegate
                .verify_first_party_caveat(self, caveat, signature)
            )
        else:
            return (
                self
                .third_party_caveat_verifier_delegate
                .verify_third_party_caveat(
                    self, caveat, root, macaroon, signature,
                )
            )

    def _update_signature(self, caveat, signature):
        if caveat.first_party():
            return (
                self
                .first_party_caveat_verifier_delegate
                .update_signature(signature, caveat)
            )
        else:
            return (
                self
                .third_party_caveat_verifier_delegate
                .update_signature(signature, caveat)
            )

    def _signatures_match(self, macaroon_signature, computed_signature):
        return constant_time_compare(
            convert_to_bytes(macaroon_signature),
            convert_to_bytes(computed_signature)
        )
