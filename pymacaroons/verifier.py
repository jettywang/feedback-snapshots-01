import binascii

try:
    # py2.7.7+ and py3.3+ have native comparison support
    from hmac import compare_digest as constant_time_compare
except ImportError:
    from pymacaroons.utils import equals as constant_time_compare

from pymacaroons.access import (
    RequestContext,
    StructuredCaveatVerifier,
)
from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.exceptions import (
    MacaroonAccessException,
    MacaroonInvalidSignatureException,
    MacaroonUnmetCaveatException,
)
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

    def __init__(self, discharge_macaroons=None):
        self.predicates = []
        self.callbacks = [self.verify_exact]
        self.calculated_signature = None
        self.first_party_caveat_verifier_delegate = (
            FirstPartyCaveatVerifierDelegate()
        )
        self.third_party_caveat_verifier_delegate = (
            ThirdPartyCaveatVerifierDelegate(
                discharge_macaroons=discharge_macaroons
            )
        )
        self.structured_caveat_verifier = StructuredCaveatVerifier()

    def satisfy_exact(self, predicate):
        if predicate is None:
            raise TypeError('Predicate cannot be none.')
        self.predicates.append(convert_to_string(predicate))

    def satisfy_general(self, func):
        if not hasattr(func, '__call__'):
            raise TypeError('General caveat verifiers must be callable.')
        self.callbacks.append(func)

    def satisfy_access(self, method, path, now):
        '''Set the single request context used for structured caveats.

        ``path`` must be the request path before any proxy or framework
        re-decoding; percent-encoding is decoded exactly once here.
        '''
        self.set_request_context(RequestContext(method, path, now))
        return self

    def set_request_context(self, request_context):
        if not isinstance(request_context, RequestContext):
            raise TypeError(
                'Request context must be a RequestContext instance.'
            )
        self.structured_caveat_verifier = StructuredCaveatVerifier(
            request_context
        )

    def verify_exact(self, predicate):
        return predicate in self.predicates

    def _predicate_met(self, predicate):
        '''Evaluate a first-party predicate exactly once.

        Structured predicates are owned by their interpreter and never fall
        through to general callbacks, even when a callback would accept
        everything.
        '''
        if self.structured_caveat_verifier.claims(predicate):
            try:
                satisfied = self.structured_caveat_verifier.check(predicate)
            except MacaroonAccessException as error:
                raise MacaroonUnmetCaveatException(
                    'Structured caveat rejected: {0} ({1})'.format(
                        predicate, error
                    )
                )
            if not satisfied:
                raise MacaroonUnmetCaveatException(
                    'Structured caveat not satisfied: {0}'.format(predicate)
                )
            return True
        return sum(callback(predicate) for callback in self.callbacks)

    def verify(self, macaroon, key):
        key = generate_derived_key(convert_to_bytes(key))
        return self.verify_discharge(
            macaroon,
            macaroon,
            key,
        )

    def verify_discharge(self, root, discharge, key):
        calculated_signature = hmac_digest(
            key, discharge.identifier_bytes
        )

        calculated_signature = self._verify_caveats(
            root, discharge, calculated_signature
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

    def _verify_caveats(self, root, macaroon, signature):
        for caveat in macaroon.caveats:
            if self._caveat_met(root,
                                caveat,
                                macaroon,
                                signature):
                signature = self._update_signature(caveat, signature)
        return signature

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
