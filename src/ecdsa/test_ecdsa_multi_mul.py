#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""ECDSA verification wired through the bounded multi-scalar interface.

These tests check the *public point combination* of a single ECDSA
verification (``u1*G + u2*Q``) end to end, signature by signature. They do
not merge signatures: combining the verification equations of several
signatures into one equation would be a different (batch) construction and
is explicitly out of scope here.
"""

from __future__ import division

import pytest

from . import curves
from .ecdsa import Private_key, Public_key, Signature
from .ellipticcurve import Point
from .multi_mul import ALLOWED_CURVES, MultiScalarError


ALLOWED = list(ALLOWED_CURVES)


@pytest.mark.parametrize("named", ALLOWED, ids=[c.name for c in ALLOWED])
class TestECDSAWithMultiScalar(object):
    def _key_and_signature(self, named):
        generator = named.generator
        order = named.order
        private = 123456789 % order
        public_point = generator * private
        public_key = Public_key(generator, public_point)
        private_key = Private_key(public_key, private)
        message = 987654321 % order
        nonce = 42424242 % (order - 1) + 1
        signature = private_key.sign(message, nonce)
        return public_key, message, signature

    def test_valid_signature_accepted(self, named):
        public_key, message, signature = self._key_and_signature(named)
        assert public_key.verifies(message, signature)
        assert public_key.verifies_via_multi_scalar(message, signature)

    def test_wrong_message_rejected(self, named):
        public_key, message, signature = self._key_and_signature(named)
        assert not public_key.verifies_via_multi_scalar(
            message + 1, signature
        )

    def test_wrong_signature_rejected(self, named):
        public_key, message, signature = self._key_and_signature(named)
        tampered = Signature(
            signature.r, (signature.s + 1) % named.order
        )
        assert not public_key.verifies_via_multi_scalar(message, tampered)

    def test_out_of_range_signature_values_rejected(self, named):
        public_key, message, signature = self._key_and_signature(named)
        order = named.order
        assert not public_key.verifies_via_multi_scalar(
            message, Signature(0, signature.s)
        )
        assert not public_key.verifies_via_multi_scalar(
            message, Signature(order, signature.s)
        )
        assert not public_key.verifies_via_multi_scalar(
            message, Signature(signature.r, 0)
        )

    def test_agree_with_classical_verifier(self, named):
        public_key, message, signature = self._key_and_signature(named)
        for tweak in (0, 1, 2, 7, -1):
            tampered = Signature(
                signature.r, (signature.s + tweak) % named.order
            )
            assert public_key.verifies(
                message, tampered
            ) == public_key.verifies_via_multi_scalar(message, tampered)

    def test_affine_public_point_accepted(self, named):
        generator = named.generator
        order = named.order
        private = 777 % order
        jacobi_public = generator * private
        affine_public = Point(
            named.curve, jacobi_public.x(), jacobi_public.y(), order
        )
        public_key = Public_key(generator, affine_public)
        private_key = Private_key(public_key, private)
        signature = private_key.sign(
            555, 314159 % (order - 1) + 1
        )
        assert public_key.verifies_via_multi_scalar(555, signature)


class TestECDSANonAllowlistedCurve(object):
    def test_brainpool_verification_returns_false_not_raises(self):
        # Brainpool is a real, supported library curve but it is not on the
        # multi-scalar allow-list; the wired verifier must reject cleanly.
        named = curves.BRAINPOOLP256r1
        generator = named.generator
        order = named.order
        private = 98765 % order
        public_key = Public_key(generator, generator * private)
        private_key = Private_key(public_key, private)
        signature = private_key.sign(42, 12345 % (order - 1) + 1)
        # The classical verifier still works ...
        assert public_key.verifies(42, signature)
        # ... while the policy-bounded path refuses the curve.
        assert not public_key.verifies_via_multi_scalar(42, signature)

    def test_direct_combination_on_brainpool_raises(self):
        named = curves.BRAINPOOLP256r1
        from .multi_mul import public_point_combination

        with pytest.raises(MultiScalarError):
            public_point_combination(
                [named.generator, named.generator * 2], [3, 4]
            )


class TestNoBatchSemantics(object):
    def test_each_signature_verified_independently(self):
        # Two signatures on the same key are verified separately; accepting
        # one must never cause the other to be accepted, which is what a
        # merged batch equation could get wrong.
        named = curves.NIST256p
        generator = named.generator
        order = named.order
        private_key = Private_key(
            Public_key(generator, generator * 555), 555
        )
        sig_a = private_key.sign(111, 12345 % (order - 1) + 1)
        sig_b = private_key.sign(222, 67890 % (order - 1) + 1)
        public_key = private_key.public_key

        assert public_key.verifies_via_multi_scalar(111, sig_a)
        assert public_key.verifies_via_multi_scalar(222, sig_b)
        assert not public_key.verifies_via_multi_scalar(222, sig_a)
        assert not public_key.verifies_via_multi_scalar(111, sig_b)
