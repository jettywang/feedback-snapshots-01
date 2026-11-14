"""
Consistency regression for the explicit signature protocol layer.

These tests guard the property that two entry points sharing one protocol
(:meth:`protocol.SignatureProtocol.verify_message`, the gateway that hashes
the message, and :meth:`protocol.SignatureProtocol.verify_digest`, the
backend that verifies a precomputed digest) accept exactly the same set of
signatures.

They first show that the permissive, default based generic API does disagree
between the two entry points on concrete inputs, then prove that the protocol
layer does not. Policy rejections (encoding, integer range, low-S, digest
length) are kept separate from mathematical verification failures, and the
lenient configuration still accepts every mathematically valid compatible
form instead of achieving consistency by disabling compatibility outright.
"""

from hashlib import sha1, sha256, sha384

import pytest

from . import protocol
from .curves import NIST256p, NIST384p
from .keys import BadDigestError, BadSignatureError, SigningKey
from .util import (
    sigdecode_der,
    sigdecode_string,
    sigencode_der_canonize,
    sigencode_string,
    sigencode_string_canonize,
)

ORDER = NIST256p.order
HALF_ORDER = ORDER // 2
MESSAGE = b"gateway-and-backend-share-one-protocol"


def _i32(value):
    return value.to_bytes(32, "big")


@pytest.fixture
def identity():
    # Deterministic key so the corpus and expected outcomes are stable.
    sk = SigningKey.from_secret_exponent(
        0x1234567890ABCDEF1234567890ABCDEF, curve=NIST256p, hashfunc=sha256
    )
    return sk, sk.get_verifying_key()


@pytest.fixture
def strict():
    return protocol.SignatureProtocol(
        curve=NIST256p,
        hashfunc=sha256,
        encoding=protocol.RAW,
        allow_truncate=False,
        require_low_s=True,
    )


@pytest.fixture
def lenient():
    # Compatibility is preserved, not banned: truncation and high-S are
    # allowed, the single fixed encoding is still enforced.
    return protocol.SignatureProtocol(
        curve=NIST256p,
        hashfunc=sha256,
        encoding=protocol.RAW,
        allow_truncate=True,
        require_low_s=False,
    )


def _outcome(call):
    """Return (accepted, exception_class) for a zero-argument verification."""
    try:
        call()
    except protocol.ProtocolError as error:
        return False, type(error)
    return True, None


def _both_paths(proto, vk, signature, message, digest):
    gateway = _outcome(lambda: proto.verify_message(vk, signature, message))
    backend = _outcome(lambda: proto.verify_digest(vk, signature, digest))
    return gateway, backend


# ---------------------------------------------------------------------------
# The generic, default driven API really does diverge between entry points.
# ---------------------------------------------------------------------------

class TestGenericApiDivergence:
    """Document the front/back disagreement the protocol layer removes."""

    def test_truncation_default_disagrees(self, identity):
        sk, vk = identity
        sk384 = SigningKey.from_secret_exponent(
            sk.privkey.secret_multiplier, curve=NIST256p, hashfunc=sha384
        )
        vk384 = sk384.get_verifying_key()
        signature = sk384.sign(
            MESSAGE,
            hashfunc=sha384,
            sigencode=sigencode_string,
            allow_truncate=True,
        )

        # Gateway: verify() defaults allow_truncate to True, so it accepts.
        assert vk384.verify(signature, MESSAGE, hashfunc=sha384) is True

        # Backend: verify_digest() defaults allow_truncate to False, so it
        # rejects the very same (signature, digest) pair.
        with pytest.raises(BadDigestError):
            vk384.verify_digest(signature, sha384(MESSAGE).digest())

    def test_default_hashfunc_is_sha1_not_the_protocol_hash(self):
        # A key built through the generic constructor keeps the library
        # default of SHA-1; a SHA-256 signature verified while relying on
        # that default is evaluated against the wrong hash and rejected.
        sk = SigningKey.generate(curve=NIST256p)
        vk = sk.get_verifying_key()
        assert vk.default_hashfunc is sha1
        signature = sk.sign(MESSAGE, hashfunc=sha256, sigencode=sigencode_string)
        with pytest.raises(BadSignatureError):
            vk.verify(signature, MESSAGE)

    def test_high_s_accepted_by_generic_api(self, identity):
        sk, vk = identity
        r, s = sigdecode_string(
            sk.sign(MESSAGE, hashfunc=sha256, sigencode=sigencode_string),
            ORDER,
        )
        high_s = _i32(r) + _i32(ORDER - s)
        # The generic verifier treats a high-S signature as perfectly valid.
        assert vk.verify(high_s, MESSAGE, hashfunc=sha256) is True


# ---------------------------------------------------------------------------
# A corpus of inputs that split a permissive integration, with the precise
# protocol verdict each one must produce.
# ---------------------------------------------------------------------------

@pytest.fixture
def corpus(identity):
    sk, vk = identity
    digest = sha256(MESSAGE).digest()

    canonical_raw = sk.sign(
        MESSAGE, hashfunc=sha256, sigencode=sigencode_string
    )
    r, s = sigdecode_string(canonical_raw, ORDER)

    # Ensure a canonical low-S baseline regardless of RFC 6979 output.
    low_s = min(s, ORDER - s)
    low_raw = _i32(r) + _i32(low_s)
    high_raw = _i32(r) + _i32(ORDER - low_s)
    assert low_s <= HALF_ORDER < ORDER - low_s

    der_canonical = sk.sign(
        MESSAGE, hashfunc=sha256, sigencode=sigencode_der_canonize
    )
    dr, ds = sigdecode_der(der_canonical, ORDER)

    # Non-minimal DER INTEGER: an unnecessary leading 0x00 on r.
    nonminimal_body = (
        b"\x02\x21\x00" + _i32(dr) + b"\x02\x20" + _i32(ds)
    )
    nonminimal_der = b"\x30" + bytes([len(nonminimal_body)]) + nonminimal_body

    return {
        "canonical_raw": low_raw,
        "high_s_raw": high_raw,
        "s_equals_order": _i32(r) + _i32(ORDER),
        "r_equals_zero": _i32(0) + _i32(low_s),
        "raw_with_trailing_byte": low_raw + b"\x00",
        "der_signature": der_canonical,
        "der_with_trailing_junk": der_canonical + b"\x00",
        "nonminimal_der_integer": nonminimal_der,
        "wrong_message_signature": canonical_raw,
        "digest": digest,
    }


class TestTwoEntryPointsAgree:
    """The gateway and backend must return identical verdicts."""

    @pytest.mark.parametrize(
        "sample",
        [
            "canonical_raw",
            "high_s_raw",
            "s_equals_order",
            "r_equals_zero",
            "raw_with_trailing_byte",
            "der_signature",
            "der_with_trailing_junk",
            "nonminimal_der_integer",
        ],
    )
    def test_strict_protocol_parity(self, strict, identity, corpus, sample):
        _, vk = identity
        signature = corpus[sample]
        gateway, backend = _both_paths(
            strict, vk, signature, MESSAGE, corpus["digest"]
        )
        assert gateway == backend

    @pytest.mark.parametrize(
        "sample",
        [
            "canonical_raw",
            "high_s_raw",
            "s_equals_order",
            "r_equals_zero",
            "raw_with_trailing_byte",
        ],
    )
    def test_lenient_protocol_parity(self, lenient, identity, corpus, sample):
        _, vk = identity
        signature = corpus[sample]
        gateway, backend = _both_paths(
            lenient, vk, signature, MESSAGE, corpus["digest"]
        )
        assert gateway == backend

    @pytest.mark.parametrize("truncate", [False, True])
    @pytest.mark.parametrize("low_s", [False, True])
    def test_full_matrix_parity(
        self, identity, corpus, truncate, low_s
    ):
        # Every policy combination must keep the two entry points in lockstep
        # across every raw sample; consistency is not achieved by disabling
        # compatibility, since truncate/low_s are exercised both ways.
        _, vk = identity
        proto = protocol.SignatureProtocol(
            curve=NIST256p,
            hashfunc=sha256,
            encoding=protocol.RAW,
            allow_truncate=truncate,
            require_low_s=low_s,
        )
        raw_samples = [
            "canonical_raw",
            "high_s_raw",
            "s_equals_order",
            "r_equals_zero",
            "raw_with_trailing_byte",
        ]
        for sample in raw_samples:
            gateway, backend = _both_paths(
                proto,
                vk,
                corpus[sample],
                MESSAGE,
                corpus["digest"],
            )
            assert gateway == backend, (truncate, low_s, sample)

    def test_digest_path_uses_supplied_digest_not_rehash(
        self, strict, identity, corpus
    ):
        _, vk = identity
        # A precomputed digest over different content must produce the same
        # verdict on both entries when fed that digest explicitly; the backend
        # never re-hashes a message.
        other_digest = sha256(b"different content").digest()
        signature = corpus["canonical_raw"]
        gateway = _outcome(
            lambda: strict.verify_message(vk, signature, MESSAGE)
        )
        backend = _outcome(
            lambda: strict.verify_digest(vk, signature, other_digest)
        )
        # Gateway accepts against MESSAGE; backend must run the identical math
        # against the supplied digest and therefore fail it, deterministically.
        assert gateway == (True, None)
        accepted, error = backend
        assert accepted is False
        assert error is protocol.MathVerificationFailure


class TestPolicyVsMath:
    """Policy rejections and mathematical failures are distinct outcomes."""

    def test_failure_categories_are_disjoint(self):
        assert not issubclass(
            protocol.MathVerificationFailure, protocol.PolicyRejection
        )
        for rejection in (
            protocol.EncodingRejection,
            protocol.IntegerRangeViolation,
            protocol.HighSRejection,
            protocol.DigestLengthRejection,
        ):
            assert issubclass(rejection, protocol.PolicyRejection)
            assert not issubclass(rejection, protocol.MathVerificationFailure)

    def test_tampered_signature_is_math_failure(self, strict, identity, corpus):
        _, vk = identity
        tampered = bytearray(corpus["canonical_raw"])
        tampered[0] ^= 0x01
        for call in (
            lambda: strict.verify_message(vk, bytes(tampered), MESSAGE),
            lambda: strict.verify_digest(
                vk, bytes(tampered), corpus["digest"]
            ),
        ):
            with pytest.raises(protocol.MathVerificationFailure):
                call()

    def test_high_s_is_policy_reject_but_math_valid(
        self, strict, lenient, identity, corpus
    ):
        _, vk = identity
        signature = corpus["high_s_raw"]
        # Strict policy refuses it before/independently of the math verdict.
        with pytest.raises(protocol.HighSRejection):
            strict.verify_message(vk, signature, MESSAGE)
        with pytest.raises(protocol.HighSRejection):
            strict.verify_digest(vk, signature, corpus["digest"])
        # The same bytes are a genuine, mathematically valid signature, so a
        # protocol without the low-S rule accepts them on both paths.
        assert lenient.verify_message(vk, signature, MESSAGE) is True
        assert (
            lenient.verify_digest(vk, signature, corpus["digest"]) is True
        )

    @pytest.mark.parametrize("sample", ["s_equals_order", "r_equals_zero"])
    def test_order_boundary_is_range_policy_rejection(
        self, strict, identity, corpus, sample
    ):
        _, vk = identity
        with pytest.raises(protocol.IntegerRangeViolation):
            strict.verify_message(vk, corpus[sample], MESSAGE)
        with pytest.raises(protocol.IntegerRangeViolation):
            strict.verify_digest(vk, corpus[sample], corpus["digest"])

    @pytest.mark.parametrize(
        "sample",
        ["raw_with_trailing_byte", "der_with_trailing_junk"],
    )
    def test_trailing_data_is_encoding_rejection(
        self, strict, identity, corpus, sample
    ):
        _, vk = identity
        with pytest.raises(protocol.EncodingRejection):
            strict.verify_message(vk, corpus[sample], MESSAGE)

    def test_nonminimal_der_integer_is_encoding_rejection(
        self, strict, identity, corpus
    ):
        _, vk = identity
        with pytest.raises(protocol.EncodingRejection):
            strict.verify_message(
                vk, corpus["nonminimal_der_integer"], MESSAGE
            )

    def test_encoding_is_never_guessed(self, identity, corpus):
        _, vk = identity
        raw_proto = protocol.SignatureProtocol(encoding=protocol.RAW)
        der_proto = protocol.SignatureProtocol(encoding=protocol.DER)
        # DER bytes handed to a raw protocol and raw bytes handed to a DER
        # protocol are both rejected as encoding mismatches.
        with pytest.raises(protocol.EncodingRejection):
            raw_proto.verify_message(vk, corpus["der_signature"], MESSAGE)
        with pytest.raises(protocol.EncodingRejection):
            der_proto.verify_message(vk, corpus["canonical_raw"], MESSAGE)
        # And each accepts its own correctly encoded form.
        assert (
            der_proto.verify_message(vk, corpus["der_signature"], MESSAGE)
            is True
        )
        assert (
            raw_proto.verify_message(vk, corpus["canonical_raw"], MESSAGE)
            is True
        )


class TestTruncationPolicy:
    """Digest truncation is one bound switch, identical on both paths."""

    def test_oversize_digest_rejected_when_truncation_off(self, identity):
        sk, _ = identity
        sk384 = SigningKey.from_secret_exponent(
            sk.privkey.secret_multiplier, curve=NIST256p, hashfunc=sha384
        )
        vk384 = sk384.get_verifying_key()
        signature = sk384.sign(
            MESSAGE,
            hashfunc=sha384,
            sigencode=sigencode_string,
            allow_truncate=True,
        )
        proto = protocol.SignatureProtocol(
            curve=NIST256p, hashfunc=sha384, allow_truncate=False
        )
        with pytest.raises(protocol.DigestLengthRejection):
            proto.verify_message(vk384, signature, MESSAGE)
        with pytest.raises(protocol.DigestLengthRejection):
            proto.verify_digest(
                vk384, signature, sha384(MESSAGE).digest()
            )

    def test_oversize_digest_accepted_on_both_paths_when_allowed(self, identity):
        sk, _ = identity
        sk384 = SigningKey.from_secret_exponent(
            sk.privkey.secret_multiplier, curve=NIST256p, hashfunc=sha384
        )
        vk384 = sk384.get_verifying_key()
        signature = sk384.sign(
            MESSAGE,
            hashfunc=sha384,
            sigencode=sigencode_string,
            allow_truncate=True,
        )
        proto = protocol.SignatureProtocol(
            curve=NIST256p,
            hashfunc=sha384,
            allow_truncate=True,
            require_low_s=False,
        )
        assert proto.verify_message(vk384, signature, MESSAGE) is True
        assert (
            proto.verify_digest(vk384, signature, sha384(MESSAGE).digest())
            is True
        )

    def test_matching_curve_and_hash_have_no_truncation_issue(self):
        # NIST384p with SHA-384 fits the order exactly, so either setting works.
        sk = SigningKey.generate(curve=NIST384p, hashfunc=sha384)
        vk = sk.get_verifying_key()
        signature = sk.sign(
            MESSAGE, hashfunc=sha384, sigencode=sigencode_string_canonize
        )
        proto = protocol.SignatureProtocol(
            curve=NIST384p, hashfunc=sha384, allow_truncate=False
        )
        assert proto.verify_message(vk, signature, MESSAGE) is True


class TestProtocolConfiguration:
    def test_invalid_encoding_rejected(self):
        with pytest.raises(ValueError):
            protocol.SignatureProtocol(encoding="guess")

    def test_flags_must_be_bool(self):
        with pytest.raises(TypeError):
            protocol.SignatureProtocol(allow_truncate="yes")
        with pytest.raises(TypeError):
            protocol.SignatureProtocol(require_low_s=1)

    def test_curve_mismatch_rejected(self, identity, corpus):
        sk, vk = identity
        other = SigningKey.generate(curve=NIST384p, hashfunc=sha256)
        proto = protocol.SignatureProtocol(curve=NIST384p, hashfunc=sha256)
        with pytest.raises(protocol.PolicyRejection):
            proto.verify_message(vk, corpus["canonical_raw"], MESSAGE)

    def test_protocols_are_value_equal(self):
        a = protocol.SignatureProtocol()
        b = protocol.SignatureProtocol()
        assert a == b
        assert hash(a) == hash(b)
        c = protocol.SignatureProtocol(require_low_s=False)
        assert a != c
