"""Structured fuzz tests for OLPC canonical JSON across the full trust path.

The release backend uses the OLPC canonical JSON encoder in
``securesystemslib.formats`` for two security-critical purposes at once:

* public key identity (``signer._utils.compute_default_keyid`` hashes the
  canonical encoding of key metadata), and
* signed payload material (canonical bytes are what end up under a
  signature, e.g. inside a DSSE envelope).

A round-trip test of the encoder alone cannot prove those two paths agree.
This module therefore fuzzes the *composition*: public key import -> keyid
computation -> DSSE signature consumption, using an independent reference
encoder and explicit byte vectors as oracles.

No external fuzzer is required: a seeded structured generator
(``random.Random`` with a fixed seed) plus a greedy shrinker keeps
failures reproducible and retains a minimal counterexample. Mutation tests
at the end prove the suite actually catches identity/signature byte
changes (boolean encoding, Unicode sort order, consumer-side re-encoding).
"""

import builtins
import hashlib
import json
import random
import unittest
from unittest import mock

from securesystemslib import exceptions, formats
from securesystemslib.dsse import Envelope
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner, Key
from securesystemslib.signer._utils import compute_default_keyid

# Fixed seed: failures reproduce byte-for-byte. Bump only intentionally.
SEED = 0xC0FFEE

# ---------------------------------------------------------------------------
# Independent reference encoder (oracle).
#
# Written in a deliberately different style from formats._encode_canonical:
# it builds whole strings instead of streaming chunks, checks bool via
# isinstance instead of identity, escapes char-by-char, and sorts dict keys
# by their UTF-8 byte encoding instead of relying on str comparison. Both
# formulations must agree on every input; UTF-8 byte order equals Unicode
# code point order, so disagreement means one side is wrong.
# ---------------------------------------------------------------------------


def _ref_escape_string(value):
    parts = ['"']
    for char in value:
        if char == '"':
            parts.append('\\"')
        elif char == "\\":
            parts.append("\\\\")
        else:
            parts.append(char)
    parts.append('"')
    return "".join(parts)


def reference_encode(obj):
    """Independent OLPC canonical JSON encoder used as test oracle."""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, str):
        return _ref_escape_string(obj)
    if obj is None:
        return "null"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, list | tuple):
        return "[" + ",".join(reference_encode(item) for item in obj) + "]"
    if isinstance(obj, dict):
        items = []
        for key in sorted(obj, key=lambda k: k.encode("utf-8")):
            if not isinstance(key, str):
                raise exceptions.FormatError(f"non-string key {key!r}")
            items.append(_ref_escape_string(key) + ":" + reference_encode(obj[key]))
        return "{" + ",".join(items) + "}"
    raise exceptions.FormatError(f"cannot encode {obj!r}")


# ---------------------------------------------------------------------------
# Explicit vectors: (object, expected canonical string). These pin the exact
# bytes for the tricky corners: Unicode ordering (incl. astral plane, where
# UTF-16-based sorters such as JCS disagree with OLPC), escaping, the
# bool/int distinction, nesting and empty containers.
# ---------------------------------------------------------------------------

CANONICAL_VECTORS = [
    ("", '""'),
    ("a", '"a"'),
    ('"', '"\\""'),
    ("\\", '"\\\\"'),
    ('\\"', '"\\\\\\""'),
    # Control characters are emitted raw: OLPC escapes only " and backslash.
    ("\n", '"\n"'),
    ("\t\r\x00", '"\t\r\x00"'),
    ("é", '"é"'),
    ("中文", '"中文"'),
    ("😀", '"😀"'),
    (True, "true"),
    (False, "false"),
    (1, "1"),
    (0, "0"),
    (-17, "-17"),
    (2**70, str(2**70)),
    (None, "null"),
    ([], "[]"),
    ({}, "{}"),
    ([1, 2, 3], "[1,2,3]"),
    ((1, 2), "[1,2]"),
    ([[]], "[[]]"),
    ([True, 1, False, 0], "[true,1,false,0]"),
    ({"x": 3, "y": 2}, '{"x":3,"y":2}'),
    ({"b": 1, "a": 2}, '{"a":2,"b":1}'),
    ({"A": [99]}, '{"A":[99]}'),
    ({"": ""}, '{"":""}'),
    ({"": None}, '{"":null}'),
    # Keys sort by code point: "Z" (0x5A) < "z" (0x7A) < "é" (0xE9).
    ({"é": 1, "z": 2, "Z": 3}, '{"Z":3,"z":2,"é":1}'),
    # Astral plane: U+FFFF < U+1F600. A UTF-16 code-unit sort (JCS-style)
    # would order these the other way round.
    ({"😀": 0, "￿": 0}, '{"￿":0,"😀":0}'),
    ({"𐀀": 1, "�": 2}, '{"�":2,"𐀀":1}'),
    # Escapes apply to keys as well as values.
    ({"\\": '"'}, '{"\\\\":"\\""}'),
    ({"\n": ""}, '{"\n":""}'),
    (
        {"a": [{"b": [None, True, "x"]}], "c": {}},
        '{"a":[{"b":[null,true,"x"]}],"c":{}}',
    ),
]

# Minimal counterexamples retained from shrinker runs of earlier revisions.
# They are regression-pinned here so a fixed seed always exercises them.
MINIMAL_COUNTEREXAMPLES = [
    {"😀": 0, "￿": 0},  # UTF-16 vs code-point sort boundary
    [True, 1],  # bool/int adjacency
    {"\\": '"'},  # escape interaction in key and value
    {"\n": ""},  # raw control character, unescaped per OLPC
    {"": None},  # empty key
]

# Types the encoder must reject outright (never silently identity-hash).
UNSUPPORTED_VALUES = [
    8.0,
    0.1,
    b"bytes",
    bytearray(1),
    {"a", "b"},
    object(),
    ValueError("nope"),
    {"x": 8.0},
    [1, 2.5],
    {"k": {1: "int key is not a string"}},
]

# Key metadata used by the keyid oracle check: contains a boolean and
# astral-plane keys so that boolean-encoding and Unicode-sort mutations
# both change the resulting identity hash.
IDENTITY_METADATA_KEYVAL = {"public": "ab" * 32, "😀": True, "￿": [False, 1]}
IDENTITY_METADATA = {
    "keytype": "ed25519",
    "scheme": "ed25519",
    "keyval": IDENTITY_METADATA_KEYVAL,
}


# ---------------------------------------------------------------------------
# Structured random generator.
# ---------------------------------------------------------------------------

_CHARS = [
    "a",
    "Z",
    "z",
    "0",
    " ",
    "~",
    "\x7f",
    '"',
    "\\",
    "\n",
    "\t",
    "\r",
    "\x00",
    "é",
    "ü",
    "中",
    "文",
    "́",
    "￿",
    "😀",
    "𐀀",
]


def _rand_string(rng):
    return "".join(rng.choice(_CHARS) for _ in range(rng.randrange(8)))


def _rand_int(rng):
    return rng.choice(
        [0, 1, -1, rng.randrange(-100, 100), rng.randrange(-(2**70), 2**70)]
    )


def _rand_value(rng, depth):
    kinds = ["none", "bool", "int", "str"]
    if depth > 0:
        kinds += ["list", "tuple", "dict"]
    kind = rng.choice(kinds)
    if kind == "none":
        return None
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "int":
        return _rand_int(rng)
    if kind == "str":
        return _rand_string(rng)
    if kind in ("list", "tuple"):
        items = [_rand_value(rng, depth - 1) for _ in range(rng.randrange(5))]
        return items if kind == "list" else tuple(items)
    obj = {}
    for _ in range(rng.randrange(5)):
        obj[_rand_string(rng)] = _rand_value(rng, depth - 1)
    return obj


def _permute(obj, rng):
    """Return an equal object with every dict's insertion order shuffled."""
    if isinstance(obj, dict):
        items = list(obj.items())
        rng.shuffle(items)
        return {key: _permute(value, rng) for key, value in items}
    if isinstance(obj, list):
        return [_permute(item, rng) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_permute(item, rng) for item in obj)
    return obj


# ---------------------------------------------------------------------------
# Greedy shrinker: on failure, reduce the input to a minimal counterexample
# so the failing assertion message (and any retained regression case) is as
# small as possible.
# ---------------------------------------------------------------------------


def _shrink_candidates(obj):
    yield None
    if isinstance(obj, str) and obj:
        yield ""
        yield obj[: len(obj) // 2]
        yield from dict.fromkeys(obj)
    elif isinstance(obj, bool):
        return
    elif isinstance(obj, int) and obj != 0:
        yield 0
        yield obj // 2
    elif isinstance(obj, list | tuple) and obj:
        yield type(obj)()
        for i in range(len(obj)):
            yield obj[:i] + obj[i + 1 :]
            yield obj[i]
    elif isinstance(obj, dict) and obj:
        yield {}
        for key in obj:
            reduced = dict(obj)
            del reduced[key]
            yield reduced
            yield {key: obj[key]}
            yield obj[key]


def _minimize(obj, fails):
    # Greedy descent: accept the first strictly-different failing candidate
    # until no candidate makes progress. The inequality guard prevents
    # no-progress loops on candidates equal to the current object.
    for _ in range(1000):
        for candidate in _shrink_candidates(obj):
            if candidate == obj:
                continue
            try:
                if fails(candidate):
                    obj = candidate
                    break
            except Exception:
                continue
        else:
            return obj
    return obj


def _encoder_mismatch(obj):
    try:
        return encode_canonical(obj) != reference_encode(obj)
    except exceptions.FormatError:
        return False


# ---------------------------------------------------------------------------
# Shared checks, reused by the mutation tests to prove sensitivity.
# ---------------------------------------------------------------------------


def _check_encoder_identity():
    for obj, expected in CANONICAL_VECTORS:
        actual = encode_canonical(obj)
        if actual != expected:
            raise AssertionError(
                f"vector mismatch for {obj!r}: {actual!r} != {expected!r}"
            )
        if actual != reference_encode(obj):
            raise AssertionError(f"oracle mismatch for {obj!r}")


def _check_keyid_oracle():
    expected = hashlib.sha256(
        reference_encode(IDENTITY_METADATA).encode("utf-8")
    ).hexdigest()
    actual = compute_default_keyid(
        IDENTITY_METADATA["keytype"],
        IDENTITY_METADATA["scheme"],
        IDENTITY_METADATA["keyval"],
    )
    if actual != expected:
        raise AssertionError(
            f"keyid {actual} does not match reference encoding hash {expected}"
        )


def _check_dsse_rejects_recoded_payload(signer):
    """A non-canonical re-encoding of the signed object must NOT verify."""
    obj = {"z": [1, True], "a": {"😀": "x"}}
    canonical = encode_canonical(obj).encode("utf-8")
    envelope = Envelope(canonical, "application/vnd.test+json", {})
    signature = envelope.sign(signer)

    recoded = json.dumps(obj).encode("utf-8")  # same object, other bytes
    assert recoded != canonical
    tampered = Envelope(
        recoded, "application/vnd.test+json", {signature.keyid: signature}
    )
    try:
        tampered.verify([signer.public_key], 1)
    except exceptions.VerificationError:
        return
    raise AssertionError(
        "DSSE accepted a re-encoded payload under the original signature: "
        "the consumer authenticated the logical object, not the actual bytes"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReferenceVectors(unittest.TestCase):
    """Explicit byte vectors and rejection of unsupported types."""

    def test_vectors_match_implementation_and_oracle(self):
        for obj, expected in CANONICAL_VECTORS:
            with self.subTest(obj=obj):
                self.assertEqual(expected, encode_canonical(obj))
                self.assertEqual(expected, reference_encode(obj))

    def test_astral_plane_exact_bytes(self):
        # Pin the exact UTF-8 byte sequence, not just the str.
        self.assertEqual(
            encode_canonical({"😀": 0}).encode("utf-8"),
            b'{"\xf0\x9f\x98\x80":0}',
        )

    def test_minimal_counterexamples_regression(self):
        for obj in MINIMAL_COUNTEREXAMPLES:
            with self.subTest(obj=obj):
                self.assertEqual(reference_encode(obj), encode_canonical(obj))

    def test_unsupported_types_rejected(self):
        for value in UNSUPPORTED_VALUES:
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    encode_canonical(value)

    def test_unsupported_type_in_keyid_material_rejected(self):
        # No identity hash may be minted from unencodable metadata.
        with self.assertRaises(exceptions.FormatError):
            compute_default_keyid("ed25519", "ed25519", {"public": 1.5})


class TestStructuredFuzz(unittest.TestCase):
    """Seeded fuzzing of the encoder against the oracle."""

    def test_encoder_matches_oracle_and_is_order_invariant(self):
        rng = random.Random(SEED)
        for i in range(400):
            value = _rand_value(rng, depth=3)
            try:
                actual = encode_canonical(value)
            except exceptions.FormatError:
                minimal = _minimize(value, _raises)
                self.fail(
                    f"FormatError on encodable input (seed {SEED:#x}, "
                    f"iteration {i}), minimal counterexample: {minimal!r}"
                )
            expected = reference_encode(value)
            if actual != expected:
                minimal = _minimize(value, _encoder_mismatch)
                self.fail(
                    f"canonical JSON mismatch (seed {SEED:#x}, iteration {i})\n"
                    f"  minimal counterexample: {minimal!r}\n"
                    f"  implementation: {encode_canonical(minimal)!r}\n"
                    f"  reference:        {reference_encode(minimal)!r}"
                )
            # Dict insertion order must not change the encoding.
            shuffled = _permute(value, rng)
            self.assertEqual(actual, encode_canonical(shuffled))

    def test_output_function_path_matches_string_path(self):
        rng = random.Random(SEED ^ 0x1)
        for _ in range(200):
            value = _rand_value(rng, depth=3)
            chunks = []
            result = encode_canonical(value, chunks.append)
            self.assertIsNone(result)
            self.assertEqual("".join(chunks), encode_canonical(value))

    def test_partial_output_boundary_on_unsupported_value(self):
        # The consumer must see the exact, incomplete prefix: every chunk up
        # to the failure, nothing fabricated, nothing marked complete.
        chunks = []
        with self.assertRaises(exceptions.FormatError):
            encode_canonical({"a": 1, "z": 8.0}, chunks.append)
        self.assertEqual('{"a":1,"z":', "".join(chunks))
        # The partial material is not parseable JSON: it cannot be mistaken
        # for a complete encoding downstream.
        with self.assertRaises(ValueError):
            json.loads("".join(chunks))

    def test_failing_callback_propagates_and_keeps_exact_prefix(self):
        rng = random.Random(SEED ^ 0x2)
        for _ in range(50):
            value = _rand_value(rng, depth=3)
            reference = reference_encode(value)
            total_chunks = []
            encode_canonical(value, total_chunks.append)
            if len(total_chunks) <= 1:
                continue
            chunks = []
            fail_after = rng.randrange(1, len(total_chunks))

            def callback(chunk, _limit=fail_after):
                if len(chunks) >= _limit:
                    raise ValueError("consumer callback failed")
                chunks.append(chunk)

            with self.assertRaises(ValueError):
                encode_canonical(value, callback)
            partial = "".join(chunks)
            # Boundary accuracy: the retained output is exactly the chunks
            # emitted before the failure, and a strict prefix of the truth.
            self.assertEqual(reference[: len(partial)], partial)
            self.assertLess(len(partial), len(reference))


def _raises(obj):
    try:
        encode_canonical(obj)
        return False
    except exceptions.FormatError:
        return True


class TestKeyidPath(unittest.TestCase):
    """Public key import -> default keyid composition."""

    @classmethod
    def setUpClass(cls):
        cls.signer = CryptoSigner.generate_ed25519()
        cls.ecdsa_signer = CryptoSigner.generate_ecdsa()

    def test_keyid_matches_reference_encoder(self):
        for signer in (self.signer, self.ecdsa_signer):
            key = signer.public_key
            with self.subTest(keytype=key.keytype):
                material = {
                    "keytype": key.keytype,
                    "scheme": key.scheme,
                    "keyval": key.keyval,
                }
                expected = hashlib.sha256(
                    reference_encode(material).encode("utf-8")
                ).hexdigest()
                self.assertEqual(key.keyid, expected)

    def test_keyid_invariant_under_metadata_dict_order(self):
        rng = random.Random(SEED ^ 0x3)
        for _ in range(150):
            keyval = {"public": _rand_string(rng) or "00"}
            for _ in range(rng.randrange(4)):
                keyval[_rand_string(rng)] = _rand_value(rng, depth=2)
            keytype = rng.choice(["ed25519", "rsa", "ecdsa"])
            scheme = rng.choice(["ed25519", "rsassa-pss-sha256", "ecdsa-sha2-nistp256"])
            baseline = compute_default_keyid(keytype, scheme, keyval)
            for _ in range(3):
                shuffled = _permute(keyval, rng)
                self.assertEqual(
                    baseline, compute_default_keyid(keytype, scheme, shuffled)
                )
            # And the hash is over exactly the reference-encoded bytes.
            material = {"keytype": keytype, "scheme": scheme, "keyval": keyval}
            self.assertEqual(
                baseline,
                hashlib.sha256(reference_encode(material).encode("utf-8")).hexdigest(),
            )

    def test_imported_key_recomputes_same_default_keyid(self):
        key = self.signer.public_key
        key_dict = key.to_dict()
        key_dict["x-custom-field"] = {"😀": [True, 1]}  # unrecognized field
        rng = random.Random(SEED ^ 0x4)
        for _ in range(20):
            shuffled = _permute(dict(key_dict), rng)
            imported = Key.from_dict(key.keyid, dict(shuffled))
            self.assertEqual(
                key.keyid,
                compute_default_keyid(
                    imported.keytype, imported.scheme, imported.keyval
                ),
            )
            # Serialization of the imported key is byte-identical regardless
            # of the input dict order.
            self.assertEqual(
                encode_canonical(key_dict),
                encode_canonical(imported.to_dict()),
            )
        # Without extra fields the imported serialization matches the
        # original key exactly.
        plain = Key.from_dict(key.keyid, key.to_dict())
        self.assertEqual(
            encode_canonical(key.to_dict()),
            encode_canonical(plain.to_dict()),
        )


class TestDSSEPath(unittest.TestCase):
    """Canonical payload -> DSSE signature consumption."""

    @classmethod
    def setUpClass(cls):
        cls.signer = CryptoSigner.generate_ed25519()

    def test_same_logical_payload_same_signed_bytes(self):
        rng = random.Random(SEED ^ 0x5)
        for _ in range(25):
            obj = _rand_value(rng, depth=3)
            if not isinstance(obj, dict):
                obj = {"v": obj}
            payload_a = encode_canonical(obj).encode("utf-8")
            payload_b = encode_canonical(_permute(obj, rng)).encode("utf-8")
            self.assertEqual(payload_a, payload_b)

            envelope = Envelope(payload_a, "application/vnd.test+json", {})
            signature = envelope.sign(self.signer)
            # An envelope built from the reordered dict carries identical
            # payload bytes and verifies against the same signature.
            twin = Envelope(
                payload_b,
                "application/vnd.test+json",
                {signature.keyid: signature},
            )
            self.assertEqual(envelope.pae(), twin.pae())
            accepted = twin.verify([self.signer.public_key], 1)
            self.assertIn(signature.keyid, accepted)

    def test_dsse_authenticates_received_bytes_not_logical_object(self):
        _check_dsse_rejects_recoded_payload(self.signer)

    def test_noncanonical_variants_of_signed_object_rejected(self):
        obj = {"b": [1, True], "a": "😀"}
        canonical = encode_canonical(obj).encode("utf-8")
        envelope = Envelope(canonical, "t", {})
        signature = envelope.sign(self.signer)
        variants = [
            json.dumps(obj).encode("utf-8"),  # " " after separators
            json.dumps(obj, sort_keys=True).encode("utf-8"),
            json.dumps(obj, separators=(",", ":")).encode("utf-8"),  # \ud83d..
            b'{"b":[1,true],"a":"\xf0\x9f\x98\x80"}',  # wrong key order
        ]
        for variant in variants:
            if variant == canonical:
                continue
            with self.subTest(variant=variant):
                tampered = Envelope(variant, "t", {signature.keyid: signature})
                with self.assertRaises(exceptions.VerificationError):
                    tampered.verify([self.signer.public_key], 1)


class TestMutations(unittest.TestCase):
    """Prove the checks above catch identity/signature byte changes."""

    @classmethod
    def setUpClass(cls):
        cls.signer = CryptoSigner.generate_ed25519()

    def test_mutation_boolean_encoding_is_caught(self):
        original = formats._encode_canonical

        def mutated(obj, output_function):
            if obj is True:
                output_function("True")
            elif obj is False:
                output_function("False")
            else:
                original(obj, output_function)

        with mock.patch.object(formats, "_encode_canonical", mutated):
            with self.assertRaises(AssertionError):
                _check_encoder_identity()
            with self.assertRaises(AssertionError):
                _check_keyid_oracle()
        # Sanity: checks pass again once the mutation is reverted.
        _check_encoder_identity()
        _check_keyid_oracle()

    def test_mutation_unicode_sort_is_caught(self):
        utf16_sorted = lambda items: builtins.sorted(  # noqa: E731
            items, key=lambda kv: kv[0].encode("utf-16-be")
        )
        with mock.patch.object(formats, "sorted", utf16_sorted, create=True):
            with self.assertRaises(AssertionError):
                _check_encoder_identity()
            with self.assertRaises(AssertionError):
                _check_keyid_oracle()
        _check_encoder_identity()
        _check_keyid_oracle()

    def test_mutation_consumer_reencoding_is_caught(self):
        original_pae = Envelope.pae

        def mutated_pae(envelope):
            # A "helpful" consumer that re-canonicalizes the payload before
            # building the PAE, then still calls it the original signature.
            try:
                obj = json.loads(envelope.payload.decode("utf-8"))
                payload = encode_canonical(obj).encode("utf-8")
            except Exception:
                payload = envelope.payload
            payload_type = envelope.payload_type.encode("utf-8")
            return b"DSSEv1 %d %b %d %b" % (
                len(payload_type),
                payload_type,
                len(payload),
                payload,
            )

        with mock.patch.object(Envelope, "pae", mutated_pae):
            with self.assertRaises(AssertionError):
                _check_dsse_rejects_recoded_payload(self.signer)
        _check_dsse_rejects_recoded_payload(self.signer)
        self.assertIs(Envelope.pae, original_pae)


if __name__ == "__main__":
    unittest.main()
