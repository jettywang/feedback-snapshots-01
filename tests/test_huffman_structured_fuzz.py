"""
Structured differential fuzzing of the HPACK Huffman decoder.

The reference oracle in this module is rebuilt bit-by-bit directly from the
RFC 7541 Appendix B code table (``hpack.huffman_constants``). It deliberately
does *not* use the nghttp2-derived state-transition table in
``hpack.huffman_table`` so that the two implementations can be checked
against each other.

The campaign focuses on the classic Huffman-decoder bug classes:

* EOS (symbol 256) must never be decoded as a regular symbol.
* Tail padding must be at most 7 bits and strictly all ones.
* Codewords that span byte boundaries must be decoded exactly.
* Bytes beyond a literal's declared length must neither take part in the
  padding nor be swallowed by the Huffman decoder.
* A header block containing an invalid Huffman string must be rejected as a
  whole; no partial header list may be delivered.

The seed is fixed so runs are reproducible. On any divergence the shortest
failing bitstream, the wrapped header block, and the failure type are saved
as JSON artifacts.
"""
from __future__ import annotations

import json
import os
import random

import pytest

from hpack import Decoder, HPACKDecodingError
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
from hpack.huffman_table import decode_huffman

SEED = int(os.environ.get("HPACK_FUZZ_SEED", "20261115"))
ARTIFACT_DIR = os.environ.get(
    "HPACK_FUZZ_ARTIFACT_DIR", "tests/fuzz_artifacts"
)
# Artifacts are capped per case category so that every bug class leaves
# evidence behind even when one category produces many divergences.
MAX_ARTIFACTS_PER_CATEGORY = 5

EOS_SYMBOL = 256
EOS_CODE = REQUEST_CODES[EOS_SYMBOL]
EOS_LENGTH = REQUEST_CODES_LENGTH[EOS_SYMBOL]

# (code, length) -> symbol, for every symbol in the RFC table including EOS.
PREFIX_LOOKUP = {
    (REQUEST_CODES[sym], REQUEST_CODES_LENGTH[sym]): sym
    for sym in range(len(REQUEST_CODES))
}


class OracleRejection(Exception):
    """The reference oracle rejected a bitstream."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def oracle_decode(
    data: bytes,
    *,
    eos_is_symbol: bool = False,
    relaxed_padding: bool = False,
) -> bytes:
    """
    Bit-level reference decoder built straight from the RFC code table.

    The keyword arguments exist only to build the controlled-defect decoders
    used to prove the campaign's effectiveness.
    """
    out = bytearray()
    code = 0
    length = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            length += 1
            symbol = PREFIX_LOOKUP.get((code, length))
            if symbol is None:
                continue
            if symbol == EOS_SYMBOL and not eos_is_symbol:
                raise OracleRejection("eos-symbol")
            out.append(symbol & 0xFF)
            code = 0
            length = 0
    if length:
        if length > 7:
            raise OracleRejection("incomplete-codeword")
        if not relaxed_padding and code != (1 << length) - 1:
            raise OracleRejection("bad-padding")
    return bytes(out)


def encode_bits(symbols: list[int]) -> list[int]:
    """MSB-first bit list for the given symbols, from the RFC table."""
    bits = []
    for sym in symbols:
        code = REQUEST_CODES[sym]
        for shift in range(REQUEST_CODES_LENGTH[sym] - 1, -1, -1):
            bits.append((code >> shift) & 1)
    return bits


def pad_with_ones(bits: list[int]) -> list[int]:
    return bits + [1] * ((-len(bits)) % 8)


def bits_to_bytes(bits: list[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def encode_symbols(symbols: list[int]) -> bytes:
    return bits_to_bytes(pad_with_ones(encode_bits(symbols)))


def encode_prefix_integer(value: int, prefix_bits: int, flags: int) -> bytes:
    """HPACK integer encoding (RFC 7541 Section 5.1)."""
    max_first = (1 << prefix_bits) - 1
    if value < max_first:
        return bytes([flags | value])
    out = bytearray([flags | max_first])
    value -= max_first
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def wrap_header_block(value_bytes: bytes, trailer: bytes = b"\x82") -> bytes:
    """
    Embed a Huffman bitstream in a real header block: a literal field
    without indexing, literal name "x", Huffman-coded value with its own
    independent length field, followed by an indexed field (``:method:
    GET``) that must survive decoding untouched.
    """
    block = bytearray(b"\x00\x01x")
    block += encode_prefix_integer(len(value_bytes), 7, 0x80)
    block += value_bytes
    block += trailer
    return bytes(block)


EXPECTED_TRAILER = (b":method", b"GET")


def generate_cases() -> list[tuple[str, bytes]]:
    rng = random.Random(SEED)
    cases: list[tuple[str, bytes]] = []

    # Every single-byte symbol, canonically encoded.
    for sym in range(256):
        cases.append((f"single/{sym}", encode_symbols([sym])))

    # Exhaustive mutation of the last 1..7 bits of every single-byte
    # symbol encoding. This hits both the padding bits and, for mutations
    # longer than the padding, the codeword's own tail.
    for sym in range(256):
        padded = pad_with_ones(encode_bits([sym]))
        for width in range(1, 8):
            for tail in range(1 << width):
                mutated = padded[:-width] + [
                    (tail >> shift) & 1
                    for shift in range(width - 1, -1, -1)
                ]
                cases.append((
                    f"tail/{sym}/{width}/{tail}", bits_to_bytes(mutated)
                ))

    # A full byte of padding (8 bits) is always illegal, even all-ones.
    for sym in range(256):
        cases.append((
            f"overlong-padding/{sym}", encode_symbols([sym]) + b"\xff"
        ))

    # Long codewords (>= 20 bits) forced to straddle byte boundaries,
    # plus bit flips and truncations of those encodings.
    long_symbols = [
        sym for sym in range(256) if REQUEST_CODES_LENGTH[sym] >= 20
    ]
    for sym in long_symbols:
        sequence = [0x61, sym, 0x61, sym]
        encoded = encode_symbols(sequence)
        cases.append((f"long/{sym}", encoded))
        cases.append((f"long-truncated/{sym}", encoded[:-1]))
        padded = pad_with_ones(encode_bits(sequence))
        for flip in range(4):
            position = rng.randrange(len(padded))
            flipped = padded[:]
            flipped[position] ^= 1
            cases.append((
                f"long-bitflip/{sym}/{flip}", bits_to_bytes(flipped)
            ))

    # The 30-bit EOS codeword injected at arbitrary bit positions.
    eos_bits = [
        (EOS_CODE >> shift) & 1 for shift in range(EOS_LENGTH - 1, -1, -1)
    ]
    cases.append(("eos/standalone", b"\xff\xff\xff\xff"))
    for i in range(64):
        base = encode_bits([rng.randrange(256) for _ in range(rng.randrange(1, 5))])
        position = rng.randrange(len(base) + 1)
        mutated = base[:position] + eos_bits + base[position:]
        cases.append((
            f"eos/{i}/{position}", bits_to_bytes(pad_with_ones(mutated))
        ))

    # Raw random byte strings.
    for i in range(512):
        cases.append((
            f"random/{i}",
            bytes(rng.randrange(256) for _ in range(rng.randrange(0, 7))),
        ))

    # Valid encodings corrupted by one or two bit flips.
    for i in range(512):
        symbols = [rng.randrange(256) for _ in range(rng.randrange(1, 6))]
        data = bytearray(encode_symbols(symbols))
        for _ in range(rng.randrange(1, 3)):
            position = rng.randrange(len(data) * 8)
            data[position // 8] ^= 1 << (7 - position % 8)
        cases.append((f"bitflip/{i}", bytes(data)))

    return cases


def classify(bitstream: bytes, raw_decoder, decoder: Decoder):
    """
    Compare the production decoder against the oracle on one bitstream,
    both raw and embedded in a real header block. Returns a failure type
    string, or None if the two agree.
    """
    try:
        expected = oracle_decode(bitstream)
    except OracleRejection:
        expected = None

    try:
        got = raw_decoder(bitstream)
        raw_ok = True
    except HPACKDecodingError:
        got = None
        raw_ok = False

    if expected is not None and not raw_ok:
        return "false-reject"
    if expected is None and raw_ok:
        return "false-accept"
    if expected is not None and got != expected:
        return "output-mismatch"

    block = wrap_header_block(bitstream)
    try:
        headers = [tuple(h) for h in decoder.decode(block, raw=True)]
        block_ok = True
    except HPACKDecodingError:
        headers = None
        block_ok = False

    if expected is None:
        # An invalid value must sink the whole block; delivering anything
        # (even a partial list) is a bug.
        if block_ok:
            return "block-false-accept"
    else:
        if not block_ok:
            return "block-false-reject"
        expected_headers = [(b"x", expected), EXPECTED_TRAILER]
        if headers != expected_headers:
            # Covers swallowed/merged trailing bytes as well as wrong
            # decoded values.
            return "block-wrong-output"
    return None


def minimize(bitstream: bytes, raw_decoder, decoder: Decoder) -> bytes:
    """Greedily shrink a diverging bitstream to its shortest form."""
    data = bitstream
    shrunk = True
    while shrunk:
        shrunk = False
        for length in range(1, len(data)):
            if classify(data[:length], raw_decoder, decoder) is not None:
                data = data[:length]
                shrunk = True
                break
    if data:
        for value in range(data[-1]):
            candidate = data[:-1] + bytes([value])
            if classify(candidate, raw_decoder, decoder) is not None:
                data = candidate
                break
    return data


def describe_oracle(bitstream: bytes) -> str:
    try:
        return f"accept:{oracle_decode(bitstream).hex()}"
    except OracleRejection as err:
        return f"reject:{err.kind}"


def describe_decoder(bitstream: bytes, raw_decoder) -> str:
    try:
        return f"accept:{raw_decoder(bitstream).hex()}"
    except HPACKDecodingError:
        return "reject"


def write_artifact(artifact_dir: str, failure: dict) -> str:
    os.makedirs(artifact_dir, exist_ok=True)
    safe_case = failure["case_id"].replace("/", "_")
    path = os.path.join(
        artifact_dir,
        f"huffman-fuzz-{failure['failure_type']}-{safe_case}.json",
    )
    with open(path, "w", encoding="utf-8") as f:
        json.dump(failure, f, indent=2)
    return path


def run_campaign(cases, raw_decoder=decode_huffman, artifact_dir=None):
    decoder = Decoder()
    failures = []
    artifacts_per_category: dict[str, int] = {}
    for case_id, bitstream in cases:
        failure_type = classify(bitstream, raw_decoder, decoder)
        if failure_type is None:
            continue
        shortest = minimize(bitstream, raw_decoder, decoder)
        failure = {
            "seed": SEED,
            "case_id": case_id,
            "failure_type": failure_type,
            "bitstream_hex": shortest.hex(),
            "header_block_hex": wrap_header_block(shortest).hex(),
            "oracle": describe_oracle(shortest),
            "decoder": describe_decoder(shortest, raw_decoder),
        }
        category = case_id.split("/")[0]
        written = artifacts_per_category.get(category, 0)
        if artifact_dir is not None and written < MAX_ARTIFACTS_PER_CATEGORY:
            failure["artifact"] = write_artifact(artifact_dir, failure)
            artifacts_per_category[category] = written + 1
        failures.append(failure)
    return failures


class TestReferenceOracle:
    """Sanity-check the independent oracle against known answers."""

    @pytest.mark.parametrize("encoded,expected", [
        (b"\xf1\xe3\xc2\xe5\xf2:k\xa0\xab\x90\xf4\xff", b"www.example.com"),
        (b"\xa8\xeb\x10d\x9c\xbf", b"no-cache"),
        (b"%\xa8I\xe9[\xa9}\x7f", b"custom-key"),
        (b"%\xa8I\xe9[\xb8\xe8\xb4\xbf", b"custom-value"),
    ])
    def test_rfc_vectors(self, encoded, expected):
        assert oracle_decode(encoded) == expected

    def test_accepts_every_single_byte_symbol(self):
        for sym in range(256):
            assert oracle_decode(encode_symbols([sym])) == bytes([sym])

    def test_rejects_eos(self):
        with pytest.raises(OracleRejection) as excinfo:
            oracle_decode(b"\xff\xff\xff\xff")
        assert excinfo.value.kind == "eos-symbol"

    def test_rejects_non_one_padding(self):
        # 00000 decodes as "0", leaving 000 as padding: not all ones.
        with pytest.raises(OracleRejection) as excinfo:
            oracle_decode(b"\x00")
        assert excinfo.value.kind == "bad-padding"

    def test_rejects_overlong_padding(self):
        # 8 one-bits: an EOS prefix longer than the 7-bit padding limit.
        with pytest.raises(OracleRejection) as excinfo:
            oracle_decode(b"\xff")
        assert excinfo.value.kind == "incomplete-codeword"


class TestStructuredFuzz:
    def test_decoder_matches_oracle(self):
        cases = generate_cases()
        failures = run_campaign(cases, artifact_dir=ARTIFACT_DIR)
        assert not failures, (
            f"{len(failures)} divergences out of {len(cases)} cases "
            f"(seed {SEED}); first: {failures[0]}"
        )

    def test_error_block_delivers_no_partial_headers(self):
        # A valid literal followed by a literal whose Huffman value is
        # invalid: the block must fail as a whole.
        block = wrap_header_block(encode_symbols([0x61]), trailer=b"")
        block += wrap_header_block(b"\x00", trailer=b"")
        with pytest.raises(HPACKDecodingError):
            Decoder().decode(block, raw=True)

    def test_bytes_beyond_field_length_are_not_padding(self):
        # b"\x00" has invalid padding; the following 0xff bytes could
        # "repair" it only if they were illegally pulled into the value.
        block = wrap_header_block(b"\x00", trailer=b"\xff\xff")
        with pytest.raises(HPACKDecodingError):
            Decoder().decode(block, raw=True)

    def test_trailing_field_is_not_swallowed(self):
        value = encode_symbols(list(b"hello"))
        headers = Decoder().decode(wrap_header_block(value), raw=True)
        assert [tuple(h) for h in headers] == [
            (b"x", b"hello"), EXPECTED_TRAILER,
        ]

    def test_shortened_length_field_is_not_hidden(self):
        # Declaring the value one byte shorter than the padded encoding
        # leaves a dangling byte that starts a new (here invalid) field;
        # it must not be silently absorbed as padding.
        value = encode_symbols(list(b"hello"))
        block = bytearray(b"\x00\x01x")
        block += encode_prefix_integer(len(value) - 1, 7, 0x80)
        block += value
        with pytest.raises(HPACKDecodingError):
            Decoder().decode(bytes(block), raw=True)


def _defective_decoder(**defects):
    def decode(data):
        try:
            return oracle_decode(data, **defects)
        except OracleRejection as err:
            raise HPACKDecodingError(err.kind) from err
    return decode


class TestControlledDefects:
    """
    Proof of effectiveness: decoders carrying a controlled defect must be
    caught by the campaign, and the divergence must be recorded.
    """

    def test_detects_eos_treated_as_regular_symbol(
        self, monkeypatch, tmp_path
    ):
        defective = _defective_decoder(eos_is_symbol=True)
        monkeypatch.setattr("hpack.hpack.decode_huffman", defective)
        cases = generate_cases()
        failures = run_campaign(
            cases, raw_decoder=defective, artifact_dir=str(tmp_path)
        )
        eos_failures = [
            f for f in failures
            if f["case_id"].startswith("eos/")
            and "false-accept" in f["failure_type"]
        ]
        assert eos_failures, "campaign missed EOS-as-symbol defect"
        artifact = eos_failures[0]["artifact"]
        with open(artifact, encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["seed"] == SEED
        assert saved["failure_type"] == eos_failures[0]["failure_type"]
        assert bytes.fromhex(saved["bitstream_hex"])
        assert bytes.fromhex(saved["header_block_hex"])

    def test_detects_relaxed_padding(self, monkeypatch, tmp_path):
        defective = _defective_decoder(relaxed_padding=True)
        monkeypatch.setattr("hpack.hpack.decode_huffman", defective)
        cases = generate_cases()
        failures = run_campaign(
            cases, raw_decoder=defective, artifact_dir=str(tmp_path)
        )
        padding_failures = [
            f for f in failures
            if f["case_id"].startswith("tail/")
            and "false-accept" in f["failure_type"]
        ]
        assert padding_failures, "campaign missed relaxed-padding defect"
        assert padding_failures[0]["bitstream_hex"]
        assert os.path.exists(padding_failures[0]["artifact"])
