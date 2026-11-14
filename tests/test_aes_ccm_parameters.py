"""Validate that every AES-CCM COSE algorithm number binds its own parameters.

These tests do not rely on pycose's round-trip behaviour for correctness.
They re-derive the expected Encrypt0 AAD, ciphertext, and tag with the
``cryptography`` AES-CCM backend using the L / M / key-length values from the
independently recorded parameter table (RFC 9053, Table 6), then compare
against pycose output and check that mismatched parameters are rejected.
"""

import hashlib
import json
from binascii import unhexlify
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from pycose import algorithms
from pycose.algorithms import CoseAlgorithm
from pycose.exceptions import CoseException, CoseInvalidParameter, CoseInvalidTag
from pycose.headers import Algorithm, IV, PartialIV
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.enc0message import Enc0Message

PARAMETER_TABLE = Path(__file__).parent / "vectors" / "aes-ccm-parameters.json"

# RFC 9053, Section 4.2, Table 6: "Algorithm Values for AES-CCM".
# name, value, L (bits), M (bits), key length (bits)
SPEC_ROWS = {
    10: ("AES-CCM-16-64-128", 16, 64, 128),
    11: ("AES-CCM-16-64-256", 16, 64, 256),
    12: ("AES-CCM-64-64-128", 64, 64, 128),
    13: ("AES-CCM-64-64-256", 64, 64, 256),
    30: ("AES-CCM-16-128-128", 16, 128, 128),
    31: ("AES-CCM-16-128-256", 16, 128, 256),
    32: ("AES-CCM-64-128-128", 64, 128, 128),
    33: ("AES-CCM-64-128-256", 64, 128, 256),
}

# CCM nonce size is 15 - L/8 bytes; the maximum message is 2^L - 1 bytes.
NONCE_BYTES = {10: 13, 11: 13, 12: 7, 13: 7, 30: 13, 31: 13, 32: 7, 33: 7}
MAX_PLAINTEXT = {
    10: (1 << 16) - 1,
    11: (1 << 16) - 1,
    12: (1 << 64) - 1,
    13: (1 << 64) - 1,
    30: (1 << 16) - 1,
    31: (1 << 16) - 1,
    32: (1 << 64) - 1,
    33: (1 << 64) - 1,
}

ALG_IDS = sorted(SPEC_ROWS)


def load_parameter_table():
    with PARAMETER_TABLE.open("r", encoding="utf-8") as f:
        return json.load(f)


TABLE = load_parameter_table()
TABLE_BY_ID = {row["identifier"]: row for row in TABLE["algorithms"]}


def key_for(alg_id):
    return bytes(range(TABLE_BY_ID[alg_id]["key_bits"] // 8))


def nonce_for(alg_id, fill=0x5A):
    return bytes([fill]) * NONCE_BYTES[alg_id]


def cose_alg(alg_id):
    return CoseAlgorithm.from_id(alg_id)


def protected_header(alg_id):
    return cbor2.dumps({1: alg_id})


def expected_aad(alg_id, external_aad=b""):
    return cbor2.dumps(["Encrypt0", protected_header(alg_id), external_aad])


def build_message(alg_id, key, nonce, plaintext, external_aad=b""):
    return Enc0Message(
        phdr={Algorithm: cose_alg(alg_id)},
        uhdr={IV: nonce},
        payload=plaintext,
        external_aad=external_aad,
        key=key,
    )


def backend_encrypt(alg_id, key, nonce, plaintext, aad):
    row = TABLE_BY_ID[alg_id]
    return AESCCM(key.k, tag_length=row["M_bits"] // 8).encrypt(nonce, plaintext, aad)


def decryption_key(alg_id, key_bytes=None):
    return SymmetricKey(k=key_bytes if key_bytes is not None else key_for(alg_id))


# ---------------------------------------------------------------------------
# Parameter table and vector provenance
# ---------------------------------------------------------------------------

def test_parameter_table_matches_rfc_9053_table_6():
    assert TABLE["specification"]["document"] == "RFC 9053"
    assert TABLE["specification"]["table"] == "Table 6: Algorithm Values for AES-CCM"
    assert sorted(TABLE_BY_ID) == ALG_IDS

    for alg_id in ALG_IDS:
        row = TABLE_BY_ID[alg_id]
        spec_name, spec_L, spec_M, spec_key = SPEC_ROWS[alg_id]
        assert row["fullname"].replace("_", "-") == spec_name
        assert row["L_bits"] == spec_L
        assert row["M_bits"] == spec_M
        assert row["key_bits"] == spec_key
        assert row["nonce_bytes"] == NONCE_BYTES[alg_id]
        assert row["max_plaintext_bytes"] == MAX_PLAINTEXT[alg_id]


@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_vector_files_match_recorded_hashes(alg_id):
    row = TABLE_BY_ID[alg_id]
    vector_path = Path(__file__).parent.parent / row["vector"]
    digest = hashlib.sha256(vector_path.read_bytes()).hexdigest()
    assert digest == row["vector_sha256"]


@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_pycose_algorithm_binds_own_parameters(alg_id):
    row = TABLE_BY_ID[alg_id]
    alg = cose_alg(alg_id)
    assert alg.identifier == alg_id
    assert alg.fullname == row["fullname"]
    assert alg.ccm_L == row["L_bits"]
    assert alg.ccm_M == row["M_bits"]
    assert alg.ccm_key_length == row["key_bits"]
    assert alg.get_nonce_length() == row["nonce_bytes"]
    assert alg.get_tag_length() == row["M_bits"] // 8
    assert alg.get_key_length() == row["key_bits"] // 8
    assert alg.get_max_message_length() == row["max_plaintext_bytes"]


# ---------------------------------------------------------------------------
# Independent Encrypt0 comparison: AAD, ciphertext, tag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_encrypt0_matches_independent_backend_on_vector(alg_id):
    row = TABLE_BY_ID[alg_id]
    vector = json.loads((Path(__file__).parent.parent / row["vector"]).read_text())
    key = SymmetricKey(k=unhexlify(vector["cek"]["k"]))
    nonce = unhexlify(vector["input"]["iv"])
    plaintext = vector["input"]["plaintext"].encode()
    external_aad = unhexlify(vector["input"]["external_aad"])

    msg = build_message(alg_id, key, nonce, plaintext, external_aad)
    assert msg.phdr_encoded == protected_header(alg_id)
    assert msg._enc_structure == expected_aad(alg_id, external_aad)

    expected = backend_encrypt(alg_id, key, nonce, plaintext, msg._enc_structure)
    assert expected == unhexlify(vector["output"]["ciphertext"])
    assert msg.encrypt() == expected

    tag_length = row["M_bits"] // 8
    assert expected[-tag_length:] == unhexlify(vector["output"]["ciphertext"])[-tag_length:]
    assert expected[:-tag_length] == unhexlify(vector["output"]["ciphertext"])[:-tag_length]

    decrypted = build_message(alg_id, key, nonce, b"")
    decrypted.payload = expected
    assert decrypted.decrypt() == plaintext


@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_encrypt0_empty_plaintext_matches_independent_backend(alg_id):
    row = TABLE_BY_ID[alg_id]
    tag_length = row["M_bits"] // 8
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    external_aad = b"empty-plaintext"

    msg = build_message(alg_id, key, nonce, b"", external_aad)
    expected = backend_encrypt(alg_id, key, nonce, b"", msg._enc_structure)

    assert msg._enc_structure == expected_aad(alg_id, external_aad)
    assert msg.encrypt() == expected
    assert len(expected) == tag_length

    decrypted = build_message(alg_id, key, nonce, b"", external_aad)
    decrypted.payload = expected
    assert decrypted.decrypt() == b""


@pytest.mark.parametrize("alg_id", [a for a in ALG_IDS if NONCE_BYTES[a] == 13])
def test_l16_plaintext_near_maximum_short_boundary(alg_id):
    max_length = MAX_PLAINTEXT[alg_id]
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    plaintext = b"A" * max_length

    msg = build_message(alg_id, key, nonce, plaintext)
    expected = backend_encrypt(alg_id, key, nonce, plaintext, msg._enc_structure)
    assert msg.encrypt() == expected

    decrypted = build_message(alg_id, key, nonce, b"")
    decrypted.payload = expected
    assert decrypted.decrypt() == plaintext


@pytest.mark.parametrize("alg_id", [a for a in ALG_IDS if NONCE_BYTES[a] == 7])
def test_l64_accepts_length_beyond_l16_limit(alg_id):
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    plaintext = b"B" * ((1 << 16) + 1)

    msg = build_message(alg_id, key, nonce, plaintext)
    expected = backend_encrypt(alg_id, key, nonce, plaintext, msg._enc_structure)
    assert msg.encrypt() == expected


# ---------------------------------------------------------------------------
# Early rejection of oversized declarations with observable substitutes
# ---------------------------------------------------------------------------

class ObservableBuffer:
    """A stand-in that reports a declared length without holding the data."""

    def __init__(self, declared_length):
        self.declared_length = declared_length
        self.len_calls = 0
        self.contents_accessed = False

    def __len__(self):
        self.len_calls += 1
        return self.declared_length

    def _refuse(self, *args, **kwargs):
        self.contents_accessed = True
        raise AssertionError("contents of an oversized declaration must not be read")

    __getitem__ = _refuse
    __iter__ = _refuse
    __bytes__ = _refuse


class BackendSpy:
    """Backend substitute that fails the test if it is ever constructed."""

    constructed = 0

    def __init__(self, *args, **kwargs):
        type(self).constructed += 1
        raise AssertionError("AES-CCM backend must not be reached for invalid parameters")


@pytest.mark.parametrize("alg_id", [a for a in ALG_IDS if NONCE_BYTES[a] == 13])
def test_l16_oversized_plaintext_rejected_before_backend(monkeypatch, alg_id):
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    oversized = ObservableBuffer(1 << 16)

    BackendSpy.constructed = 0
    monkeypatch.setattr(algorithms, "AESCCM", BackendSpy)

    with pytest.raises(CoseInvalidParameter):
        cose_alg(alg_id).encrypt(key, nonce, oversized, b"aad")

    assert BackendSpy.constructed == 0
    assert oversized.len_calls == 1
    assert oversized.contents_accessed is False


@pytest.mark.parametrize("alg_id", [a for a in ALG_IDS if NONCE_BYTES[a] == 13])
def test_l16_oversized_ciphertext_rejected_before_backend(monkeypatch, alg_id):
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    tag_length = TABLE_BY_ID[alg_id]["M_bits"] // 8
    oversized = ObservableBuffer((1 << 16) + tag_length)

    BackendSpy.constructed = 0
    monkeypatch.setattr(algorithms, "AESCCM", BackendSpy)

    with pytest.raises(CoseInvalidParameter):
        cose_alg(alg_id).decrypt(key, nonce, oversized, b"aad")

    assert BackendSpy.constructed == 0
    assert oversized.len_calls == 1
    assert oversized.contents_accessed is False


@pytest.mark.parametrize("alg_id", [a for a in ALG_IDS if NONCE_BYTES[a] == 7])
def test_l64_unrepresentable_declaration_rejected_before_backend(monkeypatch, alg_id):
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    # Larger than any addressable Python buffer, so len() itself overflows.
    oversized = ObservableBuffer(1 << 64)

    BackendSpy.constructed = 0
    monkeypatch.setattr(algorithms, "AESCCM", BackendSpy)

    with pytest.raises(CoseInvalidParameter):
        cose_alg(alg_id).encrypt(key, nonce, oversized, b"aad")

    assert BackendSpy.constructed == 0
    assert oversized.len_calls == 1
    assert oversized.contents_accessed is False


# ---------------------------------------------------------------------------
# Wrong nonce length, truncated tag, and algorithm-number substitution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_wrong_nonce_length_rejected(alg_id):
    key = SymmetricKey(k=key_for(alg_id))
    plaintext = b"nonce length check"
    alg = cose_alg(alg_id)
    correct = NONCE_BYTES[alg_id]

    bad_lengths = {correct - 1, correct + 1, 6, 7, 13, 14} - {correct}
    for bad_length in sorted(bad_lengths):
        bad_nonce = bytes([0x11]) * bad_length
        with pytest.raises(CoseInvalidParameter):
            alg.encrypt(key, bad_nonce, plaintext, b"aad")
        with pytest.raises(CoseInvalidParameter):
            alg.decrypt(key, bad_nonce, b"\x00" * (len(plaintext) + alg.get_tag_length()), b"aad")

        msg = build_message(alg_id, key, bad_nonce, plaintext)
        with pytest.raises(CoseInvalidParameter):
            msg.encrypt()


@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_wrong_key_length_rejected(alg_id):
    alg = cose_alg(alg_id)
    nonce = nonce_for(alg_id)
    correct = TABLE_BY_ID[alg_id]["key_bits"] // 8
    for bad_length in sorted({16, 24, 32} - {correct}):
        key = SymmetricKey(k=bytes([0x22]) * bad_length)
        with pytest.raises(CoseInvalidParameter):
            alg.encrypt(key, nonce, b"payload", b"aad")
        with pytest.raises(CoseInvalidParameter):
            alg.decrypt(key, nonce, b"\x00" * (7 + alg.get_tag_length()), b"aad")


@pytest.mark.parametrize("alg_id", ALG_IDS)
@pytest.mark.parametrize("cut", [1, 4, 8, 16])
def test_truncated_tag_rejected_without_plaintext(alg_id, cut):
    row = TABLE_BY_ID[alg_id]
    tag_length = row["M_bits"] // 8
    if cut > tag_length:
        pytest.skip("cut exceeds this algorithm's tag length")

    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    plaintext = b"authenticated plaintext"
    full = backend_encrypt(alg_id, key, nonce, plaintext, expected_aad(alg_id))
    truncated = full[:-cut]

    msg = build_message(alg_id, key, nonce, b"")
    msg.payload = truncated
    with pytest.raises(CoseException):
        result = msg.decrypt()
        pytest.fail(f"truncated tag returned plaintext: {result!r}")


@pytest.mark.parametrize("source_alg,target_alg", [(10, 30), (11, 31), (12, 32), (13, 33)])
def test_replace_algorithm_number_with_same_lengths_but_different_tag(source_alg, target_alg):
    plaintext = b"algorithm substitution"
    key = SymmetricKey(k=key_for(source_alg))
    nonce = nonce_for(source_alg)

    source = build_message(source_alg, key, nonce, plaintext)
    source_ct = source.encrypt()
    target = build_message(target_alg, key, nonce, plaintext)
    target_ct = target.encrypt()

    assert len(source_ct) != len(target_ct)
    assert source_ct != target_ct

    # A ciphertext produced under one CCM combination must not verify as another.
    substituted = build_message(target_alg, key, nonce, b"")
    substituted.payload = source_ct
    with pytest.raises(CoseInvalidTag):
        result = substituted.decrypt()
        pytest.fail(f"substituted algorithm returned plaintext: {result!r}")

    reverse = build_message(source_alg, key, nonce, b"")
    reverse.payload = target_ct
    with pytest.raises(CoseInvalidTag):
        reverse.decrypt()


@pytest.mark.parametrize("source_alg,target_alg", [(10, 11), (10, 12), (30, 33), (12, 13)])
def test_replace_algorithm_number_with_different_lengths(source_alg, target_alg):
    plaintext = b"algorithm substitution"
    source_key = SymmetricKey(k=key_for(source_alg))
    source_nonce = nonce_for(source_alg)

    source = build_message(source_alg, source_key, source_nonce, plaintext)
    source_ct = source.encrypt()

    substituted = build_message(target_alg, source_key, source_nonce, b"")
    substituted.payload = source_ct
    with pytest.raises(CoseInvalidParameter):
        result = substituted.decrypt()
        pytest.fail(f"substituted algorithm returned plaintext: {result!r}")


@pytest.mark.parametrize("source_alg,target_alg", [(10, 30), (12, 32)])
def test_wire_level_algorithm_number_substitution_rejected(source_alg, target_alg):
    plaintext = b"wire algorithm substitution"
    key = SymmetricKey(k=key_for(source_alg))
    nonce = nonce_for(source_alg)

    encoded = build_message(source_alg, key, nonce, plaintext).encode()
    tagged = cbor2.loads(encoded)
    cose_obj = list(tagged.value)
    cose_obj[0] = protected_header(target_alg)
    tagged.value = cose_obj

    tampered = Enc0Message.decode(cbor2.dumps(tagged))
    tampered.key = key
    with pytest.raises(CoseInvalidTag):
        result = tampered.decrypt()
        pytest.fail(f"wire substitution returned plaintext: {result!r}")


# ---------------------------------------------------------------------------
# Regression proof: deliberately swap one L mapping
# ---------------------------------------------------------------------------

def test_deliberate_l_swap_is_detected(monkeypatch):
    alg = cose_alg(10)
    spec_L = TABLE_BY_ID[10]["L_bits"]
    spec_nonce = NONCE_BYTES[10]
    key = SymmetricKey(k=key_for(10))
    nonce = nonce_for(10)

    assert alg.ccm_L == spec_L
    assert alg.get_nonce_length() == spec_nonce
    assert alg.encrypt(key, nonce, b"ok", expected_aad(10))  # baseline accepts

    # Swap the L binding for this algorithm number (16 -> 64).
    swapped_L = 64 if spec_L == 16 else 16
    monkeypatch.setattr(alg, "ccm_L", swapped_L)

    assert alg.get_nonce_length() == 15 - swapped_L // 8
    assert alg.get_nonce_length() != spec_nonce
    assert alg.get_max_message_length() != MAX_PLAINTEXT[10]

    # The parameter-table assertion is sensitive to the wrong mapping.
    with pytest.raises(AssertionError):
        assert alg.get_nonce_length() == TABLE_BY_ID[10]["nonce_bytes"]

    # And the validation now rejects the specification-correct nonce.
    with pytest.raises(CoseInvalidParameter):
        alg.encrypt(key, nonce, b"ok", expected_aad(10))

    # Restore and confirm the correct mapping works again.
    monkeypatch.undo()
    assert alg.get_nonce_length() == spec_nonce
    assert alg.encrypt(key, nonce, b"ok", expected_aad(10))


# ---------------------------------------------------------------------------
# Provenance: parse Table 6 from the pinned RFC 9053 text itself
# ---------------------------------------------------------------------------

SPEC_FILE = Path(__file__).parent.parent / ".feedback" / "specs" / "rfc9053.txt"


def parse_rfc_table_6():
    text = SPEC_FILE.read_text(encoding="utf-8-sig")
    # rindex skips the table-of-contents entry and lands on the section body.
    start = text.rindex("4.2.  AES-CCM")
    end = text.index("Table 6: Algorithm Values for AES-CCM", start)

    rows = []
    current = None
    for line in text[start:end].splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        values = [c.strip() for c in stripped.split("|")[1:-1]]

        if values[0].startswith("AES-CCM-"):
            current = {
                "name": values[0],
                "identifier": int(values[1]),
                "L_bits": int(values[2]),
                "M_bits": int(values[3]),
                "key_bits": int(values[4]),
                "description": values[5],
            }
            rows.append(current)
        elif current is not None and not values[0]:
            # Continuation rows finish the description column.
            if values[5]:
                current["description"] += " " + values[5]

    return rows


def test_parameter_table_is_derived_from_pinned_spec_text():
    assert SPEC_FILE.exists()
    digest = hashlib.sha256(SPEC_FILE.read_bytes()).hexdigest()
    assert digest == TABLE["specification"]["sha256"]

    parsed = parse_rfc_table_6()
    assert len(parsed) == len(ALG_IDS)
    assert {row["identifier"] for row in parsed} == set(ALG_IDS)

    for spec_row in parsed:
        alg_id = spec_row["identifier"]
        row = TABLE_BY_ID[alg_id]
        assert row["fullname"].replace("_", "-") == spec_row["name"]

        # The description independently repeats M, key length, and nonce size.
        assert f"{spec_row['M_bits']}-bit tag" in spec_row["description"]
        assert f"{spec_row['key_bits']}-bit key" in spec_row["description"]
        assert f"{NONCE_BYTES[alg_id]}-byte nonce" in spec_row["description"]
        assert NONCE_BYTES[alg_id] == 15 - spec_row["L_bits"] // 8

        assert row["L_bits"] == spec_row["L_bits"]
        assert row["M_bits"] == spec_row["M_bits"]
        assert row["key_bits"] == spec_row["key_bits"]


# ---------------------------------------------------------------------------
# Nonce construction from Context IV and Partial IV
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alg_id,partial_iv", [
    (10, b"\x67"),
    (30, b"\x00\x01"),
    (12, b"\x42"),
    (32, b"\x00\x00\x05"),
])
def test_partial_iv_expands_to_exact_algorithm_nonce_length(alg_id, partial_iv):
    nonce_length = NONCE_BYTES[alg_id]
    base_iv = bytes([0x80]) * nonce_length

    # A leading zero in the expanded nonce must not be trimmed away.
    expanded = partial_iv.rjust(nonce_length, b"\x00")
    expected_nonce = bytes(a ^ b for a, b in zip(expanded, base_iv))
    assert len(expected_nonce) == nonce_length

    key = SymmetricKey(k=key_for(alg_id), optional_params={"BASE_IV": base_iv})
    plaintext = b"context iv plus partial iv"
    msg = Enc0Message(
        phdr={Algorithm: cose_alg(alg_id)},
        uhdr={PartialIV: partial_iv},
        payload=plaintext,
        key=key,
    )

    assert msg._get_nonce() == expected_nonce
    expected = backend_encrypt(alg_id, key, expected_nonce, plaintext, msg._enc_structure)
    assert msg.encrypt() == expected

    decrypted = Enc0Message(
        phdr={Algorithm: cose_alg(alg_id)},
        uhdr={PartialIV: partial_iv},
        payload=b"",
        key=key,
    )
    decrypted.payload = expected
    assert decrypted.decrypt() == plaintext


@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_context_iv_wrong_length_rejected(alg_id):
    nonce_length = NONCE_BYTES[alg_id]
    key = SymmetricKey(k=key_for(alg_id), optional_params={"BASE_IV": bytes([1]) * (nonce_length + 1)})
    msg = Enc0Message(
        phdr={Algorithm: cose_alg(alg_id)},
        uhdr={PartialIV: b"\x01"},
        payload=b"payload",
        key=key,
    )
    with pytest.raises(CoseException):
        msg.encrypt()


@pytest.mark.parametrize("alg_id", ALG_IDS)
def test_partial_iv_longer_than_algorithm_iv_rejected(alg_id):
    nonce_length = NONCE_BYTES[alg_id]
    key = SymmetricKey(k=key_for(alg_id), optional_params={"BASE_IV": bytes([1]) * nonce_length})
    msg = Enc0Message(
        phdr={Algorithm: cose_alg(alg_id)},
        uhdr={PartialIV: bytes([2]) * (nonce_length + 1)},
        payload=b"payload",
        key=key,
    )
    with pytest.raises(CoseException):
        msg.encrypt()


@pytest.mark.parametrize("alg_id", ALG_IDS)
@pytest.mark.parametrize("cut", [1, 4])
def test_wire_level_truncated_tag_rejected(alg_id, cut):
    tag_length = TABLE_BY_ID[alg_id]["M_bits"] // 8
    if cut > tag_length:
        pytest.skip("cut exceeds this algorithm's tag length")

    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    plaintext = b"wire truncated tag"
    encoded = build_message(alg_id, key, nonce, plaintext).encode()

    tagged = cbor2.loads(encoded)
    cose_obj = list(tagged.value)
    cose_obj[2] = cose_obj[2][:-cut]
    tagged.value = cose_obj

    tampered = Enc0Message.decode(cbor2.dumps(tagged))
    tampered.key = key
    with pytest.raises(CoseException):
        result = tampered.decrypt()
        pytest.fail(f"truncated wire tag returned plaintext: {result!r}")
    assert tampered.payload != plaintext


@pytest.mark.parametrize("alg_id", [a for a in ALG_IDS if NONCE_BYTES[a] == 7])
def test_l64_unrepresentable_ciphertext_declaration_rejected_before_backend(monkeypatch, alg_id):
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    oversized = ObservableBuffer(1 << 64)

    BackendSpy.constructed = 0
    monkeypatch.setattr(algorithms, "AESCCM", BackendSpy)

    with pytest.raises(CoseInvalidParameter):
        cose_alg(alg_id).decrypt(key, nonce, oversized, b"aad")

    assert BackendSpy.constructed == 0
    assert oversized.len_calls == 1
    assert oversized.contents_accessed is False


@pytest.mark.parametrize("alg_id", ALG_IDS)
@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_modified_ciphertext_body_rejected(alg_id, position):
    key = SymmetricKey(k=key_for(alg_id))
    nonce = nonce_for(alg_id)
    plaintext = b"ciphertext body integrity"
    tag_length = TABLE_BY_ID[alg_id]["M_bits"] // 8

    msg = build_message(alg_id, key, nonce, plaintext)
    ciphertext = bytearray(msg.encrypt())
    body_length = len(ciphertext) - tag_length
    assert body_length > 0

    index = {"first": 0, "middle": body_length // 2, "last": body_length - 1}[position]
    ciphertext[index] ^= 0x01

    tampered = build_message(alg_id, key, nonce, b"")
    tampered.payload = bytes(ciphertext)
    with pytest.raises(CoseInvalidTag):
        result = tampered.decrypt()
        pytest.fail(f"modified ciphertext returned plaintext: {result!r}")
