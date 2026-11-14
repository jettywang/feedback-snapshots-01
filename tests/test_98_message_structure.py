"""
Strict OpenPGP message-structure validation.

These tests pin down the behavior of :meth:`PGPMessage._validate_structure`,
which enforces the packet composition grammar from RFC 4880 section 11.3.
The point is that a message must not be accepted merely because the final
Signature packet happens to verify: the one-pass signature declarations have
to match the signatures that actually close them, the signature stack has to
nest and close in the right order, and extra or uncovered content (multiple
literal data packets, a missing closing signature, a stray body, or a
compressed layer hiding extra packets) must be rejected while the original
packet sequence is still visible.

Every malformed case below is built from a message whose signature is
cryptographically valid on its own; only the surrounding structure is wrong.
A legal double-signed message is included as the positive control.
"""
import copy
from datetime import datetime, timezone

import pytest

from pgpy import PGPKey, PGPMessage
from pgpy.constants import CompressionAlgorithm, HashAlgorithm, PubKeyAlgorithm, SignatureType
from pgpy.errors import PGPStructureError
from pgpy.packet import Packet
from pgpy.packet.packets import (
    CompressedData,
    LiteralData,
    OnePassSignatureV3,
)


@pytest.fixture(scope="module")
def signer_a():
    return PGPKey.from_file("tests/testdata/keys/rsa.1.sec.asc")[0]


@pytest.fixture(scope="module")
def signer_b():
    return PGPKey.from_file("tests/testdata/keys/ecc.1.sec.asc")[0]


@pytest.fixture(scope="module")
def pub_a(signer_a):
    return PGPKey.from_file("tests/testdata/keys/rsa.1.pub.asc")[0]


@pytest.fixture(scope="module")
def pub_b(signer_b):
    return PGPKey.from_file("tests/testdata/keys/ecc.1.pub.asc")[0]


def _parse_packets(blob):
    """Parse a (binary or armored) message into its raw packet objects."""
    message = PGPMessage()
    unarmored = message.ascii_unarmor(blob)
    data = unarmored["body"]
    packets = []
    while len(data) > 0:
        packets.append(Packet(data))
    return packets


def _serialize(packets):
    return b"".join(bytes(pkt) for pkt in packets)


def _literal(text, filename=""):
    pkt = LiteralData()
    pkt.format = "b"
    pkt.filename = filename
    pkt.mtime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    pkt._contents = bytearray(text if isinstance(text, bytes) else text.encode("utf-8"))
    pkt.update_hlen()
    return pkt


def _signer_id(key):
    # the key may sign with a subkey rather than the primary key
    message = PGPMessage.new("id probe", compression=CompressionAlgorithm.Uncompressed)
    return key.sign(message).signer


def _signed_packets(keys, text="covered payload"):
    """Build a valid one-pass signed packet sequence with several signers."""
    message = PGPMessage.new(text, compression=CompressionAlgorithm.Uncompressed)
    for key in keys:
        message |= key.sign(message)
    return _parse_packets(bytes(message))


def _onepass_indexes(packets):
    return [i for i, p in enumerate(packets) if isinstance(p, OnePassSignatureV3)]


def _load_raw(packets):
    return PGPMessage.from_blob(_serialize(packets))


def _as_bytes(content):
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    return content.encode("utf-8")


class TestValidStructures:
    def test_single_signature_roundtrip_and_verifies(self, signer_a, pub_a):
        packets = _signed_packets([signer_a])
        message = _load_raw(packets)

        assert message.is_signed
        assert _as_bytes(message.message) == b"covered payload"
        assert message.signers == {_signer_id(signer_a)}
        assert pub_a.verify(message)

    def test_legal_double_signature_accepted(self, signer_a, signer_b, pub_a, pub_b):
        # positive control: two independent signatures over the same body
        packets = _signed_packets([signer_a, signer_b])
        message = _load_raw(packets)

        assert message.signers == {_signer_id(signer_a), _signer_id(signer_b)}
        assert pub_a.verify(message)
        assert pub_b.verify(message)

    def test_double_signature_keeps_both_signatures(self, signer_a, signer_b):
        packets = _signed_packets([signer_a, signer_b])
        message = _load_raw(packets)
        assert len(message.signatures) == 2

    def test_compressed_signed_message_accepted(self, signer_a, pub_a):
        # a compression layer wrapping the covered literal data is legal
        message = PGPMessage.new("compressed and signed", compression=CompressionAlgorithm.ZLIB)
        message |= signer_a.sign(message)

        loaded = PGPMessage.from_blob(bytes(message))
        assert loaded.is_compressed
        assert pub_a.verify(loaded)

    def test_unsigned_literal_message_accepted(self):
        message = PGPMessage.new("plain literal only", compression=CompressionAlgorithm.Uncompressed)
        loaded = PGPMessage.from_blob(bytes(message))
        assert _as_bytes(loaded.message) == b"plain literal only"
        assert not loaded.is_signed

    @pytest.mark.parametrize("block,expected", [
        ("tests/testdata/blocks/message.onepass.asc", {"2A834D8E5918E886"}),
        ("tests/testdata/blocks/message.two_onepass.asc", {"2A834D8E5918E886", "A5DCDC966453140E"}),
    ])
    def test_gnupg_generated_onepass_blocks_accepted(self, block, expected):
        # these blocks were produced by GnuPG, whose nested-flag polarity
        # differs from PGPy's own generator; both conventions must load
        with open(block) as handle:
            loaded = PGPMessage.from_blob(handle.read())
        assert loaded.is_signed
        assert loaded.signers == expected

    def test_leading_signature_form_accepted(self, signer_a, pub_a):
        # RFC 4880's non-one-pass Signed Message: Signature then the message
        packets = [p for p in _signed_packets([signer_a])
                   if not isinstance(p, OnePassSignatureV3)]
        # reorder to the leading-signature grammar form
        signature = next(p for p in packets if p.__class__.__name__ == "SignatureV4")
        literal = next(p for p in packets if isinstance(p, LiteralData))
        message = _load_raw([signature, literal])
        assert message.is_signed
        assert pub_a.verify(message)

    def test_lone_signature_without_body_rejected(self, signer_a):
        packets = _signed_packets([signer_a])
        lone = [p for p in packets if p.__class__.__name__ == "SignatureV4"]
        with pytest.raises(PGPStructureError, match="not followed by any message content"):
            _load_raw(lone)


class TestOnePassMismatch:
    def test_rejection_is_structural_not_cryptographic(self, signer_a, signer_b, pub_a, pub_b):
        # the same signatures verify fine in a well-formed message; only the
        # corrupted one-pass claims make the manipulated message invalid
        well_formed = _load_raw(_signed_packets([signer_a, signer_b]))
        assert pub_a.verify(well_formed)
        assert pub_b.verify(well_formed)

        packets = _signed_packets([signer_a, signer_b])
        onepass = _onepass_indexes(packets)
        packets[onepass[0]].signer, packets[onepass[1]].signer = (
            packets[onepass[1]].signer,
            packets[onepass[0]].signer,
        )
        with pytest.raises(PGPStructureError, match="signer"):
            _load_raw(packets)

    def test_signer_mismatch_rejected(self, signer_a, signer_b):
        # the signature stays valid for its own signer, but the one-pass
        # packet claims a different key produced it
        packets = _signed_packets([signer_a, signer_b])
        onepass = _onepass_indexes(packets)
        first_ops, last_ops = packets[onepass[0]], packets[onepass[-1]]
        first_ops.signer, last_ops.signer = last_ops.signer, first_ops.signer

        with pytest.raises(PGPStructureError, match="signer"):
            _load_raw(packets)

    def test_hash_algorithm_mismatch_rejected(self, signer_a):
        packets = _signed_packets([signer_a])
        ops = packets[_onepass_indexes(packets)[0]]
        original = ops.halg
        ops.halg = HashAlgorithm.SHA512 if original != HashAlgorithm.SHA512 else HashAlgorithm.SHA256

        with pytest.raises(PGPStructureError, match="hash algorithm"):
            _load_raw(packets)

    def test_public_key_algorithm_mismatch_rejected(self, signer_a, signer_b):
        packets = _signed_packets([signer_a, signer_b])
        ops = packets[_onepass_indexes(packets)[0]]
        # claim the public-key algorithm of the other signer
        ops.pubalg = signer_b.key_algorithm if ops.pubalg != signer_b.key_algorithm else PubKeyAlgorithm.RSAEncryptOrSign

        with pytest.raises(PGPStructureError, match="public-key algorithm"):
            _load_raw(packets)

    def test_signature_type_mismatch_rejected(self, signer_a):
        packets = _signed_packets([signer_a])
        ops = packets[_onepass_indexes(packets)[0]]
        ops.sigtype = SignatureType.CanonicalDocument

        with pytest.raises(PGPStructureError, match="signature type"):
            _load_raw(packets)


class TestStackOrdering:
    def test_missing_final_signature_rejected(self, signer_a):
        # one-pass packet present but its closing signature was stripped
        packets = _signed_packets([signer_a])
        del packets[-1]  # remove the final Signature packet

        with pytest.raises(PGPStructureError, match="closing signature"):
            _load_raw(packets)

    def test_swapped_closing_signatures_rejected(self, signer_a, signer_b):
        # the bracket order is wrong: closing signatures no longer line up
        # with the reversed one-pass stack, so signer correspondence breaks
        packets = _signed_packets([signer_a, signer_b])
        sig_indexes = [i for i, p in enumerate(packets) if p.__class__.__name__ == "SignatureV4"]
        assert len(sig_indexes) == 2
        packets[sig_indexes[0]], packets[sig_indexes[1]] = (
            packets[sig_indexes[1]],
            packets[sig_indexes[0]],
        )

        with pytest.raises(PGPStructureError, match="signer"):
            _load_raw(packets)

    def test_malformed_nested_flags_rejected(self, signer_a, signer_b):
        # mark both one-pass packets the same way so no boundary is defined
        packets = _signed_packets([signer_a, signer_b])
        for index in _onepass_indexes(packets):
            packets[index].nested = True

        with pytest.raises(PGPStructureError, match="nested"):
            _load_raw(packets)

    def test_onepass_not_at_start_rejected(self, signer_a):
        # move the one-pass packet behind the literal data, breaking the
        # required One-Pass -> message -> Signature ordering
        packets = _signed_packets([signer_a])
        ops_index = _onepass_indexes(packets)[0]
        ops = packets.pop(ops_index)
        literal_index = next(i for i, p in enumerate(packets) if isinstance(p, LiteralData))
        packets.insert(literal_index + 1, ops)

        with pytest.raises(PGPStructureError):
            _load_raw(packets)


class TestUncoveredContent:
    def test_multiple_literal_data_rejected(self, signer_a):
        # a second literal body is silently dropped by high-level assembly;
        # the structure check must refuse the message instead
        packets = _signed_packets([signer_a])
        extra = _literal(b"uncovered second body")
        literal_index = next(i for i, p in enumerate(packets) if isinstance(p, LiteralData))
        packets.insert(literal_index + 1, extra)

        with pytest.raises(PGPStructureError, match="single Literal Data"):
            _load_raw(packets)

    def test_extra_literal_after_signature_rejected(self, signer_a):
        # an uncovered body trailing the closing signature packet
        packets = _signed_packets([signer_a])
        packets.append(_literal(b"appended after the signature"))

        with pytest.raises(PGPStructureError):
            _load_raw(packets)

    def test_compressed_layer_hiding_extra_literal_rejected(self, signer_a):
        # the compression layer must not fold two literal packets into one
        packets = _signed_packets([signer_a])
        literal_index = next(i for i, p in enumerate(packets) if isinstance(p, LiteralData))
        original_literal = packets[literal_index]

        comp = CompressedData()
        comp.calg = CompressionAlgorithm.ZLIB
        comp.packets = [original_literal, _literal(b"smuggled inside compression")]
        comp.update_hlen()
        packets[literal_index] = comp

        with pytest.raises(PGPStructureError, match="single Literal Data"):
            _load_raw(packets)

    def test_two_top_level_compressed_packets_rejected(self, signer_a):
        packets = _signed_packets([signer_a])
        literal_index = next(i for i, p in enumerate(packets) if isinstance(p, LiteralData))
        original_literal = packets[literal_index]

        first = CompressedData()
        first.calg = CompressionAlgorithm.ZLIB
        first.packets = [original_literal]
        first.update_hlen()

        second = CompressedData()
        second.calg = CompressionAlgorithm.ZLIB
        second.packets = [_literal(b"second compressed body")]
        second.update_hlen()

        packets[literal_index:literal_index + 1] = [first, second]

        with pytest.raises(PGPStructureError, match="only packet"):
            _load_raw(packets)

    def test_empty_compressed_layer_rejected(self):
        comp = CompressedData()
        comp.calg = CompressionAlgorithm.ZLIB
        comp.packets = []
        comp.update_hlen()

        with pytest.raises(PGPStructureError, match="no packets found"):
            _load_raw([comp])


class TestValidationTiming:
    def test_check_runs_before_high_level_folding(self, signer_a):
        # prove the decision is made on the raw sequence: the malformed blob
        # cannot be salvaged by high-level assembly, and from_blob rejects it
        # while the second literal packet is still present in the stream.
        packets = _signed_packets([signer_a])
        extra = _literal(b"this would be dropped by folding")
        literal_index = next(i for i, p in enumerate(packets) if isinstance(p, LiteralData))
        packets.insert(literal_index + 1, extra)
        blob = _serialize(packets)

        # the raw packet stream really does contain two literal packets at
        # validation time, i.e. the structure is still observable
        raw_packets = _parse_packets(blob)
        assert sum(isinstance(p, LiteralData) for p in raw_packets) == 2

        # parse refuses the message on structural grounds, before __ior__ ever
        # gets a chance to accept the first and discard/reject the second body
        with pytest.raises(PGPStructureError, match="single Literal Data"):
            PGPMessage.from_blob(blob)

        # folding the same sequence by hand does not produce a valid signed
        # message either: the second literal is outside the signed body
        folded = PGPMessage()
        with pytest.raises(NotImplementedError):
            for pkt in copy.deepcopy(raw_packets):
                folded |= pkt
        assert _as_bytes(folded.message) == b"covered payload"

    def test_validator_sees_onepass_that_assembly_discards(self, signer_a):
        # __ior__ throws OnePassSignature packets away, so the cross-check
        # against the closing signature can only happen during parse.
        packets = _signed_packets([signer_a])
        ops_index = _onepass_indexes(packets)[0]
        packets[ops_index].halg = HashAlgorithm.SHA512
        blob = _serialize(packets)

        # the one-pass packet is still present in the raw stream ...
        assert any(isinstance(p, OnePassSignatureV3) for p in _parse_packets(blob))
        # ... and parse refuses it instead of silently ignoring the claim
        with pytest.raises(PGPStructureError, match="hash algorithm"):
            PGPMessage.from_blob(blob)

    def test_rejected_message_is_not_partially_built(self, signer_a):
        packets = _signed_packets([signer_a])
        del packets[-1]  # remove closing signature
        blob = _serialize(packets)

        message = PGPMessage()
        with pytest.raises(PGPStructureError):
            message.parse(blob)
        # failure happens before folding, so no message body was assembled
        assert message._message is None
