# -*- coding: utf-8 -*-
"""Hardening tests for the macaroon authorization entry point.

These tests assert that every import path (binary v1, binary v2 and JSON)
rejects structurally ambiguous macaroons instead of letting a serializer pick
one of several competing fields, while still accepting genuinely issued
tokens and preserving their permission semantics on re-export.
"""
from __future__ import unicode_literals

import pytest

from pymacaroons import Macaroon, MACAROON_V1, MACAROON_V2, Verifier
from pymacaroons.serializers import BinarySerializer, JsonSerializer
from pymacaroons.exceptions import (
    MacaroonDeserializationException,
    MacaroonInvalidSignatureException,
    MacaroonInitException,
)


SECRET_KEY = 'this is our super secret key; only we should know it'
THIRD_PARTY_KEY = '4; guaranteed random by a fair toss of the dice'


def v1_packet(key, value):
    body = key + b' ' + value + b'\n'
    return ('%04x' % (4 + len(body))).encode('ascii') + body


def uvarint(number):
    out = bytearray()
    while True:
        byte = number & 0x7f
        number >>= 7
        if number == 0:
            out.append(byte)
            break
        out.append(byte | 0x80)
    return bytes(out)


def v2_packet(field_type, data):
    return uvarint(field_type) + uvarint(len(data)) + data


def issued_macaroon(version):
    """A real macaroon produced through the library's own signing path."""
    macaroon = Macaroon(
        location='http://mybank/',
        identifier='we used our secret key',
        key=SECRET_KEY,
        version=version,
    )
    macaroon.add_first_party_caveat('account = 3735928559')
    macaroon.add_third_party_caveat(
        'http://auth.mybank/', THIRD_PARTY_KEY, 'caveat-id')
    return macaroon


@pytest.fixture(params=[MACAROON_V1, MACAROON_V2])
def issued(request):
    return issued_macaroon(request.param)


class TestIssuedTokensRoundTrip(object):
    """Legitimate, signed tokens must import and re-export unchanged."""

    def test_binary_round_trip_preserves_every_field(self, issued):
        token = issued.serialize()
        parsed = Macaroon.deserialize(token)
        assert parsed.version == issued.version
        assert parsed.location == issued.location
        assert parsed.identifier_bytes == issued.identifier_bytes
        assert parsed.signature == issued.signature
        assert len(parsed.caveats) == len(issued.caveats)
        for actual, expected in zip(parsed.caveats, issued.caveats):
            assert actual.caveat_id_bytes == expected.caveat_id_bytes
            assert actual.verification_key_id == \
                expected.verification_key_id
            assert actual._location == expected._location
        # A successful import consumes the whole token and re-exporting it
        # yields the identical permission-bearing bytes.
        assert parsed.serialize() == token

    def test_json_round_trip_preserves_every_field(self, issued):
        serializer = JsonSerializer()
        token = issued.serialize(serializer=serializer)
        parsed = Macaroon.deserialize(token, serializer=serializer)
        assert parsed.version == issued.version
        assert parsed.identifier_bytes == issued.identifier_bytes
        assert parsed.signature == issued.signature
        assert len(parsed.caveats) == len(issued.caveats)
        assert parsed.serialize(serializer=serializer) == token

    def test_issued_token_verifies_with_real_key(self, issued):
        discharge = Macaroon(
            location='http://auth.mybank/',
            identifier='caveat-id',
            key=THIRD_PARTY_KEY,
            version=issued.version,
        )
        bound = issued.prepare_for_request(discharge)
        verifier = Verifier(discharge_macaroons=[bound])
        verifier.satisfy_exact('account = 3735928559')
        assert verifier.verify(issued, SECRET_KEY)


class TestEmptyAndTruncatedInput(object):

    def test_empty_through_entry_point(self):
        with pytest.raises(MacaroonInitException):
            Macaroon.deserialize('')

    def test_empty_raw_v1_and_v2_buffer(self):
        serializer = BinarySerializer()
        with pytest.raises(MacaroonDeserializationException):
            serializer.deserialize_raw(b'')

    def test_empty_json_object(self):
        with pytest.raises(MacaroonDeserializationException):
            JsonSerializer().deserialize('{}')

    def test_truncated_v1_packet_prefix(self):
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(b'00')

    def test_v1_packet_runs_past_end_of_buffer(self):
        # Declares a longer packet than the buffer actually holds.
        broken = b'00ff' + b'identifier id\n'
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(broken)

    def test_v2_missing_end_of_section_marker(self):
        # Header section is never terminated with an EOS byte.
        raw = bytes([MACAROON_V2]) + v2_packet(2, b'id')
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)


class TestBinaryV1Ambiguity(object):

    def _raw(self, *packets):
        return b''.join(packets)

    def test_duplicate_identifier_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'one'),
            v1_packet(b'identifier', b'two'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_duplicate_location_is_rejected(self):
        raw = self._raw(
            v1_packet(b'location', b'a'),
            v1_packet(b'location', b'b'),
            v1_packet(b'identifier', b'id'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_second_root_signature_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'signature', b'\x00' * 32),
            v1_packet(b'signature', b'\x11' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_caveat_after_signature_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'signature', b'\x00' * 32),
            v1_packet(b'cid', b'ghost'),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_zero_length_packet_is_rejected(self):
        raw = b'0000' + v1_packet(b'identifier', b'id') + \
            v1_packet(b'signature', b'\x00' * 32)
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_orphan_verification_id_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'vid', b'v'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_orphan_caveat_location_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'cid', b'a'),
            v1_packet(b'cl', b'loc'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_caveat_location_before_verification_id_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'cid', b'a'),
            v1_packet(b'cl', b'loc'),
            v1_packet(b'vid', b'v'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_duplicate_verification_id_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'cid', b'a'),
            v1_packet(b'vid', b'v1'),
            v1_packet(b'vid', b'v2'),
            v1_packet(b'cl', b'loc'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_interrupted_third_party_block_is_rejected(self):
        # A 'cid' interrupts an open cid/vid block; a lenient parser would
        # attach the trailing 'cl' to a different caveat than a strict one.
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'cid', b'a'),
            v1_packet(b'vid', b'v'),
            v1_packet(b'cid', b'b'),
            v1_packet(b'cl', b'loc'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_missing_identifier_is_rejected(self):
        raw = v1_packet(b'signature', b'\x00' * 32)
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_missing_signature_is_rejected(self):
        raw = v1_packet(b'identifier', b'id')
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_unknown_key_is_rejected(self):
        raw = self._raw(
            v1_packet(b'identifier', b'id'),
            v1_packet(b'bogus', b'x'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_canonical_first_and_third_party_caveats_still_parse(self):
        # Control case: cid(first), cid(third), vid, cl is the canonical,
        # unambiguous encoding emitted by the serializer and must stay valid.
        raw = self._raw(
            v1_packet(b'location', b'loc'),
            v1_packet(b'identifier', b'id'),
            v1_packet(b'cid', b'first'),
            v1_packet(b'cid', b'third'),
            v1_packet(b'vid', b'v'),
            v1_packet(b'cl', b'loc'),
            v1_packet(b'signature', b'\x00' * 32),
        )
        parsed = BinarySerializer().deserialize_raw(raw)
        assert [c.caveat_id for c in parsed.caveats] == [
            'first', 'third']
        assert parsed.caveats[0].first_party()
        assert parsed.caveats[1].third_party()
        assert parsed.caveats[1].location == 'loc'


class TestBinaryV2Ambiguity(object):

    def _header(self, *packets):
        return bytes([MACAROON_V2]) + b''.join(packets)

    def test_trailing_byte_after_signature_is_rejected(self):
        token = issued_macaroon(MACAROON_V2).serialize()
        raw = BinarySerializer()
        decoded = raw.deserialize(token)  # control: parses
        assert decoded is not None
        rebuilt = BinarySerializer().serialize_raw(
            issued_macaroon(MACAROON_V2))
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(rebuilt + b'X')

    def test_trailing_packet_after_signature_is_rejected(self):
        rebuilt = BinarySerializer().serialize_raw(
            issued_macaroon(MACAROON_V2))
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(
                rebuilt + v2_packet(2, b'trailing'))

    def test_second_signature_is_rejected(self):
        rebuilt = BinarySerializer().serialize_raw(
            issued_macaroon(MACAROON_V2))
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(
                rebuilt + v2_packet(6, b'\x11' * 32))

    def test_duplicate_header_identifier_is_rejected(self):
        raw = self._header(
            v2_packet(1, b'loc'),
            v2_packet(2, b'a'),
            v2_packet(2, b'b'),
            b'\x00', b'\x00',
            v2_packet(6, b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_duplicate_caveat_identifier_is_rejected(self):
        raw = self._header(
            v2_packet(2, b'id'), b'\x00',
            v2_packet(2, b'a'), v2_packet(2, b'b'), b'\x00',
            b'\x00',
            v2_packet(6, b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_zero_length_field_is_rejected(self):
        raw = self._header(
            v2_packet(2, b''), b'\x00', b'\x00',
            v2_packet(6, b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_unknown_field_type_is_rejected(self):
        raw = self._header(
            bytes([5, 1]) + b'x',
            v2_packet(2, b'id'), b'\x00', b'\x00',
            v2_packet(6, b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_invalid_utf8_location_is_structural_error(self):
        raw = self._header(
            v2_packet(1, b'\xff\xff'),
            v2_packet(2, b'id'), b'\x00', b'\x00',
            v2_packet(6, b'\x00' * 32),
        )
        with pytest.raises(MacaroonDeserializationException):
            BinarySerializer().deserialize_raw(raw)

    def test_binary_identifier_round_trips_without_text_coercion(self):
        binary_identifier = bytes([0x00, 0xff, 0x10, 0xfe])
        macaroon = Macaroon(
            location='loc',
            identifier=binary_identifier,
            key=SECRET_KEY,
            version=MACAROON_V2,
        )
        parsed = Macaroon.deserialize(macaroon.serialize())
        assert parsed.identifier_bytes == binary_identifier
        assert parsed.serialize() == macaroon.serialize()


class TestJsonAmbiguity(object):

    def setup_method(self):
        self.serializer = JsonSerializer()

    def test_duplicate_v1_identifier_key_is_rejected(self):
        token = '{"identifier":"a","identifier":"b","signature":"00"}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_duplicate_v2_identifier_key_is_rejected(self):
        token = '{"i":"a","i":"b","s64":"AA"}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_plain_and_base64_spelling_together_is_rejected(self):
        token = '{"i":"a","i64":"Yg==","s64":"AA"}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_duplicate_caveat_key_is_rejected(self):
        token = ('{"identifier":"a","signature":"00",'
                 '"caveats":[{"cid":"x","cid":"y"}]}')
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_duplicate_caveat_array_is_rejected(self):
        token = ('{"i":"id","s64":"AA",'
                 '"c":[{"i":"a"}],"c":[{"i":"b"}]}')
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_unknown_top_level_key_is_rejected(self):
        token = '{"identifier":"a","signature":"00","evil":"x"}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_unknown_caveat_key_is_rejected(self):
        token = ('{"identifier":"a","signature":"00",'
                 '"caveats":[{"cid":"x","evil":"y"}]}')
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_mixed_v1_and_v2_fields_is_rejected(self):
        token = '{"identifier":"a","i":"b","s64":"AA","signature":"00"}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_non_object_json_is_rejected(self):
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('["a", "b"]')

    def test_malformed_json_is_rejected(self):
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('{not valid json')

    def test_v1_missing_signature_is_rejected(self):
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('{"identifier":"a"}')

    def test_v2_missing_signature_is_rejected(self):
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('{"i":"id"}')

    def test_v2_empty_identifier_is_rejected(self):
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('{"i":"","s64":"AA"}')

    def test_v1_caveat_missing_cid_is_rejected(self):
        token = '{"identifier":"a","signature":"00","caveats":[{"vid":"AA"}]}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_v2_caveat_missing_identifier_is_rejected(self):
        token = '{"i":"id","s64":"AA","c":[{"v64":"AA"}]}'
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize(token)

    def test_non_string_identifier_is_rejected(self):
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('{"identifier":1,"signature":"00"}')
        with pytest.raises(MacaroonDeserializationException):
            self.serializer.deserialize('{"i":1,"s64":"AA"}')

    def test_binary_identifier_uses_base64_spelling_and_round_trips(self):
        binary_identifier = bytes([0x00, 0xff, 0x10, 0xfe])
        macaroon = Macaroon(
            location='loc',
            identifier=binary_identifier,
            key=SECRET_KEY,
            version=MACAROON_V2,
        )
        token = macaroon.serialize(serializer=self.serializer)
        assert 'i64' in token
        parsed = Macaroon.deserialize(token, serializer=self.serializer)
        assert parsed.identifier_bytes == binary_identifier
        assert parsed.serialize(serializer=self.serializer) == token


class TestStructureVersusSignature(object):
    """A well-formed token with a bad signature is distinct from an
    unparseable token: only the latter is a deserialization failure."""

    @pytest.mark.parametrize('version', [MACAROON_V1, MACAROON_V2])
    def test_bad_signature_raises_verification_error(self, version):
        macaroon = Macaroon(
            location='loc',
            identifier='id',
            key=SECRET_KEY,
            version=version,
        )
        macaroon.add_first_party_caveat('a = b')
        for serializer in (BinarySerializer(), JsonSerializer()):
            token = macaroon.serialize(serializer=serializer)
            parsed = Macaroon.deserialize(token, serializer=serializer)
            verifier = Verifier()
            verifier.satisfy_exact('a = b')
            with pytest.raises(MacaroonInvalidSignatureException):
                verifier.verify(parsed, 'the-wrong-key')

    @pytest.mark.parametrize('version', [MACAROON_V1, MACAROON_V2])
    def test_ambiguous_token_raises_deserialization_error(self, version):
        # The same authorization call rejects these before any signature work
        # happens, so they can never be mistaken for a mere bad signature.
        serializer = BinarySerializer()
        if version == MACAROON_V1:
            raw = (
                v1_packet(b'identifier', b'id'),
                v1_packet(b'signature', b'\x00' * 32),
                v1_packet(b'signature', b'\x11' * 32),
            )
            blob = b''.join(raw)
            with pytest.raises(MacaroonDeserializationException):
                serializer.deserialize_raw(blob)
        else:
            rebuilt = serializer.serialize_raw(
                issued_macaroon(MACAROON_V2))
            with pytest.raises(MacaroonDeserializationException):
                serializer.deserialize_raw(rebuilt + b'trailing')
