#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1 import error
from pyasn1.type import univ
from pyasn1.codec.ber import bounded
from pyasn1.codec.ber import decoder


def encode_length(length):
    if length < 128:
        return bytes([length])

    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def tlv(tag, content):
    return bytes([tag]) + encode_length(len(content)) + content


class RecordingSink(bounded.FragmentSink):
    def __init__(self, fail_after=None):
        self.fragments = []
        self.completed = False
        self.fail_after = fail_after

    def onFragment(self, fragment):
        if self.fail_after is not None and len(self.fragments) == self.fail_after:
            raise RuntimeError('sink failure')
        self.fragments.append(bytes(fragment))

    def onComplete(self):
        self.completed = True

    def value(self):
        return b''.join(self.fragments)


class NonSeekableStream(object):
    """Forward-only stream with no seek/peek and tiny reads."""

    def __init__(self, data, chunk=3):
        self._data = data
        self._position = 0
        self._chunk = chunk
        self.read_calls = 0

    def read(self, size=-1):
        self.read_calls += 1
        if size is None or size < 0:
            size = len(self._data) - self._position
        size = min(size, self._chunk)
        part = self._data[self._position:self._position + size]
        self._position += len(part)
        return part

    def seekable(self):
        return False

    def remaining(self):
        return self._data[self._position:]


class BoundedOctetStringTestCase(BaseTestCase):

    def _payloads(self):
        return [b'', b'A', b'Quick brown fox', bytes(range(256)),
                b'Z' * 5000]

    def _constructed(self, data, fragment_sizes, indefinite, nested=False):
        pieces = []
        offset = 0
        for size in fragment_sizes:
            pieces.append(tlv(0x04, data[offset:offset + size]))
            offset += size
        if offset < len(data):
            pieces.append(tlv(0x04, data[offset:]))
        inner = b''.join(pieces)

        if nested:
            groups = b''
            half = len(pieces) // 2
            for group in (pieces[:half], pieces[half:]):
                body = b''.join(group) if group else tlv(0x04, b'')
                if indefinite:
                    groups += bytes([0x24, 0x80]) + body + b'\x00\x00'
                else:
                    groups += tlv(0x24, body)
            inner = groups

        if indefinite:
            return bytes([0x24, 0x80]) + inner + b'\x00\x00'
        return tlv(0x24, inner)

    def testPrimitiveMatchesReferenceDecoder(self):
        for data in self._payloads():
            substrate = tlv(0x04, data)
            value, stats = bounded.decodeBounded(
                io.BytesIO(substrate), univ.OctetString)
            reference, rest = decoder.decode(substrate)
            assert value.asOctets() == reference.asOctets() == data
            assert rest == b''
            assert stats.totalPayloadBytes == len(data)

    def testLegalFragmentationsProduceIdenticalBytes(self):
        data = b'Quick brown fox jumps'
        fragmentations = [
            [len(data)],
            [1] * len(data),
            [3, 5, 2, 7],
            [4, 4, 4, 4, 4, 1],
        ]
        for sizes in fragmentations:
            for indefinite in (False, True):
                for nested in (False, True):
                    substrate = self._constructed(
                        data, sizes, indefinite, nested)
                    value, stats = bounded.decodeBounded(
                        io.BytesIO(substrate), univ.OctetString)
                    reference, rest = decoder.decode(substrate)
                    assert value.asOctets() == data
                    assert value.asOctets() == reference.asOctets()
                    assert rest == b''

    def testStreamingSinkReceivesFragmentsAndSingleCompletion(self):
        data = b'abcdef'
        substrate = bytes([0x24, 0x80, 0x04, 0x03]) + b'abc' + \
            bytes([0x04, 0x03]) + b'def' + b'\x00\x00'
        # A small retain budget forces one delivery per logical fragment.
        budget = bounded.FragmentBudget(maxRetainedFragments=3)
        sink = RecordingSink()
        stats = bounded.BoundedFragmentDecoder(
            io.BytesIO(substrate), univ.OctetString, sink, budget).read()
        assert sink.value() == data
        assert sink.completed is True
        assert stats.fragmentsDelivered == 2
        assert sink.fragments == [b'abc', b'def']

    def testEmptyOctetString(self):
        for substrate in (b'\x04\x00', b'\x24\x00',
                          b'\x24\x80\x00\x00'):
            value, _ = bounded.decodeBounded(
                io.BytesIO(substrate), univ.OctetString)
            reference, rest = decoder.decode(substrate)
            assert value.asOctets() == reference.asOctets() == b''
            assert rest == b''

    def testEmptyFragmentIsLegal(self):
        # Constructed value containing an empty primitive fragment.
        substrate = b'\x24\x06\x04\x00\x04\x02AB'
        value, stats = bounded.decodeBounded(
            io.BytesIO(substrate), univ.OctetString)
        assert value.asOctets() == b'AB'
        reference, _ = decoder.decode(substrate)
        assert reference.asOctets() == b'AB'

    def testNonSeekableStreamAndNoAheadConsumption(self):
        data = bytes([0x24, 0x80, 0x04, 0x03]) + b'abc' + \
            bytes([0x04, 0x03]) + b'def' + b'\x00\x00' + b'\x02\x01\x09'
        stream = NonSeekableStream(data)
        sink = RecordingSink()
        stats = bounded.BoundedFragmentDecoder(
            stream, univ.OctetString, sink).read()
        assert sink.value() == b'abcdef'
        assert sink.completed is True
        # The next object's bytes were never pulled from the stream.
        assert stream.remaining() == b'\x02\x01\x09'
        assert stats.bytesRead == len(data) - 3
        following, _ = decoder.decode(stream.remaining())
        assert following == 9


class BoundedBitStringTestCase(BaseTestCase):

    def testPrimitiveMatchesReferenceDecoder(self):
        substrate = b'\x03\x03\x01\xa9\x8a'
        value, _ = bounded.decodeBounded(
            io.BytesIO(substrate), univ.BitString)
        reference, rest = decoder.decode(substrate)
        assert tuple(value) == tuple(reference)
        assert rest == b''

    def testConstructedDefiniteAndIndefinite(self):
        substrates = [
            b'\x23\x08\x03\x02\x00\xa9\x03\x02\x01\x8a',
            b'\x23\x80\x03\x02\x00\xa9\x03\x02\x01\x8a\x00\x00',
        ]
        for substrate in substrates:
            value, _ = bounded.decodeBounded(
                io.BytesIO(substrate), univ.BitString)
            reference, rest = decoder.decode(substrate)
            assert tuple(value) == tuple(reference)
            assert rest == b''

    def testIntermediatePaddingPreserved(self):
        fragments = (b'\x03\x02\x03\x10' + b'\x03\x01\x00' +
                     b'\x03\x02\x05\xa0' + b'\x03\x02\x01\x81')
        expected = univ.BitString(binValue='000101011000000')
        for substrate in (b'\x23' + encode_length(len(fragments)) + fragments,
                          b'\x23\x80' + fragments + b'\x00\x00'):
            value, _ = bounded.decodeBounded(
                io.BytesIO(substrate), univ.BitString)
            reference, rest = decoder.decode(substrate)
            assert tuple(value) == tuple(reference) == tuple(expected)
            assert rest == b''

    def testManyFragments(self):
        fragments = b'\x03\x02\x00\x81' * 256
        substrate = b'\x23' + encode_length(len(fragments)) + fragments
        value, stats = bounded.decodeBounded(
            io.BytesIO(substrate), univ.BitString)
        reference, _ = decoder.decode(substrate)
        assert tuple(value) == tuple(reference)
        assert stats.peakRetainedBytes <= bounded.DEFAULT_MAX_RETAINED_FRAGMENTS

    def testNonAlignedFragmentsKeepRetentionBounded(self):
        # Every fragment uses 1..7 unused bits, so the concatenation is never
        # byte-aligned and a partial byte must be carried between fragments.
        fragments = b''
        for index in range(300):
            content = bytes([(index % 7) + 1, 0xA5])
            fragments += tlv(0x03, content)
        substrate = b'\x23' + encode_length(len(fragments)) + fragments
        budget = bounded.FragmentBudget(
            maxTotalSize=100000, maxRetainedFragments=8)
        value, stats = bounded.decodeBounded(
            io.BytesIO(substrate), univ.BitString, budget)
        reference, rest = decoder.decode(substrate)
        assert tuple(value) == tuple(reference)
        assert rest == b''
        # One extra byte is the single carried partial byte.
        assert stats.peakRetainedBytes <= 9

    def testEmptyFragmentIsLegal(self):
        # A zero-content fragment with zero unused bits contributes nothing.
        substrate = b'\x23\x80\x03\x01\x00\x03\x02\x00\xff\x00\x00'
        value, _ = bounded.decodeBounded(
            io.BytesIO(substrate), univ.BitString)
        reference, rest = decoder.decode(substrate)
        assert tuple(value) == tuple(reference)
        assert rest == b''

    def testTrailingBitsOverflowRejected(self):
        for substrate in (b'\x03\x02\x08\x00',
                          b'\x23\x80\x03\x01\x05\x00\x00'):
            try:
                bounded.decodeBounded(
                    io.BytesIO(substrate), univ.BitString)
            except error.PyAsn1Error:
                pass
            else:
                assert False, 'illegal unused-bits count tolerated'

    def testEmptyBitStringRejected(self):
        try:
            bounded.decodeBounded(io.BytesIO(b'\x03\x00'), univ.BitString)
        except error.PyAsn1Error:
            pass
        else:
            assert False, 'empty BIT STRING tolerated'


class BoundedRejectionTestCase(BaseTestCase):

    def _expect_error(self, substrate, expected_type, budget=None,
                      sink=None, message=None):
        try:
            bounded.BoundedFragmentDecoder(
                io.BytesIO(substrate), expected_type,
                sink or RecordingSink(), budget or bounded.FragmentBudget()
            ).read()
        except error.PyAsn1Error as exc:
            if message is not None:
                assert message in str(exc).lower(), str(exc)
            return exc
        else:
            assert False, '%s was tolerated' % substrate

    def testWrongOuterTagRejected(self):
        self._expect_error(
            b'\x02\x01\x05', univ.OctetString, message='expected universal tag')

    def testTaggedSubtypeRejected(self):
        # Context-tagged [0] primitive shares no universal OCTET STRING tag.
        self._expect_error(
            b'\x84\x03abc', univ.OctetString, message='expected universal tag')

    def testWrongInnerTagRejected(self):
        self._expect_error(
            b'\x24\x06\x02\x01\x01\x04\x01A', univ.OctetString,
            message='unexpected inner tag')

    def testTruncatedDefiniteConstructedRejected(self):
        # Declares ten content bytes but only one five-byte fragment exists.
        self._expect_error(
            b'\x24\x0a\x04\x05hello', univ.OctetString)

    def testMissingEndOfContentsRejected(self):
        try:
            bounded.decodeBounded(
                io.BytesIO(b'\x24\x80\x04\x03abc'), univ.OctetString)
        except error.EndOfStreamError:
            pass
        else:
            assert False, 'truncated indefinite value tolerated'

    def testIndefinitePrimitiveRejected(self):
        self._expect_error(
            b'\x04\x80\x00\x00', univ.OctetString,
            message='primitive encoding must use a definite length')

    def testOversizedLengthFieldRejected(self):
        substrate = b'\x04\x89' + b'\xff' * 9
        self._expect_error(
            substrate, univ.OctetString, message='length field size')

    def testUnsupportedTypeRejected(self):
        try:
            bounded.BoundedFragmentDecoder(
                io.BytesIO(b'\x05\x00'), univ.Integer, RecordingSink())
        except error.PyAsn1Error:
            pass
        else:
            assert False, 'unsupported expected type tolerated'


class BoundedBudgetTestCase(BaseTestCase):

    def testSizeBudgetAtLimitDecodes(self):
        budget = bounded.FragmentBudget(maxTotalSize=5)
        value, stats = bounded.decodeBounded(
            io.BytesIO(b'\x04\x05hello'), univ.OctetString, budget)
        assert value.asOctets() == b'hello'
        assert stats.totalPayloadBytes == 5

    def testSizeBudgetOneOverRejectedBeforeBodyRead(self):
        budget = bounded.FragmentBudget(maxTotalSize=4)
        stream = io.BytesIO(b'\x04\x05hello')
        sink = RecordingSink()
        consumer = bounded.BoundedFragmentDecoder(
            stream, univ.OctetString, sink, budget)
        try:
            consumer.read()
        except error.PyAsn1Error as exc:
            assert 'size budget' in str(exc).lower()
            # Only the two header bytes were read; the body was not pulled.
            assert stream.tell() == 2
            assert consumer.stats.totalPayloadBytes == 0
            assert sink.completed is False
        else:
            assert False, 'one-over size budget tolerated'

    def testHugeDeclaredLengthRejectedWithinBudgetAndNoAheadRead(self):
        # A definite constructed OCTET STRING declares far more content than
        # the size budget allows. Real fragments are supplied until the budget
        # is crossed, followed by an unrelated INTEGER that must never be read.
        budget = bounded.FragmentBudget(maxTotalSize=64)
        declared = 5000
        substrate = b'\x24' + encode_length(declared) + \
            b'\x04\x01A' * 100 + b'\x02\x01\x07'
        marker_offset = len(substrate) - 3
        stream = io.BytesIO(substrate)
        sink = RecordingSink()
        consumer = bounded.BoundedFragmentDecoder(
            stream, univ.OctetString, sink, budget)
        try:
            consumer.read()
        except error.PyAsn1Error as exc:
            assert 'size budget' in str(exc).lower()
            # Never completed, never charged past the budget.
            assert sink.completed is False
            assert consumer.stats.totalPayloadBytes <= 64
            # Rejection happens inside the frame, well before the trailing
            # INTEGER, whose three bytes are therefore never consumed.
            position = stream.tell()
            assert position < marker_offset
            assert substrate[marker_offset:] == b'\x02\x01\x07'
        else:
            assert False, 'huge declared constructed length tolerated'

    def testHugePrimitiveDeclaredLengthRejectedBeforeBodyRead(self):
        budget = bounded.FragmentBudget(maxTotalSize=64)
        substrate = b'\x04' + encode_length(5000)
        stream = io.BytesIO(substrate)
        sink = RecordingSink()
        consumer = bounded.BoundedFragmentDecoder(
            stream, univ.OctetString, sink, budget)
        try:
            consumer.read()
        except error.PyAsn1Error as exc:
            assert 'size budget' in str(exc).lower()
            # The extent is charged before the body is read: nothing buffered.
            assert consumer.stats.totalPayloadBytes == 0
            assert sink.fragments == []
            assert stream.tell() == len(substrate)
        else:
            assert False, 'huge declared primitive length tolerated'

    def testFrameHeaderOverheadDoesNotConsumePayloadBudget(self):
        # Frame length (8) counts nested TLV headers, but only the four
        # payload octets count against maxTotalSize.
        budget = bounded.FragmentBudget(maxTotalSize=4)
        substrate = b'\x24\x08\x04\x02AB\x04\x02CD'
        value, stats = bounded.decodeBounded(
            io.BytesIO(substrate), univ.OctetString, budget)
        assert value.asOctets() == b'ABCD'
        assert stats.totalPayloadBytes == 4

    def testIndefiniteTrickleRejectedWithinBudget(self):
        budget = bounded.FragmentBudget(
            maxTotalSize=64, maxRetainedFragments=16)
        substrate = b'\x24\x80' + b'\x04\x01A' * 100 + b'\x00\x00'
        sink = RecordingSink()
        consumer = bounded.BoundedFragmentDecoder(
            io.BytesIO(substrate), univ.OctetString, sink, budget)
        try:
            consumer.read()
        except error.PyAsn1Error:
            assert consumer.stats.peakRetainedBytes <= 16
            assert consumer.stats.totalPayloadBytes <= 64
            assert sink.completed is False
        else:
            assert False, 'indefinite trickle over budget tolerated'

    def testNestingDepthAtLimitDecodes(self):
        budget = bounded.FragmentBudget(maxNestingDepth=10)
        inner = b'\x04\x01A'
        for _ in range(10):
            inner = tlv(0x24, inner)
        value, _ = bounded.decodeBounded(
            io.BytesIO(inner), univ.OctetString, budget)
        assert value.asOctets() == b'A'

    def testNestingDepthOneOverRejected(self):
        budget = bounded.FragmentBudget(maxNestingDepth=10)
        inner = b'\x04\x01A'
        for _ in range(11):
            inner = tlv(0x24, inner)
        try:
            bounded.decodeBounded(
                io.BytesIO(inner), univ.OctetString, budget)
        except error.PyAsn1Error as exc:
            assert 'nesting depth' in str(exc).lower()
        else:
            assert False, 'excessive nesting tolerated'

    def testRetainedFragmentsStaysWithinBudget(self):
        budget = bounded.FragmentBudget(
            maxTotalSize=4096, maxRetainedFragments=100)
        substrate = tlv(0x04, b'Z' * 1000)
        value, stats = bounded.decodeBounded(
            io.BytesIO(substrate), univ.OctetString, budget)
        assert value.asOctets() == b'Z' * 1000
        assert stats.peakRetainedBytes <= 100
        assert stats.fragmentsDelivered == 10

    def testZeroRetainBudgetFlushesImmediately(self):
        budget = bounded.FragmentBudget(
            maxTotalSize=4096, maxRetainedFragments=0)
        substrate = tlv(0x04, b'Z' * 50)
        sink = RecordingSink()
        stats = bounded.BoundedFragmentDecoder(
            io.BytesIO(substrate), univ.OctetString, sink, budget).read()
        assert stats.peakRetainedBytes == 0
        assert sink.value() == b'Z' * 50

    def testNegativeBudgetRejected(self):
        try:
            bounded.FragmentBudget(maxTotalSize=-1)
        except ValueError:
            pass
        else:
            assert False, 'negative budget tolerated'


class BoundedCallbackFailureTestCase(BaseTestCase):

    def testCallbackFailurePropagatesAndNeverCompletes(self):
        budget = bounded.FragmentBudget(maxRetainedFragments=3)
        substrate = b'\x24\x0a\x04\x03abc\x04\x03def'
        sink = RecordingSink(fail_after=1)
        try:
            bounded.BoundedFragmentDecoder(
                io.BytesIO(substrate), univ.OctetString, sink, budget).read()
        except RuntimeError as exc:
            assert str(exc) == 'sink failure'
            assert sink.completed is False
        else:
            assert False, 'sink failure was swallowed'


class CompleteOnlyBusinessEntryTestCase(BaseTestCase):
    """Model a handler that may run only on a fully validated value."""

    def business_entry(self, stream, expected_type):
        sink = RecordingSink()
        bounded.BoundedFragmentDecoder(
            stream, expected_type, sink).read()
        # Reached only because onComplete semantics guarantee a whole value.
        if not sink.completed:
            raise AssertionError('business entry saw an incomplete value')
        return sink.value()

    def testCompleteValueReachesBusinessEntry(self):
        substrate = b'\x24\x80\x04\x02AB\x04\x02CD\x00\x00'
        value = self.business_entry(
            NonSeekableStream(substrate), univ.OctetString)
        assert value == b'ABCD'

    def testTruncatedPayloadNeverReachesBusinessEntry(self):
        # Indefinite value cut off before its end-of-contents marker.
        substrate = b'\x24\x80\x04\x02AB\x04\x02CD'
        stream = NonSeekableStream(substrate)
        entered = False
        try:
            self.business_entry(stream, univ.OctetString)
            entered = True
        except error.EndOfStreamError:
            pass
        assert entered is False
        # Nothing past the bytes actually present was invented or consumed.
        assert stream.remaining() == b''

    def testRejectedPayloadNeverReachesBusinessEntry(self):
        # A constructed OCTET STRING hiding an INTEGER fragment is invalid.
        substrate = b'\x24\x06\x02\x01\x01\x04\x01A'
        stream = NonSeekableStream(substrate)
        entered = False
        try:
            self.business_entry(stream, univ.OctetString)
            entered = True
        except error.PyAsn1Error:
            pass
        assert entered is False


class BoundedStatsTestCase(BaseTestCase):

    def testStatsRecordReadsAndRetention(self):
        data = b'abcdef'
        substrate = bytes([0x24, 0x80, 0x04, 0x03]) + b'abc' + \
            bytes([0x04, 0x03]) + b'def' + b'\x00\x00'
        budget = bounded.FragmentBudget(maxRetainedFragments=3)
        stream = NonSeekableStream(substrate, chunk=2)
        sink = RecordingSink()
        stats = bounded.BoundedFragmentDecoder(
            stream, univ.OctetString, sink, budget).read()
        assert stats.readCalls == stream.read_calls
        assert stats.readCalls > 0
        assert stats.bytesRead == len(substrate)
        assert stats.totalPayloadBytes == len(data)
        assert stats.fragmentsDelivered == 2
        assert stats.peakRetainedBytes <= 3
        assert sink.value() == data

    def testStatsReprContainsCounters(self):
        stats = bounded.ConsumptionStats()
        text = repr(stats)
        for field in ('readCalls', 'bytesRead', 'fragmentsDelivered',
                      'totalPayloadBytes', 'peakRetainedBytes'):
            assert field in text


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
