#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import gc
import io
import os
import sys
import unittest
import weakref

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.cer import decoder as cer_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import DecoderTerminatedError
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import univ


class IncrementalStream(object):
    """Seekable stream that only exposes bytes the test has fed.

    `read()` returns :obj:`None` when the requested bytes have not arrived
    yet, which is the non-blocking stream contract `readFromStream`
    understands: yield a `SubstrateUnderrunError` sentinel, let the caller
    feed more and resume. No `BytesIO` subclass is used so that both
    seekable and non-seekable wrapping paths can be exercised.
    """

    def __init__(self, data=b'', available=0):
        self._stream = io.BytesIO(data)
        self._size = len(data)
        self._available = available
        self.reads = 0

    def seekable(self):
        return True

    def tell(self):
        return self._stream.tell()

    def seek(self, n, whence=os.SEEK_SET):
        return self._stream.seek(n, whence)

    def read(self, size=-1):
        position = self._stream.tell()

        if size is None or size < 0:
            if position >= self._available:
                return None if self._available < self._size else b''

            size = self._available - position

        else:
            size = min(size, self._available - position)
            if size <= 0:
                return None if self._available < self._size else b''

        self.reads += 1
        return self._stream.read(size)

    def feed(self, count=1):
        self._available = min(self._available + count, self._size)
        return self

    @property
    def available(self):
        return self._available

    @property
    def size(self):
        return self._size


class NonSeekableNonBlockingStream(object):
    """Non-seekable stream alternating between data and `None`."""

    def __init__(self, data=b''):
        self._stream = io.BytesIO(data)
        self._reads = 0

    def seekable(self):
        return False

    def read(self, size=-1):
        self._reads += 1
        if not self._reads % 2:
            return None

        return self._stream.read(size)


def _encodeLength(length):
    if length < 128:
        return bytes([length])

    octets = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(octets)]) + octets


def _encodeSequence(body, indefinite=False):
    if indefinite:
        return b'\x30\x80' + body + b'\x00\x00'

    return b'\x30' + _encodeLength(len(body)) + body


def _encodeOctetString(value):
    value = value.encode('ascii')
    return b'\x04' + _encodeLength(len(value)) + value


class IncrementalPauseTestCase(BaseTestCase):
    """Pause at every tag, length, child value and EOC boundary.

    The substrate is a nested indefinite-length SEQUENCE OF SEQUENCE OF
    OCTET STRING. Bytes are released one at a time, so the decoder must
    suspend and resume at each framing step instead of requiring the whole
    element.
    """

    # 30 80                outer SEQUENCE OF, indefinite
    #   30 80              inner SEQUENCE OF, indefinite
    #     04 03 61 62 63   OCTET STRING 'abc'
    #     04 02 64 65      OCTET STRING 'de'
    #     00 00            inner end-of-octets
    #   00 00              outer end-of-octets
    substrate = bytes((
        0x30, 0x80,
        0x30, 0x80,
        0x04, 0x03, 0x61, 0x62, 0x63,
        0x04, 0x02, 0x64, 0x65,
        0x00, 0x00,
        0x00, 0x00
    ))

    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = univ.SequenceOf(
            componentType=univ.SequenceOf(componentType=univ.OctetString()))
        self.stream = IncrementalStream(self.substrate)
        self.decoder = ber_decoder.StreamingDecoder(
            self.stream, asn1Spec=self.schema)

    def testPauseAndResumeAtEveryBoundary(self):
        iterator = iter(self.decoder)
        pauses = []
        partials = []
        value = None

        while True:
            result = next(iterator)

            if not isinstance(result, SubstrateUnderrunError):
                value = result
                break

            pauses.append(self.stream.tell())
            partial = result.context.get('asn1Object')
            if partial is not None:
                partials.append(partial)

            self.stream.feed(1)

        # Pauses after: nothing read, outer tag, outer length, inner tag,
        # inner length, child tag/length, child value, both end-of-octets
        # and the final end-of-item probe.
        assert pauses[0] == 0, 'Decoder consumed bytes before any arrived'
        assert 1 in pauses, 'Decoder did not pause after the tag octet'
        assert 2 in pauses, 'Decoder did not pause after the length octet'
        assert 4 in pauses, 'Decoder did not pause after the nested tag'
        assert 6 in pauses, 'Decoder did not pause inside the child value'
        assert 9 in pauses, 'Decoder did not pause at inner end-of-octets'
        assert 11 in pauses, 'Decoder did not pause at the second child'
        assert 15 in pauses, 'Decoder did not pause at outer end-of-octets'

        assert pauses == sorted(pauses), 'Decoder seeked behind a pause point'
        assert len(pauses) > 5, 'Decoder did not resume incrementally'

        assert self.stream.tell() == self.stream.size == 17
        assert value == [[b'abc', b'de']], 'Wrong value after resumption'

        # The half-built containers are exposed only through the sentinel
        # context, never as a decoded value. They belong to this decoder
        # alone and are not the shared schema.
        assert partials, 'Partial object was never reported to the caller'
        for partial in partials:
            assert isinstance(partial, univ.SequenceOf)
            assert partial is not self.schema

        assert not self.schema.isValue, 'Decoding mutated the shared schema'

    def testSentinelAlwaysCarriesAnErrorObject(self):
        iterator = iter(self.decoder)
        result = next(iterator)

        assert isinstance(result, SubstrateUnderrunError)
        assert result is not None
        assert hasattr(result, 'context')

        self.stream.feed(self.stream.size)
        for result in iterator:
            assert result is not None

        self.decoder.close()


class TerminationContractTestCase(BaseTestCase):
    codecs = (
        ('ber', ber_decoder),
        ('cer', cer_decoder),
        ('der', der_decoder),
    )

    # Definite-length SEQUENCE OF SEQUENCE OF OCTET STRING, decodable by
    # BER, CER and DER alike.
    substrate = _encodeSequence(
        _encodeSequence(_encodeOctetString('abc') + _encodeOctetString('de')))
    # Same shape, different payload, to prove one decoder's position does
    # not influence another's.
    otherSubstrate = _encodeSequence(
        _encodeSequence(_encodeOctetString('xyz')))
    # 'abc' followed by a universal NULL where an OCTET STRING is required.
    invalidSubstrate = _encodeSequence(
        _encodeOctetString('abc') + b'\x05\x00')

    def _makeDecoder(self, decoderModule, substrate=None):
        schema = univ.SequenceOf(
            componentType=univ.SequenceOf(componentType=univ.OctetString()))
        stream = IncrementalStream(
            self.substrate if substrate is None else substrate)
        decoder = decoderModule.StreamingDecoder(stream, asn1Spec=schema)
        return decoder, stream, schema

    def _pumpToPartialObject(self, decoder, stream):
        iterator = iter(decoder)

        while True:
            result = next(iterator)
            if isinstance(result, SubstrateUnderrunError):
                assert 'asn1Object' in result.context, (
                    'Expected a partially built object in the sentinel context')
                stream.feed(1)

            else:
                return result

    def testCloseReleasesAllReferences(self):
        for name, decoderModule in self.codecs:
            with self.subTest(codec=name):
                decoder, stream, schema = self._makeDecoder(decoderModule)
                iterator = iter(decoder)
                next(iterator)

                streamRef = weakref.ref(stream)
                schemaRef = weakref.ref(schema)
                decoderRef = weakref.ref(decoder)
                iteratorRef = weakref.ref(iterator)

                decoder.close()

                assert decoder.closed
                assert iteratorRef() is decoder, 'Iteration escaped the decoder'

                del decoder, stream, schema, iterator
                gc.collect()

                assert streamRef() is None, 'Input stream retained after close'
                assert schemaRef() is None, 'Schema retained after close'
                assert decoderRef() is None, 'Decoder retained after close'

    def testReuseAfterCloseIsRejected(self):
        for name, decoderModule in self.codecs:
            with self.subTest(codec=name):
                decoder, stream, schema = self._makeDecoder(decoderModule)
                next(iter(decoder))
                position = stream.tell()
                reads = stream.reads

                decoder.close()
                decoder.close()  # idempotent

                assert decoder.closed
                assert stream.tell() == position == 0
                assert stream.reads == reads

                try:
                    next(iter(decoder))

                except DecoderTerminatedError:
                    pass

                else:
                    assert False, 'Terminated decoder resumed decoding'

                assert stream.reads == reads, (
                    'Terminated decoder consumed more input')

                # The same schema is safe to use for a new request.
                decoder2, stream2, _ = self._makeDecoder(decoderModule)
                stream2.feed(stream2.size)
                value = self._pumpToPartialObject(decoder2, stream2)

                assert value == [[b'abc', b'de']]
                assert not schema.isValue

    def testExceptionTerminatesDecoder(self):
        for name, decoderModule in self.codecs:
            with self.subTest(codec=name):
                decoder, stream, schema = self._makeDecoder(
                    decoderModule, self.invalidSubstrate)
                stream.feed(stream.size)

                try:
                    for _ in decoder:
                        pass

                except PyAsn1Error:
                    pass

                else:
                    assert False, 'Invalid nested value tolerated'

                assert decoder.closed, (
                    'Decoder left open after a decoding exception')

                streamRef = weakref.ref(stream)
                schemaRef = weakref.ref(schema)
                decoderRef = weakref.ref(decoder)
                del decoder, stream, schema
                gc.collect()

                assert streamRef() is None, 'Input retained after exception'
                assert schemaRef() is None, 'Schema retained after exception'
                assert decoderRef() is None, 'Decoder retained after exception'

    def testExceptionLeavesSchemaReusable(self):
        for name, decoderModule in self.codecs:
            with self.subTest(codec=name):
                schema = univ.SequenceOf(
                    componentType=univ.SequenceOf(
                        componentType=univ.OctetString()))
                stream = IncrementalStream(self.invalidSubstrate)
                stream.feed(stream.size)
                decoder = decoderModule.StreamingDecoder(
                    stream, asn1Spec=schema)

                try:
                    list(decoder)

                except PyAsn1Error:
                    pass

                else:
                    assert False, 'Invalid nested value tolerated'

                assert decoder.closed
                assert not schema.isValue, 'Shared schema turned into a value'
                assert schema.getComponentByPosition(0, instantiate=False) is univ.noValue

                freshStream = IncrementalStream(self.otherSubstrate)
                freshStream.feed(freshStream.size)
                freshDecoder = decoderModule.StreamingDecoder(
                    freshStream, asn1Spec=schema)

                value = None
                for value in freshDecoder:
                    pass

                assert value == [[b'xyz']], 'New request polluted by old state'
                assert freshStream.tell() == freshStream.size

    def testExhaustedDecoderStopsInsteadOfRaising(self):
        for name, decoderModule in self.codecs:
            with self.subTest(codec=name):
                decoder, stream, _ = self._makeDecoder(decoderModule)
                stream.feed(stream.size)

                values = list(decoder)

                assert len(values) == 1
                assert decoder.closed

                try:
                    next(decoder)

                except StopIteration:
                    pass

                else:
                    assert False, 'Exhausted decoder did not stop'

    def testOldIteratorCannotBeResumedAfterClose(self):
        for name, decoderModule in self.codecs:
            with self.subTest(codec=name):
                decoder, stream, schema = self._makeDecoder(decoderModule)
                iterator = iter(decoder)
                next(iterator)

                reads = stream.reads
                position = stream.tell()

                decoder.close()

                for candidate in (iterator, decoder):
                    try:
                        next(candidate)

                    except DecoderTerminatedError:
                        pass

                    else:
                        assert False, 'Old iterator resumed after close'

                assert stream.reads == reads, 'Old iterator read new bytes'
                assert stream.tell() == position


class DebugScopeBalanceTestCase(BaseTestCase):
    """Aborted parsing must not leak its tokens onto the global scope stack.

    `debug.scope` is process-global; the null logger installed by
    `BaseTestCase.setUp` leaves every `if LOG:` branch enabled, so this
    runs the same code path a debugging user would.
    """

    substrate = bytes((
        0x30, 0x80,
        0x04, 0x03, 0x61, 0x62, 0x63,
        0x00, 0x00
    ))

    def testAbandonedParseRestoresScopeDepth(self):
        from pyasn1 import debug

        stream = IncrementalStream(self.substrate, available=2)
        schema = univ.SequenceOf(componentType=univ.OctetString())
        decoder = ber_decoder.StreamingDecoder(stream, asn1Spec=schema)

        depth = len(debug.scope)
        iterator = iter(decoder)
        next(iterator)
        next(iterator)
        next(iterator)

        # Suspended frames legitimately hold their tokens until the pass
        # ends; each resume must not stack up another copy.
        suspendedDepth = len(debug.scope)
        assert suspendedDepth > depth, (
            'Expected the suspended parse to hold a scope token')
        next(iterator)
        assert len(debug.scope) == suspendedDepth, (
            'Each resume added tokens to the global debug scope')

        decoder.close()

        assert len(debug.scope) == depth, (
            'Terminating the parse left tokens on the global debug scope')

        # A new request on the same schema starts from the same depth.
        replacement = IncrementalStream(self.substrate, available=2)
        decoder2 = ber_decoder.StreamingDecoder(
            replacement, asn1Spec=schema)
        next(iter(decoder2))
        decoder2.close()

        assert len(debug.scope) == depth, (
            'Next request inherited scope state from the aborted one')


class InterleavedDecoderTestCase(BaseTestCase):
    """Two decoders sharing one schema must not share decoding state."""

    substrate = _encodeSequence(
        _encodeSequence(_encodeOctetString('abc') + _encodeOctetString('de')),
        indefinite=True)
    otherSubstrate = _encodeSequence(
        _encodeSequence(_encodeOctetString('xyz')))

    def _make(self, decoderModule, substrate):
        schema = univ.SequenceOf(
            componentType=univ.SequenceOf(componentType=univ.OctetString()))
        stream = IncrementalStream(substrate)
        decoder = decoderModule.StreamingDecoder(stream, asn1Spec=schema)
        return decoder, stream

    def testInterleavedDecodingKeepsIndependentValues(self):
        decoderA, streamA = self._make(ber_decoder, self.substrate)
        decoderB, streamB = self._make(ber_decoder, self.otherSubstrate)

        iteratorA = iter(decoderA)
        iteratorB = iter(decoderB)

        valueA = valueB = None

        for _ in range(200):
            for iterator, stream in ((iteratorA, streamA),
                                     (iteratorB, streamB)):
                try:
                    result = next(iterator)

                except StopIteration:
                    continue

                if isinstance(result, SubstrateUnderrunError):
                    stream.feed(1)

                elif iterator is iteratorA:
                    valueA = result

                else:
                    valueB = result

            if valueA is not None and valueB is not None:
                break

        assert valueA == [[b'abc', b'de']], 'First decoder got %r' % (valueA,)
        assert valueB == [[b'xyz']], 'Second decoder got %r' % (valueB,)
        assert valueA is not valueB

        assert streamA.tell() == streamA.size
        assert streamB.tell() == streamB.size

    def testCancelledDecoderDoesNotAffectTheOther(self):
        decoderA, streamA = self._make(ber_decoder, self.substrate)
        decoderB, streamB = self._make(ber_decoder, self.otherSubstrate)

        streamA.feed(streamA.size)
        streamB.feed(5)

        iteratorA = iter(decoderA)
        iteratorB = iter(decoderB)

        # B stops in the middle of a nested value; capture its partial
        # object and consumption position as ownership evidence.
        partial = None
        while partial is None:
            result = next(iteratorB)
            assert isinstance(result, SubstrateUnderrunError)
            partial = result.context.get('asn1Object')
            if partial is None:
                streamB.feed(1)

        positionB = streamB.tell()
        readsB = streamB.reads

        # A decodes correctly while B is suspended.
        valueA = next(iteratorA)
        assert valueA == [[b'abc', b'de']]
        assert streamA.tell() == streamA.size

        # The request owning B is cancelled.
        decoderB.close()

        assert decoderB.closed
        assert streamB.tell() == positionB, 'Cancellation moved the input'
        assert streamB.reads == readsB, 'Cancellation read more input'

        # B's half-built object is not attached to the shared schema and
        # no value is produced for the cancelled request.
        assert isinstance(partial, univ.SequenceOf)
        assert partial is not decoderB
        assert partial is not streamB
        try:
            next(iteratorB)

        except DecoderTerminatedError:
            pass

        else:
            assert False, 'Cancelled decoder produced a value'

        # A remains independent and can finish.
        try:
            next(iteratorA)

        except StopIteration:
            pass

        else:
            assert False, 'First decoder produced more than one value'

    def testNonSeekableNonBlockingSubstrateResumes(self):
        raw = NonSeekableNonBlockingStream(self._encode())
        schema = univ.SequenceOf(componentType=univ.Integer())
        decoder = ber_decoder.StreamingDecoder(raw, asn1Spec=schema)
        iterator = iter(decoder)

        underruns = 0
        value = None

        for _ in range(100):
            result = next(iterator)

            if isinstance(result, SubstrateUnderrunError):
                underruns += 1

            else:
                value = result
                break

        assert underruns > 0, 'Non-blocking wrapped stream never suspended'
        assert value == [7]

        # The pass is only known to be over once the trailing end-of-stream
        # probe runs; it may report underrun before confirming the end, but
        # it must never produce a second value.
        for _ in range(10):
            try:
                result = next(iterator)

            except StopIteration:
                break

            assert isinstance(result, SubstrateUnderrunError), (
                'Non-blocking wrapped stream produced a second value')

        else:
            assert False, 'Non-blocking wrapped stream never ended'

        assert decoder.closed

    @staticmethod
    def _encode():
        return b'\x30\x03\x02\x01\x07'


class NoHalfObjectTestCase(BaseTestCase):
    """A cancelled parse must not hand its partial object to the caller."""

    substrate = _encodeSequence(
        _encodeSequence(_encodeOctetString('abc') + _encodeOctetString('de')))
    schema = staticmethod(lambda: univ.SequenceOf(
        componentType=univ.SequenceOf(componentType=univ.OctetString())))

    def testPartialObjectBelongsToTheCancelledDecoder(self):
        schema = self.schema()
        stream = IncrementalStream(self.substrate, available=7)
        decoder = ber_decoder.StreamingDecoder(stream, asn1Spec=schema)

        partials = []
        result = None

        while True:
            result = next(decoder)
            if not isinstance(result, SubstrateUnderrunError):
                break

            partial = result.context.get('asn1Object')
            if partial is not None:
                partials.append(partial)
                break

        assert partials, 'No partial object reported'
        partial = partials[0]

        assert isinstance(partial, univ.SequenceOf)
        assert partial is not schema
        assert not schema.isValue
        assert schema.getComponentByPosition(0, instantiate=False) is univ.noValue

        decoder.close()

        # The decoder never returned the partial object as a value, and
        # the schema remains a pure template.
        assert not schema.isValue
        assert schema.getComponentByPosition(0, instantiate=False) is univ.noValue

        # A fresh request gets its own object.
        stream2 = IncrementalStream(bytes((
            0x30, 0x07, 0x30, 0x05, 0x04, 0x03, 0x78, 0x79, 0x7a)))
        stream2.feed(stream2.size)
        decoder2 = ber_decoder.StreamingDecoder(stream2, asn1Spec=schema)
        values = list(decoder2)

        assert len(values) == 1
        assert values[0] == [[b'xyz']]
        assert values[0] is not partial
        assert schema.getComponentByPosition(0, instantiate=False) is univ.noValue


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
