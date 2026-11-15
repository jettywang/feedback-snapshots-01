#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.codec.ber import streaming_encoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class ShortWriteSink(object):
    """Sink that records writes and optionally accepts only a few octets."""

    def __init__(self, limit=None):
        self.limit = limit
        self.chunks = []
        self.total = 0

    def write(self, chunk):
        self.chunks.append(chunk)

        accepted = len(chunk)

        if self.limit is not None:
            accepted = min(accepted, self.limit)

        self.total += accepted
        return accepted

    def getvalue(self):
        return b''.join(self.chunks)


class RecordingIterable(object):
    """Iterable that records how much of itself has been consumed."""

    def __init__(self, values):
        self.values = values
        self.consumed = 0

    def __iter__(self):
        for value in self.values:
            self.consumed += 1
            yield value


class FailingIterable(object):
    """Iterable that yields some values, then raises."""

    def __init__(self, values, error=None):
        self.values = values
        self.error = error or RuntimeError('producer failed')
        self.consumed = 0

    def __iter__(self):
        for value in self.values:
            self.consumed += 1
            yield value

        raise self.error


class StreamingSequenceOfTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.spec = univ.SequenceOf(componentType=univ.Integer())

    def testEmpty(self):
        substrate = b''.join(
            streaming_encoder.encodeStream([], asn1Spec=self.spec))

        assert substrate == b'\x30\x80\x00\x00'

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=self.spec)
        assert not asn1Object
        assert trailing == b''

    def testPlainList(self):
        substrate = b''.join(
            streaming_encoder.encodeStream(
                [univ.Integer(1), univ.Integer(2)], asn1Spec=self.spec))

        assert substrate == b'\x30\x80\x02\x01\x01\x02\x01\x02\x00\x00'

    def testGeneratorIsConsumedLazily(self):
        values = RecordingIterable(
            [univ.Integer(1), univ.Integer(2), univ.Integer(3)])

        iterator = iter(
            streaming_encoder.encodeStream(values, asn1Spec=self.spec))

        # header only, no component touched yet
        assert next(iterator) == b'\x30\x80'
        assert values.consumed == 0

        assert next(iterator) == b'\x02\x01\x01'
        assert values.consumed == 1

        assert next(iterator) == b'\x02\x01\x02'
        assert values.consumed == 2

    def testNestedGenerator(self):
        inner = univ.SequenceOf(componentType=univ.Integer())
        outer = univ.SequenceOf(componentType=inner)

        def innerComponents():
            for value in (1, 2):
                yield univ.Integer(value)

        def outerComponents():
            for values in ((1, 2), (3,)):
                yield (univ.Integer(value) for value in values)

        substrate = b''.join(
            streaming_encoder.encodeStream(
                outerComponents(), asn1Spec=outer))

        assert substrate == bytes((
            48, 128,
            48, 128, 2, 1, 1, 2, 1, 2, 0, 0,
            48, 128, 2, 1, 3, 0, 0,
            0, 0))

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=outer)

        assert trailing == b''
        assert len(asn1Object) == 2
        assert asn1Object[0][0] == 1
        assert asn1Object[0][1] == 2
        assert asn1Object[1][0] == 3

    def testNestedPyasn1ValuesMatchRegularIndefiniteMode(self):
        inner = univ.SequenceOf(componentType=univ.Integer())
        outer = univ.SequenceOf(componentType=inner)

        nested = inner.clone()
        nested.extend([1, 2])

        second = inner.clone()
        second.extend([3])

        value = outer.clone()
        value.extend([nested, second])

        expected = encoder.encode(value, defMode=False)
        substrate = b''.join(streaming_encoder.encodeStream(value))

        assert substrate == expected

    def testScalarIsDefiniteLength(self):
        assert b''.join(
            streaming_encoder.encodeStream(univ.Integer(12))) == b'\x02\x01\x0c'

    def testExplicitlyTaggedScalarIsDefiniteLength(self):
        value = univ.Integer(5).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))

        substrate = b''.join(streaming_encoder.encodeStream(value))

        assert substrate == b'\xa2\x03\x02\x01\x05'

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=value)

        assert trailing == b''
        assert asn1Object == 5

    def testSizeConstraintIsEnforcedWhileConsuming(self):
        spec = univ.SequenceOf(componentType=univ.Integer()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 2))

        chunks = []

        try:
            for chunk in streaming_encoder.encodeStream(
                    [univ.Integer(1), univ.Integer(2), univ.Integer(3)],
                    asn1Spec=spec):
                chunks.append(chunk)

        except PyAsn1Error:
            pass

        else:
            assert False, 'oversized SEQUENCE OF tolerated'

        substrate = b''.join(chunks)

        assert not substrate.endswith(b'\x00\x00')
        assert substrate.endswith(b'\x02\x01\x02')

    def testMinimumSizeConstraintFailsBeforeTerminator(self):
        spec = univ.SequenceOf(componentType=univ.Integer()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(3, 5))

        chunks = []

        try:
            for chunk in streaming_encoder.encodeStream(
                    [univ.Integer(1)], asn1Spec=spec):
                chunks.append(chunk)

        except PyAsn1Error:
            pass

        else:
            assert False, 'undersized SEQUENCE OF tolerated'

        assert not b''.join(chunks).endswith(b'\x00\x00')


class StreamingStringFragmentsTestCase(BaseTestCase):
    def testFragmentsAreEncodedAsConstructedString(self):
        substrate = b''.join(
            streaming_encoder.encodeStream(
                [b'quick ', b'brown'], asn1Spec=univ.OctetString()))

        assert substrate == b'\x24\x80\x04\x06quick \x04\x05brown\x00\x00'

        asn1Object, trailing = decoder.decode(
            substrate, asn1Spec=univ.OctetString())

        assert trailing == b''
        assert asn1Object == b'quick brown'

    def testCharacterStringUsesItsOwnFragmentTag(self):
        substrate = b''.join(
            streaming_encoder.encodeStream(
                ['ab', 'cd'], asn1Spec=char.UTF8String()))

        assert substrate == b'\x2c\x80\x0c\x02ab\x0c\x02cd\x00\x00'

    def testGeneratorOfFragments(self):
        def fragments():
            for fragment in (b'one', b'two', b'three'):
                yield fragment

        substrate = b''.join(
            streaming_encoder.encodeStream(
                fragments(), asn1Spec=univ.OctetString()))

        asn1Object, trailing = decoder.decode(
            substrate, asn1Spec=univ.OctetString())

        assert trailing == b''
        assert asn1Object == b'onetwothree'

    def testMaxChunkSizeSplitsFragmentsLazily(self):
        values = RecordingIterable([b'abc', b'def'])

        substrate = b''.join(
            streaming_encoder.encodeStream(
                values, asn1Spec=univ.OctetString(), maxChunkSize=1))

        assert substrate == bytes((
            36, 128,
            4, 1, 97,
            4, 1, 98,
            4, 1, 99,
            4, 1, 100,
            4, 1, 101,
            4, 1, 102,
            0, 0))

    def testMaxChunkSizeDoesNotSplitMultiOctetCharacters(self):
        substrate = b''.join(
            streaming_encoder.encodeStream(
                ['ééé'], asn1Spec=char.UTF8String(),
                maxChunkSize=2))

        asn1Object, trailing = decoder.decode(
            substrate, asn1Spec=char.UTF8String())

        assert trailing == b''
        assert asn1Object == 'ééé'

    def testBytesFragmentsOfCharacterStringKeepCharacterBoundaries(self):
        # A UTF-8 character is two octets wide; chunking must not split it,
        # or the constructed string would decode to different text.
        substrate = b''.join(
            streaming_encoder.encodeStream(
                [b'\xc3\xa9\xc3\xa9'], asn1Spec=char.UTF8String(),
                maxChunkSize=2))

        asn1Object, trailing = decoder.decode(
            substrate, asn1Spec=char.UTF8String())

        assert trailing == b''
        assert asn1Object == 'éé'

    def testPermittedAlphabetFragmentIsRejected(self):
        spec = char.IA5String().subtype(
            subtypeSpec=constraint.PermittedAlphabetConstraint('A', 'B'))

        chunks = []

        try:
            for chunk in streaming_encoder.encodeStream(
                    ['AB', 'X'], asn1Spec=spec):
                chunks.append(chunk)

        except PyAsn1Error:
            pass

        else:
            assert False, 'illegal fragment tolerated'

        assert not b''.join(chunks).endswith(b'\x00\x00')

    def testPlainStringValueStaysPrimitive(self):
        substrate = b''.join(
            streaming_encoder.encodeStream(
                'abc', asn1Spec=univ.OctetString()))

        assert substrate == b'\x04\x03abc'

    def testImplicitlyTaggedFragments(self):
        spec = univ.OctetString().subtype(
            implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 3))

        substrate = b''.join(
            streaming_encoder.encodeStream([b'ab', b'cd'], asn1Spec=spec))

        assert substrate == b'\xa3\x80\x04\x02ab\x04\x02cd\x00\x00'

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=spec)

        assert trailing == b''
        assert asn1Object == b'abcd'

    def testExplicitlyTaggedFragments(self):
        spec = univ.OctetString().subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))

        substrate = b''.join(
            streaming_encoder.encodeStream([b'ab', b'cd'], asn1Spec=spec))

        assert substrate == bytes((
            161, 128,
            36, 128, 4, 2, 97, 98, 4, 2, 99, 100, 0, 0,
            0, 0))

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=spec)

        assert trailing == b''
        assert asn1Object == b'abcd'

    def testStringSizeConstraintCountsFragments(self):
        spec = univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 3))

        chunks = []

        try:
            for chunk in streaming_encoder.encodeStream(
                    [b'abc', b'def'], asn1Spec=spec):
                chunks.append(chunk)

        except PyAsn1Error:
            pass

        else:
            assert False, 'oversized fragmented string tolerated'

        assert not b''.join(chunks).endswith(b'\x00\x00')


class StreamingRecordTestCase(BaseTestCase):
    def testSequence(self):
        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('name', char.UTF8String()))

        value = Record()
        value['id'] = 7
        value['name'] = 'abc'

        substrate = b''.join(streaming_encoder.encodeStream(value))

        assert substrate == b'\x30\x80\x02\x01\x07\x0c\x03abc\x00\x00'

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=Record())

        assert trailing == b''
        assert asn1Object['id'] == 7
        assert asn1Object['name'] == 'abc'

    def testOptionalAndDefaultedComponentsAreNotMaterialised(self):
        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('note', univ.OctetString()),
                namedtype.DefaultedNamedType('count', univ.Integer(5)))

        value = Record()
        value['id'] = 1

        for givenSpec in (None, Record()):
            substrate = b''.join(
                streaming_encoder.encodeStream(value, asn1Spec=givenSpec))

            assert substrate == b'\x30\x80\x02\x01\x01\x00\x00'
            assert value.getComponentByName(
                'note', instantiate=False) is univ.noValue
            assert value.getComponentByName(
                'count', instantiate=False) is univ.noValue

    def testChoice(self):
        choiceSpec = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()),
                namedtype.NamedType('text', univ.OctetString())))

        value = choiceSpec.clone()
        value['text'] = 'abc'

        substrate = b''.join(streaming_encoder.encodeStream(value))

        assert substrate == b'\x04\x03abc'

        asn1Object, trailing = decoder.decode(
            substrate, asn1Spec=choiceSpec)

        assert trailing == b''
        assert asn1Object.getName() == 'text'


class Permission(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resource', char.UTF8String()),
        namedtype.NamedType(
            'actions', univ.SequenceOf(componentType=univ.Integer())))


class Grant(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subject', char.UTF8String()),
        namedtype.NamedType(
            'perms', univ.SequenceOf(componentType=Permission())))


class StreamingAuthorizationRecordTestCase(BaseTestCase):
    """End-to-end shape of the feature: an authorization grant."""

    def _permissions(self):
        for resource, actions in (('files', (1, 2)), ('network', (3,))):
            permission = Permission()
            permission['resource'] = resource
            permission['actions'].extend(actions)

            yield permission

    def _permissionSpec(self):
        return univ.SequenceOf(componentType=Permission())

    def testChannelAcceptsShortWritesAndValueDecodes(self):
        class ShortChannel(object):
            def __init__(self, limit):
                self.limit = limit
                self.octets = b''
                self.calls = 0

            def write(self, chunk):
                written = 0

                while written < len(chunk):
                    take = min(len(chunk) - written, self.limit)
                    self.octets += chunk[written:written + take]
                    written += take
                    self.calls += 1

                return len(chunk)

        channel = ShortChannel(limit=2)

        written = streaming_encoder.encodeStreamTo(
            channel, self._permissions(), asn1Spec=self._permissionSpec())

        assert written == len(channel.octets)
        assert channel.calls > 1

        asn1Object, trailing = decoder.decode(
            channel.octets, asn1Spec=self._permissionSpec())

        assert trailing == b''
        assert len(asn1Object) == 2
        assert asn1Object[0]['resource'] == 'files'
        assert asn1Object[0]['actions'][1] == 2

    def testFailedMidStreamBytesAreNotACompleteGrant(self):
        class PromptlyFailingChannel(object):
            def __init__(self):
                self.octets = b''

            def write(self, chunk):
                self.octets += chunk
                raise IOError('connection lost while transferring')

        channel = PromptlyFailingChannel()

        try:
            streaming_encoder.encodeStreamTo(
                channel, self._permissions(),
                asn1Spec=self._permissionSpec())

        except streaming_encoder.StreamingEncodeError as exc:
            assert 'transport must be terminated' in str(exc)

        else:
            assert False, 'channel failure tolerated'

        try:
            decoder.decode(channel.octets, asn1Spec=self._permissionSpec())

        except PyAsn1Error:
            pass

        else:
            assert False, 'partial authorization grant decoded as complete'

    def testGrantEncodedFromValueMatchesRegularIndefiniteMode(self):
        grant = Grant()
        grant['subject'] = 'alice'

        for permission in self._permissions():
            grant['perms'].append(permission)

        expected = encoder.encode(grant, defMode=False)
        substrate = b''.join(streaming_encoder.encodeStream(grant))

        assert substrate == expected

        asn1Object, trailing = decoder.decode(
            substrate, asn1Spec=Grant())

        assert trailing == b''
        assert asn1Object['subject'] == 'alice'
        assert asn1Object['perms'][0]['resource'] == 'files'


class StreamingTerminationTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.spec = univ.SequenceOf(componentType=univ.Integer())

    def testCompleteIsSetWhenFinalEocIsDelivered(self):
        spec = univ.SequenceOf(componentType=univ.Integer())

        encoderInstance = iter(
            streaming_encoder.encodeStream(
                [univ.Integer(1)], asn1Spec=spec))

        while True:
            try:
                chunk = next(encoderInstance)

            except StopIteration:
                break

            if chunk == b'\x00\x00':
                # the last EOC has been handed over; the value is complete
                # even if the consumer never asks for another chunk
                assert encoderInstance.complete
                assert not encoderInstance.aborted

    def testProducerFailureDoesNotEmitTerminator(self):
        values = FailingIterable([univ.Integer(1), univ.Integer(2)])

        encoderInstance = streaming_encoder.encodeStream(
            values, asn1Spec=self.spec)

        chunks = []

        try:
            for chunk in encoderInstance:
                chunks.append(chunk)

        except streaming_encoder.StreamingEncodeError as exc:
            assert 'transport must be terminated' in str(exc)
            assert exc.octetsEmitted == len(b''.join(chunks))
            assert isinstance(exc.cause, RuntimeError)

        else:
            assert False, 'producer failure tolerated'

        substrate = b''.join(chunks)

        assert not substrate.endswith(b'\x00\x00')
        assert not encoderInstance.complete
        assert encoderInstance.aborted

        try:
            decoder.decode(substrate, asn1Spec=self.spec)

        except PyAsn1Error:
            pass

        else:
            assert False, 'truncated stream decoded as a complete object'

    def testHeaderOnlyPrefixIsNotACompleteValue(self):
        def empty():
            raise RuntimeError('no data')
            yield univ.Integer(1)

        encoderInstance = streaming_encoder.encodeStream(
            empty(), asn1Spec=self.spec)

        chunks = []

        try:
            for chunk in encoderInstance:
                chunks.append(chunk)

        except streaming_encoder.StreamingEncodeError as exc:
            assert exc.octetsEmitted == len(b''.join(chunks))

        else:
            assert False, 'producer failure tolerated'

        assert chunks == [b'\x30\x80']
        assert not encoderInstance.complete

        try:
            decoder.decode(b''.join(chunks), asn1Spec=self.spec)

        except PyAsn1Error:
            pass

        else:
            assert False, 'header-only prefix decoded as a value'

    def testExplicitAbortNeverEmitsTerminator(self):
        values = RecordingIterable([univ.Integer(1), univ.Integer(2)])

        encoderInstance = streaming_encoder.encodeStream(
            values, asn1Spec=self.spec)

        chunks = [next(encoderInstance), next(encoderInstance)]

        encoderInstance.abort()

        assert not encoderInstance.complete
        assert encoderInstance.aborted
        assert not b''.join(chunks).endswith(b'\x00\x00')

        try:
            next(encoderInstance)

        except streaming_encoder.StreamingAbortError:
            pass

        else:
            assert False, 'aborted encoder resumed'

    def testCancellationByCloseNeverEmitsTerminator(self):
        encoderInstance = streaming_encoder.encodeStream(
            [univ.Integer(1), univ.Integer(2)], asn1Spec=self.spec)

        chunks = [next(encoderInstance), next(encoderInstance)]

        encoderInstance.close()

        assert not encoderInstance.complete
        assert encoderInstance.aborted
        assert not b''.join(chunks).endswith(b'\x00\x00')

    def testContextManagerAbortsUnfinishedValue(self):
        encoderInstance = streaming_encoder.encodeStream(
            [univ.Integer(1), univ.Integer(2)], asn1Spec=self.spec)

        with encoderInstance:
            chunks = [next(encoderInstance), next(encoderInstance)]

        assert encoderInstance.aborted
        assert not encoderInstance.complete
        assert not b''.join(chunks).endswith(b'\x00\x00')

    def testScalarConstraintFailureEmitsNothing(self):
        spec = univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, 10))

        encoderInstance = streaming_encoder.encodeStream(100, asn1Spec=spec)

        try:
            next(encoderInstance)

        except PyAsn1Error:
            pass

        else:
            assert False, 'constraint violation tolerated'

        assert encoderInstance.octetsEmitted == 0
        assert not encoderInstance.complete

    def testInconsistentValueFailsBeforeHeader(self):
        spec = univ.SequenceOf(componentType=univ.Integer()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(2, 3))

        value = spec.clone()
        value.extend([1])

        encoderInstance = streaming_encoder.encodeStream(value)

        try:
            next(encoderInstance)

        except PyAsn1Error:
            pass

        else:
            assert False, 'inconsistent value tolerated'

        assert encoderInstance.octetsEmitted == 0

    def testMissingMandatoryComponentFailsBeforeHeader(self):
        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()))

        for value, givenSpec in ((Record(), None), ({}, Record())):
            encoderInstance = streaming_encoder.encodeStream(
                value, asn1Spec=givenSpec)

            try:
                next(encoderInstance)

            except PyAsn1Error:
                pass

            else:
                assert False, 'incomplete record tolerated'

            assert encoderInstance.octetsEmitted == 0
            assert not encoderInstance.complete


class StreamingSinkTestCase(BaseTestCase):
    def testValidStreamIsWrittenCompletely(self):
        sink = ShortWriteSink()

        spec = univ.SequenceOf(componentType=univ.Integer())

        written = streaming_encoder.encodeStreamTo(
            sink, [univ.Integer(1), univ.Integer(2)], asn1Spec=spec)

        substrate = sink.getvalue()

        assert written == len(substrate)
        assert substrate == b'\x30\x80\x02\x01\x01\x02\x01\x02\x00\x00'

        asn1Object, trailing = decoder.decode(substrate, asn1Spec=spec)

        assert trailing == b''
        assert len(asn1Object) == 2

    def testShortWriteIsRejectedWithoutTerminator(self):
        sink = ShortWriteSink(limit=2)

        spec = univ.SequenceOf(componentType=univ.Integer())

        try:
            streaming_encoder.encodeStreamTo(
                sink, [univ.Integer(1)], asn1Spec=spec)

        except streaming_encoder.ShortWriteError as exc:
            assert 'transport must be terminated' in str(exc)

        else:
            assert False, 'short write tolerated'

        substrate = sink.getvalue()

        assert not substrate.endswith(b'\x00\x00')

    def testSinkFailureDuringWriteDoesNotCompleteValue(self):
        class FailingSink(object):
            def __init__(self):
                self.chunks = []
                self.calls = 0

            def write(self, chunk):
                self.calls += 1

                if self.calls > 1:
                    raise IOError('connection reset')

                self.chunks.append(chunk)
                return len(chunk)

        sink = FailingSink()
        spec = univ.SequenceOf(componentType=univ.Integer())

        try:
            streaming_encoder.encodeStreamTo(
                sink, [univ.Integer(1), univ.Integer(2)], asn1Spec=spec)

        except streaming_encoder.StreamingEncodeError as exc:
            assert 'transport must be terminated' in str(exc)

        else:
            assert False, 'sink failure tolerated'

        substrate = b''.join(sink.chunks)

        assert not substrate.endswith(b'\x00\x00')


class StreamingDerTestCase(BaseTestCase):
    def testDerRejectsStreamingEntry(self):
        try:
            der_encoder.encodeStream(univ.Integer(1))

        except PyAsn1Error as exc:
            assert 'DER does not support streaming encoding' in str(exc)

        else:
            assert False, 'DER silently downgraded to indefinite-length BER'

    def testDerStillEncodesDefiniteLength(self):
        value = univ.SequenceOf(componentType=univ.Integer())
        value.extend([1, 2])

        assert der_encoder.encode(value) == b'\x30\x06\x02\x01\x01\x02\x01\x02'

    def testBerDefModeIsRejected(self):
        try:
            streaming_encoder.encodeStream(univ.Integer(1), defMode=True)

        except PyAsn1Error:
            pass

        else:
            assert False, 'defMode accepted by the indefinite-length encoder'


class StreamingBufferingTestCase(BaseTestCase):
    def testPeakBufferDoesNotGrowWithPayload(self):
        spec = univ.SequenceOf(componentType=univ.Integer())

        def values(count):
            for value in range(count):
                yield univ.Integer(value)

        small = self._peakMemory(values(10), spec)
        large = self._peakMemory(values(5000), spec)

        # A 500x larger payload must not hold a proportional buffer; the
        # bound is what it takes to encode one component at a time.
        assert large < small + 65536, (small, large)

    def testLargeStringFragmentIsNotCopiedWholeWhenChunked(self):
        payload = b'x' * 100000

        spec = univ.OctetString()

        def chunks():
            yield payload

        peak = self._peakMemory(chunks(), spec, maxChunkSize=4096)

        assert peak < len(payload) // 4, peak

    def _peakMemory(self, value, asn1Spec, **options):
        import tracemalloc

        tracemalloc.start()

        try:
            for chunk in streaming_encoder.encodeStream(
                    value, asn1Spec=asn1Spec, **options):
                pass

            _, peak = tracemalloc.get_traced_memory()

        finally:
            tracemalloc.stop()

        return peak


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
