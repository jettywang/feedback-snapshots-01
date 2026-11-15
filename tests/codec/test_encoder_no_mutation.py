#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest
from itertools import product

from tests.base import BaseTestCase

from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native import encoder as native_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import base
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class DefaultedComponentsNoMutationTestCase(BaseTestCase):
    codecs = (
        ('ber-def', lambda value: ber_encoder.encode(value, defMode=True)),
        ('ber-indef', lambda value: ber_encoder.encode(value, defMode=False)),
        ('cer', cer_encoder.encode),
        ('der', der_encoder.encode),
        ('native', native_encoder.encode),
    )

    def _makeRecord(self, containerType, optionalPresent, defaultState):
        roomTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        houseTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)

        record = containerType(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType(
                    'room', univ.Integer().subtype(implicitTag=roomTag)
                ),
                namedtype.DefaultedNamedType(
                    'house', univ.Integer(0).subtype(implicitTag=houseTag)
                )
            )
        )

        record['id'] = 123

        if optionalPresent:
            record['room'] = 321

        if defaultState == 'explicit-default':
            record['house'] = 0

        elif defaultState == 'explicit-nondefault':
            record['house'] = 7

        elif defaultState != 'absent':
            raise AssertionError('unknown default state %r' % (defaultState,))

        return record

    def _snapshot(self, value, names):
        snapshot = []

        for name in names:
            component = value.getComponentByName(name, instantiate=False)

            if component is univ.noValue:
                snapshot.append((name, univ.noValue))

            else:
                snapshot.append(
                    (name, component.prettyPrint(), component.isValue,
                     str(component.tagSet))
                )

        return tuple(snapshot)

    def _assertDefaultedState(self, record, defaultState):
        component = record.getComponentByName('house', instantiate=False)

        if defaultState == 'absent':
            assert component is univ.noValue

        else:
            assert component is not univ.noValue

    def _assertEncodedRecord(self, codecName, encoded, optionalPresent, defaultState):
        if codecName == 'native':
            if optionalPresent:
                assert encoded['room'] == 321
            else:
                assert 'room' not in encoded

            if defaultState in ('absent', 'explicit-default'):
                assert encoded['house'] == 0
            else:
                assert encoded['house'] == 7

            return

        if optionalPresent:
            assert b'\x80\x02\x01\x41' in encoded
        else:
            assert b'\x80\x02\x01\x41' not in encoded

        if defaultState == 'explicit-nondefault':
            assert b'\x81\x01\x07' in encoded
        else:
            assert b'\x81\x01\x00' not in encoded
            assert b'\x81\x01\x07' not in encoded

    def testOptionalAndDefaultedComponentsAreNotMutated(self):
        for containerType, optionalPresent, defaultState in product(
                (univ.Sequence, univ.Set),
                (False, True),
                ('absent', 'explicit-default', 'explicit-nondefault')):

            for codecName, encodeFun in self.codecs:
                with self.subTest(
                        containerType=containerType.__name__,
                        optionalPresent=optionalPresent,
                        defaultState=defaultState,
                        codecName=codecName):

                    record = self._makeRecord(
                        containerType, optionalPresent, defaultState
                    )
                    before = self._snapshot(record, ('id', 'room', 'house'))

                    encoded = encodeFun(record)

                    assert self._snapshot(record, ('id', 'room', 'house')) == before
                    self._assertDefaultedState(record, defaultState)

                    if not optionalPresent:
                        assert record.getComponentByName(
                            'room', instantiate=False
                        ) is univ.noValue

                    self._assertEncodedRecord(
                        codecName, encoded, optionalPresent, defaultState
                    )

    def testAbsentDefaultedConstructedComponentIsNotMutated(self):
        inner = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType('note', univ.OctetString()),
                namedtype.DefaultedNamedType('count', univ.Integer(5)),
            )
        )

        outer = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.DefaultedNamedType('inner', inner),
            )
        )

        expected = {
            'ber-def': bytes((48, 3, 2, 1, 1)),
            'ber-indef': bytes((48, 128, 2, 1, 1, 0, 0)),
            'cer': bytes((48, 128, 2, 1, 1, 0, 0)),
            'der': bytes((48, 3, 2, 1, 1)),
            'native': {'id': 1, 'inner': {'count': 5}},
        }

        for codecName, encodeFun in self.codecs:
            with self.subTest(codecName=codecName):
                record = outer.clone()
                record['id'] = 1

                before = self._snapshot(record, ('id', 'inner'))

                assert encodeFun(record) == expected[codecName]
                assert self._snapshot(record, ('id', 'inner')) == before
                assert record.getComponentByName(
                    'inner', instantiate=False
                ) is univ.noValue


class ReusedSchemaSigningTestCase(BaseTestCase):
    """Schema and value reuse across interleaved signing requests.

    Two request payloads are built from one signing schema, and encoded in an
    interleaved order through one encoder instance. Bytes must equal those of a
    fresh schema per request, and every lazy path (index access, clone,
    subtype, successful encoding, failed encoding) must leave the shared schema
    and the sibling request objects structurally unchanged. The snapshots read
    components with ``instantiate=False`` so observing the object cannot itself
    materialize the slot under test.
    """

    codecs = (
        ('ber-def', lambda value, **kwargs: ber_encoder.encode(
            value, defMode=True, **kwargs)),
        ('ber-indef', lambda value, **kwargs: ber_encoder.encode(
            value, defMode=False, **kwargs)),
        ('cer', cer_encoder.encode),
        ('der', der_encoder.encode),
        ('native', native_encoder.encode),
    )

    # (requestId, serial, issuer, version, alt, nonce, algorithm)
    requests = {
        'alpha': (7, 100, None, None, None, None, None),
        'beta': (8, 101, 5, 3, 'txt', b'nn', 4),
    }

    expected = {
        'ber-def': {
            'alpha': bytes((48, 8, 2, 1, 7, 48, 3, 2, 1, 100)),
            'beta': bytes((
                48, 26, 2, 1, 8, 48, 14, 2, 1, 101, 128, 1, 5, 129, 1, 3,
                131, 3, 97, 98, 99, 4, 2, 110, 110, 2, 1, 4)),
        },
        'ber-indef': {
            'alpha': bytes((48, 128, 2, 1, 7, 48, 128, 2, 1, 100, 0, 0, 0, 0)),
            'beta': bytes((
                48, 128, 2, 1, 8, 48, 128, 2, 1, 101, 128, 1, 5, 129, 1, 3,
                131, 3, 97, 98, 99, 0, 0, 4, 2, 110, 110, 2, 1, 4, 0, 0)),
        },
        'cer': {
            'alpha': bytes((48, 128, 2, 1, 7, 48, 128, 2, 1, 100, 0, 0, 0, 0)),
            'beta': bytes((
                48, 128, 2, 1, 8, 48, 128, 2, 1, 101, 128, 1, 5, 129, 1, 3,
                131, 3, 97, 98, 99, 0, 0, 4, 2, 110, 110, 2, 1, 4, 0, 0)),
        },
        'der': {
            'alpha': bytes((48, 8, 2, 1, 7, 48, 3, 2, 1, 100)),
            'beta': bytes((
                48, 26, 2, 1, 8, 48, 14, 2, 1, 101, 128, 1, 5, 129, 1, 3,
                131, 3, 97, 98, 99, 4, 2, 110, 110, 2, 1, 4)),
        },
        'native': {
            'alpha': {
                'requestId': 7,
                'payload': {'serial': 100, 'version': 1},
                'algorithm': 2
            },
            'beta': {
                'requestId': 8,
                'payload': {
                    'serial': 101, 'issuer': 5, 'version': 3,
                    'alt': {'txt': b'abc'}
                },
                'nonce': b'nn',
                'algorithm': 4
            },
        },
    }

    def _signingSchema(self):
        contextTags = [
            tag.Tag(tag.tagClassContext, tag.tagFormatSimple, idx)
            for idx in range(4)
        ]

        return univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('requestId', univ.Integer()),
                namedtype.NamedType(
                    'payload',
                    univ.Sequence(
                        componentType=namedtype.NamedTypes(
                            namedtype.NamedType(
                                'serial',
                                univ.Integer().subtype(
                                    subtypeSpec=constraint.ValueRangeConstraint(
                                        0, 1000)
                                )
                            ),
                            namedtype.OptionalNamedType(
                                'issuer',
                                univ.Integer().subtype(
                                    implicitTag=contextTags[0])
                            ),
                            namedtype.DefaultedNamedType(
                                'version',
                                univ.Integer(1).subtype(
                                    implicitTag=contextTags[1])
                            ),
                            namedtype.OptionalNamedType(
                                'alt',
                                univ.Choice(
                                    componentType=namedtype.NamedTypes(
                                        namedtype.NamedType(
                                            'num',
                                            univ.Integer().subtype(
                                                implicitTag=contextTags[2])
                                        ),
                                        namedtype.NamedType(
                                            'txt',
                                            univ.OctetString().subtype(
                                                implicitTag=contextTags[3])
                                        )
                                    )
                                )
                            )
                        )
                    )
                ),
                namedtype.OptionalNamedType('nonce', univ.OctetString()),
                namedtype.DefaultedNamedType('algorithm', univ.Integer(2))
            )
        )

    def _build(self, schema, name):
        requestId, serial, issuer, version, alt, nonce, algorithm = \
            self.requests[name]

        request = schema.clone()
        request['requestId'] = requestId
        request['payload']['serial'] = serial

        if issuer is not None:
            request['payload']['issuer'] = issuer

        if version is not None:
            request['payload']['version'] = version

        if alt == 'num':
            request['payload']['alt']['num'] = 4

        elif alt == 'txt':
            request['payload']['alt']['txt'] = b'abc'

        elif alt is not None:
            raise AssertionError('unknown alternative %r' % (alt,))

        if nonce is not None:
            request['nonce'] = nonce

        if algorithm is not None:
            request['algorithm'] = algorithm

        return request

    def _slots(self, value):
        """Structural component slots, read without instantiating anything."""
        if not isinstance(value, base.ConstructedAsn1Type):
            return 'simple'

        if value._componentValues is univ.noValue:
            return 'schema'

        slots = []

        if isinstance(value, univ.Choice):
            slots.append(('chosen-alternative', value._currentIdx))

        if isinstance(value, univ.SequenceOfAndSetOfBase):
            for idx in range(len(value)):
                component = value.getComponentByPosition(
                    idx, instantiate=False)

                if component is univ.noValue:
                    slots.append((idx, 'noValue'))

                else:
                    slots.append((
                        idx,
                        component.isValue,
                        component.__class__.__name__,
                        id(component)
                    ))

            return tuple(slots)

        for idx in range(value._componentTypeLen or len(value._dynamicNames)):
            try:
                component = value._componentValues[idx]

            except (IndexError, KeyError):
                slots.append((idx, '<missing>'))
                continue

            if component is univ.noValue:
                slots.append((idx, 'noValue'))

            else:
                slots.append((
                    idx,
                    component.isValue,
                    component.__class__.__name__,
                    id(component)
                ))

        return tuple(slots)

    def _state(self, value):
        """Recursive picture of a value: slots plus declared-component state."""
        if value is univ.noValue:
            return 'noValue'

        if not isinstance(value, base.ConstructedAsn1Type):
            return (
                value.__class__.__name__,
                value.isValue,
                value.prettyPrint()
            )

        componentType = getattr(value, 'componentType', None)

        declared = ()

        if componentType:
            declared = tuple(
                (namedType.name,
                 self._state(value.getComponentByName(
                     namedType.name, instantiate=False)))
                for namedType in componentType.namedTypes
            )

        return (
            value.__class__.__name__,
            value.isValue,
            self._slots(value),
            declared
        )

    def _instantiatedNames(self, value):
        """Declared component names whose slot holds a non-[]noValue[] object."""
        return tuple(
            namedType.name
            for namedType in value.componentType.namedTypes
            if value.getComponentByName(
                namedType.name, instantiate=False) is not univ.noValue
        )

    def testIndexAccessDoesNotLeakIntoValueObjects(self):
        schema = self._signingSchema()
        request = self._build(schema, 'beta')

        before = self._state(request)

        payload = request['payload']
        alternative = payload['alt']

        assert payload is request.getComponentByName(
            'payload', instantiate=False)
        assert alternative is payload.getComponentByName(
            'alt', instantiate=False)
        assert alternative['txt'] == b'abc'

        assert self._state(request) == before

    def testSchemaAccessDoesNotInstantiateSlots(self):
        schema = self._signingSchema()

        assert self._instantiatedNames(schema) == ()
        before = self._slots(schema)

        payloadSchema = schema.getComponentByName(
            'payload', instantiate=False)

        assert payloadSchema is univ.noValue
        assert self._instantiatedNames(schema) == ()
        assert self._slots(schema) == before

    def testCloneAndSubtypeKeepRequestsIndependent(self):
        schema = self._signingSchema()

        for name in ('alpha', 'beta'):
            request = self._build(schema, name)
            before = self._state(request)

            for derivation in (request.clone(cloneValueFlag=True),
                               request.subtype(cloneValueFlag=True)):
                assert derivation['requestId'] == request['requestId']
                assert derivation.getComponentByName(
                    'payload', instantiate=False) is not request.getComponentByName(
                        'payload', instantiate=False)

                # Mutate through the derived object in every nested shape the
                # payload has: scalar, optional, defaulted and CHOICE.
                derivation['payload']['serial'] = 999
                derivation['payload']['alt']['num'] = 999

            assert self._state(request) == before
            assert request['payload']['serial'] == self.requests[name][1]

            if self.requests[name][5] is None:
                assert request.getComponentByName(
                    'nonce', instantiate=False) is univ.noValue
            else:
                assert bytes(request['nonce']) == self.requests[name][5]

            untouchedAlternative = request['payload'].getComponentByName(
                'alt', instantiate=False)

            if untouchedAlternative is univ.noValue:
                assert self.requests[name][4] is None
            else:
                assert untouchedAlternative._currentIdx is not None
                assert untouchedAlternative.getName() == self.requests[name][4]

    def testSuccessfulEncodingLeavesRequestsAndSchemaUntouched(self):
        for codecName, encodeFun in self.codecs:
            with self.subTest(codecName=codecName):
                schema = self._signingSchema()

                alpha = self._build(schema, 'alpha')
                beta = self._build(schema, 'beta')

                beforeSchema = self._state(schema)
                beforeAlpha = self._state(alpha)
                beforeBeta = self._state(beta)

                alphaPayload = alpha.getComponentByName(
                    'payload', instantiate=False)

                assert self._instantiatedNames(alpha) == (
                    'requestId', 'payload')
                assert self._instantiatedNames(alphaPayload) == ('serial',)

                first = encodeFun(alpha)
                second = encodeFun(beta)

                assert first == self.expected[codecName]['alpha']
                assert second == self.expected[codecName]['beta']

                assert self._state(schema) == beforeSchema
                assert self._state(alpha) == beforeAlpha
                assert self._state(beta) == beforeBeta

                assert alpha.getComponentByName(
                    'payload', instantiate=False).getComponentByName(
                        'issuer', instantiate=False) is univ.noValue
                assert alpha.getComponentByName(
                    'payload', instantiate=False).getComponentByName(
                        'version', instantiate=False) is univ.noValue
                assert alpha.getComponentByName(
                    'nonce', instantiate=False) is univ.noValue
                assert alpha.getComponentByName(
                    'algorithm', instantiate=False) is univ.noValue

    def testSchemaDrivenEncodingLeavesSchemaUntouched(self):
        for codecName, encodeFun in self.codecs:
            with self.subTest(codecName=codecName):
                if codecName == 'native':
                    # The native encoder has no schema parameter.
                    continue

                schema = self._signingSchema()

                alpha = self._build(schema, 'alpha')
                beta = self._build(schema, 'beta')

                beforeSchema = self._state(schema)
                beforeAlpha = self._state(alpha)
                beforeBeta = self._state(beta)

                alphaBytes = encodeFun(alpha, asn1Spec=schema)
                betaBytes = encodeFun(beta, asn1Spec=schema)
                alphaBytesAgain = encodeFun(alpha, asn1Spec=schema)

                assert alphaBytes == self.expected[codecName]['alpha']
                assert betaBytes == self.expected[codecName]['beta']
                assert alphaBytesAgain == alphaBytes

                assert self._state(schema) == beforeSchema
                assert self._state(alpha) == beforeAlpha
                assert self._state(beta) == beforeBeta

    def testFailedEncodingLeavesValueUntouched(self):
        schema = self._signingSchema()
        request = self._build(schema, 'beta')

        # Replace the mandatory serial with a schema-only slot, so the leaf
        # encoder is what fails and the surrounding structure must survive.
        request['payload'].setComponentByPosition(0)

        before = self._state(request)

        try:
            der_encoder.encode(request)
        except PyAsn1Error:
            pass
        else:
            assert False, 'out-of-range serial encoded'

        assert self._state(request) == before
        assert request.getComponentByName(
            'nonce', instantiate=False) is not univ.noValue

    def testFailedEncodingLeavesSiblingUntouched(self):
        schema = self._signingSchema()

        good = self._build(schema, 'alpha')
        bad = self._build(schema, 'beta')
        bad['payload'].setComponentByPosition(0)

        beforeGood = self._state(good)
        goodBytes = der_encoder.encode(good)

        try:
            der_encoder.encode(bad)
        except PyAsn1Error:
            pass
        else:
            assert False, 'out-of-range serial encoded'

        assert self._state(good) == beforeGood
        assert der_encoder.encode(good) == goodBytes

    def testLegalDefaultAndExplicitAssignmentEncodeAlikeButStayDistinct(self):
        schema = self._signingSchema()

        omitted = self._build(schema, 'alpha')
        explicit = self._build(schema, 'alpha')

        # Writing a value equal to the DEFAULT keeps the slot and still encodes
        # to the omitted form; the two are distinguishable only by state.
        explicit['payload']['version'] = 1
        explicit['algorithm'] = 2

        assert self._instantiatedNames(
            omitted.getComponentByName('payload', instantiate=False)) == (
                'serial',)
        assert self._instantiatedNames(
            explicit.getComponentByName('payload', instantiate=False)) == (
                'serial', 'version')

        for codecName, encodeFun in self.codecs:
            if codecName == 'native':
                # The native encoder renders defaults rather than omitting them.
                continue

            with self.subTest(codecName=codecName):
                assert encodeFun(omitted) == encodeFun(explicit)
                assert encodeFun(omitted) == self.expected[codecName]['alpha']

        # A non-default value must survive; a later request may not drag the
        # schema's notion of the default with it.
        explicit['payload']['version'] = 3

        assert der_encoder.encode(explicit) != self.expected['der']['alpha']
        assert der_encoder.encode(omitted) == self.expected['der']['alpha']

        assert self._instantiatedNames(
            omitted.getComponentByName('payload', instantiate=False)) == (
                'serial',)
        assert schema.getComponentByName(
            'payload', instantiate=False) is univ.noValue

    def testSharedMutableSubcomponentIsDetected(self):
        schema = self._signingSchema()

        shared = self._build(schema, 'alpha').getComponentByName(
            'payload', instantiate=False)

        first = schema.clone()
        first['requestId'] = 10
        first.setComponentByName('payload', shared)

        second = schema.clone()
        second['requestId'] = 11
        second.setComponentByName('payload', shared)

        assert first.getComponentByName(
            'payload', instantiate=False) is shared
        assert second.getComponentByName(
            'payload', instantiate=False) is shared

        before = self._state(shared)

        first['payload']['serial'] = 12

        assert second['payload']['serial'] == 12
        assert self._state(shared) != before

    def testSparseSequenceOfComponentIsNotMaterializedOnFailure(self):
        elementType = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('value', univ.Integer())
            )
        )

        sparse = univ.SequenceOf(componentType=elementType)
        sparse.setComponentByPosition(2, elementType)
        sparse.getComponentByPosition(
            2, instantiate=False).setComponentByPosition(0, 1)

        before = self._slots(sparse)

        try:
            der_encoder.encode(sparse)
        except PyAsn1Error:
            pass
        else:
            assert False, 'sparse SEQUENCE OF encoded'

        assert self._slots(sparse) == before
        assert sparse.getComponentByPosition(
            0, instantiate=False) is univ.noValue


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
