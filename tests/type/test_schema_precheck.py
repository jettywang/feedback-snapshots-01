#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import univ
from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type.base import noValue
from pyasn1.type.schema import precheck
from pyasn1.type.schema import precheck_evidence


class SequenceWindowTestCase(BaseTestCase):
    """Optional/defaulted SEQUENCE fields open a tag-ambiguous window."""

    def setUp(self):
        BaseTestCase.setUp(self)

        class AmbiguousSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('first', univ.Integer()),
                namedtype.NamedType('second', univ.Integer()))

        self.schema = AmbiguousSequence()
        self.findings = precheck.precheck(self.schema)

    def testDetectsConflict(self):
        conflicts = [f for f in self.findings
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        conflict = conflicts[0]
        assert conflict.containerKind == 'SEQUENCE'
        assert conflict.fieldPaths == (
            'AmbiguousSequence.first', 'AmbiguousSequence.second')
        assert conflict.wireSignature == ((0, 2),)
        assert conflict.renderedTag == '[0:2]'
        assert conflict.tagKinds == ('universal', 'universal')

    def testRationaleNamesAnchor(self):
        conflict = [f for f in self.findings
                    if isinstance(f, precheck.TagConflict)][0]
        assert 'first' in conflict.rationale
        assert 'SEQUENCE' in conflict.rationale

    def testMandatoryAnchorIsNotAConflict(self):
        class OrderedSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('first', univ.Integer()),
                namedtype.OptionalNamedType('second', univ.Integer()))

        conflicts = [f for f in precheck.precheck(OrderedSequence())
                     if isinstance(f, precheck.TagConflict)]
        assert conflicts == []

    def testDefaultedFieldOpensWindow(self):
        class DefaultedSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.DefaultedNamedType('d', univ.Integer(0)),
                namedtype.NamedType('e', univ.Integer()))

        conflicts = [f for f in precheck.precheck(DefaultedSequence())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        assert conflicts[0].fieldPaths == (
            'DefaultedSequence.d', 'DefaultedSequence.e')

    def testThreeFieldWindowDedupesFieldSets(self):
        # Three same-tagged fields: the optional/defaulted windows overlap, so
        # the (tag, field-set) pair is reported once rather than per anchor.
        class ThreeFields(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('opt', univ.Integer()),
                namedtype.DefaultedNamedType('dflt', univ.Integer(1)),
                namedtype.NamedType('mand', univ.Integer()))

        conflicts = precheck.SchemaPrecheck(ThreeFields()).conflicts
        fieldSets = [tuple(c.fieldPaths) for c in conflicts]
        assert len(fieldSets) == len(set(fieldSets))
        # Every control must decode: all but the reference field are retagged.
        for conflict in conflicts:
            evidence = precheck_evidence.build_evidence(
                ThreeFields(), conflict)
            assert evidence.controlOutcome.startswith('uniquely decoded')
            relabelledTags = [
                tuple(nt.asn1Object.tagSet.superTags)
                for nt in evidence.relabelledSchema.componentType.namedTypes]
            # No tag is shared by two fields after relabelling.
            assert len(relabelledTags) == len(set(relabelledTags))

    def testWindowStopsAtMandatoryField(self):
        # optional a, mandatory b, optional c: a can never be confused with c
        # because mandatory b terminates the window.
        class StoppedSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.OctetString()),
                namedtype.NamedType('b', univ.Integer()),
                namedtype.OptionalNamedType('c', univ.OctetString()))

        conflicts = [f for f in precheck.precheck(StoppedSequence())
                     if isinstance(f, precheck.TagConflict)]
        assert conflicts == []


class SetAndChoiceTestCase(BaseTestCase):
    """SET and CHOICE select by tag only, so any duplicate tag collides."""

    def testSetConflict(self):
        class AmbiguousSet(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        conflicts = [f for f in precheck.precheck(AmbiguousSet())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        assert conflicts[0].containerKind == 'SET'
        assert conflicts[0].fieldPaths == (
            'AmbiguousSet.a', 'AmbiguousSet.b')

    def testChoiceConflict(self):
        class AmbiguousChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        conflicts = [f for f in precheck.precheck(AmbiguousChoice())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        assert conflicts[0].containerKind == 'CHOICE'

    def testDistinctTagsAreClean(self):
        class DistinctChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString()))

        assert precheck.SchemaPrecheck(
            DistinctChoice()).isStaticallyUnambiguous


class TaggingModeTestCase(BaseTestCase):
    """Implicit and explicit tagging produce distinct wire identities."""

    def testImplicitAndExplicitSameNumberDoNotCollide(self):
        class MixedChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'implicit', univ.Integer().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0))),
                namedtype.NamedType(
                    'explicit', univ.Integer().subtype(explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0))))

        conflicts = [f for f in precheck.precheck(MixedChoice())
                     if isinstance(f, precheck.TagConflict)]
        assert conflicts == []

    def testExplicitCollisionIsDetectedAndLabelled(self):
        class ExplicitChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'a', univ.Integer().subtype(explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0))),
                namedtype.NamedType(
                    'b', univ.Integer().subtype(explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0))))

        conflicts = [f for f in precheck.precheck(ExplicitChoice())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        # Full two-level signature, both produced by explicit tagging.
        assert conflicts[0].wireSignature == ((0, 2), (128, 0))
        assert conflicts[0].tagKinds == ('explicit', 'explicit')

    def testImplicitCollisionIsLabelledImplicit(self):
        class ImplicitChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'a', univ.Integer().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0))),
                namedtype.NamedType(
                    'b', univ.Integer().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0))))

        conflicts = [f for f in precheck.precheck(ImplicitChoice())
                     if isinstance(f, precheck.TagConflict)]
        assert conflicts[0].tagKinds == ('implicit', 'implicit')


class NestedChoiceTestCase(BaseTestCase):
    """An untagged CHOICE is transparent and must be flattened."""

    def testFlattenUntaggedChoiceAgainstSibling(self):
        class Sub(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('k', univ.Integer()))

        class Host(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType(
                    'which', univ.Choice(componentType=namedtype.NamedTypes(
                        namedtype.NamedType('s', Sub()),
                        namedtype.NamedType('i', univ.Integer())))),
                namedtype.NamedType('anchor', Sub()))

        conflicts = [f for f in precheck.precheck(Host())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        assert conflicts[0].fieldPaths == (
            'Host.which.s', 'Host.anchor')

    def testConflictInsideUntaggedChoice(self):
        class Inner(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('x', univ.Integer()),
                namedtype.NamedType('y', univ.Integer()))

        class Host(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('pick', Inner()))

        conflicts = [f for f in precheck.precheck(Host())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        assert conflicts[0].fieldPaths == ('Host.pick.x', 'Host.pick.y')


class OpenTypeTestCase(BaseTestCase):
    """ANY and ANY DEFINED BY need runtime context and are never 'safe'."""

    def testBareAnyIsOpenContext(self):
        class BareAny(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('raw', univ.Any()))

        findings = precheck.precheck(BareAny())
        openFindings = [f for f in findings
                        if isinstance(f, precheck.OpenTypeFinding)]
        assert len(openFindings) == 1
        assert openFindings[0].path == 'BareAny.raw'
        assert openFindings[0].governingField is None
        # No deterministic collision, but the schema is not declared safe.
        assert precheck.SchemaPrecheck(BareAny()).openTypes

    def testAnyDefinedByNamesGoverningField(self):
        openType = opentype.OpenType('id', {1: univ.Integer()})

        class Governed(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(),
                                    openType=openType))

        openFindings = [f for f in precheck.precheck(Governed())
                        if isinstance(f, precheck.OpenTypeFinding)]
        assert len(openFindings) == 1
        assert openFindings[0].governingField == 'id'
        assert openFindings[0].path == 'Governed.blob'

    def testSequenceOfAnyIsMarked(self):
        class Bag(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'items', univ.SequenceOf(componentType=univ.Any())))

        openFindings = [f for f in precheck.precheck(Bag())
                        if isinstance(f, precheck.OpenTypeFinding)]
        assert len(openFindings) == 1
        assert openFindings[0].isCollection is True


class RecursionAndSharingTestCase(BaseTestCase):
    """Recursion terminates; legal shared types are not false cycles."""

    def testRecursiveSchemaTerminatesWithoutFalseCycle(self):
        class Link(univ.Sequence):
            pass

        class Node(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType('next', Link()))

        Link.componentType = namedtype.NamedTypes(
            namedtype.NamedType('node', Node()))

        previous_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(120)
        try:
            findings = precheck.precheck(Node())
        finally:
            sys.setrecursionlimit(previous_limit)
        assert findings == []

    def testRecursiveSchemaStillReportsRealConflict(self):
        class Link(univ.Sequence):
            pass

        class Node(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.OctetString()),
                namedtype.NamedType('b', univ.OctetString()),
                namedtype.OptionalNamedType('next', Link()))

        Link.componentType = namedtype.NamedTypes(
            namedtype.NamedType('node', Node()))

        conflicts = [f for f in precheck.precheck(Node())
                     if isinstance(f, precheck.TagConflict)]
        assert len(conflicts) == 1
        assert conflicts[0].fieldPaths == ('Node.a', 'Node.b')

    def testSharedTypeReportedAtEveryParentWithoutCycle(self):
        shared = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.OptionalNamedType('x', univ.Integer()),
            namedtype.NamedType('y', univ.Integer())))

        class Host(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('left', shared),
                namedtype.NamedType('right', shared))

        conflicts = [f for f in precheck.precheck(Host())
                     if isinstance(f, precheck.TagConflict)]
        paths = sorted(tuple(c.fieldPaths) for c in conflicts)
        assert ('Host.left.x', 'Host.left.y') in paths
        assert ('Host.right.x', 'Host.right.y') in paths
        assert len(conflicts) == 2

    def testRunIsIdempotent(self):
        class C(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        checker = precheck.SchemaPrecheck(C())
        first = [(f.path, getattr(f, 'fieldPaths', ())) for f in checker.run()]
        second = [(f.path, getattr(f, 'fieldPaths', ())) for f in checker.run()]
        assert first == second
        assert len(first) == 1


class ReadOnlyTestCase(BaseTestCase):
    """The prechecker never instantiates values or mutates the schema."""

    def testPrecheckDoesNotMaterializeValues(self):
        class S(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        schema = S()
        snapshot = repr(schema)
        precheck.precheck(schema)
        precheck.SchemaPrecheck(schema).run()
        assert repr(schema) == snapshot
        assert schema.isValue is False
        for idx in range(len(schema.componentType)):
            assert schema.getComponentByPosition(
                idx, instantiate=False) is noValue

    def testEvidenceDoesNotMutateOriginal(self):
        class S(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        schema = S()
        original_tags = [
            (nt.name, tuple(nt.asn1Object.tagSet.superTags))
            for nt in schema.componentType.namedTypes]
        for conflict in precheck.SchemaPrecheck(schema).conflicts:
            precheck_evidence.build_evidence(schema, conflict)
        assert [
            (nt.name, tuple(nt.asn1Object.tagSet.superTags))
            for nt in schema.componentType.namedTypes] == original_tags
        assert schema.isValue is False

    def testRejectsNonSchemaInput(self):
        try:
            precheck.SchemaPrecheck(42)
        except TypeError:
            pass
        else:
            assert 0, 'non-schema input tolerated'


class EvidenceTestCase(BaseTestCase):
    """Each deterministic conflict gets minimal and control encodings."""

    def _assertEvidence(self, schema):
        checker = precheck.SchemaPrecheck(schema)
        assert checker.conflicts
        evidence = precheck_evidence.build_all_evidence(
            schema, checker.run())
        assert len(evidence) == len(checker.conflicts)
        for item in evidence:
            assert item.ambiguousEncoding
            assert item.ambiguousHex == item.ambiguousEncoding.hex()
            assert item.controlHex == item.controlEncoding.hex()
            # The ambiguous substrate cannot be routed uniquely.
            assert item.decodeOutcome.startswith('raises')
            # The relabelled control routes deterministically.
            assert item.controlOutcome.startswith('uniquely decoded')
        return evidence

    def testSequenceEvidence(self):
        class S(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        evidence = self._assertEvidence(S())
        # SEQUENCE { INTEGER 0 } -- the colliding member only.
        assert evidence[0].ambiguousEncoding == bytes.fromhex('3003020100')

    def testChoiceEvidence(self):
        class C(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        evidence = self._assertEvidence(C())
        assert evidence[0].ambiguousEncoding == bytes.fromhex('020100')

    def testSetEvidenceIncludesAllMandatoryMembers(self):
        class S(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        evidence = self._assertEvidence(S())
        # Both mandatory members are present in the deterministic control.
        assert evidence[0].controlEncoding == bytes.fromhex(
            '3106020100800100')

    def testExplicitChoiceEvidence(self):
        class C(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'a', univ.Integer().subtype(explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0))),
                namedtype.NamedType(
                    'b', univ.Integer().subtype(explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0))))

        evidence = self._assertEvidence(C())
        # Explicit wrapper [0] around INTEGER 0; the control keeps field "a"
        # on [0] and moves field "b" to the unused [1]. The reference field
        # "a" still carries the original colliding tag, so its bytes match the
        # ambiguous substrate while the relabelled schema makes the choice
        # unique.
        assert evidence[0].ambiguousEncoding == bytes.fromhex('a003020100')
        assert evidence[0].controlEncoding == bytes.fromhex('a003020100')
        assert '"a"' in evidence[0].controlOutcome
        assert evidence[0].relabelledSchema is not evidence[0].conflict

    def testNestedChoiceControlSelectsOneAlternative(self):
        class Inner(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType(
                    'key', univ.OctetString().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0))),
                namedtype.NamedType(
                    'value', univ.OctetString().subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0))))

        class Outer(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.NamedType('inner', Inner()))

        schema = Outer()
        conflict = precheck.SchemaPrecheck(schema).conflicts[0]
        evidence = precheck_evidence.build_evidence(schema, conflict)
        assert evidence.controlOutcome.startswith('uniquely decoded')
        from pyasn1.codec.ber import decoder
        decoded, rest = decoder.decode(
            evidence.controlEncoding,
            asn1Spec=evidence.relabelledSchema)
        assert rest == b'' and decoded.isValue
        # The transparent CHOICE resolves to exactly one alternative; the
        # first field 'key' is the untouched reference, so it is selected.
        assert decoded['inner'].getName() == 'key'

    def testCollectionElementConflictRetagsInsideElement(self):
        class Element(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        class Bag(univ.SequenceOf):
            componentType = Element()

        schema = Bag()
        conflict = precheck.SchemaPrecheck(schema).conflicts[0]
        assert conflict.fieldPaths == (
            'Bag.<element>.a', 'Bag.<element>.b')
        evidence = precheck_evidence.build_evidence(schema, conflict)
        assert evidence.controlOutcome.startswith('uniquely decoded')
        # The control carries one relabelled element, not an empty container.
        assert len(evidence.controlEncoding) > 2
        from pyasn1.codec.ber import decoder
        decoded, rest = decoder.decode(
            evidence.controlEncoding,
            asn1Spec=evidence.relabelledSchema)
        assert rest == b'' and decoded.isValue
        # The single element's two fields now carry distinct tags.
        element = decoded[0]
        elementTags = [
            tuple(nt.asn1Object.tagSet.superTags)
            for nt in element.componentType.namedTypes]
        assert len(elementTags) == len(set(elementTags))

    def testMandatoryOpenAnyIsReportedNotSilentlyDropped(self):
        class WithOpen(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()),
                namedtype.NamedType('raw', univ.Any()))

        schema = WithOpen()
        conflict = precheck.SchemaPrecheck(schema).conflicts[0]
        evidence = precheck_evidence.build_evidence(schema, conflict)
        assert evidence.controlOutcome.startswith('control not synthesised')
        assert 'raw' in evidence.controlOutcome

    def testOptionalOpenAnyDoesNotBlockControl(self):
        class WithOptionalOpen(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.OptionalNamedType('a', univ.OctetString()),
                namedtype.NamedType('b', univ.OctetString()),
                namedtype.OptionalNamedType('raw', univ.Any()))

        schema = WithOptionalOpen()
        conflict = precheck.SchemaPrecheck(schema).conflicts[0]
        evidence = precheck_evidence.build_evidence(schema, conflict)
        assert evidence.controlOutcome.startswith('uniquely decoded')

    def testControlActuallyDecodesViaBerDecoder(self):
        from pyasn1.codec.ber import decoder

        class S(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        schema = S()
        conflict = precheck.SchemaPrecheck(schema).conflicts[0]
        evidence = precheck_evidence.build_evidence(schema, conflict)
        # The control must decode without error against the relabelled schema.
        decoded, rest = decoder.decode(
            evidence.controlEncoding,
            asn1Spec=evidence.relabelledSchema)
        assert rest == b''
        assert decoded.isValue

    def testBuildEvidenceRejectsOpenTypeFinding(self):
        finding = precheck.OpenTypeFinding('x', 'needs context')
        try:
            precheck_evidence.build_evidence(univ.Sequence(), finding)
        except TypeError:
            pass
        else:
            assert 0, 'open-type finding accepted as a conflict'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
