"""Import-order differential tests for open-type registries.

A long-running backend imports :mod:`pyasn1_modules` RFC modules lazily as
features are used.  Because ``OpenType`` holds its type map by reference and
RFC modules mutate the shared maps with ``dict.update`` at import time, an
ASN.1 object must not change its security interpretation merely because an
unrelated feature was loaded next door.

These tests exercise the three real registries
(:data:`rfc5652.cmsContentTypesMap`, :data:`rfc5652.cmsAttributesMap` and
:data:`rfc5280.certificateExtensionsMap`) in *separate interpreter
processes*, vary the import order, and compare fixed-DER decode structure
plus DER re-encoding.

Findings are classified as:
  * equivalent alias  - same OID, wire-equivalent schema, allowed to coexist
  * incompatible override - same OID, different decoding contract; the
    sources are retained instead of being silently overwritten
  * swallowed unknown OID - an unregistered OID whose raw bytes stop
    surviving after unrelated modules are imported

Import failures are reported separately and never count as findings.
"""

import glob
import itertools
import json
import os
import subprocess
import sys
import unittest

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import univ

from pyasn1_modules import rfc5280
from pyasn1_modules import rfc5652
from pyasn1_modules.guarded_registry import GuardedRegistry
from pyasn1_modules.guarded_registry import schema_fingerprint
from pyasn1_modules.guarded_registry import schemas_equivalent


HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(HERE, 'registry_order_worker.py')

CONTENT_FAMILY = 'cmsContentTypesMap'
ATTRIBUTE_FAMILY = 'cmsAttributesMap'
EXTENSION_FAMILY = 'certificateExtensionsMap'
FAMILIES = (CONTENT_FAMILY, ATTRIBUTE_FAMILY, EXTENSION_FAMILY)


def _all_rfc_modules():
    package_dir = os.path.dirname(rfc5652.__file__)
    names = [
        os.path.basename(path)[:-3]
        for path in glob.glob(os.path.join(package_dir, 'rfc*.py'))
    ]
    return sorted(names)


def _run_worker(order):
    """Run the snapshot worker in a fresh interpreter."""
    proc = subprocess.run(
        [sys.executable, WORKER, *order],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            'status': 'import-error',
            'order': list(order),
            'import_error': [
                'subprocess', 'WorkerError', proc.stderr.strip()],
        }
    return json.loads(proc.stdout)


def _registry_fingerprints(snapshot, family):
    return {
        oid: (None if entry is None else tuple(entry['fingerprint']))
        for oid, entry in snapshot['registries'][family].items()
    }


def _minimal_order(modules, predicate):
    """Smallest module prefix whose worker snapshot satisfies predicate."""
    snapshot = _run_worker(modules)
    if not predicate(snapshot):
        return None, snapshot
    prefix = list(modules)
    while len(prefix) > 1:
        trial = prefix[:-1]
        trial_snapshot = _run_worker(trial)
        if predicate(trial_snapshot):
            prefix = trial
            snapshot = trial_snapshot
        else:
            break
    return prefix, snapshot


def build_difference_report(order_before, order_after, family, oid, der_hex):
    """Canonical report emitted when two orders resolve an OID differently.

    Always carries the minimal module sequences on both sides and the exact
    fixed DER that exhibits the difference, so a finding is reproducible
    without re-running the whole matrix.
    """
    before = _run_worker(order_before)
    after = _run_worker(order_after)
    return {
        'family': family,
        'oid': oid,
        'der_hex': der_hex,
        'minimal_sequence_before': list(order_before),
        'minimal_sequence_after': list(order_after),
        'schema_before': before['registries'][family].get(oid),
        'schema_after': after['registries'][family].get(oid),
    }


class RegistryCoverageTest(unittest.TestCase):
    """The relationship scan itself must always be observable."""

    @classmethod
    def setUpClass(cls):
        cls.modules = _all_rfc_modules()
        cls.baseline = _run_worker([])
        cls.full = _run_worker(cls.modules)
        cls.import_errors = []
        if cls.full['status'] != 'ok':
            cls.import_errors.append(
                (tuple(cls.modules), cls.full.get('import_error')))

    def test_worker_snapshots_are_healthy(self):
        # Import failures are surfaced, not counted as vulnerabilities.
        self.assertEqual(self.baseline['status'], 'ok')
        self.assertEqual(self.full['status'], 'ok',
                         msg='worker import failure: %r' % self.import_errors)

    def test_coverage_records_registry_relationships(self):
        # Even with zero differential, the covered OID->source relationships
        # remain available for review.
        for family in FAMILIES:
            covered = self.full['coverage'][family]
            self.assertTrue(covered, msg='%s had no coverage' % family)
        self.assertGreater(
            len(self.full['coverage'][ATTRIBUTE_FAMILY]),
            len(self.baseline['coverage'][ATTRIBUTE_FAMILY]))

    def test_fixed_der_roundtrips_in_every_snapshot(self):
        for snapshot in (self.baseline, self.full):
            for fixture, outcome in snapshot['decode'].items():
                self.assertTrue(
                    outcome['roundtrip'],
                    msg='%s failed DER round-trip under order %r'
                        % (fixture, snapshot['order']))


class UnknownOidProtectionTest(unittest.TestCase):
    """An unregistered OID's raw value must not be swallowed by imports."""

    UNKNOWN_OID = '1.3.6.1.4.1.99999.42.1'

    def test_unknown_attribute_stays_raw_under_full_import(self):
        snapshot = _run_worker(_all_rfc_modules())
        outcome = snapshot['decode']['cms_attribute_unknown']
        self.assertTrue(outcome['raw_preserved'])
        self.assertFalse(
            outcome['registered'],
            msg='unrelated modules claimed the unknown OID %s'
                % self.UNKNOWN_OID)
        self.assertEqual(outcome['leaf_type'], 'AttributeValue')
        self.assertTrue(outcome['roundtrip'])

    def test_unknown_oid_resolves_to_no_schema_in_registry(self):
        snapshot = _run_worker(_all_rfc_modules())
        self.assertNotIn(
            self.UNKNOWN_OID,
            snapshot['registries'][ATTRIBUTE_FAMILY])


class EquivalentAliasTest(unittest.TestCase):
    """Re-registration with a wire-identical schema is an allowed alias."""

    def test_subclass_with_shared_wire_schema_is_equivalent(self):
        # rfc7906.Classification subclasses rfc2634.ESSSecurityLabel without
        # changing the tag/type contract: this is an alias, not a conflict.
        from pyasn1_modules import rfc2634
        from pyasn1_modules import rfc7906
        self.assertTrue(schemas_equivalent(
            rfc2634.ESSSecurityLabel(), rfc7906.Classification()))

    def test_guarded_registry_allows_equivalent_alias(self):
        registry = GuardedRegistry()
        oid = univ.ObjectIdentifier('1.3.6.1.4.1.99999.77.2')
        registry.update({oid: univ.OctetString()}, __source__='feature-a')
        registry.update({oid: univ.OctetString()}, __source__='feature-b')
        self.assertEqual(registry.incompatible_overrides, {})
        self.assertEqual(len(registry.provenance[oid]), 2)
        # Plain-dict read protocol still works for explicit users.
        self.assertIsInstance(registry[oid], univ.OctetString)
        self.assertIn(oid, registry)

    def test_duplicate_friendlyname_definitions_are_aliases(self):
        # Both modules define a BMPString-constrained FriendlyName for the
        # same PKCS#9 OID; different classes, identical wire schema.
        from pyasn1_modules import rfc2985
        from pyasn1_modules import rfc7292
        self.assertTrue(schemas_equivalent(
            rfc2985.FriendlyName(), rfc7292.FriendlyName()))


class IncompatibleOverrideTest(unittest.TestCase):
    """Different wire schemas on one OID must retain every source."""

    CONFLICT_OID = '1.2.840.113549.1.9.16.2.2'  # ESS security label

    def test_guarded_registry_flags_real_incompatible_override(self):
        # Controlled conflict: OctetString (tag 0x04) vs Integer (tag 0x02)
        # can never decode the same bytes, proving the discriminator fires.
        registry = GuardedRegistry()
        witness = univ.ObjectIdentifier('1.3.6.1.4.1.99999.77.1')
        registry.update({witness: univ.OctetString()}, __source__='mod-a')
        registry.update({witness: univ.Integer()}, __source__='mod-b')
        self.assertIn(witness, registry.incompatible_overrides)
        clash = registry.incompatible_overrides[witness][0]
        self.assertEqual(clash['source'], 'mod-b')
        self.assertNotEqual(clash['existing'], clash['incoming'])
        # Both sources remain inspectable instead of vanishing.
        sources = {entry[1] for entry in registry.provenance[witness]}
        self.assertEqual(sources, {'mod-a', 'mod-b'})

    def test_order_changes_resolution_when_conflict_is_simulated(self):
        """End-to-end proof via an isolated OpenType, no global mutation."""
        oid = univ.ObjectIdentifier('1.3.6.1.4.1.99999.77.3')
        blob = der_encoder.encode(univ.OctetString(b'abcd'))

        def decode_with(schema):
            type_map = {oid: schema}
            sequence = univ.Sequence(componentType=namedtype.NamedTypes(
                namedtype.NamedType('oid', univ.ObjectIdentifier()),
                namedtype.NamedType(
                    'value', univ.Any(),
                    openType=opentype.OpenType('oid', type_map))))
            structure = sequence.clone()
            structure['oid'] = oid
            structure['value'] = univ.Any(blob)
            decoded, _ = der_decoder.decode(
                der_encoder.encode(structure),
                asn1Spec=sequence, decodeOpenTypes=True)
            return decoded['value']

        as_octets = decode_with(univ.OctetString())
        self.assertEqual(type(as_octets).__name__, 'OctetString')
        self.assertEqual(bytes(as_octets), b'abcd')

        # Same bytes, same OID, but an Integer-typed registration cannot
        # consume the OctetString payload: import order would turn a valid
        # object into a hard decode failure, which is the incompatible case
        # the guard is required to retain provenance for.
        with self.assertRaises(Exception):
            decode_with(univ.Integer())
        with self.assertRaises(Exception):
            der_decoder.decode(blob, asn1Spec=univ.Integer())
        self.assertNotEqual(
            schema_fingerprint(univ.OctetString()),
            schema_fingerprint(univ.Integer()))

    def test_real_registry_scan_distinguishes_alias_from_conflict(self):
        """Scan every RFC module in separate processes and classify."""
        modules = _all_rfc_modules()
        full = _run_worker(modules)
        self.assertEqual(full['status'], 'ok')

        # Per-OID provenance across modules, collected in isolation so that
        # import dependencies do not masquerade as registrations.
        provenance = {family: {} for family in FAMILIES}
        import_failures = []
        baseline = _run_worker([])
        for module_name in modules:
            snapshot = _run_worker([module_name])
            if snapshot['status'] != 'ok':
                import_failures.append(
                    (module_name, snapshot['import_error']))
                continue
            for family in FAMILIES:
                base = baseline['registries'][family]
                for oid, entry in snapshot['registries'][family].items():
                    if entry is None or base.get(oid) == entry:
                        continue
                    provenance[family].setdefault(oid, set()).add(
                        (module_name, tuple(entry['fingerprint']),
                         entry['type']))

        incompatible = {}
        aliases = {}
        for family, by_oid in provenance.items():
            for oid, records in by_oid.items():
                fingerprints = {record[1] for record in records}
                if len(fingerprints) > 1:
                    incompatible[(family, oid)] = sorted(records)
                else:
                    aliases[(family, oid)] = sorted(
                        record[0] for record in records)

        # Import errors must never be reported as registry findings.
        self.assertEqual(import_failures, [])

        # The security-label OID currently resolves to wire-identical
        # schemas, so it is classified as an alias rather than a conflict:
        # the discriminator does not cry wolf on subclass re-registration.
        self.assertNotIn(
            (ATTRIBUTE_FAMILY, self.CONFLICT_OID), incompatible)
        self.assertIn(
            (ATTRIBUTE_FAMILY, self.CONFLICT_OID), aliases)

        # Alias coverage is retained for audit even when no true conflict
        # exists in the shipped registries.
        self.assertTrue(aliases)


class MinimalSequenceReportingTest(unittest.TestCase):
    """When a difference exists, report the smallest module sequence + DER."""

    def test_minimal_sequence_locates_single_feature_registration(self):
        # rfc3779 contributes the IPAddrBlocks certificate extension; the
        # minimal sequence that registers it is just [rfc3779].
        target_oid = '1.3.6.1.5.5.7.1.7'
        prefix, snapshot = _minimal_order(
            ['rfc3779'],
            lambda snap: target_oid in snap['coverage'][EXTENSION_FAMILY])
        self.assertEqual(prefix, ['rfc3779'])
        self.assertIn(
            target_oid, snapshot['registries'][EXTENSION_FAMILY])

    def test_minimal_sequence_for_two_module_alias(self):
        # rfc5083 registers AuthEnvelopedData; rfc6032 re-registers the same
        # OID as an equivalent alias.  Both orders converge, and the minimal
        # sequence exposing the OID stays a single module.
        target_oid = '1.2.840.113549.1.9.16.1.23'
        for order in (['rfc5083', 'rfc6032'], ['rfc6032', 'rfc5083']):
            snapshot = _run_worker(order)
            self.assertEqual(snapshot['status'], 'ok')
            entry = snapshot['registries'][CONTENT_FAMILY][target_oid]
            self.assertEqual(
                entry['fingerprint'],
                _run_worker(['rfc5083'])['registries'][CONTENT_FAMILY][
                    target_oid]['fingerprint'])

        prefix, _ = _minimal_order(
            ['rfc5083', 'rfc6032'],
            lambda snap: target_oid in snap['coverage'][CONTENT_FAMILY])
        self.assertEqual(prefix, ['rfc5083'])

    def test_difference_report_contract_carries_sequence_and_der(self):
        # The report shape is locked down so a real finding always includes
        # both minimal module sequences and the exact DER hex. Here the two
        # orders converge (an alias), but the contract is identical for an
        # incompatible override.
        import tests.registry_order_worker as worker
        der_hex = worker._encode_fixtures()['cms_content'].hex()
        report = build_difference_report(
            [], ['rfc5083'], CONTENT_FAMILY,
            '1.2.840.113549.1.9.16.1.23', der_hex)
        self.assertEqual(report['minimal_sequence_before'], [])
        self.assertEqual(report['minimal_sequence_after'], ['rfc5083'])
        self.assertEqual(report['der_hex'], der_hex)
        self.assertIsNone(report['schema_before'])
        self.assertIsNotNone(report['schema_after'])
        # The same DER decodes and round-trips under both orders.
        for order in (report['minimal_sequence_before'],
                      report['minimal_sequence_after']):
            snapshot = _run_worker(order)
            self.assertTrue(
                snapshot['decode']['cms_content']['roundtrip'])


if __name__ == '__main__':
    unittest.main()
