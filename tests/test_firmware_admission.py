#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pyasn1_modules import rfc4108
from pyasn1_modules import rfc5652

import firmware_admission as fa


HW_TYPE_A = '1.3.6.1.4.1.424242.1.1'
HW_TYPE_B = '1.3.6.1.4.1.424242.1.2'
COMMUNITY_OPS = '1.3.6.1.4.1.424242.2.1'
PKG_X = '1.3.6.1.4.1.424242.3.1'
PKG_Y = '1.3.6.1.4.1.424242.3.2'
PKG_Z = '1.3.6.1.4.1.424242.3.3'


def preferred(oid, ver):
    pref = rfc4108.PreferredPackageIdentifier()
    pref['fwPkgID'] = oid
    pref['verNum'] = ver
    ident = rfc4108.PreferredOrLegacyPackageIdentifier()
    ident['preferred'] = pref
    return ident


def legacy(name):
    ident = rfc4108.PreferredOrLegacyPackageIdentifier()
    ident['legacy'] = name
    return ident


def signed_attr(oid, value):
    attr = rfc5652.Attribute()
    attr['attrType'] = oid
    attr['attrValues'][0] = univ.Any(der_encode(value))
    # round-trip through DER so the checker sees realistic input
    attr, rest = der_decode(der_encode(attr), asn1Spec=rfc5652.Attribute())
    assert not rest
    return attr


def target_hw_attr(hw_types):
    value = rfc4108.TargetHardwareIdentifiers()
    for i, hw_type in enumerate(hw_types):
        value[i] = hw_type
    return signed_attr(rfc4108.id_aa_targetHardwareIDs, value)


def community_attr(communities):
    value = rfc4108.CommunityIdentifiers()
    for i, community in enumerate(communities):
        value[i] = community
    return signed_attr(rfc4108.id_aa_communityIdentifiers, value)


def community_oid(oid):
    ci = rfc4108.CommunityIdentifier()
    ci['communityOID'] = oid
    return ci


def community_hw_list(hw_type, serial_entries):
    ci = rfc4108.CommunityIdentifier()
    modules = ci['hwModuleList']
    modules['hwType'] = hw_type
    for i, entry in enumerate(serial_entries):
        modules['hwSerialEntries'][i] = entry
    return ci


def serial_block(low, high):
    entry = rfc4108.HardwareSerialEntry()
    entry['block']['low'] = low
    entry['block']['high'] = high
    return entry


def serial_single(serial):
    entry = rfc4108.HardwareSerialEntry()
    entry['single'] = serial
    return entry


def raw_signed_attr(oid, der_bytes):
    attr = rfc5652.Attribute()
    attr['attrType'] = oid
    attr['attrValues'][0] = univ.Any(der_bytes)
    attr, rest = der_decode(der_encode(attr), asn1Spec=rfc5652.Attribute())
    assert not rest
    return attr


def pkg_id_attr(ident, stale=None):
    value = rfc4108.FirmwarePackageIdentifier()
    value['name'] = ident
    if stale is not None:
        value['stale'] = stale
    return signed_attr(rfc4108.id_aa_firmwarePackageID, value)


def preferred_stale(ver):
    stale = rfc4108.PreferredOrLegacyStalePackageIdentifier()
    stale['preferredStaleVerNum'] = ver
    return stale


def legacy_stale(name):
    stale = rfc4108.PreferredOrLegacyStalePackageIdentifier()
    stale['legacyStaleVersion'] = name
    return stale


def pkg_info_attr(dependencies=(), fw_pkg_type=None):
    value = rfc4108.FirmwarePackageInfo()
    if fw_pkg_type is not None:
        value['fwPkgType'] = fw_pkg_type
    for i, dep in enumerate(dependencies):
        value['dependencies'][i] = dep
    return signed_attr(rfc4108.id_aa_firmwarePackageInfo, value)


class AdmissionCheckTestCase(unittest.TestCase):

    def setUp(self):
        self.dev1 = fa.DeviceIdentity(HW_TYPE_A, b'\x00\x15')
        self.dev2 = fa.DeviceIdentity(HW_TYPE_A, b'\x00\x40')
        self.dev3 = fa.DeviceIdentity(
            HW_TYPE_B, b'\x00\x15', community_oids=[COMMUNITY_OPS])

    def scoped_attrs(self):
        return [
            target_hw_attr([HW_TYPE_A]),
            community_attr([community_hw_list(
                HW_TYPE_A, [serial_block(b'\x00\x10', b'\x00\x1f')])]),
            pkg_id_attr(preferred(PKG_X, 3)),
        ]

    def test_batch_valid_signature_targets_single_device(self):
        # Signature is equally valid for everyone, yet the package may
        # only be delivered to dev1.
        unsigned = [
            target_hw_attr([HW_TYPE_B]),
            community_attr([community_oid(COMMUNITY_OPS)]),
        ]
        decisions = fa.check_batch(
            self.scoped_attrs(), [self.dev1, self.dev2, self.dev3],
            unsigned_attrs=unsigned)

        self.assertEqual(3, len(decisions))

        self.assertTrue(decisions[0].installable)
        self.assertEqual([], decisions[0].reasons)

        self.assertFalse(decisions[1].installable)
        self.assertEqual('notInCommunity', decisions[1].error_code)
        self.assertTrue(any('notInCommunity' in r for r in decisions[1].reasons))

        self.assertFalse(decisions[2].installable)
        self.assertEqual('wrongHardware', decisions[2].error_code)
        self.assertTrue(any('wrongHardware' in r for r in decisions[2].reasons))
        self.assertTrue(any('notInCommunity' in r for r in decisions[2].reasons))

        # per-device reasons stay independent
        self.assertNotEqual(decisions[1].reasons, decisions[2].reasons)

        # unsigned sidecar metadata did not widen the target scope
        for decision in decisions[1:]:
            self.assertFalse(decision.installable)
        for decision in decisions:
            self.assertEqual(
                sorted([fa.TARGET_HARDWARE_IDS, fa.COMMUNITY_IDENTIFIERS]),
                sorted(decision.ignored_unsigned))

        # attributes that actually participated are listed
        self.assertEqual(
            [fa.TARGET_HARDWARE_IDS, fa.COMMUNITY_IDENTIFIERS,
             fa.FIRMWARE_PACKAGE_ID],
            decisions[0].attributes_used)

    def test_dependency_satisfied(self):
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(dependencies=[preferred(PKG_Y, 2)]),
        ]
        manifest = [fa.InstalledPackage(preferred(PKG_Y, 5))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertTrue(decision.installable)
        self.assertIn(fa.FIRMWARE_PACKAGE_INFO, decision.attributes_used)

    def test_missing_dependency(self):
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(dependencies=[preferred(PKG_Y, 2)]),
        ]
        decision = fa.check_package(attrs, self.dev1, [])
        self.assertFalse(decision.installable)
        self.assertEqual('missingDependency', decision.error_code)

    def test_wrong_dependency_version(self):
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(dependencies=[preferred(PKG_Y, 2)]),
        ]
        manifest = [fa.InstalledPackage(preferred(PKG_Y, 1))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertEqual('wrongDependencyVersion', decision.error_code)

    def test_dependency_cycle_rejected(self):
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(dependencies=[preferred(PKG_Y, 1)]),
        ]
        manifest = [fa.InstalledPackage(
            preferred(PKG_Y, 5), dependencies=[preferred(PKG_X, 1)])]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertTrue(any('cycle' in r for r in decision.reasons))

    def test_self_dependency_cycle_rejected(self):
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(dependencies=[preferred(PKG_X, 1)]),
        ]
        decision = fa.check_package(attrs, self.dev1, [])
        self.assertFalse(decision.installable)
        self.assertTrue(any('cycle' in r for r in decision.reasons))

    def test_stale_package_conflict(self):
        attrs = [pkg_id_attr(preferred(PKG_X, 4), stale=preferred_stale(3))]
        manifest = [fa.InstalledPackage(preferred(PKG_X, 3))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertEqual('stalePackage', decision.error_code)

    def test_stale_threshold_not_reached(self):
        attrs = [pkg_id_attr(preferred(PKG_X, 4), stale=preferred_stale(3))]
        manifest = [fa.InstalledPackage(preferred(PKG_X, 2))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertTrue(decision.installable)

    def test_installed_version_conflicts_with_declared(self):
        attrs = [pkg_id_attr(preferred(PKG_X, 2))]
        manifest = [fa.InstalledPackage(preferred(PKG_X, 5))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertEqual('stalePackage', decision.error_code)

    def test_breaks_installed_dependency(self):
        attrs = [pkg_id_attr(preferred(PKG_Y, 3))]
        manifest = [
            fa.InstalledPackage(preferred(PKG_Y, 1)),
            fa.InstalledPackage(
                preferred(PKG_Z, 1), dependencies=[preferred(PKG_Y, 5)]),
        ]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertEqual('breaksDependency', decision.error_code)

    def test_unknown_identifier_form_not_guessed(self):
        # FirmwarePackageIdentifier whose name is a CHOICE extension
        # (context-specific tag 9) unknown to this schema
        attrs = [raw_signed_attr(
            rfc4108.id_aa_firmwarePackageID, b'\x30\x03\x89\x01\x2a')]
        decision = fa.check_package(attrs, self.dev1, [])
        self.assertFalse(decision.installable)
        self.assertTrue(any('string equality' in r for r in decision.reasons))

    def test_unknown_dependency_form_not_guessed(self):
        # FirmwarePackageInfo with a dependency of unknown CHOICE form
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            raw_signed_attr(
                rfc4108.id_aa_firmwarePackageInfo,
                b'\x30\x05\x30\x03\x89\x01\x2a'),
        ]
        decision = fa.check_package(attrs, self.dev1, [])
        self.assertFalse(decision.installable)
        self.assertEqual('missingDependency', decision.error_code)

    def test_legacy_identifier_matching(self):
        attrs = [
            pkg_id_attr(legacy(b'pkgX-1.0')),
            pkg_info_attr(dependencies=[legacy(b'pkgY-2.0')]),
        ]
        manifest = [fa.InstalledPackage(legacy(b'pkgY-2.0'))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertTrue(decision.installable)

        manifest = [fa.InstalledPackage(legacy(b'pkgY-1.9'))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertEqual('missingDependency', decision.error_code)

    def test_legacy_stale_conflict(self):
        attrs = [pkg_id_attr(
            legacy(b'pkgX-1.1'), stale=legacy_stale(b'pkgX-1.0'))]
        manifest = [fa.InstalledPackage(legacy(b'pkgX-1.0'))]
        decision = fa.check_package(attrs, self.dev1, manifest)
        self.assertFalse(decision.installable)
        self.assertEqual('stalePackage', decision.error_code)

    def test_unsigned_metadata_cannot_widen_scope(self):
        attrs = [
            target_hw_attr([HW_TYPE_A]),
            community_attr([community_hw_list(
                HW_TYPE_A, [serial_single(b'\x00\x15')])]),
            pkg_id_attr(preferred(PKG_X, 3)),
        ]
        unsigned = [
            target_hw_attr([HW_TYPE_B]),
            community_attr([community_oid(COMMUNITY_OPS)]),
            pkg_id_attr(preferred(PKG_X, 99)),
        ]
        decision = fa.check_package(
            attrs, self.dev3, [], unsigned_attrs=unsigned)
        self.assertFalse(decision.installable)
        self.assertEqual('wrongHardware', decision.error_code)
        self.assertEqual(
            sorted([fa.TARGET_HARDWARE_IDS, fa.COMMUNITY_IDENTIFIERS,
                    fa.FIRMWARE_PACKAGE_ID]),
            sorted(decision.ignored_unsigned))

    def test_attributes_used_reflect_participation(self):
        attrs = [pkg_id_attr(preferred(PKG_X, 3))]
        decision = fa.check_package(attrs, self.dev1, [])
        self.assertEqual([fa.FIRMWARE_PACKAGE_ID], decision.attributes_used)
        self.assertTrue(any(
            'targetHardwareIDs absent' in n for n in decision.notes))
        self.assertTrue(any(
            'communityIdentifiers absent' in n for n in decision.notes))

    def test_missing_package_id_not_installable(self):
        attrs = [target_hw_attr([HW_TYPE_A])]
        decision = fa.check_package(attrs, self.dev1, [])
        self.assertFalse(decision.installable)
        self.assertEqual('badSignedAttrs', decision.error_code)

    def test_unsupported_package_type(self):
        dev = fa.DeviceIdentity(
            HW_TYPE_A, b'\x00\x15', supported_fw_pkg_types=[1, 2])
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(fw_pkg_type=7),
        ]
        decision = fa.check_package(attrs, dev, [])
        self.assertFalse(decision.installable)
        self.assertEqual('unsupportedPackageType', decision.error_code)

    def test_batch_per_device_manifests(self):
        attrs = [
            pkg_id_attr(preferred(PKG_X, 3)),
            pkg_info_attr(dependencies=[preferred(PKG_Y, 2)]),
        ]
        manifests = [
            [fa.InstalledPackage(preferred(PKG_Y, 5))],
            [],
        ]
        decisions = fa.check_batch(
            attrs, [self.dev1, self.dev2], manifests=manifests)
        self.assertTrue(decisions[0].installable)
        self.assertFalse(decisions[1].installable)
        self.assertEqual('missingDependency', decisions[1].error_code)


if __name__ == '__main__':
    unittest.main()
