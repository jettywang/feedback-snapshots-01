#
# This file is part of pyasn1-modules software.
#
# Tests for RFC 3779 resource extension chain validation (rfc3779chain).
#
import ipaddress
import os
import sys
import unittest

from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc3779
from pyasn1_modules import rfc3779chain
from pyasn1_modules.rfc3779chain import (
    AFI_IPV4,
    AFI_IPV6,
    ResourceKind,
    ResourceSyntaxError,
    TrustAnchorResources,
)

try:  # package import under ``python -m unittest discover``
    from tests import _rfc3779_certs as cert_builder
except ImportError:  # direct execution as a script
    sys.path.insert(0, os.path.dirname(__file__))
    import _rfc3779_certs as cert_builder


def bits32(address):
    return format(int(ipaddress.ip_address(address)), '032b')


def bits128(value):
    return format(value, '0128b')


class InheritedOverclaimTestCase(unittest.TestCase):
    """Two layers of inheritance, then an overclaim of a single address."""

    def setUp(self):
        self.anchor = TrustAnchorResources(ipv4=['192.0.2.0/24'])
        self.inheriting = cert_builder.build_certificate(
            'inherit-ca', 10,
            [cert_builder.ip_extension(
                [cert_builder.ip_inherit_family(AFI_IPV4)])])
        leaf_entries = [
            cert_builder.ip_range_entry(
                bits32('192.0.2.0'), bits32('192.0.3.0'))]
        self.leaf = cert_builder.build_certificate(
            'leaf', 11,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4, leaf_entries)])])

    def test_overclaim_localized_to_leaf_and_entry(self):
        report = rfc3779chain.check_resource_chain(
            [self.inheriting, self.leaf], self.anchor)

        self.assertTrue(report.parsed)
        self.assertFalse(report.resources_valid)
        self.assertEqual(1, len(report.violations))
        violation = report.violations[0]
        self.assertEqual(1, violation.certificate_position)
        self.assertEqual('leaf', violation.certificate_label)
        self.assertEqual(AFI_IPV4, violation.family)
        self.assertEqual('ipv4', violation.field)
        self.assertEqual(0, violation.entry_index)
        self.assertEqual('range', violation.entry_form)
        self.assertEqual(
            '192.0.2.0-192.0.3.0', violation.entry_text)

    def test_rejected_interval_is_minimal_single_address(self):
        report = rfc3779chain.check_resource_chain(
            [self.inheriting, self.leaf], self.anchor)
        violation = report.violations[0]
        self.assertEqual(1, len(violation.rejected))
        gap = violation.rejected[0]
        extra = int(ipaddress.ip_address('192.0.3.0'))
        self.assertEqual(extra, gap.start)
        self.assertEqual(extra, gap.end)
        self.assertEqual(
            '192.0.3.0',
            rfc3779chain.format_ip_interval(AFI_IPV4, gap))

    def test_inheritance_keeps_anchor_provenance(self):
        report = rfc3779chain.check_resource_chain(
            [self.inheriting, self.leaf], self.anchor)
        records = [
            record for record in report.delegations
            if record.family == AFI_IPV4]
        self.assertEqual(ResourceKind.INHERIT, records[0].kind)
        self.assertEqual(
            'trust-anchor',
            records[0].effective_entries[0].source_label)
        self.assertEqual(-1, records[0].effective_entries[0].source_index)

    def test_location_string_identifies_cert_and_entry(self):
        report = rfc3779chain.check_resource_chain(
            [self.inheriting, self.leaf], self.anchor)
        self.assertIn('leaf', report.violations[0].location)
        self.assertIn('entry 0', report.violations[0].location)


class LargeIPv6DelegationTestCase(unittest.TestCase):
    """A huge but contained IPv6 range must validate without expansion."""

    def test_large_range_contained(self):
        low = int(ipaddress.ip_address('2001:db8::1'))
        high = int(ipaddress.ip_address(
            '2001:db8:ffff:ffff:ffff:ffff:ffff:fffe'))
        holder = cert_builder.build_certificate(
            'v6-holder', 12,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV6,
                    [cert_builder.ip_range_entry(
                        bits128(low), bits128(high))])])])
        anchor = TrustAnchorResources(ipv6=['2001:db8::/32'])

        report = rfc3779chain.check_resource_chain([holder], anchor)
        self.assertTrue(report.parsed)
        self.assertTrue(report.resources_valid)
        self.assertEqual([], report.violations)

        interval = (report.certificates[0].ip_families[0]
                    .entries[0].interval)
        # Endpoint arithmetic only: no address list is ever materialized.
        self.assertEqual(low, interval.start)
        self.assertEqual(high, interval.end)
        self.assertGreater(interval.end - interval.start, 1 << 64)


class ASAdjacentRangeTestCase(unittest.TestCase):
    """An AS range adjacent to, but not inside, the granted range."""

    def test_adjacent_range_rejected_by_single_asn(self):
        holder = cert_builder.build_certificate(
            'as-holder', 13,
            [cert_builder.as_extension(
                entries=[cert_builder.as_range_entry(65000, 65200)])])
        anchor = TrustAnchorResources(asnum=['64500-65199'])

        report = rfc3779chain.check_resource_chain([holder], anchor)
        self.assertFalse(report.resources_valid)
        violation = report.violations[0]
        self.assertIsNone(violation.family)
        self.assertEqual('asnum', violation.field)
        self.assertEqual(0, violation.entry_index)
        self.assertEqual('as-range', violation.entry_form)
        self.assertEqual(
            [rfc3779chain.Interval(65200, 65200)],
            list(violation.rejected))
        self.assertEqual(
            'AS65200',
            rfc3779chain.format_as_interval(violation.rejected[0]))

    def test_contained_range_valid(self):
        holder = cert_builder.build_certificate(
            'as-holder', 14,
            [cert_builder.as_extension(
                entries=[cert_builder.as_range_entry(64600, 65000)])])
        anchor = TrustAnchorResources(asnum=['64500-65199'])
        report = rfc3779chain.check_resource_chain([holder], anchor)
        self.assertTrue(report.resources_valid)


class ASInheritanceAndRDITestCase(unittest.TestCase):
    def test_as_inherit_propagates_anchor_resources(self):
        anchor = TrustAnchorResources(asnum=['64500-65199'])
        inheriting = cert_builder.build_certificate(
            'as-inherit', 15,
            [cert_builder.as_extension(inherit=True)])
        holder = cert_builder.build_certificate(
            'as-holder', 16,
            [cert_builder.as_extension(
                entries=[cert_builder.as_id_entry(65000)])])
        report = rfc3779chain.check_resource_chain(
            [inheriting, holder], anchor)
        self.assertTrue(report.resources_valid)
        inherit_record = next(
            record for record in report.delegations
            if record.field == 'asnum'
            and record.certificate_label == 'as-inherit')
        self.assertEqual(ResourceKind.INHERIT, inherit_record.kind)
        self.assertEqual(
            'trust-anchor',
            inherit_record.effective_entries[0].source_label)

    def test_as_inherit_overclaim_after_two_layers(self):
        anchor = TrustAnchorResources(asnum=['64500-65199'])
        inheriting = cert_builder.build_certificate(
            'as-inherit', 17,
            [cert_builder.as_extension(inherit=True)])
        holder = cert_builder.build_certificate(
            'as-holder', 18,
            [cert_builder.as_extension(
                entries=[cert_builder.as_id_entry(65200)])])
        report = rfc3779chain.check_resource_chain(
            [inheriting, holder], anchor)
        self.assertFalse(report.resources_valid)
        violation = report.violations[0]
        self.assertEqual('asnum', violation.field)
        self.assertEqual(65200, violation.rejected[0].start)

    def test_rdi_is_separate_from_asnum(self):
        # No anchor RDI resources: any explicit RDI overclaims.
        holder = cert_builder.build_certificate(
            'rdi-holder', 19,
            [cert_builder.as_extension(
                entries=[cert_builder.as_id_entry(100)], field='rdi')])
        report = rfc3779chain.check_resource_chain(
            [holder], TrustAnchorResources(asnum=['1-1000']))
        rdi_violation = next(
            violation for violation in report.violations
            if violation.field == 'rdi')
        self.assertIsNone(rdi_violation.family)
        self.assertEqual(100, rdi_violation.rejected[0].start)


class FourSemanticsTestCase(unittest.TestCase):
    """Prefix, range, inherit and a missing extension stay distinct."""

    def test_missing_extension_is_absent_not_empty_or_inherit(self):
        certificate = cert_builder.build_certificate('bare', 20, [])
        resources = rfc3779chain.parse_certificate_resources(
            certificate, 0)
        self.assertFalse(resources.ip_extension_present)
        self.assertEqual((), resources.ip_families)
        self.assertIsNone(resources.asnum)
        self.assertIsNone(resources.rdi)

        report = rfc3779chain.check_resource_chain(
            [certificate], TrustAnchorResources(ipv4=['10.0.0.0/8']))
        record = next(
            record for record in report.delegations
            if record.field == 'ipv4')
        self.assertEqual(ResourceKind.ABSENT, record.kind)
        self.assertTrue(report.resources_valid)

    def test_explicit_empty_family_distinct_from_absent(self):
        certificate = cert_builder.build_certificate(
            'empty', 21,
            [cert_builder.ip_extension(
                [cert_builder.ip_empty_family(AFI_IPV4)])])
        resources = rfc3779chain.parse_certificate_resources(
            certificate, 0)
        view = resources.ip_families[0]
        self.assertEqual(ResourceKind.EMPTY, view.kind)
        self.assertEqual((), view.entries)

        report = rfc3779chain.check_resource_chain(
            [certificate], TrustAnchorResources(ipv4=['10.0.0.0/8']))
        record = next(
            record for record in report.delegations
            if record.field == 'ipv4')
        self.assertEqual(ResourceKind.EMPTY, record.kind)

    def test_inherit_distinct_from_explicit(self):
        certificate = cert_builder.build_certificate(
            'inheriting', 22,
            [cert_builder.ip_extension(
                [cert_builder.ip_inherit_family(AFI_IPV4)])])
        resources = rfc3779chain.parse_certificate_resources(
            certificate, 0)
        self.assertEqual(
            ResourceKind.INHERIT,
            resources.ip_families[0].kind)

    def test_prefix_and_range_are_different_forms(self):
        entries = [
            cert_builder.ip_prefix_entry(bits32('10.1.0.0')[:24]),
            cert_builder.ip_range_entry(
                bits32('10.2.0.5'), bits32('10.2.0.9'))]
        certificate = cert_builder.build_certificate(
            'forms', 23,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4, entries)])])
        resources = rfc3779chain.parse_certificate_resources(
            certificate, 0)
        forms = [
            entry.form
            for entry in resources.ip_families[0].entries]
        self.assertEqual(['prefix', 'range'], forms)


class CanonicalizationTestCase(unittest.TestCase):
    """Non-canonical or malformed representations are refused."""

    def _ip_cert(self, entries, family=AFI_IPV4):
        return cert_builder.build_certificate(
            'malformed', 30,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(family, entries)])])

    def test_inverted_ip_range_refused(self):
        certificate = self._ip_cert([
            cert_builder.ip_range_entry(
                bits32('10.0.0.9'), bits32('10.0.0.5'))])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate],
                TrustAnchorResources(ipv4=['10.0.0.0/8']))

    def test_overlapping_entries_refused(self):
        certificate = self._ip_cert([
            cert_builder.ip_prefix_entry(bits32('10.0.0.0')[:24]),
            cert_builder.ip_prefix_entry(bits32('10.0.0.128')[:25])])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate],
                TrustAnchorResources(ipv4=['10.0.0.0/8']))

    def test_full_width_aligned_range_is_legitimate(self):
        # Full-width endpoints can never name a prefix of the same width, so
        # a 10.0.0.0 - 10.0.0.255 range with 32-bit endpoints is canonical.
        anchor = TrustAnchorResources(ipv4=['10.0.0.0/8'])
        certificate = self._ip_cert([
            cert_builder.ip_range_entry(
                bits32('10.0.0.0'), bits32('10.0.0.255'))])
        report = rfc3779chain.check_resource_chain(
            [certificate], anchor)
        self.assertTrue(report.resources_valid)

    def test_short_endpoint_prefix_block_range_refused(self):
        # 24-bit endpoints 10.0.0.0 - 10.0.0.255 exactly span the /24 block,
        # which a 24-bit addressPrefix (10.0.0.0/24) already expresses.
        certificate = self._ip_cert([
            cert_builder.ip_range_entry(
                bits32('10.0.0.0')[:24],
                bits32('10.0.0.255')[:24])])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate],
                TrustAnchorResources(ipv4=['10.0.0.0/8']))

    def test_larger_aligned_block_is_legitimate_range(self):
        # 24-bit endpoints spanning 10.0.0.0 - 10.0.1.255 form a /23-sized
        # block, but a /23 needs fewer than 24 endpoint bits, so the range
        # encoding is canonical and must be accepted.
        anchor = TrustAnchorResources(ipv4=['10.0.0.0/22'])
        certificate = self._ip_cert([
            cert_builder.ip_range_entry(
                bits32('10.0.0.0')[:24], bits32('10.0.1.255')[:24])])
        report = rfc3779chain.check_resource_chain(
            [certificate], anchor)
        self.assertTrue(report.resources_valid)

    def test_omitted_endpoint_bits_follow_rfc3779(self):
        # RFC 3779 2.2.3.5: omitted low-order bits of min are zero and of
        # max are one.  With 24-bit endpoints the low octet is implicit.
        certificate = self._ip_cert([
            cert_builder.ip_range_entry(
                bits32('10.0.0.5')[:24],
                bits32('10.0.1.9')[:24])])
        resources = rfc3779chain.parse_certificate_resources(
            certificate, 0)
        interval = resources.ip_families[0].entries[0].interval
        self.assertEqual(
            int(ipaddress.ip_address('10.0.0.0')), interval.start)
        self.assertEqual(
            int(ipaddress.ip_address('10.0.1.255')), interval.end)

    def test_non_der_bit_string_refused(self):
        # A BER BIT STRING with one unused trailing bit is never DER
        # canonical.  Take a valid IPAddrBlocks DER encoding and splice in a
        # BER BIT STRING, recomputing the enclosing lengths so the substrate
        # decodes structurally but fails canonicalization.
        item = rfc3779.IPAddressOrRange()
        item.setComponentByName(
            'addressPrefix',
            univ.BitString.fromBinaryString('00001010'))
        family = rfc3779.IPAddressFamily()
        family.setComponentByPosition(0, AFI_IPV4)
        sequence = univ.SequenceOf(
            componentType=rfc3779.IPAddressOrRange())
        sequence.append(item)
        choice = rfc3779.IPAddressChoice()
        choice.setComponentByName('addressesOrRanges', sequence)
        family.setComponentByPosition(1, choice)
        blocks = rfc3779.IPAddrBlocks()
        blocks.append(family)
        valid = der_encoder.encode(blocks)

        ber_prefix = bytes([0x03, 0x02, 0x01, 0x80])
        der_prefix = bytes([0x03, 0x02, 0x00, 0x0A])
        self.assertIn(der_prefix, valid)
        family_body = (
            bytes([0x04, 0x02]) + AFI_IPV4
            + bytes([0x30, len(ber_prefix)]) + ber_prefix)
        family_der = bytes([0x30, len(family_body)]) + family_body
        blocks_der = bytes([0x30, len(family_der)]) + family_der

        extension = (
            rfc3779.id_pe_ipAddrBlocks, blocks_der, True)
        certificate = cert_builder.build_certificate(
            'ber', 31, [extension])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.parse_certificate_resources(certificate, 0)

    def test_mismatched_endpoint_size_refused(self):
        short_min = bits32('10.0.0.5')[:24]   # 24-bit endpoint
        full_max = bits32('10.0.0.9')         # 32-bit endpoint
        certificate = self._ip_cert([
            cert_builder.ip_range_entry(short_min, full_max)])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate],
                TrustAnchorResources(ipv4=['10.0.0.0/8']))

    def test_inverted_as_range_refused(self):
        certificate = cert_builder.build_certificate(
            'bad-as', 32,
            [cert_builder.as_extension(
                entries=[cert_builder.as_range_entry(100, 90)])])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate], TrustAnchorResources(asnum=['1-200']))

    def test_single_value_as_range_refused(self):
        certificate = cert_builder.build_certificate(
            'bad-as', 33,
            [cert_builder.as_extension(
                entries=[cert_builder.as_range_entry(100, 100)])])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate], TrustAnchorResources(asnum=['1-200']))

    def test_overlapping_as_entries_refused(self):
        certificate = cert_builder.build_certificate(
            'bad-as', 34,
            [cert_builder.as_extension(entries=[
                cert_builder.as_id_entry(100),
                cert_builder.as_range_entry(100, 200)])])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [certificate], TrustAnchorResources(asnum=['1-1000']))


class AnchorSpecificationTestCase(unittest.TestCase):
    def test_anchor_prefix_range_and_host_parsing(self):
        prefix = cert_builder.ip_prefix_entry(
            bits32('192.0.2.0')[:24])
        holder = cert_builder.build_certificate(
            'h', 40,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4, [prefix])])])
        anchor = TrustAnchorResources(
            ipv4=['192.0.2.0/24', '198.51.100.1'],
            asnum=[65000, '65100-65200'])
        report = rfc3779chain.check_resource_chain([holder], anchor)
        self.assertTrue(report.resources_valid)

    def test_anchor_overlap_refused(self):
        anchor = TrustAnchorResources(
            ipv4=['10.0.0.0/24', '10.0.0.128/25'])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [cert_builder.build_certificate('h', 41, [])], anchor)

    def test_anchor_prefix_aligned_range_refused(self):
        anchor = TrustAnchorResources(ipv4=['10.0.0.0-10.0.0.255'])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [cert_builder.build_certificate('h', 42, [])], anchor)

    def test_anchor_inverted_range_refused(self):
        anchor = TrustAnchorResources(ipv4=['10.0.0.9-10.0.0.1'])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [cert_builder.build_certificate('h', 43, [])], anchor)

    def test_anchor_as_out_of_range_refused(self):
        anchor = TrustAnchorResources(asnum=[1 << 32])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.check_resource_chain(
                [cert_builder.build_certificate('h', 44, [])], anchor)


class ContainmentEdgeTestCase(unittest.TestCase):
    def test_unknown_family_in_child_rejected(self):
        anchor = TrustAnchorResources(ipv4=['10.0.0.0/8'])
        holder = cert_builder.build_certificate(
            'v6-only', 50,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV6,
                    [cert_builder.ip_prefix_entry(
                        bits128(0x20010db8000000000000000000000000)[:32])])])])
        report = rfc3779chain.check_resource_chain([holder], anchor)
        self.assertFalse(report.resources_valid)
        self.assertEqual(AFI_IPV6, report.violations[0].family)

    def test_child_without_resources_then_grandchild_overclaims(self):
        # An ABSENT parent cannot pass resources on, even when the anchor
        # still holds them.
        anchor = TrustAnchorResources(ipv4=['10.0.0.0/8'])
        empty_parent = cert_builder.build_certificate('p', 51, [])
        grandchild = cert_builder.build_certificate(
            'g', 52,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4,
                    [cert_builder.ip_prefix_entry(
                        bits32('10.1.0.0')[:24])])])])
        report = rfc3779chain.check_resource_chain(
            [empty_parent, grandchild], anchor)
        self.assertFalse(report.resources_valid)
        violation = report.violations[0]
        self.assertEqual(1, violation.certificate_position)
        self.assertEqual(
            int(ipaddress.ip_address('10.1.0.0')),
            violation.rejected[0].start)

    def test_partial_overlap_reports_only_uncovered_part(self):
        # Parent 10.0.0.0/24; child range 10.0.0.200 - 10.0.1.50.  Only the
        # part above 10.0.0.255 should be reported.
        anchor = TrustAnchorResources(ipv4=['10.0.0.0/24'])
        holder = cert_builder.build_certificate(
            'partial', 53,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4,
                    [cert_builder.ip_range_entry(
                        bits32('10.0.0.200'),
                        bits32('10.0.1.50'))])])])
        report = rfc3779chain.check_resource_chain([holder], anchor)
        gap = report.violations[0].rejected[0]
        self.assertEqual(
            int(ipaddress.ip_address('10.0.1.0')), gap.start)
        self.assertEqual(
            int(ipaddress.ip_address('10.0.1.50')), gap.end)

    def test_whole_space_prefix_does_not_expand(self):
        # 0.0.0.0/0 against an anchor holding only a /8: the gap is computed
        # as endpoint intervals, never by materializing 2^32 addresses.  The
        # /0 prefix is the empty BIT STRING defined by RFC 3779.
        anchor = TrustAnchorResources(ipv4=['10.0.0.0/8'])
        zero_prefix = rfc3779.IPAddressOrRange()
        zero_prefix.setComponentByName(
            'addressPrefix', univ.BitString.fromBinaryString(''))
        holder = cert_builder.build_certificate(
            'whole', 54,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4, [zero_prefix])])])
        report = rfc3779chain.check_resource_chain([holder], anchor)
        self.assertFalse(report.resources_valid)
        violation = report.violations[0]
        self.assertEqual('0.0.0.0/0', violation.entry_text)
        gaps = violation.rejected
        self.assertLess(len(gaps), 5)
        total = sum(g.end - g.start + 1 for g in gaps)
        self.assertEqual((1 << 32) - (1 << 24), total)

    def test_multiple_grants_produce_minimal_gap_set(self):
        granted = [
            rfc3779chain.Interval(10, 20),
            rfc3779chain.Interval(80, 90)]
        gaps = rfc3779chain._subtract_interval(
            rfc3779chain.Interval(0, 100), granted)
        self.assertEqual(
            [rfc3779chain.Interval(0, 9),
             rfc3779chain.Interval(21, 79),
             rfc3779chain.Interval(91, 100)],
            gaps)

    def test_duplicate_family_refused(self):
        blocks = rfc3779.IPAddrBlocks()
        blocks.append(cert_builder.ip_inherit_family(AFI_IPV4))
        blocks.append(cert_builder.ip_inherit_family(AFI_IPV4))
        extension = (
            rfc3779.id_pe_ipAddrBlocks,
            der_encoder.encode(blocks), True)
        certificate = cert_builder.build_certificate(
            'dup', 55, [extension])
        with self.assertRaises(ResourceSyntaxError):
            rfc3779chain.parse_certificate_resources(certificate, 0)


class TrustSemanticsTestCase(unittest.TestCase):
    def test_parse_success_is_not_trust(self):
        holder = cert_builder.build_certificate('h', 60, [])
        report = rfc3779chain.check_resource_chain(
            [holder], TrustAnchorResources())
        self.assertTrue(report.parsed)
        self.assertTrue(report.resources_valid)
        with self.assertRaises(AttributeError):
            report.trusted

    def test_successful_containment_does_not_assert_trust(self):
        holder = cert_builder.build_certificate(
            'h', 61,
            [cert_builder.ip_extension(
                [cert_builder.ip_explicit_family(
                    AFI_IPV4,
                    [cert_builder.ip_prefix_entry(
                        bits32('10.0.0.0')[:8])])])])
        report = rfc3779chain.check_resource_chain(
            [holder], TrustAnchorResources(ipv4=['10.0.0.0/8']))
        self.assertTrue(report.resources_valid)
        self.assertFalse(hasattr(report, 'is_trusted'))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
