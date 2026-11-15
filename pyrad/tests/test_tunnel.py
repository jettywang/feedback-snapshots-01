import unittest

from io import StringIO

from pyrad import packet
from pyrad import tunnel
from pyrad.dictionary import Dictionary


TUNNEL_DICTIONARY = (
    'ATTRIBUTE Tunnel-Type 64 integer has_tag\n'
    'VALUE Tunnel-Type VLAN 13\n'
    'VALUE Tunnel-Type L2TP 3\n'
    'ATTRIBUTE Tunnel-Medium-Type 65 integer has_tag\n'
    'VALUE Tunnel-Medium-Type IEEE-802 6\n'
    'VALUE Tunnel-Medium-Type IPv4 1\n'
    'ATTRIBUTE Tunnel-Private-Group-ID 81 string has_tag\n'
)


def tunnel_dictionary():
    return Dictionary(StringIO(TUNNEL_DICTIONARY))


class TunnelTestCase(unittest.TestCase):
    def setUp(self):
        self.dictionary = tunnel_dictionary()

    def make_reply(self, attributes=()):
        request = packet.AuthPacket(
            code=packet.AccessRequest, secret=b'secret',
            authenticator=b'0123456789ABCDEF', dict=self.dictionary)
        reply = request.CreateReply()
        for name, value in attributes:
            reply.AddAttribute(name, value)
        raw = reply.ReplyPacket()
        decoded = packet.AuthPacket(packet=raw, secret=b'secret',
                                    dict=self.dictionary)
        decoded.request_authenticator = request.authenticator
        return decoded


class AssemblyTests(TunnelTestCase):
    def testTwoIncompleteCandidatesAreNotCombined(self):
        # Candidate 1 has the type and medium, candidate 2 the private
        # group ID.  Together they would look like VLAN 100, which neither
        # candidate authorizes.
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '100'),
            ('Tunnel-Type:2', 'L2TP'),
        ])
        assembly = tunnel.assemble_tunnel_candidates(reply)

        self.assertEqual([candidate.tag for candidate in assembly.candidates],
                         [1, 2])
        first = assembly.candidate(1)
        second = assembly.candidate(2)
        self.assertFalse(first.complete)
        self.assertFalse(second.complete)
        self.assertIsNone(first.private_group_id)
        self.assertIsNone(second.medium_type)
        self.assertFalse(any(candidate.complete
                             for candidate in assembly.candidates))

    def testTwoGroupsOnlyLegalWhenMergedAreRejected(self):
        # Group 1: Tunnel-Type + Tunnel-Medium-Type, no group ID.
        # Group 2: Tunnel-Private-Group-ID only.
        # Merged they would be VLAN 100; separately neither authorizes it.
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '100'),
        ])
        adapter = tunnel.TunnelApplicationAdapter(
            tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        with self.assertRaises(tunnel.TunnelAuthorizationError) as raised:
            adapter.apply(reply)

        result = adapter.validate(reply)
        self.assertEqual(result.approved, ())
        self.assertIsNone(result.assignment)
        codes = {diagnostic.code
                 for diagnostic in raised.exception.diagnostics}
        self.assertIn('missing_tunnel_attribute', codes)
        self.assertIn('no_approved_tunnel_candidate', codes)
        # Each candidate contains only fields of its own tag.
        for candidate in result.candidates:
            for field in (candidate.tunnel_type, candidate.medium_type,
                          candidate.private_group_id):
                if field is not None:
                    self.assertEqual(field.tag, candidate.tag)

    def testIncompleteCandidatesAreNotApproved(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '100'),
        ])
        policy = tunnel.TunnelPolicy(allowed_vlans=range(1, 4095))
        result = tunnel.validate_tunnel_candidates(reply, policy)

        self.assertIsNone(result.assignment)
        self.assertEqual(result.approved, ())
        codes = {diagnostic.code for candidate in result.candidates
                 for diagnostic in candidate.diagnostics}
        self.assertIn('missing_tunnel_attribute', codes)

    def testCompleteUntaggedCandidate(self):
        # No tags: the integer attributes use tag 0 and the string value
        # starts with 'v' (0x76), so it has no tag.  All three belong to
        # the same untagged candidate.
        reply = self.make_reply([
            ('Tunnel-Type', 'VLAN'),
            ('Tunnel-Medium-Type', 'IEEE-802'),
            ('Tunnel-Private-Group-ID', '100'),
        ])
        assembly = tunnel.assemble_tunnel_candidates(reply)

        self.assertEqual(len(assembly.candidates), 1)
        candidate = assembly.candidates[0]
        self.assertEqual(candidate.tag, 0)
        self.assertTrue(candidate.complete)
        self.assertEqual(candidate.tunnel_type.source, 'Tunnel-Type:0')
        self.assertEqual(candidate.private_group_id.source,
                         'Tunnel-Private-Group-ID')
        self.assertFalse(candidate.private_group_id.tag_present)

    def testExplicitTagZeroAndUntaggedShareCandidate(self):
        reply = self.make_reply([
            ('Tunnel-Type:0', 'VLAN'),
            ('Tunnel-Medium-Type', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:0', '100'),
        ])
        assembly = tunnel.assemble_tunnel_candidates(reply)

        self.assertEqual(len(assembly.candidates), 1)
        self.assertTrue(assembly.candidates[0].complete)
        self.assertEqual(assembly.candidates[0].private_group_id.source,
                         'Tunnel-Private-Group-ID:0')

    def testStringValueStartingWithTagOctet(self):
        # RFC 2868 section 3.6: a leading octet above 0x1F is part of the
        # value of Tunnel-Private-Group-ID, not a tag.
        reply = self.make_reply([
            ('Tunnel-Type:3', 'VLAN'),
            ('Tunnel-Medium-Type:3', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:3', ' 100'),
        ])
        candidate = tunnel.assemble_tunnel_candidates(reply).candidate(3)

        self.assertEqual(candidate.private_group_id.tag, 3)
        self.assertEqual(candidate.private_group_id.value, ' 100')

    def testDifferentTagsAreAlternatives(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
            ('Tunnel-Type:2', 'L2TP'),
            ('Tunnel-Medium-Type:2', 'IPv4'),
            ('Tunnel-Private-Group-ID:2', '200'),
        ])
        assembly = tunnel.assemble_tunnel_candidates(reply)

        self.assertEqual([candidate.tag for candidate in assembly.candidates],
                         [1, 2])
        self.assertEqual(assembly.candidate(1).private_group_id.value, '100')
        self.assertEqual(assembly.candidate(2).private_group_id.value, '200')
        self.assertTrue(all(candidate.complete
                            for candidate in assembly.candidates))

    def testDuplicateValueIsReported(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
        ])
        assembly = tunnel.assemble_tunnel_candidates(reply)
        candidate = assembly.candidate(1)

        self.assertTrue(candidate.complete)
        codes = [diagnostic.code for diagnostic in candidate.diagnostics]
        self.assertIn('duplicate_tunnel_attribute', codes)
        self.assertNotIn('conflicting_tunnel_values', codes)
        self.assertFalse(candidate.valid)

    def testConflictingValuesAreReported(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Type:1', 'L2TP'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
        ])
        candidate = tunnel.assemble_tunnel_candidates(reply).candidate(1)

        codes = [diagnostic.code for diagnostic in candidate.diagnostics]
        self.assertIn('duplicate_tunnel_attribute', codes)
        self.assertIn('conflicting_tunnel_values', codes)
        # The first value is kept for diagnostics, but the candidate is
        # never valid.
        self.assertEqual(candidate.tunnel_type.value,
                         tunnel.TUNNEL_TYPE_VLAN)
        self.assertFalse(candidate.valid)

    def testMalformedIntegerIsKeptAsDiagnostic(self):
        pkt = packet.AuthPacket(dict=self.dictionary)
        pkt[64] = [b'\x01\x00\x00']  # three octets, not tag plus integer
        assembly = tunnel.assemble_tunnel_candidates(pkt)

        self.assertEqual(assembly.candidates, ())
        self.assertEqual(assembly.diagnostics[0].code,
                         'malformed_tunnel_attribute')

    def testInvalidIntegerTagIsRejected(self):
        pkt = packet.AuthPacket(dict=self.dictionary)
        pkt[64] = [b'\x20\x00\x00\x0d']  # tag 32 is not valid
        assembly = tunnel.assemble_tunnel_candidates(pkt)

        self.assertEqual(assembly.candidates, ())
        self.assertEqual(assembly.diagnostics[0].code, 'invalid_tunnel_tag')


class PolicyTests(TunnelTestCase):
    def setUp(self):
        super().setUp()
        self.reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
        ])

    def validate(self, allowed_vlans=range(100, 201), **kwargs):
        policy = tunnel.TunnelPolicy(allowed_vlans=allowed_vlans, **kwargs)
        return tunnel.validate_tunnel_candidates(self.reply, policy)

    def testVlanInRangeIsApprovedWithSources(self):
        result = self.validate()

        self.assertIsNotNone(result.assignment)
        assignment = result.assignment
        self.assertEqual(assignment.vlan_id, 100)
        self.assertEqual(assignment.sources, {
            'Tunnel-Type': 'Tunnel-Type:1',
            'Tunnel-Medium-Type': 'Tunnel-Medium-Type:1',
            'Tunnel-Private-Group-ID': 'Tunnel-Private-Group-ID:1',
        })

    def testVlanOutsideLocalRangeIsRejected(self):
        # Authenticated packet does not make arbitrary VLANs configurable.
        result = self.validate(allowed_vlans=range(200, 301))

        self.assertIsNone(result.assignment)
        self.assertEqual(result.approved, ())
        codes = {diagnostic.code for candidate in result.candidates
                 for diagnostic in candidate.diagnostics}
        self.assertIn('vlan_not_allowed', codes)

    def testEmptyAllowedRangeDeniesVlan(self):
        result = self.validate(allowed_vlans=())

        self.assertIsNone(result.assignment)
        self.assertIn('vlan_not_allowed', {
            diagnostic.code for candidate in result.candidates
            for diagnostic in candidate.diagnostics})

    def testVlanIdMustBeDecimal(self):
        for value in ('0x64', 'vlan100', '100 ', '+100', '4095'):
            reply = self.make_reply([
                ('Tunnel-Type:1', 'VLAN'),
                ('Tunnel-Medium-Type:1', 'IEEE-802'),
                ('Tunnel-Private-Group-ID:1', value),
            ])
            result = tunnel.validate_tunnel_candidates(
                reply, tunnel.TunnelPolicy(allowed_vlans=range(1, 4095)))
            self.assertIsNone(result.assignment, value)

    def testUnsupportedTunnelTypeIsKeptAsDiagnostic(self):
        result = self.validate(allowed_tunnel_types=(13,))
        self.assertIsNotNone(result.assignment)

        reply = self.make_reply([
            ('Tunnel-Type:1', 'L2TP'),
            ('Tunnel-Medium-Type:1', 'IPv4'),
            ('Tunnel-Private-Group-ID:1', '100'),
        ])
        result = tunnel.validate_tunnel_candidates(
            reply, tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))
        self.assertIsNone(result.assignment)
        self.assertIn('unsupported_tunnel_type', {
            diagnostic.code for candidate in result.candidates
            for diagnostic in candidate.diagnostics})

    def testVlanRequiresIeee802Medium(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IPv4'),
            ('Tunnel-Private-Group-ID:1', '100'),
        ])
        result = tunnel.validate_tunnel_candidates(
            reply, tunnel.TunnelPolicy(
                allowed_vlans=range(100, 201),
                allowed_medium_types=(1, 6)))
        self.assertIsNone(result.assignment)
        self.assertIn('incompatible_tunnel_medium', {
            diagnostic.code for candidate in result.candidates
            for diagnostic in candidate.diagnostics})

    def testTwoApprovedCandidatesAreAmbiguous(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
            ('Tunnel-Type:2', 'VLAN'),
            ('Tunnel-Medium-Type:2', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '200'),
        ])
        result = tunnel.validate_tunnel_candidates(
            reply, tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        self.assertEqual(len(result.approved), 2)
        self.assertIsNone(result.assignment)
        self.assertIn('ambiguous_tunnel_candidates',
                      {diagnostic.code for diagnostic in result.diagnostics})

    def testExplicitTagSelectsOneCandidate(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
            ('Tunnel-Type:2', 'VLAN'),
            ('Tunnel-Medium-Type:2', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '200'),
        ])
        result = tunnel.validate_tunnel_candidates(
            reply, tunnel.TunnelPolicy(allowed_vlans=range(100, 201),
                                       selected_tag=2))

        self.assertEqual(result.assignment.tag, 2)
        self.assertEqual(result.assignment.vlan_id, 200)
        self.assertEqual(result.assignment.sources['Tunnel-Type'],
                         'Tunnel-Type:2')

    def testMissingCandidateDoesNotBorrowFromAnother(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '100'),
        ])
        result = tunnel.validate_tunnel_candidates(
            reply, tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        self.assertEqual(result.approved, ())
        self.assertIsNone(result.assignment)
        # No approved assignment can claim a value from tag 2 while the
        # other fields came from tag 1.
        for candidate in result.candidates:
            for field in (candidate.tunnel_type, candidate.medium_type,
                          candidate.private_group_id):
                if field is not None:
                    self.assertEqual(field.tag, candidate.tag)
            self.assertFalse(candidate.complete)


class AdapterTests(TunnelTestCase):
    def testAdapterReturnsSingleAssignment(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
        ])
        adapter = tunnel.TunnelApplicationAdapter(
            tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))
        assignment = adapter.apply(reply)

        self.assertEqual(assignment.vlan_id, 100)
        self.assertEqual(assignment.sources, {
            'Tunnel-Type': 'Tunnel-Type:1',
            'Tunnel-Medium-Type': 'Tunnel-Medium-Type:1',
            'Tunnel-Private-Group-ID': 'Tunnel-Private-Group-ID:1',
        })

    def testAdapterRejectsIncompleteMergedCandidates(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '100'),
            ('Tunnel-Type:2', 'L2TP'),
        ])
        adapter = tunnel.TunnelApplicationAdapter(
            tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        with self.assertRaises(tunnel.TunnelAuthorizationError) as raised:
            adapter.apply(reply)
        codes = {diagnostic.code for diagnostic in raised.exception.diagnostics}
        self.assertIn('missing_tunnel_attribute', codes)
        # Nothing is borrowed from tag 2 to complete tag 1.
        self.assertIn('no_approved_tunnel_candidate', codes)

    def testAdapterRejectsVlanOutsideRange(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '300'),
        ])
        adapter = tunnel.TunnelApplicationAdapter(
            tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        with self.assertRaises(tunnel.TunnelAuthorizationError):
            adapter.apply(reply)

    def testAdapterRequiresPolicy(self):
        with self.assertRaises(TypeError):
            tunnel.TunnelApplicationAdapter(None)


class NormalMultiCandidateTests(TunnelTestCase):
    def testUntaggedAndTaggedCandidatesRemainSeparate(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
            ('Tunnel-Type', 'VLAN'),
            ('Tunnel-Medium-Type', 'IEEE-802'),
            ('Tunnel-Private-Group-ID', '200'),
        ])
        assembly = tunnel.assemble_tunnel_candidates(reply)

        self.assertEqual([candidate.tag for candidate in assembly.candidates],
                         [0, 1])
        self.assertEqual(assembly.candidate(0).private_group_id.source,
                         'Tunnel-Private-Group-ID')
        self.assertEqual(assembly.candidate(1).private_group_id.source,
                         'Tunnel-Private-Group-ID:1')

    def testOneOfTwoVlanCandidatesIsInLocalRange(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
            ('Tunnel-Type:2', 'VLAN'),
            ('Tunnel-Medium-Type:2', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:2', '300'),
        ])
        adapter = tunnel.TunnelApplicationAdapter(
            tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))
        assignment = adapter.apply(reply)

        self.assertEqual(assignment.tag, 1)
        self.assertEqual(assignment.vlan_id, 100)
        self.assertEqual(set(assignment.sources),
                         {'Tunnel-Type', 'Tunnel-Medium-Type',
                          'Tunnel-Private-Group-ID'})

    def testMalformedOtherCandidateDoesNotBlockApproval(self):
        pkt = packet.AuthPacket(dict=self.dictionary)
        pkt[64] = [b'\x01\x00\x00\x0d', b'\x02\x00']
        pkt[65] = [b'\x01\x00\x00\x06']
        pkt[81] = [b'\x01100']
        result = tunnel.validate_tunnel_candidates(
            pkt, tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        # The malformed tag 2 value stays in the diagnostics, but does not
        # change the meaning of the complete tag 1 candidate.
        self.assertIn('malformed_tunnel_attribute',
                      {diagnostic.code for diagnostic in result.diagnostics})
        self.assertEqual(result.assignment.tag, 1)
        self.assertEqual(result.assignment.vlan_id, 100)

    def testNormalMultiCandidatePacketSelectsByTag(self):
        reply = self.make_reply([
            ('Tunnel-Type:1', 'VLAN'),
            ('Tunnel-Medium-Type:1', 'IEEE-802'),
            ('Tunnel-Private-Group-ID:1', '100'),
            ('Tunnel-Type:2', 'L2TP'),
            ('Tunnel-Medium-Type:2', 'IPv4'),
            ('Tunnel-Private-Group-ID:2', '200'),
        ])
        result = tunnel.validate_tunnel_candidates(
            reply, tunnel.TunnelPolicy(allowed_vlans=range(100, 201)))

        self.assertEqual([candidate.tag for candidate in result.approved],
                         [1])
        self.assertEqual(result.assignment.tag, 1)
        self.assertEqual(result.assignment.vlan_id, 100)
        self.assertEqual(result.assignment.sources['Tunnel-Type'],
                         'Tunnel-Type:1')
        # The L2TP candidate keeps its policy diagnostic; it is not merged
        # into the approved VLAN candidate.
        second = [candidate for candidate in result.candidates
                  if candidate.tag == 2][0]
        self.assertIn('unsupported_tunnel_type', {
            diagnostic.code for diagnostic in second.diagnostics})


class PolicyValueTests(unittest.TestCase):
    def testSingleIntAllowedVlan(self):
        policy = tunnel.TunnelPolicy(allowed_vlans=100)
        self.assertIn(100, policy.allowed_vlans)
        self.assertNotIn(101, policy.allowed_vlans)

    def testNegativeVlanIsRejected(self):
        self.assertIsNone(tunnel._parse_vlan_id('-1'))
        self.assertIsNone(tunnel._parse_vlan_id(''))

    def testInvalidSelectedTag(self):
        with self.assertRaises(ValueError):
            tunnel.TunnelPolicy(selected_tag=32)


if __name__ == '__main__':
    unittest.main()
