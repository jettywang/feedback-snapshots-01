import struct
import unittest
import uuid

from uefi_firmware.secureboot import (
    EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    SecureBootVariable, SignatureList, parse_secure_boot_policy)


OWNER_A = uuid.UUID('aaaaaaaa-1111-2222-3333-444444444444').bytes_le
OWNER_B = uuid.UUID('bbbbbbbb-5555-6666-7777-888888888888').bytes_le
OWNER_C = uuid.UUID('cccccccc-9999-aaaa-bbbb-cccccccccccc').bytes_le

X509_GUID = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le
SHA256_GUID = uuid.UUID('c1c41626-504c-4092-aca9-41f936934328').bytes_le
X509_SHA256_GUID = uuid.UUID(
    '3bd2a492-96c0-4079-b420-fcf98ef103ed').bytes_le
UNKNOWN_GUID = uuid.UUID('12345678-1234-5678-9abc-def012345678').bytes_le

CERT_A = b'der-certificate-A' * 2
CERT_B = b'der-certificate-B' * 2
DIGEST_A = bytes(range(32))
UNKNOWN = b'opaque-signature-payload'
HASH_TYPE = uuid.UUID('c1c41626-504c-4092-aca9-41f936934328').bytes_le
REVOCATION_TIME = b'\x18\x0b\x11\x10\x00\x00\x00\x00' + b'\x00' * 8


def make_list(signature_type, owner_payloads, header=b''):
    signature_size = 16 + len(owner_payloads[0][1])
    body = b''.join(owner + payload for owner, payload in owner_payloads)
    size = 28 + len(header) + len(body)
    return signature_type + struct.pack(
        '<III', size, len(header), signature_size) + header + body


def make_variable(lists):
    return b''.join(lists)


class SignatureListTest(unittest.TestCase):

    def test_header_owner_and_certificate_payload_are_separate(self):
        data = make_list(X509_GUID, [(OWNER_A, CERT_A), (OWNER_B, CERT_B)],
                         header=b'list-header')
        signature_list = SignatureList(data)
        self.assertTrue(signature_list.valid)
        self.assertEqual(signature_list.signature_type_guid,
                         'a5c059a1-94e4-4aa7-87b5-ab155c2bf072')
        self.assertEqual(signature_list.kind, 'certificate')
        self.assertEqual(signature_list.signature_list_size, len(data))
        self.assertEqual(signature_list.signature_header_size, 11)
        self.assertEqual(signature_list.signature_header, b'list-header')
        self.assertEqual(signature_list.signature_size, 16 + len(CERT_A))
        self.assertEqual(len(signature_list.entries), 2)
        self.assertEqual(signature_list.entries[0].owner_guid,
                         'aaaaaaaa-1111-2222-3333-444444444444')
        self.assertEqual(signature_list.entries[0].payload, CERT_A)

        entry = signature_list.entries[0].to_dict()
        self.assertEqual(entry['kind'], 'certificate')
        self.assertEqual(entry['certificate'], CERT_A.hex())
        self.assertNotIn('digest', entry)
        self.assertNotIn('publicKey', entry)

    def test_image_digest_is_not_a_certificate_field(self):
        data = make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)])
        entry = SignatureList(data).entries[0].to_dict()
        self.assertEqual(entry['kind'], 'image_digest')
        self.assertEqual(entry['digest'], DIGEST_A.hex())
        self.assertEqual(entry['digestAlgorithm'], 'sha256')
        self.assertNotIn('certificate', entry)

    def test_certificate_hash_has_its_own_fields(self):
        payload = HASH_TYPE + bytes(range(32)) + REVOCATION_TIME
        data = make_list(X509_SHA256_GUID, [(OWNER_A, payload)])
        signature_list = SignatureList(data)
        self.assertTrue(signature_list.valid)
        entry = signature_list.entries[0].to_dict()
        self.assertEqual(entry['kind'], 'certificate_digest')
        self.assertEqual(entry['certificateDigest'], bytes(range(32)).hex())
        self.assertEqual(entry['hashType'],
                         'c1c41626-504c-4092-aca9-41f936934328')
        self.assertEqual(entry['revocationTime'], REVOCATION_TIME.hex())
        self.assertNotIn('digest', entry)
        self.assertNotIn('certificate', entry)

    def test_unknown_payload_is_kept_as_opaque(self):
        data = make_list(UNKNOWN_GUID, [(OWNER_C, UNKNOWN)])
        signature_list = SignatureList(data)
        self.assertTrue(signature_list.valid)
        self.assertTrue(signature_list.unknown_type)
        entry = signature_list.entries[0].to_dict()
        self.assertEqual(entry['kind'], 'unknown')
        self.assertEqual(entry['payload'], UNKNOWN.hex())
        self.assertNotIn('digest', entry)
        self.assertNotIn('certificate', entry)

    def test_signature_size_must_include_the_owner(self):
        data = X509_GUID + struct.pack('<III', 28, 0, 8)
        signature_list = SignatureList(data)
        self.assertFalse(signature_list.valid)
        self.assertIn('SignatureSize', signature_list.errors[0])
        self.assertEqual(signature_list.entries, [])

    def test_fixed_size_type_rejects_a_short_payload(self):
        data = make_list(SHA256_GUID, [(OWNER_A, b'short-digest')])
        signature_list = SignatureList(data)
        self.assertFalse(signature_list.valid)
        self.assertIn('expects 32', signature_list.errors[0])
        self.assertEqual(len(signature_list.entries), 1)

    def test_list_size_must_hold_the_declared_entries(self):
        data = make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)])
        data = data[:16] + struct.pack('<III', len(data) + 1, 0, 48) + \
            data[28:]
        variable = SecureBootVariable(data, name='db')
        self.assertFalse(variable.valid)
        self.assertIn('extends past', variable.errors[0])
        # The complete entry that was present is still exposed.
        self.assertEqual(len(variable.entries), 1)

    def test_remainder_is_reported_and_not_dropped(self):
        data = make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)])
        data = data[:16] + struct.pack('<III', len(data) + 3, 0, 48) + \
            data[28:] + b'xyz'
        variable = SecureBootVariable(data, name='db')
        self.assertFalse(variable.valid)
        self.assertEqual(variable.signature_lists[0].trailing_data, b'xyz')


class ShortPolicyTest(unittest.TestCase):
    '''The short-list scenario: several owners, an unknown type and a
    declared allow/revoke overlap.'''

    def setUp(self):
        self.db = make_variable([
            make_list(X509_GUID, [(OWNER_A, CERT_A), (OWNER_A, CERT_B)]),
            make_list(SHA256_GUID, [(OWNER_B, DIGEST_A), (OWNER_B, DIGEST_A)]),
            make_list(UNKNOWN_GUID, [(OWNER_C, UNKNOWN)]),
        ])
        self.dbx = make_variable([
            make_list(SHA256_GUID, [(OWNER_C, DIGEST_A)]),
        ])
        self.policy = parse_secure_boot_policy(
            db=self.db, dbx=self.dbx,
            attributes={
                'db': EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                'dbx': EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
            })

    def test_every_entry_is_retained(self):
        view = self.policy.to_dict()
        self.assertEqual(view['allow']['entryCount'], 5)
        self.assertEqual(view['revoke']['entryCount'], 1)
        self.assertEqual(len(self.policy.entries), 6)

    def test_same_owner_can_have_several_entries(self):
        owners = [
            owner for owner in self.policy.to_dict()['owners']
            if owner['role'] == 'db' and owner['owner'].startswith('aaaaaaaa')
        ]
        self.assertEqual(len(owners), 1)
        self.assertEqual(owners[0]['entryCount'], 2)
        self.assertEqual(owners[0]['kinds'], ['certificate'])

    def test_duplicate_entries_are_reported_not_collapsed(self):
        duplicates = self.policy.to_dict()['duplicates']
        hashes = [
            duplicate for duplicate in duplicates
            if duplicate['kind'] == 'image_digest']
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]['count'], 2)
        self.assertEqual(len(hashes[0]['entries']), 2)
        # Both occurrences are also still present in the detailed allow view.
        detailed = self.policy.to_dict()['allow']['detailedEntries']
        self.assertEqual(len([
            entry for entry in detailed
            if entry['signatureTypeName'] == 'EFI_CERT_SHA256_GUID'
        ]), 2)

    def test_duplicate_identity_ignores_the_owner(self):
        db = make_variable([
            make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)]),
            make_list(SHA256_GUID, [(OWNER_B, DIGEST_A)]),
        ])
        view = parse_secure_boot_policy(db=db).to_dict()
        duplicate = view['duplicates'][0]
        self.assertEqual(duplicate['count'], 2)
        self.assertEqual(duplicate['owners'], [
            'aaaaaaaa-1111-2222-3333-444444444444',
            'bbbbbbbb-5555-6666-7777-888888888888',
        ])
        self.assertEqual(duplicate['signature']['digest'], DIGEST_A.hex())

    def test_unknown_type_is_grouped_and_kept(self):
        view = self.policy.to_dict()
        unknown = view['unknownTypes']
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]['signatureType'],
                         '12345678-1234-5678-9abc-def012345678')
        self.assertEqual(unknown[0]['count'], 1)
        self.assertEqual(unknown[0]['entries'][0]['kind'], 'unknown')

    def test_conflict_keeps_both_sides_and_is_not_a_boot_verdict(self):
        view = self.policy.to_dict()
        self.assertEqual(len(view['conflicts']), 1)
        conflict = view['conflicts'][0]
        self.assertEqual(conflict['signatureTypeName'],
                         'EFI_CERT_SHA256_GUID')
        self.assertEqual(conflict['allowCount'], 2)
        self.assertEqual(conflict['revokeCount'], 1)
        self.assertEqual(
            [entry['role'] for entry in conflict['allowEntries']],
            ['db', 'db'])
        self.assertEqual(conflict['revokeEntries'][0]['role'], 'dbx')
        self.assertEqual(conflict['signature']['digest'], DIGEST_A.hex())
        self.assertEqual(view['assessment']['secureBootBootDecision'],
                         'not-determined')
        self.assertFalse(view['assessment']['peImageEvaluated'])
        self.assertEqual(view['assessment']['signatureVerification'],
                         'not-performed')

    def test_authenticated_write_attributes_are_evidence_only(self):
        view = self.policy.to_dict()
        variables = {
            variable['name']: variable
            for variable in view['variables']}
        self.assertTrue(
            variables['db']['timeBasedAuthenticatedWrite'])
        self.assertTrue(variables['dbx']['authenticatedWriteAttribute'])
        self.assertFalse(variables['db']['sourceProvenanceVerified'])
        self.assertIn('does not establish',
                      ' '.join(view['limitations']))
        self.assertEqual(view['assessment']['sourceProvenanceVerification'],
                         'not-performed')

    def test_roles_keep_separate_meaning_and_counts(self):
        declared = self.policy.to_dict()['declaredPolicy']
        self.assertFalse(declared['PK']['supplied'])
        self.assertFalse(declared['KEK']['supplied'])
        self.assertEqual(declared['db']['certificateEntries'], 2)
        self.assertEqual(declared['db']['imageDigestEntries'], 2)
        self.assertEqual(declared['db']['unknownEntries'], 1)
        self.assertEqual(declared['dbx']['imageDigestEntries'], 1)


class VariableIdentityTest(unittest.TestCase):

    def test_caller_supplied_name_and_guid_are_reported(self):
        data = make_variable([make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)])])
        variable = SecureBootVariable(
            data, name=b'db',
            guid=uuid.UUID('d719b2cb-3d3a-4596-a3bc-dad00e67656f'))
        view = variable.to_dict()
        self.assertEqual(view['name'], 'db')
        self.assertEqual(view['role'], 'db')
        self.assertEqual(view['guid'],
                         'd719b2cb-3d3a-4596-a3bc-dad00e67656f')

    def test_non_role_name_is_not_assigned_a_policy_role(self):
        data = make_variable([make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)])])
        variable = SecureBootVariable(data, name='CustomDatabase')
        self.assertIsNone(variable.role)

    def test_empty_variable_is_empty_not_an_error(self):
        variable = SecureBootVariable(b'', name='db')
        self.assertTrue(variable.valid)
        self.assertEqual(variable.entries, [])

    def test_short_list_header_is_reported(self):
        variable = SecureBootVariable(X509_GUID + b'\x00' * 4, name='PK')
        self.assertFalse(variable.valid)
        self.assertIn('truncated', variable.errors[0])
        self.assertEqual(variable.unparsed_data,
                         X509_GUID + b'\x00' * 4)

    def test_nvar_authenticated_flag_is_one_byte(self):
        data = make_variable([make_list(SHA256_GUID, [(OWNER_A, DIGEST_A)])])
        variable = SecureBootVariable(data, name='db', attributes=b'\x40')
        self.assertTrue(variable.nvar_attributes)
        self.assertTrue(variable.authenticated_write)
        self.assertTrue(variable.authenticated_write_attribute)
        self.assertFalse(variable.time_based_authenticated_write)


if __name__ == '__main__':
    unittest.main()
