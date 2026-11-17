'''Read-only views of UEFI Secure Boot signature databases.

The caller supplies the bytes of an already-extracted variable (PK, KEK, db
or dbx), together with the variable's identity.  This module describes the
signature lists it finds; it does not authenticate the variable, verify a
certificate, or decide whether a PE image may boot.

The wire format is a sequence of EFI_SIGNATURE_LIST structures:

    EFI_GUID SignatureType;
    UINT32   SignatureListSize;
    UINT32   SignatureHeaderSize;
    UINT32   SignatureSize;

followed by SignatureHeaderSize bytes of list header and then one or more
EFI_SIGNATURE_DATA entries:

    EFI_GUID SignatureOwner;
    UINT8    SignatureData[SignatureSize - 16];

SignatureSize includes the owner GUID.  Keeping the owner separate from the
signature payload matters: an owner identifies who supplied an entry, not
which certificate or image digest the entry contains.
'''

import struct
import uuid

from .utils import sguid

__all__ = [
    'EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS',
    'EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS',
    'GLOBAL_VARIABLE_GUID',
    'IMAGE_SECURITY_DATABASE_GUID',
    'SECURE_BOOT_ROLES',
    'SIGNATURE_TYPES',
    'SignatureEntry',
    'SignatureList',
    'SecureBootVariable',
    'SecureBootPolicy',
    'parse_signature_list',
    'parse_signature_database',
    'parse_secure_boot_variable',
    'parse_secure_boot_policy',
]

# EFI_VARIABLE_ATTRIBUTES, as stored in an authenticated variable header.
EFI_VARIABLE_NON_VOLATILE = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004
EFI_VARIABLE_HARDWARE_ERROR_RECORD = 0x00000008
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020
EFI_VARIABLE_APPEND_WRITE = 0x00000040

# The obsolete EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS bit is 0x10.  NVAR
# stores the same attribute in one byte (NVRAM_ATTRIBUTES["AUTHWD"] == 0x40),
# which is why the value is accepted from either representation below.

GLOBAL_VARIABLE_GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
IMAGE_SECURITY_DATABASE_GUID = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'

SECURE_BOOT_ROLES = {
    'PK': {
        'name': 'PK',
        'meaning': 'Platform Key: the enrollment trust anchor.',
    },
    'KEK': {
        'name': 'KEK',
        'meaning': 'Key Exchange Key: keys authorized by declared policy '
                   'to update the signature databases.',
    },
    'db': {
        'name': 'db',
        'meaning': 'Authorized signature database (allow entries).',
    },
    'dbx': {
        'name': 'dbx',
        'meaning': 'Forbidden signature database (revoke entries).',
    },
}

# SignatureType GUIDs from the UEFI specification.  "kind" is deliberately
# coarse and explicit so a caller can keep certificates, image digests and
# unrecognized payloads apart instead of reducing every entry to one hash.
SIGNATURE_TYPES = {
    # Certificates.
    'a5c059a1-94e4-4aa7-87b5-ab155c2bf072': {
        'name': 'EFI_CERT_X509_GUID',
        'kind': 'certificate',
        'certificate_format': 'x509',
    },
    '4aafd29d-68df-49ee-8aa9-347d375665a7': {
        'name': 'EFI_CERT_TYPE_PKCS7_GUID',
        'kind': 'signed_data',
        'signed_data_format': 'pkcs7',
    },
    # X.509 certificate hashes.  These are not image digests and carry a
    # hash-type GUID and a revocation time in the signature payload.
    '3bd2a492-96c0-4079-b420-fcf98ef103ed': {
        'name': 'EFI_CERT_X509_SHA256_GUID',
        'kind': 'certificate_digest',
        'digest_algorithm': 'sha256',
        'digest_size': 32,
        'digest_offset': 16,
        'revocation_time_size': 16,
    },
    '7076876e-80c2-4ee6-aad2-28b349a6865b': {
        'name': 'EFI_CERT_X509_SHA384_GUID',
        'kind': 'certificate_digest',
        'digest_algorithm': 'sha384',
        'digest_size': 48,
        'digest_offset': 16,
        'revocation_time_size': 16,
    },
    '446dbf63-2502-4cda-bcfa-2465d2b0fe9d': {
        'name': 'EFI_CERT_X509_SHA512_GUID',
        'kind': 'certificate_digest',
        'digest_algorithm': 'sha512',
        'digest_size': 64,
        'digest_offset': 16,
        'revocation_time_size': 16,
    },
    # Image digests.  The payload itself is the digest.
    '826ca512-cf10-4ac9-b187-be01496631bd': {
        'name': 'EFI_CERT_SHA1_GUID',
        'kind': 'image_digest',
        'digest_algorithm': 'sha1',
        'digest_size': 20,
    },
    '0b6e5233-a65c-44c9-9407-d9ab83bfc8bd': {
        'name': 'EFI_CERT_SHA224_GUID',
        'kind': 'image_digest',
        'digest_algorithm': 'sha224',
        'digest_size': 28,
    },
    'c1c41626-504c-4092-aca9-41f936934328': {
        'name': 'EFI_CERT_SHA256_GUID',
        'kind': 'image_digest',
        'digest_algorithm': 'sha256',
        'digest_size': 32,
    },
    'ff3e5307-9fd0-48c9-85f1-8ad56c701e01': {
        'name': 'EFI_CERT_SHA384_GUID',
        'kind': 'image_digest',
        'digest_algorithm': 'sha384',
        'digest_size': 48,
    },
    '093e0fae-a6c4-4f50-9f1b-d41e2b89c19a': {
        'name': 'EFI_CERT_SHA512_GUID',
        'kind': 'image_digest',
        'digest_algorithm': 'sha512',
        'digest_size': 64,
    },
    # Public-key payloads.  They are not DER certificates and are not
    # image hashes; represent them as their own kind.
    '3c5766e8-269c-4e34-aa14-ed776e85b3b6': {
        'name': 'EFI_CERT_RSA2048_GUID',
        'kind': 'public_key',
        'key_algorithm': 'rsa2048',
    },
    '67f8444f-8743-48f1-a328-1eaab8736080': {
        'name': 'EFI_CERT_RSA2048_SHA1_GUID',
        'kind': 'signed_public_key',
        'key_algorithm': 'rsa2048-sha1',
    },
    'e2b36190-879b-4a3d-ad8d-f2e7bba32784': {
        'name': 'EFI_CERT_RSA2048_SHA256_GUID',
        'kind': 'signed_public_key',
        'key_algorithm': 'rsa2048-sha256',
    },
    'a7717414-c616-4977-9420-844712a735bf': {
        'name': 'EFI_CERT_TYPE_RSA2048_SHA256_GUID',
        'kind': 'signed_public_key',
        'key_algorithm': 'rsa2048-sha256',
    },
}

_UNKNOWN_TYPE = {
    'name': None,
    'kind': 'unknown',
}


def _as_bytes(value):
    if value is None:
        return b''
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, bytes):
        return value
    raise TypeError('expected bytes, got %s' % type(value).__name__)


def _decode_name(name):
    if name is None:
        return None
    if isinstance(name, bytes):
        # UEFI variable names are UTF-16LE.  An ASCII/UTF-8 byte string is
        # accepted too because callers often have the name from a CLI.
        if b'\x00' in name:
            try:
                return name.decode('utf-16le')
            except UnicodeDecodeError:
                pass
        try:
            return name.decode('utf-8')
        except UnicodeDecodeError:
            return name.decode('utf-16le', 'replace')
    return str(name)


def _guid_string(value):
    '''Return a lowercase RFC4122 string for a GUID in bytes or text.'''
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = _as_bytes(value)
        if len(value) != 16:
            return value.hex()
        return sguid(value)
    try:
        return str(uuid.UUID(str(value))).lower()
    except (ValueError, AttributeError, TypeError):
        return str(value).lower()


class SignatureEntry(object):
    '''One EFI_SIGNATURE_DATA entry, typed by its SignatureType GUID.'''

    def __init__(self, owner, signature_type, payload, role=None,
                 list_index=0, index=0, offset=0):
        self.owner = _as_bytes(owner)
        self.signature_type = _as_bytes(signature_type)
        self.payload = _as_bytes(payload)
        self.role = role
        self.list_index = list_index
        self.index = index
        self.offset = offset
        self._type = SIGNATURE_TYPES.get(
            _guid_string(self.signature_type), _UNKNOWN_TYPE)

    @property
    def owner_guid(self):
        return _guid_string(self.owner)

    @property
    def signature_type_guid(self):
        return _guid_string(self.signature_type)

    @property
    def signature_type_name(self):
        return self._type.get('name')

    @property
    def kind(self):
        return self._type.get('kind', 'unknown')

    @property
    def unknown_type(self):
        return self.kind == 'unknown'

    @property
    def expected_payload_size(self):
        # Public-key payload layouts differ between RSA2048 variants, so
        # they are typed but not length-checked here.  Digest layouts are
        # fixed by their SignatureType GUIDs.
        if self.kind == 'image_digest':
            return self._type.get('digest_size')
        if self.kind == 'certificate_digest':
            return (self._type.get('digest_offset', 0) +
                    self._type.get('digest_size', 0) +
                    self._type.get('revocation_time_size', 0))
        return None

    @property
    def payload_size_valid(self):
        expected = self.expected_payload_size
        return expected is None or len(self.payload) == expected

    @property
    def signature_identity(self):
        '''The signature value, excluding its owner and variable role.'''
        return (self.signature_type, self.payload)

    @property
    def typed_payload(self):
        '''The payload rendered as its declared type, never as one hash.'''
        kind = self.kind
        if kind == 'image_digest':
            return {
                'digestAlgorithm': self._type.get('digest_algorithm'),
                'digest': self.payload.hex(),
            }
        if kind == 'certificate':
            return {
                'certificateFormat': self._type.get('certificate_format'),
                'certificate': self.payload.hex(),
            }
        if kind == 'signed_data':
            return {
                'signedDataFormat': self._type.get('signed_data_format'),
                'signedData': self.payload.hex(),
            }
        if kind == 'certificate_digest':
            offset = self._type.get('digest_offset', 0)
            size = self._type.get('digest_size', 0)
            digest = self.payload[offset:offset + size]
            time_start = offset + size
            time_end = time_start + self._type.get('revocation_time_size', 0)
            value = {
                'hashType': _guid_string(self.payload[:16]),
                'digestAlgorithm': self._type.get('digest_algorithm'),
                'certificateDigest': digest.hex(),
                'revocationTime': self.payload[time_start:time_end].hex(),
            }
            if len(digest) != size:
                value['certificateDigestTruncated'] = True
            return value
        if kind == 'public_key':
            return {
                'keyAlgorithm': self._type.get('key_algorithm'),
                'publicKey': self.payload.hex(),
            }
        if kind == 'signed_public_key':
            return {
                'keyAlgorithm': self._type.get('key_algorithm'),
                'signedPublicKey': self.payload.hex(),
            }
        return {
            'payload': self.payload.hex(),
        }

    def to_dict(self):
        value = {
            'index': self.index,
            'listIndex': self.list_index,
            'offset': self.offset,
            'owner': self.owner_guid,
            'signatureType': self.signature_type_guid,
            'signatureTypeName': self.signature_type_name,
            'kind': self.kind,
            'unknownType': self.unknown_type,
            'payloadSize': len(self.payload),
            'payloadSizeValid': self.payload_size_valid,
        }
        if self.role is not None:
            value['role'] = self.role
        value.update(self.typed_payload)
        return value


class SignatureList(object):
    '''A parsed EFI_SIGNATURE_LIST and all of its signature entries.

    A malformed list is kept, not discarded.  Complete entries are still
    exposed and every header or size problem is recorded in ``errors`` so a
    caller can explain why the bytes are not a trustworthy policy statement.
    '''

    HEADER_SIZE = 28
    OWNER_SIZE = 16

    def __init__(self, data, index=0, role=None, offset=0):
        self.data = _as_bytes(data)
        self.index = index
        self.role = role
        self.offset = offset
        self.signature_type = b''
        self.signature_type_guid = None
        self.signature_type_name = None
        self.signature_list_size = 0
        self.signature_header_size = 0
        self.signature_size = 0
        self.signature_header = b''
        self.trailing_data = b''
        self.remaining_data = b''
        self.entries = []
        self.errors = []
        self.process()

    @property
    def type_info(self):
        return SIGNATURE_TYPES.get(self.signature_type_guid, _UNKNOWN_TYPE)

    @property
    def kind(self):
        return self.type_info.get('kind', 'unknown')

    @property
    def unknown_type(self):
        return self.kind == 'unknown'

    @property
    def valid(self):
        return not self.errors

    def process(self):
        self.signature_type = b''
        self.signature_type_guid = None
        self.signature_type_name = None
        self.signature_list_size = 0
        self.signature_header_size = 0
        self.signature_size = 0
        self.signature_header = b''
        self.trailing_data = b''
        self.remaining_data = b''
        self.entries = []
        self.errors = []

        if len(self.data) < self.HEADER_SIZE:
            self.errors.append(
                'signature list header is truncated: %d of %d bytes' % (
                    len(self.data), self.HEADER_SIZE))
            return False

        self.signature_type = self.data[0:16]
        self.signature_type_guid = _guid_string(self.signature_type)
        self.signature_type_name = self.type_info.get('name')
        (self.signature_list_size,
         self.signature_header_size,
         self.signature_size) = struct.unpack(
             '<III', self.data[16:self.HEADER_SIZE])

        if self.signature_list_size < self.HEADER_SIZE:
            self.errors.append(
                'SignatureListSize %d is smaller than the %d-byte header' % (
                    self.signature_list_size, self.HEADER_SIZE))
            return False

        if self.signature_list_size > len(self.data):
            self.errors.append(
                'SignatureListSize %d extends past the %d bytes supplied' % (
                    self.signature_list_size, len(self.data)))
            usable = len(self.data)
        else:
            usable = self.signature_list_size

        if self.signature_size < self.OWNER_SIZE:
            self.errors.append(
                'SignatureSize %d is smaller than the 16-byte owner GUID' % (
                    self.signature_size))
            return False

        header_end = self.HEADER_SIZE + self.signature_header_size
        if header_end > usable:
            self.errors.append(
                'SignatureHeaderSize %d does not fit in '
                'SignatureListSize %d' % (
                    self.signature_header_size, self.signature_list_size))
            return False
        self.signature_header = self.data[self.HEADER_SIZE:header_end]

        body = self.data[header_end:usable]
        count, remainder = divmod(len(body), self.signature_size)
        if remainder:
            self.errors.append(
                'signature data is %d bytes, not a multiple of SignatureSize '
                '%d' % (len(body), self.signature_size))

        for entry_index in range(count):
            start = header_end + entry_index * self.signature_size
            entry_data = self.data[start:start + self.signature_size]
            owner = entry_data[:self.OWNER_SIZE]
            payload = entry_data[self.OWNER_SIZE:]
            entry = SignatureEntry(
                owner, self.signature_type, payload, role=self.role,
                list_index=self.index, index=entry_index,
                offset=self.offset + start)
            self.entries.append(entry)
            if not entry.payload_size_valid:
                self.errors.append(
                    'entry %d has %d payload bytes; %s expects %d' % (
                        entry_index, len(payload),
                        self.signature_type_name or self.signature_type_guid,
                        entry.expected_payload_size))

        if remainder:
            trailing_start = header_end + count * self.signature_size
            self.trailing_data = self.data[
                trailing_start:usable]
        if self.signature_list_size < len(self.data):
            # Bytes beyond the declared list are left for the caller's
            # next-list parsing loop.  They are not part of this list and
            # do not make it malformed: a caller may pass a whole variable.
            self.remaining_data = self.data[self.signature_list_size:]

        return self.valid

    def to_dict(self):
        return {
            'index': self.index,
            'offset': self.offset,
            'role': self.role,
            'signatureType': self.signature_type_guid,
            'signatureTypeName': self.signature_type_name,
            'kind': self.kind,
            'unknownType': self.unknown_type,
            'signatureListSize': self.signature_list_size,
            'signatureHeaderSize': self.signature_header_size,
            'signatureSize': self.signature_size,
            'signatureHeader': self.signature_header.hex(),
            'entryCount': len(self.entries),
            'entries': [entry.to_dict() for entry in self.entries],
            'trailingData': self.trailing_data.hex(),
            'remainingData': self.remaining_data.hex(),
            'errors': list(self.errors),
            'valid': self.valid,
        }


class SecureBootVariable(object):
    '''The signature-list content of one supplied variable.

    ``name`` and ``guid`` are the caller's identity for the extracted bytes.
    The view is read-only: it never writes to flash, never recalculates an
    authenticated variable header, and never treats the authenticated-write
    attribute as proof of where the bytes came from.
    '''

    def __init__(self, data, name=None, guid=None, attributes=None):
        self.data = _as_bytes(data)
        self.name = _decode_name(name)
        self.role = self._role_for(self.name)
        self.guid = _guid_string(guid)
        raw_attributes = attributes
        self.attributes = self._attributes(attributes)
        # A one-byte attribute is the NVAR representation, where bit 0x40
        # is that store's AUTHWD flag; the EFI attribute words are wider.
        self.nvar_attributes = bool(
            isinstance(raw_attributes,
                       (bytes, bytearray, memoryview)) and
            len(_as_bytes(raw_attributes)) == 1)
        self.signature_lists = []
        self.errors = []
        self.unparsed_data = b''
        self.process()

    @staticmethod
    def _role_for(name):
        if name is None:
            return None
        return {
            'pk': 'PK',
            'kek': 'KEK',
            'db': 'db',
            'dbx': 'dbx',
        }.get(str(name).lower())

    @staticmethod
    def _attributes(attributes):
        if attributes is None:
            return None
        if isinstance(attributes, (bytes, bytearray, memoryview)):
            attributes = _as_bytes(attributes)
            if len(attributes) == 1:
                return attributes[0]
            if len(attributes) >= 4:
                return struct.unpack('<I', attributes[:4])[0]
            raise ValueError('variable attributes must be 1 or 4 bytes')
        return int(attributes)

    @property
    def authenticated_write(self):
        if self.attributes is None:
            return None
        if self.nvar_attributes:
            return bool(self.attributes & 0x40)
        return bool(self.attributes & (
            EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
            EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS))

    @property
    def authenticated_write_attribute(self):
        if self.attributes is None:
            return None
        if self.nvar_attributes:
            return bool(self.attributes & 0x40)
        return bool(self.attributes &
                    EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)

    @property
    def time_based_authenticated_write(self):
        if self.attributes is None:
            return None
        if self.nvar_attributes:
            # NVAR's one-byte flags have no time-based bit; 0x20 is HER.
            return False
        return bool(self.attributes &
                    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

    @property
    def entries(self):
        entries = []
        for signature_list in self.signature_lists:
            entries.extend(signature_list.entries)
        return entries

    @property
    def valid(self):
        return (not self.errors and
                all(signature_list.valid for signature_list in
                    self.signature_lists))

    def process(self):
        self.signature_lists = []
        self.errors = []
        self.unparsed_data = b''

        offset = 0
        while offset < len(self.data):
            if len(self.data) - offset < SignatureList.HEADER_SIZE:
                if offset == 0:
                    self.errors.append(
                        'signature list header is truncated: %d of %d '
                        'bytes' % (len(self.data), SignatureList.HEADER_SIZE))
                else:
                    self.errors.append(
                        'trailing bytes at offset %d are too short for a '
                        'signature list header' % offset)
                self.unparsed_data = self.data[offset:]
                break

            # Copy only this list rather than the rest of the variable, so
            # parsing many short lists stays linear in the input size.
            list_size = struct.unpack(
                '<I', self.data[offset + 16:offset + 20])[0]
            supplied = min(
                max(list_size, SignatureList.HEADER_SIZE),
                len(self.data) - offset)
            signature_list = SignatureList(
                self.data[offset:offset + supplied],
                index=len(self.signature_lists),
                role=self.role, offset=offset)
            self.signature_lists.append(signature_list)
            self.errors.extend(
                'list %d: %s' % (signature_list.index, error)
                for error in signature_list.errors)

            if signature_list.signature_list_size < \
                    SignatureList.HEADER_SIZE:
                self.unparsed_data = self.data[offset:]
                break

            next_offset = offset + signature_list.signature_list_size
            if next_offset <= offset:
                # A zero-sized claim must not make this loop spin.
                self.unparsed_data = self.data[offset:]
                break
            if next_offset > len(self.data):
                self.unparsed_data = self.data[offset:]
                break
            offset = next_offset

        return self.valid

    def to_dict(self):
        return {
            'name': self.name,
            'role': self.role,
            'guid': self.guid,
            'attributes': self.attributes,
            'nvarAttributes': self.nvar_attributes,
            'authenticatedWrite': self.authenticated_write,
            'authenticatedWriteAttribute': self.authenticated_write_attribute,
            'timeBasedAuthenticatedWrite':
                self.time_based_authenticated_write,
            'sourceProvenanceVerified': False,
            'entryCount': len(self.entries),
            'signatureLists': [
                signature_list.to_dict()
                for signature_list in self.signature_lists
            ],
            'unparsedData': self.unparsed_data.hex(),
            'errors': list(self.errors),
            'valid': self.valid,
        }


class SecureBootPolicy(object):
    '''A read-only policy view joining PK, KEK, db and dbx views.

    Every duplicate entry is retained.  ``conflicts`` only reports exact
    signature-value overlaps between db and dbx; it is not a boot decision.
    '''

    def __init__(self, variables=()):
        self.variables = []
        self.errors = []
        self.conflicts = []
        self.duplicates = []
        self.owner_summary = []
        self.unknown_types = []
        for variable in self._coerce_variables(variables):
            self.variables.append(variable)
        self.process()

    @staticmethod
    def _coerce_variables(variables):
        if variables is None:
            return []
        if isinstance(variables, SecureBootVariable):
            return [variables]
        if isinstance(variables, dict):
            items = []
            for name, value in variables.items():
                if isinstance(value, SecureBootVariable):
                    items.append(value)
                else:
                    items.append(SecureBootVariable(value, name=name))
            return items

        items = []
        for value in variables:
            if isinstance(value, SecureBootVariable):
                items.append(value)
            elif isinstance(value, (tuple, list)) and len(value) >= 2:
                name, data = value[0], value[1]
                options = value[2] if len(value) > 2 else {}
                if not isinstance(options, dict):
                    options = {}
                items.append(SecureBootVariable(
                    data, name=name,
                    guid=options.get('guid'),
                    attributes=options.get('attributes')))
            else:
                raise TypeError(
                    'variables must contain SecureBootVariable objects or '
                    '(name, data[, options]) tuples')
        return items

    @property
    def by_role(self):
        roles = {'PK': [], 'KEK': [], 'db': [], 'dbx': []}
        for variable in self.variables:
            if variable.role in roles:
                roles[variable.role].append(variable)
        return roles

    @property
    def entries(self):
        entries = []
        for variable_index, variable in enumerate(self.variables):
            for entry in variable.entries:
                entries.append((variable_index, entry))
        return entries

    @property
    def allow_entries(self):
        return self._entries_for('db')

    @property
    def revoke_entries(self):
        return self._entries_for('dbx')

    def _entries_for(self, role):
        values = []
        for variable_index, variable in enumerate(self.variables):
            if variable.role != role:
                continue
            for entry in variable.entries:
                values.append((variable_index, entry))
        return values

    def _entry_ref(self, variable_index, entry):
        variable = self.variables[variable_index]
        return {
            'variable': variable.name,
            'role': variable.role,
            'variableIndex': variable_index,
            'listIndex': entry.list_index,
            'entryIndex': entry.index,
            'owner': entry.owner_guid,
            'signatureType': entry.signature_type_guid,
            'signatureTypeName': entry.signature_type_name,
            'kind': entry.kind,
        }

    def _duplicate_groups(self):
        groups = {}
        for variable_index, entry in self.entries:
            variable = self.variables[variable_index]
            key = (variable.role, entry.signature_identity)
            groups.setdefault(key, []).append((variable_index, entry))

        duplicates = []
        for (_, _), values in groups.items():
            if len(values) < 2:
                continue
            first = values[0][1]
            duplicates.append({
                'role': self.variables[values[0][0]].role,
                'owner': first.owner_guid,
                'owners': sorted({
                    entry.owner_guid for _, entry in values}),
                'signatureType': first.signature_type_guid,
                'signatureTypeName': first.signature_type_name,
                'kind': first.kind,
                'signature': first.typed_payload,
                'count': len(values),
                'entries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in values
                ],
            })
        return duplicates

    def _owner_groups(self):
        groups = {}
        for variable_index, entry in self.entries:
            variable = self.variables[variable_index]
            key = (variable.role, entry.owner)
            groups.setdefault(key, []).append((variable_index, entry))

        summaries = []
        for (role, _), values in groups.items():
            first = values[0][1]
            summaries.append({
                'role': role,
                'owner': first.owner_guid,
                'entryCount': len(values),
                'kinds': sorted({entry.kind for _, entry in values}),
                'entries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in values
                ],
            })
        return summaries

    def _unknown_type_groups(self):
        groups = {}
        for variable_index, entry in self.entries:
            if not entry.unknown_type:
                continue
            groups.setdefault(
                entry.signature_type, []).append((variable_index, entry))

        unknown = []
        for values in groups.values():
            first = values[0][1]
            unknown.append({
                'signatureType': first.signature_type_guid,
                'signatureTypeName': first.signature_type_name,
                'count': len(values),
                'payloads': [
                    entry.payload.hex() for _, entry in values],
                'entries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in values
                ],
            })
        return unknown

    def _allow_revoke_conflicts(self):
        allowed = {}
        revoked = {}
        for variable_index, entry in self.allow_entries:
            allowed.setdefault(entry.signature_identity, []).append(
                (variable_index, entry))
        for variable_index, entry in self.revoke_entries:
            revoked.setdefault(entry.signature_identity, []).append(
                (variable_index, entry))

        conflicts = []
        for identity in allowed:
            if identity not in revoked:
                continue
            allow_values = allowed[identity]
            revoke_values = revoked[identity]
            first = allow_values[0][1]
            signature = first.typed_payload
            conflicts.append({
                'signatureType': first.signature_type_guid,
                'signatureTypeName': first.signature_type_name,
                'kind': first.kind,
                'signature': signature,
                'allowOwners': sorted({
                    entry.owner_guid for _, entry in allow_values}),
                'revokeOwners': sorted({
                    entry.owner_guid for _, entry in revoke_values}),
                'allowEntries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in allow_values
                ],
                'revokeEntries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in revoke_values
                ],
                'allowCount': len(allow_values),
                'revokeCount': len(revoke_values),
                'nature': 'declared-allow-and-revoke',
            })
        return conflicts

    def _role_summary(self, role):
        variables = self.by_role[role]
        entries = [entry for variable in variables for entry in
                   variable.entries]
        kinds = {}
        for entry in entries:
            kinds[entry.kind] = kinds.get(entry.kind, 0) + 1
        return {
            'role': role,
            'meaning': SECURE_BOOT_ROLES[role]['meaning'],
            'supplied': bool(variables),
            'variableCount': len(variables),
            'namespaces': [
                variable.guid for variable in variables
                if variable.guid is not None
            ],
            'entryCount': len(entries),
            'kinds': kinds,
            'certificateEntries': kinds.get('certificate', 0),
            'imageDigestEntries': kinds.get('image_digest', 0),
            'unknownEntries': kinds.get('unknown', 0),
            'errors': sum(len(variable.errors) for variable in variables),
        }

    def _detailed_entries(self, role):
        values = []
        for variable_index, entry in self._entries_for(role):
            value = {
                'variable': self.variables[variable_index].name,
                'variableIndex': variable_index,
            }
            value.update(entry.to_dict())
            values.append(value)
        return values

    @property
    def limitations(self):
        return [
            'This view describes the supplied variable bytes; it does not '
            'verify the variable signature, certificate chain, or firmware '
            'boot path.',
            'An authenticated-write or time-based-authenticated-write '
            'attribute is reported as stored evidence only. It does not '
            'establish who wrote the variable or that the variable store '
            'was not modified.',
            'A db/dbx overlap is a declaration-level conflict. It is not a '
            'determination that a particular PE image is allowed or denied.',
            'PK, KEK, db and dbx are reported by their declared roles. '
            'Platform-specific enrollment rules are not enforced here.',
            'Unknown SignatureType values are preserved as unknown payloads, '
            'not interpreted as certificates or image digests.',
        ]

    @property
    def assessment(self):
        return {
            'scope': 'declared signature-list content',
            'readOnly': True,
            'signatureVerification': 'not-performed',
            'sourceProvenanceVerification': 'not-performed',
            'peImageEvaluated': False,
            'secureBootBootDecision': 'not-determined',
        }

    def process(self):
        self.errors = []
        self.duplicates = self._duplicate_groups()
        self.owner_summary = self._owner_groups()
        self.unknown_types = self._unknown_type_groups()
        self.conflicts = self._allow_revoke_conflicts()
        for variable_index, variable in enumerate(self.variables):
            for error in variable.errors:
                self.errors.append(
                    'variable %s: %s' % (variable.name, error))
        return True

    def to_dict(self):
        allow = self.allow_entries
        revoke = self.revoke_entries
        return {
            'kind': 'uefi-secure-boot-signature-policy',
            'readOnly': True,
            'assessment': self.assessment,
            'variables': [
                variable.to_dict() for variable in self.variables],
            'declaredPolicy': {
                'PK': self._role_summary('PK'),
                'KEK': self._role_summary('KEK'),
                'db': self._role_summary('db'),
                'dbx': self._role_summary('dbx'),
            },
            'allow': {
                'variable': 'db',
                'entryCount': len(allow),
                'entries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in allow],
                'detailedEntries': self._detailed_entries('db'),
            },
            'revoke': {
                'variable': 'dbx',
                'entryCount': len(revoke),
                'entries': [
                    self._entry_ref(variable_index, entry)
                    for variable_index, entry in revoke],
                'detailedEntries': self._detailed_entries('dbx'),
            },
            'duplicates': self.duplicates,
            'owners': self.owner_summary,
            'unknownTypes': self.unknown_types,
            'conflicts': self.conflicts,
            'errors': list(self.errors),
            'limitations': self.limitations,
        }

    def showinfo(self, ts=''):
        print('%sSecure Boot signature policy (read-only)' % ts)
        for role in ('PK', 'KEK', 'db', 'dbx'):
            summary = self._role_summary(role)
            print('%s  %s: supplied=%s entries=%d certificates=%d '
                  'digests=%d unknown=%d' % (
                      ts, role, summary['supplied'],
                      summary['entryCount'], summary['certificateEntries'],
                      summary['imageDigestEntries'],
                      summary['unknownEntries']))
        if self.conflicts:
            print('%s  db/dbx conflicts: %d' % (ts, len(self.conflicts)))
        for limitation in self.limitations:
            print('%s  limitation: %s' % (ts, limitation))


def parse_signature_list(data, index=0, role=None, offset=0):
    '''Parse one EFI_SIGNATURE_LIST, retaining malformed input as errors.'''
    return SignatureList(data, index=index, role=role, offset=offset)


def parse_signature_database(data, name=None, guid=None, attributes=None):
    '''Parse the variable bytes for one signature database.'''
    return SecureBootVariable(
        data, name=name, guid=guid, attributes=attributes)


def parse_secure_boot_variable(name, data, guid=None, attributes=None):
    '''Parse one caller-identified variable.

    This is a convenience wrapper around ``SecureBootVariable`` whose
    argument order puts the caller-supplied identity first.
    '''
    return SecureBootVariable(
        data, name=name, guid=guid, attributes=attributes)


def parse_secure_boot_policy(variables=None, pk=None, kek=None, db=None,
                             dbx=None, guid=None, attributes=None):
    '''Build and parse a policy from variables or role keyword arguments.

    ``variables`` may be a mapping of names to bytes, an iterable of
    ``SecureBootVariable`` objects, or ``(name, data[, options])`` tuples.
    When the keywords are used, ``guid`` and ``attributes`` may be a single
    value for every role or a mapping keyed by role.
    '''
    if variables is not None:
        return SecureBootPolicy(variables)

    values = []
    for role, data in (('PK', pk), ('KEK', kek), ('db', db), ('dbx', dbx)):
        if data is None:
            continue
        if isinstance(data, SecureBootVariable):
            values.append(data)
            continue
        if isinstance(guid, dict):
            role_guid = guid.get(role, guid.get(role.upper()))
        else:
            role_guid = guid
        if isinstance(attributes, dict):
            role_attributes = attributes.get(
                role, attributes.get(role.upper()))
        else:
            role_attributes = attributes
        values.append(SecureBootVariable(
            data, name=role, guid=role_guid,
            attributes=role_attributes))
    return SecureBootPolicy(values)
