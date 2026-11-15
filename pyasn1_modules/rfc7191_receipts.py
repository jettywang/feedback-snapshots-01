#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
# Correlation of RFC 7191 Key Package Receipts and Errors with send records.

"""Delivery-assurance correlation for RFC 7191 key packages.

A key distribution service knows which package it sent to which protected
recipients.  When a signed RFC 7191 ``KeyPackageReceipt`` or
``KeyPackageError`` arrives, the outer CMS layer has already authenticated
its signer.  This module answers the remaining question: which send record
does the evidence belong to, and which recipient does it actually confirm?

Security properties enforced here:

* Package identifiers are compared in both RFC 7191 representations
  (``pkgID`` and ``attribute``).  The two alternatives are never mixed.
* ``receiptsFrom``, ``receiptsTo``, ``receivedBy``/``errorBy`` and the
  authenticated subject all take part in the decision.
* The claimed ``receivedBy``/``errorBy`` is evidence, not authority.  It must
  equal the authenticated subject exactly.
* Entities are compared by the complete ``SIREntityName`` encoding.  Two
  names with the same display text but different DER encodings are different
  entities and are never merged.
* Repeated evidence is idempotent.  A forged source, conflicting evidence,
  or an error that names no correlatable package never advances a recipient
  to ``confirmed``.
* Raw DER evidence is retained for every accepted and rejected item.

The module performs no transport or message-service work.

A minimal timeline::

    record = SendRecord(
        package_id=PackageIdentifier.for_pkg_id(b'package-0001'),
        recipients=(alice, bob),
        receipt_request=ReceiptRequest(
            receipts_to=(kta,), receipts_from=(alice, bob)),
        receipt_recipient=kta,
    )
    correlator = ReceiptCorrelator(record)
    correlator.add(VerifiedReceipt.from_cms(content_info, authenticated_alice))
    result = correlator.result
    result.complete          # False while Bob has not answered
    result.pending()         # Bob's exact SIR entity name
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from pyasn1_modules import rfc5652
from pyasn1_modules import rfc7191


__all__ = [
    'CorrelationError',
    'CorrelationResult',
    'DeliveryStatus',
    'EntityName',
    'PackageCorrelation',
    'PackageIdentifier',
    'ReceiptCorrelator',
    'ReceiptEvidence',
    'ReceiptRequest',
    'RecipientState',
    'RejectedEvidence',
    'SendRecord',
    'SentPackageRecord',
    'VerifiedReceipt',
    'correlate_receipts',
    'entity_from_siren',
    'package_identifier_from_der',
]


_ID_DN = rfc7191.id_dn
_RECEIPT_TYPE = rfc7191.id_ct_KP_keyPackageReceipt
_ERROR_TYPE = rfc7191.id_ct_KP_keyPackageError


class CorrelationError(ValueError):
    """The supplied evidence or send record cannot be used."""


class DeliveryStatus(Enum):
    """State of one protected recipient in a send record."""

    PENDING = 'pending'
    CONFIRMED = 'confirmed'
    FAILED = 'failed'
    CONFLICTED = 'conflicted'


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, univ.OctetString):
        return bytes(value)
    raise CorrelationError('expected octets, got %s' % type(value).__name__)


def _der(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    try:
        return der_encoder(value)
    except PyAsn1Error as exc:
        raise CorrelationError('value has no DER encoding') from exc


def _decode_der(encoded, spec, what):
    encoded = _as_bytes(encoded)
    try:
        value, rest = der_decoder(encoded, asn1Spec=spec)
    except PyAsn1Error as exc:
        raise CorrelationError('%s is not valid DER' % what) from exc
    if rest:
        raise CorrelationError('trailing data after %s' % what)
    return value


def _oid_text(value):
    return str(value)


def _normalise_type(value):
    try:
        return univ.ObjectIdentifier(_oid_text(value))
    except PyAsn1Error as exc:
        raise CorrelationError('malformed object identifier') from exc


def _tlv_bounds(encoded, offset=0):
    """Return ``(start, contentStart, end)`` of one DER element."""
    encoded = _as_bytes(encoded)
    start = offset
    if offset >= len(encoded):
        raise CorrelationError('truncated DER element')
    tag = encoded[offset]
    offset += 1
    if tag & 0x1f == 0x1f:
        while offset < len(encoded) and encoded[offset] & 0x80:
            offset += 1
        offset += 1
    if offset >= len(encoded):
        raise CorrelationError('truncated DER element')
    length = encoded[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7f
        if not count or count > 4 or offset + count > len(encoded):
            raise CorrelationError('invalid DER length')
        length = int.from_bytes(encoded[offset:offset + count], 'big')
        offset += count
    end = offset + length
    if end > len(encoded):
        raise CorrelationError('truncated DER element')
    return start, offset, end


def _children_of(encoded):
    """Yield each child element's DER from an encoded SEQUENCE."""
    encoded = _as_bytes(encoded)
    _, content_start, end = _tlv_bounds(encoded, 0)
    cursor = content_start
    while cursor < end:
        child_start, _, child_end = _tlv_bounds(encoded, cursor)
        yield encoded[child_start:child_end]
        cursor = child_end


def _identifier_field_der(content_der, package_id):
    """Find the exact identifier field bytes inside receipt/error content.

    Rather than assuming a field position that depends on omitted DEFAULT
    fields, every child is tried; only the child that decodes to the same
    identifier is accepted.  This keeps the evidence tied to the bytes that
    actually appeared in the content.
    """
    for child in _children_of(content_der):
        candidates = [child]
        if child[0] == 0xa0:
            _, content_start, end = _tlv_bounds(child, 0)
            candidates.append(child[content_start:end])
        for candidate_der in candidates:
            try:
                candidate = PackageIdentifier.from_der(candidate_der)
            except CorrelationError:
                continue
            if candidate == package_id:
                return child
    raise CorrelationError('identifier field is absent from content')


class EntityName:
    """An exact SIR entity name.

    Identity is the pair (``sirenType`` OID, raw ``sirenValue`` octets).
    ``sirenValue`` is the DER-encoded SIR name value; for the standard DN
    type it is the DER of an X.509 ``Name``.  The class deliberately offers
    no display-name based comparison.
    """

    __slots__ = ('_type', '_value_der')

    def __init__(self, siren_type, siren_value):
        self._type = _normalise_type(siren_type)
        self._value_der = _as_bytes(siren_value)
        if not self._value_der:
            raise CorrelationError('SIR entity name value is empty')

    @property
    def siren_type(self):
        return self._type

    @property
    def value_der(self):
        return self._value_der

    @property
    def name_der(self):
        """Raw DER of the encoded Name for the standard DN name type."""
        if self._type == _ID_DN:
            return self._value_der
        return None

    def evidence(self):
        return {
            'sirenType': _oid_text(self._type),
            'sirenValue': self._value_der.hex(),
        }

    def __eq__(self, other):
        if not isinstance(other, EntityName):
            return NotImplemented
        return self._type == other._type and self._value_der == other._value_der

    def __hash__(self):
        return hash((self._type, self._value_der))

    def __repr__(self):
        return 'EntityName(sirenType=%s, sirenValue=%s)' % (
            _oid_text(self._type), self._value_der.hex())

    @classmethod
    def from_asn1(cls, value):
        try:
            siren_type = value['sirenType']
            siren_value = _as_bytes(value['sirenValue'])
        except (PyAsn1Error, KeyError) as exc:
            raise CorrelationError('malformed SIR entity name') from exc
        return cls(siren_type, siren_value)

    @classmethod
    def from_der(cls, encoded):
        return cls.from_asn1(
            _decode_der(encoded, rfc7191.SIREntityName(), 'SIR entity name'))

    @classmethod
    def from_dn(cls, name_der, siren_type=_ID_DN):
        """Build the standard DN entity name from encoded X.509 Name bytes."""
        name_der = _as_bytes(name_der)
        if not name_der:
            raise CorrelationError('encoded Name is empty')
        return cls(siren_type, name_der)


def entity_from_siren(value):
    """Build an exact entity identity from an RFC 7191 ``SIREntityName``."""
    return EntityName.from_asn1(value)


class PackageIdentifier:
    """The exact RFC 7191 ``KeyPkgIdentifier`` CHOICE.

    ``pkgID`` and ``attribute`` are alternative identities.  They are kept
    apart even when their octets happen to be equal.  The complete encoded
    identifier is retained as evidence.
    """

    __slots__ = ('_kind', '_identity', '_encoded', '_attr_type',
                 '_attr_values', '_field_der')

    def __init__(self, kind, identity, encoded, attr_type=None,
                 attr_values=()):
        if kind not in ('pkgID', 'attribute'):
            raise CorrelationError('unsupported package identifier alternative')
        identity = _as_bytes(identity)
        encoded = _as_bytes(encoded)
        if not identity or not encoded:
            raise CorrelationError('package identifier is empty')
        self._kind = kind
        self._identity = identity
        self._encoded = encoded
        self._attr_type = attr_type
        self._attr_values = tuple(_as_bytes(v) for v in attr_values)
        self._field_der = None

    @property
    def kind(self):
        return self._kind

    @property
    def der(self):
        """Complete DER encoding of the ``KeyPkgIdentifier`` CHOICE."""
        return self._encoded

    @property
    def field_der(self):
        """DER of the identifier field as it appeared in the evidence.

        This is the ``KeyPkgIdentifier`` value inside ``receiptOf`` or
        ``errorOf``.  It is ``None`` for identifiers built from local send
        policy rather than taken from received content.
        """
        return self._field_der

    def _with_field_der(self, field_der):
        result = PackageIdentifier(
            self._kind, self._identity, self._encoded,
            attr_type=self._attr_type, attr_values=self._attr_values)
        result._field_der = _as_bytes(field_der)
        return result

    @property
    def pkg_id(self):
        """Raw ``KeyPkgID`` octets, or ``None`` for the attribute form."""
        if self._kind != 'pkgID':
            return None
        return self._identity

    @property
    def attribute_type(self):
        return self._attr_type

    @property
    def attribute_values(self):
        return self._attr_values

    def evidence(self):
        result = {'kind': self._kind, 'der': self._encoded.hex()}
        if self._field_der is not None:
            result['fieldDer'] = self._field_der.hex()
        if self._kind == 'pkgID':
            result['pkgID'] = self._identity.hex()
        else:
            result['attributeType'] = self._attr_type
            result['attributeValues'] = [v.hex() for v in self._attr_values]
        return result

    def __eq__(self, other):
        if not isinstance(other, PackageIdentifier):
            return NotImplemented
        return self._kind == other._kind and self._identity == other._identity

    def __hash__(self):
        return hash((self._kind, self._identity))

    def __repr__(self):
        return 'PackageIdentifier(kind=%r, der=%s)' % (
            self._kind, self._encoded.hex())

    @classmethod
    def for_pkg_id(cls, octets):
        """Build the ``pkgID`` alternative from raw octets."""
        value = rfc7191.KeyPkgIdentifier()
        value['pkgID'] = _as_bytes(octets)
        return cls._from_asn1(value)

    @classmethod
    def for_attribute(cls, attr_type, value_der):
        """Build the ``attribute`` alternative with one attribute value."""
        value = rfc7191.KeyPkgIdentifier()
        attribute = rfc7191.SingleAttribute()
        attribute['attrType'] = _normalise_type(attr_type)
        attribute['attrValues'][0] = _as_bytes(value_der)
        value['attribute'] = attribute
        return cls._from_asn1(value)

    @classmethod
    def _from_asn1(cls, value, encoded=None):
        try:
            choice = value.getName()
        except PyAsn1Error as exc:
            raise CorrelationError('package identifier choice is absent') from exc
        if choice == 'pkgID':
            identity = _as_bytes(value['pkgID'])
            if encoded is None:
                encoded = _der(cls._canonical_pkg_id(identity))
            return cls('pkgID', identity, encoded)
        if choice == 'attribute':
            attribute = value['attribute']
            identity = _der(attribute)
            attribute_values = []
            try:
                for item in attribute['attrValues']:
                    attribute_values.append(_as_bytes(item))
            except PyAsn1Error as exc:
                raise CorrelationError('malformed package identifier attribute') from exc
            if encoded is None:
                encoded = _der(cls._canonical_attribute(attribute))
            return cls(
                'attribute', identity, encoded,
                attr_type=_oid_text(attribute['attrType']),
                attr_values=attribute_values,
            )
        raise CorrelationError('unsupported package identifier alternative')

    @staticmethod
    def _canonical_pkg_id(identity):
        value = rfc7191.KeyPkgIdentifier()
        value['pkgID'] = identity
        return value

    @staticmethod
    def _canonical_attribute(attribute):
        value = rfc7191.KeyPkgIdentifier()
        value['attribute'] = attribute
        return value

    @classmethod
    def from_asn1(cls, value):
        return cls._from_asn1(value)

    @classmethod
    def from_der(cls, encoded):
        encoded = _as_bytes(encoded)
        value = _decode_der(encoded, rfc7191.KeyPkgIdentifier(),
                            'package identifier')
        return cls._from_asn1(value, encoded=encoded)


def package_identifier_from_der(encoded):
    """Decode a DER ``KeyPkgIdentifier`` and preserve its original bytes."""
    return PackageIdentifier.from_der(encoded)


class ReceiptRequest:
    """The RFC 7191 ``KeyPkgReceiptReq`` attached to a sent package.

    ``receipts_from=None`` means the optional SIR list was absent, which per
    RFC 7191 Section 3 asks every receiver for a receipt.  ``receipts_to`` is
    never empty and names the entities authorised to submit receipt evidence
    for this package.
    """

    __slots__ = ('_encrypt', '_from', '_to')

    def __init__(self, receipts_to, receipts_from=None, encrypt_receipt=False):
        to = tuple(receipts_to)
        if not to:
            raise CorrelationError('receiptsTo must name at least one entity')
        if len(set(to)) != len(to):
            raise CorrelationError('duplicate entity in receiptsTo')
        if receipts_from is not None:
            receipts_from = tuple(receipts_from)
            if not receipts_from:
                raise CorrelationError('receiptsFrom must be absent or non-empty')
            if len(set(receipts_from)) != len(receipts_from):
                raise CorrelationError('duplicate entity in receiptsFrom')
        self._encrypt = bool(encrypt_receipt)
        self._from = receipts_from
        self._to = to

    @property
    def encrypt_receipt(self):
        return self._encrypt

    @property
    def receipts_from(self):
        return self._from

    @property
    def receipts_to(self):
        return self._to

    def asks(self, entity):
        """Whether this request asks ``entity`` to return a receipt."""
        if self._from is None:
            return True
        return entity in self._from

    def authorises(self, entity):
        """Whether ``entity`` may submit receipt evidence for this package."""
        return entity in self._to

    def evidence(self):
        return {
            'encryptReceipt': self._encrypt,
            'receiptsFrom': (
                None if self._from is None
                else [entity.evidence() for entity in self._from]),
            'receiptsTo': [entity.evidence() for entity in self._to],
        }

    @classmethod
    def from_asn1(cls, value):
        receipts_from = None
        if value['receiptsFrom'].isValue:
            receipts_from = tuple(
                EntityName.from_asn1(item) for item in value['receiptsFrom'])
        receipts_to = tuple(
            EntityName.from_asn1(item) for item in value['receiptsTo'])
        return cls(
            receipts_to=receipts_to,
            receipts_from=receipts_from,
            encrypt_receipt=bool(value['encryptReceipt']),
        )


@dataclass(frozen=True)
class SendRecord:
    """One package sent to a set of protected recipients.

    ``recipients`` come from local distribution policy.  They are never
    derived from a receipt's claimed names.  ``receipt_recipient`` is the
    local entity that expects to receive the receipts named in
    ``receiptsTo``.  It is required whenever a receipt request is present,
    so ``receiptsTo`` always takes part in the decision; evidence addressed
    elsewhere is rejected as misdelivered.
    """

    package_id: PackageIdentifier
    recipients: Tuple[EntityName, ...]
    receipt_request: Optional[ReceiptRequest] = None
    receipt_recipient: Optional[EntityName] = None

    def __post_init__(self):
        if not isinstance(self.package_id, PackageIdentifier):
            raise CorrelationError('package_id must be a PackageIdentifier')
        recipients = tuple(self.recipients)
        if not recipients:
            raise CorrelationError('a send record needs at least one recipient')
        if len(set(recipients)) != len(recipients):
            raise CorrelationError('duplicate recipient in send record')
        if self.receipt_request is not None and not isinstance(
                self.receipt_request, ReceiptRequest):
            raise CorrelationError('receipt_request has the wrong type')
        if self.receipt_recipient is not None and not isinstance(
                self.receipt_recipient, EntityName):
            raise CorrelationError('receipt_recipient must be an entity name')
        if self.receipt_request is not None and self.receipt_recipient is None:
            raise CorrelationError(
                'receipt_recipient is required when a receipt is requested')
        object.__setattr__(self, 'recipients', recipients)

    def requires_receipt_from(self, entity):
        if entity not in self.recipients:
            return False
        if self.receipt_request is None:
            return False
        return self.receipt_request.asks(entity)

    def evidence(self):
        return {
            'packageId': self.package_id.evidence(),
            'recipients': [entity.evidence() for entity in self.recipients],
            'receiptRequest': (
                None if self.receipt_request is None
                else self.receipt_request.evidence()),
            'receiptRecipient': (
                None if self.receipt_recipient is None
                else self.receipt_recipient.evidence()),
        }

    @classmethod
    def from_key_package_attribute(cls, attribute, recipients,
                                   receipt_recipient=None):
        """Build a send record from a KeyPkgIdentifierAndReceiptReq value."""
        if isinstance(attribute, (bytes, bytearray)):
            attribute = _decode_der(
                attribute,
                rfc7191.KeyPkgIdentifierAndReceiptReq(),
                'key package identifier and receipt request')
        elif not isinstance(attribute, rfc7191.KeyPkgIdentifierAndReceiptReq):
            raise CorrelationError(
                'attribute must be KeyPkgIdentifierAndReceiptReq or DER')
        package_id = PackageIdentifier.for_pkg_id(
            _as_bytes(attribute['pkgID']))
        request = None
        if attribute['receiptReq'].isValue:
            request = ReceiptRequest.from_asn1(attribute['receiptReq'])
        return cls(
            package_id=package_id,
            recipients=tuple(recipients),
            receipt_request=request,
            receipt_recipient=receipt_recipient,
        )


SentPackageRecord = SendRecord


@dataclass(frozen=True)
class VerifiedReceipt:
    """Authenticated RFC 7191 receipt or error evidence.

    Construct instances with :meth:`create` for raw content or
    :meth:`from_cms` for a signed CMS ``ContentInfo``.  The
    ``authenticated_entity`` argument is the subject established by the
    already-completed outer authentication; it is not taken from the
    receipt.
    """

    kind: str
    authenticated_entity: EntityName
    package_id: Optional[PackageIdentifier]
    claimed_entity: EntityName
    payload: object
    evidence: dict
    receipt_der: bytes = b''

    @classmethod
    def create(cls, content, authenticated_entity, receipt_der=b'',
               content_type=None):
        """Build evidence from receipt/error content and an authenticated subject.

        ``content`` may be a DER octet string or an already decoded
        ``KeyPackageReceipt``/``KeyPackageError``.  ``content_type`` is an
        optional expected RFC 7191 content-type OID.
        """
        authenticated_entity = _coerce_entity(authenticated_entity)
        if content_type is not None:
            content_type = _normalise_type(content_type)
            if content_type not in (_RECEIPT_TYPE, _ERROR_TYPE):
                raise CorrelationError('not a receipt or error content type')

        receipt_der = _as_bytes(receipt_der)

        if isinstance(content, (bytes, bytearray)):
            content = _as_bytes(content)
            if content_type == _RECEIPT_TYPE:
                receipt = _decode_der(
                    content, rfc7191.KeyPackageReceipt(), 'key package receipt')
                return cls._from_receipt(
                    receipt, authenticated_entity, receipt_der, content)
            if content_type == _ERROR_TYPE:
                error = _decode_der(
                    content, rfc7191.KeyPackageError(), 'key package error')
                return cls._from_error(
                    error, authenticated_entity, receipt_der, content)
            try:
                receipt = _decode_der(
                    content, rfc7191.KeyPackageReceipt(), 'key package receipt')
            except CorrelationError:
                receipt = None
            if receipt is not None:
                return cls._from_receipt(
                    receipt, authenticated_entity, receipt_der, content)
            try:
                error = _decode_der(
                    content, rfc7191.KeyPackageError(), 'key package error')
            except CorrelationError as exc:
                raise CorrelationError(
                    'content is neither a key package receipt nor error'
                ) from exc
            return cls._from_error(
                error, authenticated_entity, receipt_der, content)

        if isinstance(content, rfc7191.KeyPackageReceipt):
            kind, expected = 'receipt', _RECEIPT_TYPE
        elif isinstance(content, rfc7191.KeyPackageError):
            kind, expected = 'error', _ERROR_TYPE
        else:
            raise CorrelationError(
                'content must be KeyPackageReceipt, KeyPackageError, or DER')
        if content_type is not None and content_type != expected:
            raise CorrelationError('content does not match its content type')
        if kind == 'receipt':
            return cls._from_receipt(content, authenticated_entity, receipt_der)
        return cls._from_error(content, authenticated_entity, receipt_der)

    @classmethod
    def _from_receipt(cls, receipt, authenticated_entity, receipt_der,
                      content_der=None):
        package_id = PackageIdentifier.from_asn1(receipt['receiptOf'])
        claimed = EntityName.from_asn1(receipt['receivedBy'])
        if content_der is None:
            content_der = _der(receipt)
        if not receipt_der:
            receipt_der = content_der
        try:
            package_id = package_id._with_field_der(
                _identifier_field_der(content_der, package_id))
        except CorrelationError:
            pass
        evidence = {
            'contentType': _oid_text(_RECEIPT_TYPE),
            'version': int(receipt['version']),
            'receiptOf': package_id.evidence(),
            'receivedBy': claimed.evidence(),
            'authenticatedEntity': authenticated_entity.evidence(),
            'contentDer': content_der.hex(),
            'receiptDer': receipt_der.hex(),
        }
        return cls(
            kind='receipt',
            authenticated_entity=authenticated_entity,
            package_id=package_id,
            claimed_entity=claimed,
            payload=receipt,
            evidence=evidence,
            receipt_der=receipt_der,
        )

    @classmethod
    def _from_error(cls, error, authenticated_entity, receipt_der,
                    content_der=None):
        claimed = EntityName.from_asn1(error['errorBy'])
        package_id = None
        if error['errorOf'].isValue:
            package_id = PackageIdentifier.from_asn1(error['errorOf'])
        if content_der is None:
            content_der = _der(error)
        if not receipt_der:
            receipt_der = content_der
        if package_id is not None:
            try:
                package_id = package_id._with_field_der(
                    _identifier_field_der(content_der, package_id))
            except CorrelationError:
                pass
        code = error['errorCode']
        try:
            choice = code.getName()
        except PyAsn1Error as exc:
            raise CorrelationError('key package error has no error code') from exc
        if choice == 'enum':
            error_code = {
                'kind': 'enum',
                'value': int(code['enum']),
                'name': code['enum'].prettyPrint(),
            }
        elif choice == 'oid':
            error_code = {'kind': 'oid', 'value': _oid_text(code['oid'])}
        else:
            raise CorrelationError('malformed key package error code')
        evidence = {
            'contentType': _oid_text(_ERROR_TYPE),
            'version': int(error['version']),
            'errorOf': None if package_id is None else package_id.evidence(),
            'errorBy': claimed.evidence(),
            'errorCode': error_code,
            'authenticatedEntity': authenticated_entity.evidence(),
            'contentDer': content_der.hex(),
            'receiptDer': receipt_der.hex(),
        }
        return cls(
            kind='error',
            authenticated_entity=authenticated_entity,
            package_id=package_id,
            claimed_entity=claimed,
            payload=error,
            evidence=evidence,
            receipt_der=receipt_der,
        )

    @classmethod
    def from_cms(cls, content_info, authenticated_entity, verify_outer=None):
        """Extract evidence from a signed CMS ``ContentInfo``.

        ``verify_outer`` is an optional callback ``(signer_info,
        content_info) -> bool`` representing the separately performed CMS
        signature/trust check.  A missing callback means the caller asserts
        that the outer authentication already succeeded.
        """
        authenticated_entity = _coerce_entity(authenticated_entity)

        if isinstance(content_info, (bytes, bytearray)):
            source_der = _as_bytes(content_info)
            content_info = _decode_der(
                source_der, rfc5652.ContentInfo(), 'CMS ContentInfo')
        else:
            source_der = _der(content_info)

        if content_info['contentType'] != rfc5652.id_signedData:
            raise CorrelationError('outer content is not SignedData')

        signed_data = _decode_der(
            content_info['content'], rfc5652.SignedData(), 'CMS SignedData')

        signer_infos = signed_data['signerInfos']
        if len(signer_infos) != 1:
            raise CorrelationError(
                'exactly one signer is required for receipt correlation')
        signer_info = signer_infos[0]
        if verify_outer is not None and not verify_outer(signer_info,
                                                          content_info):
            raise CorrelationError('outer authentication failed')

        encap = signed_data['encapContentInfo']
        content_type = encap['eContentType']
        if content_type not in (_RECEIPT_TYPE, _ERROR_TYPE):
            raise CorrelationError(
                'CMS content is not a key package receipt or error')
        if not encap['eContent'].isValue:
            raise CorrelationError('signed receipt content is missing')

        return cls.create(
            _as_bytes(encap['eContent']),
            authenticated_entity,
            receipt_der=source_der,
            content_type=content_type,
        )


ReceiptEvidence = VerifiedReceipt


def _coerce_entity(value):
    if isinstance(value, EntityName):
        return value
    if isinstance(value, rfc7191.SIREntityName):
        return EntityName.from_asn1(value)
    raise CorrelationError('authenticated entity must be a SIR entity name')


@dataclass(frozen=True)
class RejectedEvidence:
    """Evidence that could not advance delivery state, with its reason."""

    receipt: VerifiedReceipt
    reason: str
    package_id: Optional[PackageIdentifier] = None

    def as_dict(self):
        return {
            'packageId': (
                None if self.package_id is None
                else self.package_id.evidence()),
            'kind': self.receipt.kind,
            'reason': self.reason,
            'evidence': self.receipt.evidence,
        }


@dataclass(frozen=True)
class RecipientState:
    """Final state for one protected recipient of one package."""

    entity: EntityName
    status: DeliveryStatus
    confirmations: Tuple[VerifiedReceipt, ...] = ()
    errors: Tuple[VerifiedReceipt, ...] = ()
    rejected: Tuple[RejectedEvidence, ...] = ()
    duplicate_count: int = 0
    conflict_reason: Optional[str] = None

    def as_dict(self):
        return {
            'entity': self.entity.evidence(),
            'status': self.status.value,
            'duplicateCount': self.duplicate_count,
            'conflictReason': self.conflict_reason,
            'confirmations': [r.evidence for r in self.confirmations],
            'errors': [r.evidence for r in self.errors],
            'rejected': [r.as_dict() for r in self.rejected],
        }


@dataclass(frozen=True)
class PackageCorrelation:
    """Correlation state for one send record."""

    record: SendRecord
    recipients: Tuple[RecipientState, ...]
    rejected: Tuple[RejectedEvidence, ...] = ()

    def recipient(self, entity):
        for state in self.recipients:
            if state.entity == entity:
                return state
        return None

    def pending_entities(self):
        return tuple(
            state.entity for state in self.recipients
            if state.status is DeliveryStatus.PENDING)

    def as_dict(self):
        return {
            'record': self.record.evidence(),
            'recipients': [state.as_dict() for state in self.recipients],
            'rejected': [item.as_dict() for item in self.rejected],
        }


def _payload_key(receipt):
    """Identity of received content for idempotent duplicate handling."""
    return (
        receipt.kind,
        receipt.package_id,
        receipt.claimed_entity,
        receipt.evidence['contentDer'],
    )


def _error_code_key(receipt):
    if receipt.kind != 'error':
        return None
    code = receipt.evidence['errorCode']
    return (code['kind'], code['value'])


def _check_evidence(record, receipt):
    """Return a rejection reason or ``None`` when evidence is attributable."""
    if receipt.package_id is None:
        return 'error does not identify a package'
    if receipt.package_id != record.package_id:
        return 'package identifier does not match the send record'

    subject = receipt.authenticated_entity
    claimed = receipt.claimed_entity
    if claimed != subject:
        field_name = 'receivedBy' if receipt.kind == 'receipt' else 'errorBy'
        return '%s does not match the authenticated subject' % field_name

    if subject not in record.recipients:
        return 'authenticated subject is not a protected recipient'

    request = record.receipt_request
    if request is None:
        if receipt.kind == 'receipt':
            return 'send record did not request a receipt'
        return None

    if not request.authorises(record.receipt_recipient):
        return 'receiptsTo does not include this receipt recipient'
    if not request.asks(subject):
        return 'authenticated subject is not in receiptsFrom'
    return None


def _correlate_package(record, receipts):
    states = {}
    rejected_for_package = []

    for entity in record.recipients:
        states[entity] = {
            'confirmations': [],
            'errors': [],
            'rejected': [],
            'seen': set(),
            'duplicates': 0,
        }

    for receipt in receipts:
        if receipt.package_id != record.package_id:
            continue

        subject = receipt.authenticated_entity
        reason = _check_evidence(record, receipt)

        if subject not in states:
            rejected_for_package.append(RejectedEvidence(
                receipt=receipt,
                reason=reason or 'authenticated subject is not a protected recipient',
                package_id=record.package_id))
            continue

        entry = states[subject]
        key = _payload_key(receipt)
        if key in entry['seen']:
            # Identical evidence is idempotent whether it was accepted or
            # rejected the first time.
            entry['duplicates'] += 1
            continue
        entry['seen'].add(key)

        if reason is not None:
            entry['rejected'].append(RejectedEvidence(
                receipt=receipt,
                reason=reason,
                package_id=record.package_id))
            continue

        if receipt.kind == 'receipt':
            entry['confirmations'].append(receipt)
        else:
            entry['errors'].append(receipt)

    recipient_states = []
    for entity in record.recipients:
        entry = states[entity]
        confirmations = tuple(entry['confirmations'])
        errors = tuple(entry['errors'])
        conflict_reason = None

        if confirmations and errors:
            status = DeliveryStatus.CONFLICTED
            conflict_reason = 'both confirmation and failure evidence are present'
        elif confirmations:
            status = DeliveryStatus.CONFIRMED
        elif errors:
            codes = {_error_code_key(error) for error in errors}
            if len(codes) > 1:
                status = DeliveryStatus.CONFLICTED
                conflict_reason = 'failure evidence contains conflicting error codes'
            else:
                status = DeliveryStatus.FAILED
        else:
            status = DeliveryStatus.PENDING

        recipient_states.append(RecipientState(
            entity=entity,
            status=status,
            confirmations=confirmations,
            errors=errors,
            rejected=tuple(entry['rejected']),
            duplicate_count=entry['duplicates'],
            conflict_reason=conflict_reason,
        ))

    return PackageCorrelation(
        record=record,
        recipients=tuple(recipient_states),
        rejected=tuple(rejected_for_package),
    )


@dataclass(frozen=True)
class CorrelationResult:
    """Aggregate correlation state for one or more send records."""

    packages: Tuple[PackageCorrelation, ...]
    unrouted: Tuple[RejectedEvidence, ...] = ()

    @property
    def complete(self):
        """True only when every protected recipient confirmed delivery."""
        return all(
            state.status is DeliveryStatus.CONFIRMED
            for package in self.packages
            for state in package.recipients)

    @property
    def resolved(self):
        """True when no recipient is still waiting for evidence."""
        return all(
            state.status is not DeliveryStatus.PENDING
            for package in self.packages
            for state in package.recipients)

    def pending(self):
        """Recipients whose confirmation is still missing."""
        return tuple(
            {
                'packageId': package.record.package_id.evidence(),
                'entity': state.entity.evidence(),
                'status': state.status.value,
            }
            for package in self.packages
            for state in package.recipients
            if state.status is DeliveryStatus.PENDING)

    def rejected(self):
        """All rejected evidence, including evidence routed to no package."""
        result = []
        for package in self.packages:
            for item in package.rejected:
                result.append(item.as_dict())
            for state in package.recipients:
                for item in state.rejected:
                    result.append(item.as_dict())
        for item in self.unrouted:
            result.append(item.as_dict())
        return tuple(result)

    def failures(self):
        """Recipients with a legal failure receipt."""
        return tuple(
            {
                'packageId': package.record.package_id.evidence(),
                'entity': state.entity.evidence(),
                'status': state.status.value,
                'errors': [error.evidence for error in state.errors],
            }
            for package in self.packages
            for state in package.recipients
            if state.status is DeliveryStatus.FAILED)

    def conflicts(self):
        """Recipients with mutually incompatible evidence."""
        return tuple(
            {
                'packageId': package.record.package_id.evidence(),
                'entity': state.entity.evidence(),
                'status': state.status.value,
                'reason': state.conflict_reason,
                'confirmations': [r.evidence for r in state.confirmations],
                'errors': [e.evidence for e in state.errors],
            }
            for package in self.packages
            for state in package.recipients
            if state.status is DeliveryStatus.CONFLICTED)

    def status(self):
        """Readable final state: missing confirmations and rejection evidence."""
        lines = []
        for package in self.packages:
            identifier = package.record.package_id.evidence()
            lines.append('package %s:%s' % (
                identifier['kind'], identifier['der']))
            for state in package.recipients:
                label = '%s/%s' % (
                    state.entity.evidence()['sirenType'],
                    state.entity.evidence()['sirenValue'])
                if state.status is DeliveryStatus.PENDING:
                    lines.append('  %s: missing confirmation' % label)
                elif state.status is DeliveryStatus.CONFIRMED:
                    lines.append('  %s: confirmed by %s' % (
                        label, state.confirmations[0].evidence['contentDer']))
                elif state.status is DeliveryStatus.FAILED:
                    lines.append('  %s: failed with %s by %s' % (
                        label, state.errors[0].evidence['errorCode'],
                        state.errors[0].evidence['contentDer']))
                else:
                    lines.append('  %s: conflicted (%s)' % (
                        label, state.conflict_reason))
            for item in package.rejected:
                lines.append('  rejected %s evidence %s: %s' % (
                    item.receipt.kind,
                    item.receipt.evidence['contentDer'],
                    item.reason))
            for state in package.recipients:
                for item in state.rejected:
                    lines.append('  rejected %s evidence %s: %s' % (
                        item.receipt.kind,
                        item.receipt.evidence['contentDer'],
                        item.reason))
        for item in self.unrouted:
            lines.append('unrouted %s evidence %s: %s' % (
                item.receipt.kind,
                item.receipt.evidence['contentDer'],
                item.reason))
        return '\n'.join(lines)

    def as_dict(self):
        return {
            'complete': self.complete,
            'resolved': self.resolved,
            'packages': [package.as_dict() for package in self.packages],
            'pending': list(self.pending()),
            'rejected': list(self.rejected()),
            'failures': list(self.failures()),
            'conflicts': list(self.conflicts()),
        }


def _normalise_records(send_records):
    if isinstance(send_records, SendRecord):
        send_records = (send_records,)
    records = tuple(send_records)
    if not records:
        raise CorrelationError('no send records supplied')
    for record in records:
        if not isinstance(record, SendRecord):
            raise CorrelationError('send record has the wrong type')
    identifiers = [record.package_id for record in records]
    if len(set(identifiers)) != len(identifiers):
        raise CorrelationError('send records contain duplicate package identifiers')
    return records


def _normalise_receipts(receipts):
    if isinstance(receipts, VerifiedReceipt):
        receipts = (receipts,)
    result = tuple(receipts)
    for receipt in result:
        if not isinstance(receipt, VerifiedReceipt):
            raise CorrelationError('receipt evidence has the wrong type')
    return result


def correlate_receipts(send_records, receipts):
    """Correlate authenticated receipt/error evidence with send records."""
    records = _normalise_records(send_records)
    receipts = _normalise_receipts(receipts)

    by_package: Dict[PackageIdentifier, List[VerifiedReceipt]] = {
        record.package_id: [] for record in records}
    unrouted = []
    for receipt in receipts:
        if receipt.package_id is None:
            unrouted.append(RejectedEvidence(
                receipt=receipt,
                reason='error does not identify a package',
            ))
        elif receipt.package_id not in by_package:
            unrouted.append(RejectedEvidence(
                receipt=receipt,
                reason='no send record matches the package identifier',
            ))
        else:
            by_package[receipt.package_id].append(receipt)

    packages = tuple(
        _correlate_package(record, by_package[record.package_id])
        for record in records)

    return CorrelationResult(
        packages=packages,
        unrouted=tuple(unrouted),
    )


class ReceiptCorrelator:
    """Timeline-oriented wrapper around :func:`correlate_receipts`.

    Add already-authenticated evidence as it arrives; :attr:`result` is
    recomputed from all evidence and duplicate handling stays idempotent.
    """

    def __init__(self, send_records):
        self._records = _normalise_records(send_records)
        self._receipts = []

    @property
    def records(self):
        return self._records

    @property
    def receipts(self):
        return tuple(self._receipts)

    def add(self, receipt):
        if not isinstance(receipt, VerifiedReceipt):
            raise CorrelationError('receipt evidence has the wrong type')
        self._receipts.append(receipt)
        return receipt

    def add_receipt(self, content, authenticated_entity, receipt_der=b'',
                    content_type=None):
        return self.add(VerifiedReceipt.create(
            content,
            authenticated_entity,
            receipt_der=receipt_der,
            content_type=content_type,
        ))

    def add_cms(self, content_info, authenticated_entity, verify_outer=None):
        return self.add(VerifiedReceipt.from_cms(
            content_info,
            authenticated_entity,
            verify_outer=verify_outer,
        ))

    ingest = add

    @property
    def result(self):
        return correlate_receipts(self._records, self._receipts)

    def correlate(self):
        return self.result

    def status(self):
        return self.result.status()
