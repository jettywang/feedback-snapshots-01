"""DER certificate builder for RFC 3779 chain tests.

No cryptographic library is available in the test environment, and resource
chain validation does not verify signatures, so these certificates carry a
placeholder signature.  Everything around the RFC 3779 extensions is real
DER produced by pyasn1 and decodes through rfc5280 / rfc3779.
"""

from pyasn1.type import univ, useful, char
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

from pyasn1_modules import rfc3779
from pyasn1_modules import rfc5280


_RSA_ENCRYPTION = univ.ObjectIdentifier('1.2.840.113549.1.1.1')


def _field_instance(sequence_cls, index):
    return sequence_cls.componentType[index].getType().clone()


def _name(cn):
    name = _field_instance(rfc5280.TBSCertificate, 3)
    rdn_sequence = rfc5280.RDNSequence()
    rdn = rfc5280.RelativeDistinguishedName()
    atv = rfc5280.AttributeTypeAndValue()
    atv.setComponentByName('type', rfc5280.id_at_commonName)
    atv.setComponentByName('value', char.UTF8String(cn))
    rdn.append(atv)
    rdn_sequence.append(rdn)
    name.setComponentByName('rdnSequence', rdn_sequence)
    return name


def _time(value):
    time_obj = rfc5280.Time()
    time_obj.setComponentByName(
        'generalTime', useful.GeneralizedTime(value))
    return time_obj


def _bit_string(binary):
    return univ.BitString.fromBinaryString(binary)


def ip_prefix_entry(binary):
    item = rfc3779.IPAddressOrRange()
    item.setComponentByName('addressPrefix', _bit_string(binary))
    return item


def ip_range_entry(min_binary, max_binary):
    address_range = rfc3779.IPAddressRange()
    address_range.setComponentByName('min', _bit_string(min_binary))
    address_range.setComponentByName('max', _bit_string(max_binary))
    item = rfc3779.IPAddressOrRange()
    item.setComponentByName('addressRange', address_range)
    return item


def ip_inherit_family(family):
    family_obj = rfc3779.IPAddressFamily()
    family_obj.setComponentByPosition(0, family)
    choice = rfc3779.IPAddressChoice()
    choice.setComponentByName('inherit', '')
    family_obj.setComponentByPosition(1, choice)
    return family_obj


def ip_explicit_family(family, entries):
    family_obj = rfc3779.IPAddressFamily()
    family_obj.setComponentByPosition(0, family)
    sequence = univ.SequenceOf(
        componentType=rfc3779.IPAddressOrRange())
    for entry in entries:
        sequence.append(entry)
    choice = rfc3779.IPAddressChoice()
    choice.setComponentByName('addressesOrRanges', sequence)
    family_obj.setComponentByPosition(1, choice)
    return family_obj


def ip_empty_family(family):
    return ip_explicit_family(family, [])


def ip_extension(families, critical=True):
    blocks = rfc3779.IPAddrBlocks()
    for family_obj in families:
        blocks.append(family_obj)
    return rfc3779.id_pe_ipAddrBlocks, der_encoder.encode(blocks), critical


def as_id_entry(value):
    item = rfc3779.ASIdOrRange()
    item.setComponentByName('id', value)
    return item


def as_range_entry(low, high):
    as_range = rfc3779.ASRange()
    as_range.setComponentByName('min', low)
    as_range.setComponentByName('max', high)
    item = rfc3779.ASIdOrRange()
    item.setComponentByName('range', as_range)
    return item


def as_extension(entries=None, inherit=False, field='asnum'):
    choice = rfc3779.ASIdentifierChoice()
    if inherit:
        choice.setComponentByName('inherit', '')
    else:
        sequence = univ.SequenceOf(
            componentType=rfc3779.ASIdOrRange())
        for entry in entries or ():
            sequence.append(entry)
        choice.setComponentByName('asIdsOrRanges', sequence)
    identifiers = rfc3779.ASIdentifiers()
    index = 0 if field == 'asnum' else 1
    tagged_choice = identifiers.componentType[index].getType().clone()
    # Copy the choice payload into a field instance carrying the explicit
    # context tag required by RFC 3779.
    tagged_choice.setComponentByName(
        choice.getName(), choice[choice.getName()])
    identifiers.setComponentByPosition(
        index, tagged_choice, matchTags=False, matchConstraints=False)
    return (rfc3779.id_pe_autonomousSysIds,
            der_encoder.encode(identifiers), True)


def build_certificate(cn, serial, extensions):
    """Build DER bytes of an X.509 v3 certificate carrying ``extensions``.

    Each extension is a tuple ``(oid, extn_value_bytes, critical)``.
    """
    tbs = rfc5280.TBSCertificate()
    tbs.setComponentByPosition(0, 2)
    tbs.setComponentByPosition(1, serial)

    signature_algorithm = rfc5280.AlgorithmIdentifier()
    signature_algorithm.setComponentByName('algorithm', _RSA_ENCRYPTION)
    tbs.setComponentByPosition(2, signature_algorithm)
    tbs.setComponentByPosition(3, _name(cn))

    validity = rfc5280.Validity()
    validity.setComponentByName('notBefore', _time('20200101000000Z'))
    validity.setComponentByName('notAfter', _time('20400101000000Z'))
    tbs.setComponentByPosition(4, validity)
    tbs.setComponentByPosition(5, _name(cn))

    spki = rfc5280.SubjectPublicKeyInfo()
    algorithm = rfc5280.AlgorithmIdentifier()
    algorithm.setComponentByName('algorithm', _RSA_ENCRYPTION)
    spki.setComponentByName('algorithm', algorithm)
    spki.setComponentByName(
        'subjectPublicKey', univ.BitString.fromBinaryString('00000000'))
    tbs.setComponentByPosition(6, spki)

    extension_sequence = _field_instance(rfc5280.TBSCertificate, 9)
    for oid, value, critical in extensions:
        extension = rfc5280.Extension()
        extension.setComponentByName('extnID', oid)
        extension.setComponentByName('critical', critical)
        extension.setComponentByName('extnValue', value)
        extension_sequence.append(extension)
    tbs.setComponentByPosition(9, extension_sequence)

    certificate = rfc5280.Certificate()
    certificate.setComponentByName('tbsCertificate', tbs)
    certificate.setComponentByName(
        'signatureAlgorithm', signature_algorithm)
    certificate.setComponentByName(
        'signature', univ.BitString.fromBinaryString('00000000'))
    return der_encoder.encode(certificate)


def decode_certificate(der_bytes):
    certificate, rest = der_decoder.decode(
        der_bytes, asn1Spec=rfc5280.Certificate())
    assert rest == b''
    return certificate
