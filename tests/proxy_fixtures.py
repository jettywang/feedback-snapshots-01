#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Synthetic RFC 3820 certificate builders shared by tests and tooling.

No private keys are used: these certificates are structural fixtures for offline
admission review.  Signature bytes are deterministic placeholders.
"""

import datetime

from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_modules import proxychain
from pyasn1_modules import rfc3820
from pyasn1_modules import rfc5280

US = rfc5280.id_at_countryName
O = rfc5280.id_at_organizationName
CN = rfc5280.id_at_commonName

LOCAL_POLICY = univ.ObjectIdentifier('1.3.6.1.4.1.55555.1')
READ = ('read', 'file-a')
WRITE = ('write', 'file-a')
READ_B = ('read', 'file-b')

NOT_BEFORE = '261101000000Z'
NOT_AFTER = '261201000000Z'
NOW = datetime.datetime(2026, 11, 15, tzinfo=datetime.timezone.utc)


def algorithm():
    return rfc5280.AlgorithmIdentifier().setComponentByName(
        'algorithm', univ.ObjectIdentifier('1.2.840.113549.1.1.11')
    )


def name(*parts):
    result = rfc5280.Name()
    for oid, value in parts:
        atv = rfc5280.AttributeTypeAndValue()
        atv['type'] = oid
        atv['value'] = char.UTF8String(value)
        rdn = rfc5280.RelativeDistinguishedName()
        rdn.append(atv)
        result['rdnSequence'].append(rdn)
    return result


def extension(oid, value, critical=True):
    ext = rfc5280.Extension()
    ext['extnID'] = oid
    ext['critical'] = critical
    ext['extnValue'] = value
    return ext


def key_usage(*names):
    return extension(rfc5280.id_ce_keyUsage,
                     der_encoder(rfc5280.KeyUsage(','.join(names))))


def ext_key_usage(*purposes):
    value = rfc5280.ExtKeyUsageSyntax()
    for purpose in purposes:
        value.append(rfc5280.KeyPurposeId(purpose))
    return extension(rfc5280.id_ce_extKeyUsage, der_encoder(value))


def basic_constraints(ca=False, path_len=None):
    value = rfc5280.BasicConstraints()
    value['cA'] = ca
    if path_len is not None:
        value['pathLenConstraint'] = path_len
    return extension(rfc5280.id_ce_basicConstraints, der_encoder(value))


def proxy_info(language, policy=None, path_len=None, critical=True):
    info = rfc3820.ProxyCertInfoExtension()
    if path_len is not None:
        info['pCPathLenConstraint'] = path_len
    info['proxyPolicy']['policyLanguage'] = language
    if policy is not None:
        info['proxyPolicy']['policy'] = policy
    return extension(rfc3820.id_pe_proxyCertInfo, der_encoder(info), critical)


def certificate(serial, issuer, subject, extensions,
                version='v3', not_before=NOT_BEFORE, not_after=NOT_AFTER):
    tbs = rfc5280.TBSCertificate()
    tbs['version'] = version
    tbs['serialNumber'] = serial
    tbs['signature'] = algorithm()
    tbs['issuer'] = issuer
    tbs['validity']['notBefore']['utcTime'] = useful.UTCTime(not_before)
    tbs['validity']['notAfter']['utcTime'] = useful.UTCTime(not_after)
    tbs['subject'] = subject
    spki = rfc5280.SubjectPublicKeyInfo()
    spki['algorithm'] = algorithm()
    spki['subjectPublicKey'] = univ.BitString.fromOctetString(
        bytes([serial % 256]) * 32
    )
    tbs['subjectPublicKeyInfo'] = spki
    for ext in extensions:
        tbs['extensions'].append(ext)
    cert = rfc5280.Certificate()
    cert['tbsCertificate'] = tbs
    cert['signatureAlgorithm'] = algorithm()
    cert['signature'] = univ.BitString.fromOctetString(
        bytes([serial % 256]) * 32
    )
    return cert


def make_eec(subject_cn='Alice', extensions=None, issuer_name=None):
    if issuer_name is None:
        issuer_name = name((US, 'US'), (O, 'Example'))
    subject = name((US, 'US'), (O, 'Example'), (CN, subject_cn))
    if extensions is None:
        extensions = [key_usage('digitalSignature'), basic_constraints()]
    return certificate(1, issuer_name, subject, extensions)


def make_proxy(issuer, cn, language, policy=None, path_len=None,
               critical=True, serial=100, key_usage_names=None,
               extra_extensions=None, not_before=NOT_BEFORE,
               not_after=NOT_AFTER):
    if key_usage_names is None:
        key_usage_names = ('digitalSignature',)
    extensions = [
        proxy_info(language, policy=policy, path_len=path_len,
                   critical=critical),
        key_usage(*key_usage_names),
    ]
    extensions.extend(extra_extensions or ())
    return certificate(
        serial,
        issuer['tbsCertificate']['subject'],
        proxychain.append_cn_subject(
            issuer['tbsCertificate']['subject'], cn
        ),
        extensions,
        not_before=not_before,
        not_after=not_after,
    )


def legal_chain():
    eec = make_eec()
    first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                       path_len=1, serial=2)
    second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                        path_len=0, serial=3)
    return eec, [first, second]
