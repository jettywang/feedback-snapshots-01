"""Constructors for the small set of RFC 4210 PKIMessages used in tests.

These helpers only build ASN.1 values and their DER encodings; the outer
PKIMessage protection is represented by a fixed dummy BIT STRING because the
transaction validator assumes protection verification happened upstream.
"""

from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_modules import rfc2459
from pyasn1_modules import rfc2511
from pyasn1_modules import rfc4210

DUMMY_PROTECTION = b"outer-protection-verified-by-caller"


def rfc822_name(address):
    """Build a GeneralName rfc822Name choice (implicitly tagged [1])."""
    name = rfc2459.GeneralName()
    name.setComponentByName(
        "rfc822Name",
        char.IA5String(address).subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 1)))
    return name


def directory_name(common_name):
    """Build an untagged rfc2459.Name with one CN attribute."""
    attr = rfc2459.AttributeTypeAndValue()
    attr.setComponentByName("type", univ.ObjectIdentifier("2.5.4.3"))
    attr.setComponentByName("value", char.UTF8String(common_name))
    rdn = rfc2459.RelativeDistinguishedName()
    rdn.setComponentByPosition(0, attr)
    rdn_seq = rfc2459.RDNSequence()
    rdn_seq.setComponentByPosition(0, rdn)
    name = rfc2459.Name()
    name.setComponentByPosition(0, rdn_seq)
    return name


def cert_subject(certificate):
    """Return the bare subject Name of a CMPCertificate."""
    return certificate.getComponentByName(
        "tbsCertificate").getComponentByName("subject")


def cert_spki(certificate):
    """Return the bare SubjectPublicKeyInfo of a CMPCertificate."""
    return certificate.getComponentByName(
        "tbsCertificate").getComponentByName("subjectPublicKeyInfo")


def _generalized_time(moment):
    return useful.GeneralizedTime(
        moment.strftime("%Y%m%d%H%M%SZ")).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))


def _header(sender, recipient, transaction_id, sender_nonce,
            recip_nonce=None, message_time=None):
    header = rfc4210.PKIHeader()
    header.setComponentByName("pvno", 2)
    header.setComponentByName("sender", sender)
    header.setComponentByName("recipient", recipient)
    if message_time is not None:
        header.setComponentByName("messageTime",
                                  _generalized_time(message_time))
    header.setComponentByName(
        "transactionID",
        univ.OctetString(transaction_id).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 4)))
    header.setComponentByName(
        "senderNonce",
        univ.OctetString(sender_nonce).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 5)))
    if recip_nonce is not None:
        header.setComponentByName(
            "recipNonce",
            univ.OctetString(recip_nonce).subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 6)))
    return header


def _message(header, body):
    message = rfc4210.PKIMessage()
    message.setComponentByName("header", header)
    message.setComponentByName("body", body)
    message.setComponentByName(
        "protection",
        univ.BitString(hexValue=DUMMY_PROTECTION.hex()).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 0)))
    return message


def encode(message):
    return der_encoder.encode(message)


def ir(cert_specs, sender, recipient, transaction_id, sender_nonce,
       message_time=None):
    """Build an ir PKIMessage.

    ``cert_specs`` is a list of either bare ``certReqId`` integers or
    ``(certReqId, subject Name|None, SubjectPublicKeyInfo|None)`` tuples,
    so the template can request a specific subject/public key that issued
    certificates are bound to.
    """
    body = rfc4210.PKIBody()
    body.setComponentByName("ir", rfc2511.CertReqMessages().subtype(
        explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0)))
    tagged_messages = body.getComponentByName("ir")
    for index, spec in enumerate(cert_specs):
        if isinstance(spec, (tuple, list)):
            cert_req_id, subject, spki = spec
        else:
            cert_req_id, subject, spki = spec, None, None
        cert_request = rfc2511.CertRequest()
        cert_request.setComponentByName("certReqId", cert_req_id)
        cert_template = rfc2511.CertTemplate()
        if subject is not None:
            subject_field = cert_template.componentType.getTypeByPosition(
                cert_template.componentType.getPositionByName("subject"))
            tagged_subject = subject_field.clone()
            tagged_subject.setComponentByPosition(
                0, subject.getComponentByPosition(0))
            cert_template.setComponentByName("subject", tagged_subject)
        if spki is not None:
            spki_field = cert_template.componentType.getTypeByPosition(
                cert_template.componentType.getPositionByName("publicKey"))
            tagged_spki = spki_field.clone()
            tagged_spki.setComponentByName(
                "algorithm", spki.getComponentByName("algorithm"))
            tagged_spki.setComponentByName(
                "subjectPublicKey",
                spki.getComponentByName("subjectPublicKey"))
            cert_template.setComponentByName("publicKey", tagged_spki)
        cert_request.setComponentByName("certTemplate", cert_template)
        cert_req_msg = rfc2511.CertReqMsg()
        cert_req_msg.setComponentByName("certReq", cert_request)
        tagged_messages.setComponentByPosition(index, cert_req_msg)
    return encode(_message(
        _header(sender, recipient, transaction_id, sender_nonce,
                message_time=message_time), body))


def _status_info(status, failure_bits=None):
    status_info = rfc4210.PKIStatusInfo()
    status_info.setComponentByName("status", status)
    if failure_bits is not None:
        status_info.setComponentByName(
            "failInfo", rfc4210.PKIFailureInfo(failure_bits))
    return status_info


def _cert_response(cert_req_id, status, certificate=None):
    response = rfc4210.CertResponse()
    response.setComponentByName("certReqId", cert_req_id)
    response.setComponentByName(
        "status", _status_info(status))
    if certificate is not None:
        choice = rfc4210.CertOrEncCert()
        # The named CHOICE component already carries the implicit [0] tag.
        schema = choice.componentType.getTypeByPosition(
            choice.componentType.getPositionByName("certificate"))
        tagged_cert = schema.clone()
        tagged_cert.setComponentByName(
            "tbsCertificate",
            certificate.getComponentByName("tbsCertificate"))
        tagged_cert.setComponentByName(
            "signatureAlgorithm",
            certificate.getComponentByName("signatureAlgorithm"))
        tagged_cert.setComponentByName(
            "signatureValue",
            certificate.getComponentByName("signatureValue"))
        choice.setComponentByName("certificate", tagged_cert)
        certified = rfc4210.CertifiedKeyPair()
        certified.setComponentByName("certOrEncCert", choice)
        response.setComponentByName("certifiedKeyPair", certified)
    return response


def ip(results, sender, recipient, transaction_id, sender_nonce,
       recip_nonce, message_time=None):
    """``results``: list of (certReqId, PKIStatus int, CMPCertificate|None)."""
    response_seq = rfc4210.CertRepMessage().getComponentByName("response")
    for index, (cert_req_id, status, certificate) in enumerate(results):
        response_seq.setComponentByPosition(
            index, _cert_response(cert_req_id, status, certificate))
    body = rfc4210.PKIBody()
    body.setComponentByName(
        "ip", rfc4210.CertRepMessage().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 1)))
    body.getComponentByName("ip").setComponentByName(
        "response", response_seq)
    return encode(_message(
        _header(sender, recipient, transaction_id, sender_nonce,
                recip_nonce, message_time), body))


def poll_req(cert_req_ids, sender, recipient, transaction_id,
             sender_nonce, recip_nonce, message_time=None):
    body = rfc4210.PKIBody()
    body.setComponentByName(
        "pollReq", rfc4210.PollReqContent().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 25)))
    content = body.getComponentByName("pollReq")
    for index, cert_req_id in enumerate(cert_req_ids):
        entry = rfc4210.PollReqContent.CertReq()
        entry.setComponentByName("certReqId", cert_req_id)
        content.setComponentByPosition(index, entry)
    return encode(_message(
        _header(sender, recipient, transaction_id, sender_nonce,
                recip_nonce, message_time), body))


def poll_rep(entries, sender, recipient, transaction_id, sender_nonce,
             recip_nonce, message_time=None):
    """``entries``: list of (certReqId, checkAfter seconds)."""
    body = rfc4210.PKIBody()
    body.setComponentByName(
        "pollRep", rfc4210.PollRepContent().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 26)))
    content = body.getComponentByName("pollRep")
    for index, (cert_req_id, check_after) in enumerate(entries):
        rep = rfc4210.PollRepContent.CertReq()
        rep.setComponentByName("certReqId", cert_req_id)
        rep.setComponentByName("checkAfter", check_after)
        content.setComponentByPosition(index, rep)
    return encode(_message(
        _header(sender, recipient, transaction_id, sender_nonce,
                recip_nonce, message_time), body))


def cert_conf(entries, sender, recipient, transaction_id, sender_nonce,
              recip_nonce, message_time=None, reject=False):
    """``entries``: list of (certReqId, certHash bytes)."""
    body = rfc4210.PKIBody()
    body.setComponentByName(
        "certConf", rfc4210.CertConfirmContent().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 24)))
    content = body.getComponentByName("certConf")
    for index, (cert_req_id, cert_hash) in enumerate(entries):
        cert_status = rfc4210.CertStatus()
        cert_status.setComponentByName("certHash", univ.OctetString(cert_hash))
        cert_status.setComponentByName("certReqId", cert_req_id)
        if reject:
            cert_status.setComponentByName(
                "statusInfo", _status_info(
                    int(rfc4210.PKIStatus.namedValues.getValue("rejection"))))
        content.setComponentByPosition(index, cert_status)
    return encode(_message(
        _header(sender, recipient, transaction_id, sender_nonce,
                recip_nonce, message_time), body))


def pki_conf(sender, recipient, transaction_id, sender_nonce,
             recip_nonce, message_time=None):
    body = rfc4210.PKIBody()
    body.setComponentByName(
        "pkiconf", rfc4210.PKIConfirmContent().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 19)))
    return encode(_message(
        _header(sender, recipient, transaction_id, sender_nonce,
                recip_nonce, message_time), body))


def minimal_certificate(serial_number, subject_oid="1.2.3.4",
                        public_key_bytes=b"\x00\x01\x02\x03"):
    """Build a DER-valid (not signed by a real CA) rfc2459 Certificate.

    The signature is a deterministic dummy RSA signature; structure and DER
    are valid, cryptographic verification is out of scope for the offline
    validator.  The demo script uses real CA-signed certificates instead.
    """
    algorithm = rfc2459.AlgorithmIdentifier()
    algorithm.setComponentByName(
        "algorithm", univ.ObjectIdentifier("1.2.840.113549.1.1.11"))
    algorithm.setComponentByName("parameters", univ.Null())

    attr = rfc2459.AttributeTypeAndValue()
    attr.setComponentByName(
        "type", univ.ObjectIdentifier("2.5.4.3"))
    attr.setComponentByName("value", char.UTF8String(
        "minimal-%d" % serial_number))
    rdn = rfc2459.RelativeDistinguishedName()
    rdn.setComponentByPosition(0, attr)
    rdn_seq = rfc2459.RDNSequence()
    rdn_seq.setComponentByPosition(0, rdn)
    name = rfc2459.Name()
    name.setComponentByPosition(0, rdn_seq)
    _ = subject_oid

    spki = rfc2459.SubjectPublicKeyInfo()
    spki.setComponentByName("algorithm", algorithm)
    spki.setComponentByName(
        "subjectPublicKey",
        univ.BitString(hexValue=public_key_bytes.hex()))

    tbs = rfc2459.TBSCertificate()
    tbs.setComponentByName(
        "version",
        rfc2459.Version(2).subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 0)))
    tbs.setComponentByName("serialNumber", serial_number)
    tbs.setComponentByName("signature", algorithm)
    tbs.setComponentByName("issuer", name)
    validity = rfc2459.Validity()
    validity.setComponentByName(
        "notBefore",
        rfc2459.Time().setComponentByName(
            "utcTime", useful.UTCTime("260101000000Z")))
    validity.setComponentByName(
        "notAfter",
        rfc2459.Time().setComponentByName(
            "utcTime", useful.UTCTime("370101000000Z")))
    tbs.setComponentByName("validity", validity)
    tbs.setComponentByName("subject", name)
    tbs.setComponentByName("subjectPublicKeyInfo", spki)

    certificate = rfc4210.CMPCertificate()
    certificate.setComponentByName("tbsCertificate", tbs)
    certificate.setComponentByName("signatureAlgorithm", algorithm)
    certificate.setComponentByName(
        "signatureValue",
        univ.BitString(hexValue=("00" * 16)))
    return certificate
