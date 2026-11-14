"""Offline prototype for a private USM AES-GCM privacy extension.

This is a design-validation test, not a production feature. It registers a
throw-away privacy service under a PySNMP enterprise arc, builds real
SNMPv3/USM authPriv messages through the existing security model, and pins
down which layer rejects each mutation.

The private OID is deliberately outside ``snmpPrivProtocols`` and outside
``usmAesCfb128Protocol``. Nothing here changes default algorithms.
"""

from __future__ import annotations

import inspect
import secrets
import struct

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyasn1.codec.ber import decoder
from pyasn1.type import univ

from pysnmp.entity import config, engine
from pysnmp.proto import errind, error
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414 import service
from pysnmp.proto.secmod.rfc3826.priv.aes import Aes

# PySNMP enterprise 20408, private experimental branch. Not a standards OID.
GCM_SERVICE_ID = (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1, 9, 1)
GCM_LABEL = b"PySNMP-USM-GCM-private-v1"
NONCE_SIZE = 12
TAG_SIZE = 16


class PrivateGcm(Aes):
    """AES-128-GCM with a private, non-standard USM shape.

    ``msgPrivacyParameters`` = 12-byte nonce || 16-byte tag.
    ``encryptedPDU`` = ciphertext only, same length as the BER scopedPDU.

    The USM privacy service interface receives only the localized key,
    ``(boots, time, privParameters)`` and the data. It has no engine ID,
    user name, msgID, msgFlags, security level or context argument, so the
    AAD can only bind what is available here.
    """

    SERVICE_ID = GCM_SERVICE_ID
    KEY_SIZE = 16

    # Test hook for deterministic nonces. Production must use a fresh
    # random 96-bit nonce per message; reusing a nonce with AES-GCM is
    # catastrophic.
    nonce_factory = staticmethod(lambda: secrets.token_bytes(NONCE_SIZE))

    @staticmethod
    def _aad(boots: int, engine_time: int) -> bytes:
        return GCM_LABEL + struct.pack("!II", int(boots), int(engine_time))

    def encrypt_data(self, encryptKey, privParameters, dataToEncrypt):
        boots, engine_time, _ = privParameters
        key = encryptKey.asOctets()[: self.KEY_SIZE]
        nonce = self.nonce_factory()
        sealed = AESGCM(key).encrypt(
            nonce, bytes(dataToEncrypt), self._aad(boots, engine_time)
        )
        ciphertext, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]
        return univ.OctetString(ciphertext), univ.OctetString(nonce + tag)

    def decrypt_data(self, decryptKey, privParameters, encryptedData):
        boots, engine_time, params = privParameters
        params = bytes(params)
        if len(params) != NONCE_SIZE + TAG_SIZE:
            raise error.StatusInformation(errorIndication=errind.decryptionError)
        nonce, tag = params[:NONCE_SIZE], params[NONCE_SIZE:]
        key = decryptKey.asOctets()[: self.KEY_SIZE]
        try:
            return AESGCM(key).decrypt(
                nonce,
                bytes(encryptedData) + tag,
                self._aad(boots, engine_time),
            )
        except InvalidTag:
            raise error.StatusInformation(errorIndication=errind.decryptionError)


@pytest.fixture
def gcm_engine(monkeypatch):
    monkeypatch.setitem(config.PRIV_SERVICES, GCM_SERVICE_ID, PrivateGcm())
    snmp_engine = engine.SnmpEngine()
    config.add_v3_user(
        snmp_engine,
        "gcm-user",
        authProtocol=config.USM_AUTH_HMAC96_SHA,
        authKey="auth-passphrase",
        privProtocol=GCM_SERVICE_ID,
        privKey="priv-passphrase",
    )
    yield snmp_engine, PrivateGcm()


def _localized_keys(snmp_engine, security_engine_id: bytes, user_name: bytes):
    mib_builder = snmp_engine.get_mib_builder()
    (usm_user_entry,) = mib_builder.import_symbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )
    (key_entry,) = mib_builder.import_symbols("PYSNMP-USM-MIB", "pysnmpUsmKeyEntry")
    idx = usm_user_entry.getInstIdFromIndices(security_engine_id, user_name)
    auth = key_entry.getNode(key_entry.name + (1,) + idx).syntax.asOctets()
    priv = key_entry.getNode(key_entry.name + (2,) + idx).syntax.asOctets()
    return auth, priv


def _scoped_pdu(snmp_engine, context_name=b"ctx-a"):
    pdu = v2c.ResponsePDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_request_id(pdu, 1234)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)])

    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, snmp_engine.snmpEngineID)
    scoped_pdu.setComponentByPosition(1, context_name)
    scoped_pdu.getComponentByPosition(2).setComponentByType(
        pdu.tagSet,
        pdu,
        verifyConstraints=False,
        matchTags=False,
        matchConstraints=False,
    )
    return scoped_pdu


def _build_message(snmp_engine, context_name=b"ctx-a", security_level=3):
    scoped_pdu = _scoped_pdu(snmp_engine, context_name)
    msg = rfc3412.SNMPv3Message()
    msg.setComponentByPosition(0, 3)
    header = msg.setComponentByPosition(1).getComponentByPosition(1)
    header.setComponentByPosition(0, 777)
    header.setComponentByPosition(1, 65507)
    header.setComponentByPosition(
        2, {1: b"\x00", 2: b"\x01", 3: b"\x03"}[security_level]
    )
    header.setComponentByPosition(3, 3)

    auth_key, priv_key = _localized_keys(
        snmp_engine, snmp_engine.snmpEngineID.asOctets(), b"gcm-user"
    )
    state_reference = snmp_engine.security_models[3]._cache.push(
        msgUserName=b"gcm-user",
        usmUserSecurityName="gcm-user",
        usmUserAuthProtocol=config.USM_AUTH_HMAC96_SHA,
        usmUserAuthKeyLocalized=univ.OctetString(auth_key),
        usmUserPrivProtocol=GCM_SERVICE_ID,
        usmUserPrivKeyLocalized=univ.OctetString(priv_key),
    )
    (security_parameters, whole_msg) = snmp_engine.security_models[
        3
    ].generate_response_message(
        snmp_engine,
        3,
        msg,
        65507,
        3,
        snmp_engine.snmpEngineID,
        "gcm-user",
        security_level,
        scoped_pdu,
        state_reference,
        None,
    )
    return security_parameters, whole_msg


def _decode(whole_msg):
    msg, _ = decoder.decode(whole_msg, asn1Spec=rfc3412.SNMPv3Message())
    return msg, msg.getComponentByPosition(2)


def _process(snmp_engine, whole_msg):
    msg, sec_params = _decode(whole_msg)
    flags = msg.getComponentByPosition(1).getComponentByPosition(2).asOctets()[0]
    security_level = {0x00: 1, 0x01: 2, 0x03: 3}[flags & 0x03]
    try:
        result = snmp_engine.security_models[3].process_incoming_message(
            snmp_engine, 3, 65507, sec_params, 3, security_level, whole_msg, msg
        )
        return "OK", result[2].getComponentByPosition(1).asOctets()
    except error.StatusInformation as exc:
        return exc["errorIndication"].__str__(), exc.get("oid")


def _replace(whole_msg, old, new):
    assert len(old) == len(new)
    index = whole_msg.find(old)
    assert index >= 0
    return whole_msg[:index] + new + whole_msg[index + len(old) :]


def _flip(data, index):
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def test_baseline_private_gcm_message_is_accepted(gcm_engine):
    snmp_engine, _ = gcm_engine
    _, whole_msg = _build_message(snmp_engine)
    outcome, context = _process(snmp_engine, whole_msg)
    assert outcome == "OK"
    assert context == b"ctx-a"


def test_engine_identity_change_fails_at_hmac(gcm_engine):
    snmp_engine, _ = gcm_engine
    auth_key, priv_key = _localized_keys(
        snmp_engine, snmp_engine.snmpEngineID.asOctets(), b"gcm-user"
    )
    original_id = snmp_engine.snmpEngineID.asOctets()
    changed_id = original_id[:-1] + bytes([original_id[-1] ^ 0x01])
    config.add_v3_user(
        snmp_engine,
        "gcm-user",
        authProtocol=config.USM_AUTH_HMAC96_SHA,
        authKey=auth_key,
        privProtocol=GCM_SERVICE_ID,
        privKey=priv_key,
        securityEngineId=changed_id,
        authKeyType=config.USM_KEY_TYPE_LOCALIZED,
        privKeyType=config.USM_KEY_TYPE_LOCALIZED,
    )
    _, whole_msg = _build_message(snmp_engine)
    outcome, _ = _process(snmp_engine, _replace(whole_msg, original_id, changed_id))
    assert outcome == "Authenticator mismatched"


def test_engine_identity_change_without_local_user_fails_earlier(gcm_engine):
    snmp_engine, _ = gcm_engine
    original_id = snmp_engine.snmpEngineID.asOctets()
    changed_id = original_id[:-1] + bytes([original_id[-1] ^ 0x01])
    _, whole_msg = _build_message(snmp_engine)
    outcome, _ = _process(snmp_engine, _replace(whole_msg, original_id, changed_id))
    assert outcome == "Unknown SNMP security name encountered"


def test_ciphertext_changes_fail_at_hmac(gcm_engine):
    snmp_engine, _ = gcm_engine
    _, whole_msg = _build_message(snmp_engine)
    msg, _ = _decode(whole_msg)
    ciphertext = msg.getComponentByPosition(3).getComponentByPosition(1).asOctets()
    first = whole_msg.find(ciphertext)
    for offset in (0, len(ciphertext) // 2, len(ciphertext) - 1):
        mutated = _flip(whole_msg, first + offset)
        outcome, _ = _process(snmp_engine, mutated)
        assert outcome == "Authenticator mismatched"


def test_context_ciphertext_splice_fails_at_hmac(gcm_engine):
    snmp_engine, _ = gcm_engine
    _, whole_msg_a = _build_message(snmp_engine, context_name=b"ctx-a")
    _, whole_msg_b = _build_message(snmp_engine, context_name=b"ctx-b")
    msg_a, _ = _decode(whole_msg_a)
    msg_b, _ = _decode(whole_msg_b)
    ciphertext_a = msg_a.getComponentByPosition(3).getComponentByPosition(1).asOctets()
    ciphertext_b = msg_b.getComponentByPosition(3).getComponentByPosition(1).asOctets()
    assert len(ciphertext_a) == len(ciphertext_b)
    # Replacing the encrypted scopedPDU (which carries the context name)
    # while keeping A's HMAC must fail before GCM is reached.
    spliced = _replace(whole_msg_a, ciphertext_a, ciphertext_b)
    outcome, _ = _process(snmp_engine, spliced)
    assert outcome == "Authenticator mismatched"


def test_same_nonce_different_context_changes_ciphertext_and_tag(
    gcm_engine, monkeypatch
):
    snmp_engine, plugin = gcm_engine
    monkeypatch.setattr(
        PrivateGcm, "nonce_factory", staticmethod(lambda: b"\x00" * NONCE_SIZE)
    )
    _, priv_key = _localized_keys(
        snmp_engine, snmp_engine.snmpEngineID.asOctets(), b"gcm-user"
    )
    _, whole_msg_a = _build_message(snmp_engine, context_name=b"ctx-a")
    _, whole_msg_b = _build_message(snmp_engine, context_name=b"ctx-b")
    msg_a, sec_a = _decode(whole_msg_a)
    msg_b, _ = _decode(whole_msg_b)
    ciphertext_a = msg_a.getComponentByPosition(3).getComponentByPosition(1)
    ciphertext_b = msg_b.getComponentByPosition(3).getComponentByPosition(1)
    assert ciphertext_a != ciphertext_b

    sec_params, _ = decoder.decode(sec_a, asn1Spec=service.UsmSecurityParameters())
    priv_params = sec_params.getComponentByPosition(5)
    assert priv_params.asOctets()[:NONCE_SIZE] == b"\x00" * NONCE_SIZE

    # With the same nonce (test-only), a different context yields a
    # different ciphertext and the old tag no longer verifies. This is
    # why GCM binds context through ciphertext integrity, not AAD.
    with pytest.raises(error.StatusInformation) as raised:
        plugin.decrypt_data(
            univ.OctetString(priv_key),
            (sec_params[1], sec_params[2], priv_params),
            ciphertext_b,
        )
    assert raised.value["errorIndication"] is errind.decryptionError


def test_privacy_parameters_change_fails_at_hmac(gcm_engine):
    snmp_engine, _ = gcm_engine
    _, whole_msg = _build_message(snmp_engine)
    msg, sec_params_bytes = _decode(whole_msg)
    sec_params, _ = decoder.decode(
        sec_params_bytes, asn1Spec=service.UsmSecurityParameters()
    )
    priv_params = sec_params.getComponentByPosition(5).asOctets()
    mutated = _flip(whole_msg, whole_msg.find(priv_params) + 1)
    outcome, _ = _process(snmp_engine, mutated)
    assert outcome == "Authenticator mismatched"


def test_plugin_alone_rejects_ciphertext_nonce_and_tag_changes(gcm_engine):
    snmp_engine, plugin = gcm_engine
    _, priv_key = _localized_keys(
        snmp_engine, snmp_engine.snmpEngineID.asOctets(), b"gcm-user"
    )
    _, whole_msg = _build_message(snmp_engine)
    msg, sec_params_bytes = _decode(whole_msg)
    sec_params, _ = decoder.decode(
        sec_params_bytes, asn1Spec=service.UsmSecurityParameters()
    )
    ciphertext = msg.getComponentByPosition(3).getComponentByPosition(1)
    priv_params = sec_params.getComponentByPosition(5)
    key = univ.OctetString(priv_key)

    cases = {
        "ciphertext": (
            univ.OctetString(_flip(ciphertext.asOctets(), 0)),
            priv_params,
        ),
        "nonce": (
            ciphertext,
            univ.OctetString(_flip(priv_params.asOctets(), 0)),
        ),
        "tag": (
            ciphertext,
            univ.OctetString(_flip(priv_params.asOctets(), NONCE_SIZE)),
        ),
    }
    for name, (ct, params) in cases.items():
        with pytest.raises(error.StatusInformation) as raised:
            plugin.decrypt_data(key, (sec_params[1], sec_params[2], params), ct)
        assert raised.value["errorIndication"] is errind.decryptionError


def test_plugin_signature_has_no_engine_user_or_context(gcm_engine):
    _, plugin = gcm_engine
    signature = inspect.signature(plugin.decrypt_data)
    assert list(signature.parameters) == [
        "decryptKey",
        "privParameters",
        "encryptedData",
    ]
    encrypt_signature = inspect.signature(plugin.encrypt_data)
    assert list(encrypt_signature.parameters) == [
        "encryptKey",
        "privParameters",
        "dataToEncrypt",
    ]
    parameter_names = " ".join(
        list(signature.parameters) + list(encrypt_signature.parameters)
    ).lower()
    for unavailable in ("engine", "user", "context", "msgid", "flags"):
        assert unavailable not in parameter_names


def test_intact_message_replay_within_window_is_accepted(gcm_engine):
    snmp_engine, _ = gcm_engine
    _, whole_msg = _build_message(snmp_engine)
    first, _ = _process(snmp_engine, whole_msg)
    second, _ = _process(snmp_engine, whole_msg)
    assert first == "OK"
    assert second == "OK"


def test_retransmission_rebuilds_nonce_and_ciphertext(gcm_engine):
    snmp_engine, _ = gcm_engine
    sec_params_1, whole_msg_1 = _build_message(snmp_engine)
    sec_params_2, whole_msg_2 = _build_message(snmp_engine)
    msg_1, _ = _decode(whole_msg_1)
    msg_2, _ = _decode(whole_msg_2)
    priv_1 = msg_1.getComponentByPosition(2)
    priv_2 = msg_2.getComponentByPosition(2)
    assert priv_1 != priv_2
    assert msg_1.getComponentByPosition(3) != msg_2.getComponentByPosition(3)


def test_priv_to_authnopriv_downgrade_is_rejected_by_usm(gcm_engine):
    snmp_engine, _ = gcm_engine
    # A valid authNoPriv message would authenticate, but the authoritative
    # engine still rejects it because the configured user supports privacy.
    _, whole_msg = _build_message(snmp_engine, security_level=2)
    outcome, _ = _process(snmp_engine, whole_msg)
    assert outcome == "Unsupported SNMP security level"


def test_noauthnopriv_downgrade_is_rejected_by_usm(gcm_engine):
    snmp_engine, _ = gcm_engine
    _, whole_msg = _build_message(snmp_engine, security_level=1)
    outcome, _ = _process(snmp_engine, whole_msg)
    assert outcome == "Unsupported SNMP security level"


def test_decryption_error_report_is_noauthnopriv(gcm_engine):
    snmp_engine, _ = gcm_engine
    report_pdu = v2c.ReportPDU()
    v2c.apiPDU.set_defaults(report_pdu)
    v2c.apiPDU.set_varbinds(
        report_pdu,
        [((1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0), v2c.Integer(1))],
    )
    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, snmp_engine.snmpEngineID)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByType(
        report_pdu.tagSet,
        report_pdu,
        verifyConstraints=False,
        matchTags=False,
        matchConstraints=False,
    )

    msg = rfc3412.SNMPv3Message()
    msg.setComponentByPosition(0, 3)
    header = msg.setComponentByPosition(1).getComponentByPosition(1)
    header.setComponentByPosition(0, 777)
    header.setComponentByPosition(1, 65507)
    header.setComponentByPosition(2, b"\x03")
    header.setComponentByPosition(3, 3)

    auth_key, priv_key = _localized_keys(
        snmp_engine, snmp_engine.snmpEngineID.asOctets(), b"gcm-user"
    )
    state_reference = snmp_engine.security_models[3]._cache.push(
        msgUserName=b"gcm-user",
        usmUserSecurityName="gcm-user",
        usmUserAuthProtocol=config.USM_AUTH_HMAC96_SHA,
        usmUserAuthKeyLocalized=univ.OctetString(auth_key),
        usmUserPrivProtocol=GCM_SERVICE_ID,
        usmUserPrivKeyLocalized=univ.OctetString(priv_key),
    )
    security_parameters, whole_msg = snmp_engine.security_models[
        3
    ].generate_response_message(
        snmp_engine,
        3,
        msg,
        65507,
        3,
        snmp_engine.snmpEngineID,
        "gcm-user",
        3,
        scoped_pdu,
        state_reference,
        errind.decryptionError,
    )
    msg, _ = _decode(whole_msg)
    assert msg.getComponentByPosition(1).getComponentByPosition(2) == b"\x04"
    sec_params, _ = decoder.decode(
        security_parameters, asn1Spec=service.UsmSecurityParameters()
    )
    assert sec_params.getComponentByPosition(4).asOctets() == b""
    assert sec_params.getComponentByPosition(5).asOctets() == b""
