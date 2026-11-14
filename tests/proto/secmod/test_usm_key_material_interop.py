"""Interop regression for the three USM key-material entry points.

Integrators hand us USM key material in three forms: plain-text
pass-phrases, master (non-localized) keys, and already localized keys.
All three entry points must produce equivalent authenticated and
encrypted messages on the same SNMP engine, while a key localized for
one engine must never authenticate or decrypt traffic of another.

The expected values below are computed independently of the pysnmp
implementation: the password-to-key expansion of RFC 3414 A.2 is
re-implemented in this file with :mod:`hashlib`, applied with SHA-256
as RFC 7860 section 9.3 specifies, the HMAC-SHA-256-192 message digest
follows RFC 7860 section 4, and the AES-128 CFB ciphertext follows
RFC 3826 section 3. Every expectation is checked through the real
``generate_request_message``/``generate_response_message`` and
``process_incoming_message`` paths of the USM security model, never by
comparing internal key variables alone.

The companion table mapping each piece of input material to its engine
identity lives in ``usm_key_material_vectors.md`` next to this file.
"""

import hashlib
import hmac as hmac_module
import time

import pytest
from pyasn1.codec.ber import decoder

from pysnmp import error as pysnmp_error
from pysnmp.entity import config, engine
from pysnmp.proto import errind, error, rfc1902
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414 import localkey, service
from pysnmp.smi.error import NoSuchInstanceError, NoSuchObjectError

# Binary (non-printable) engine identities used throughout the vectors
ENGINE_A_ID = bytes.fromhex("80001f8880ff001020304001")
ENGINE_B_ID = bytes.fromhex("80001f88800100fedcba9802")
ENGINE_C_ID = bytes.fromhex("80001f8880cafe00beefcafe03")

USER_NAME = "usr-interop"
AUTH_PASSWORD = "authPassw0rd!"
PRIV_PASSWORD = "privPassw0rd!"

# RFC 3414 A.2 master keys (SHA-256, RFC 7860 9.3), engine independent
MASTER_AUTH_KEY = bytes.fromhex(
    "3c28b829a6af93f8c0c1e73ffaa3afcb17178ff4dfe439423d05cb6048dc090f"
)
MASTER_PRIV_KEY = bytes.fromhex(
    "e772948eec60a487fb653c36b4e88e40c44bec338a14e18c72b78d557549c410"
)

# Localized keys: master key mixed with the engine identity (SHA-256)
LOCAL_AUTH_KEY_A = bytes.fromhex(
    "4b43a0c4276374eee6ec777c1db235f63b4e952784f521f616233138ac58c08d"
)
LOCAL_PRIV_KEY_A = bytes.fromhex("728305f77414ead88e7687707a09ce89")
LOCAL_AUTH_KEY_B = bytes.fromhex(
    "38e74b4842baa85faf662734c53cac0000f4cb8ec02b6b4b13d650d17b02336b"
)
LOCAL_PRIV_KEY_B = bytes.fromhex("70a60af373680914ce48cfcc12a6ec42")
LOCAL_AUTH_KEY_C = bytes.fromhex(
    "970b5a1b091c43be1deb0c48cd511f7dc646b38f2f85f9ad59ec0ca6dc6025b8"
)
LOCAL_PRIV_KEY_C = bytes.fromhex("6e330f5dff68a613f612a3ddb56729cd")

# Wire vector: authPriv GET request from ENGINE_A to ENGINE_B with
# snmpEngineBoots=1, snmpEngineTime=0, AES salt 0102030405060709,
# msgID=1, request-id=1, HMAC-SHA-256-192 + AES-128-CFB
WIRE_GET_REQUEST_B = bytes.fromhex(
    "30818b020103300e020101020300ffe304010702010304473045040c"
    "80001f88800100fedcba9802020101020100040b7573722d696e7465"
    "726f7004187bfe4cbd4c6b6d91bb14d9ce15876011a7b3ece4bdd52a"
    "1f04080102030405060709042d66353a4ab546bf24204bdc4f75e087"
    "3fd262d49e721ea3036dce1050d671a696ce479b3e3a98aab13b9553"
    "1025"
)
WIRE_AUTH_PARAMETERS = bytes.fromhex("7bfe4cbd4c6b6d91bb14d9ce15876011a7b3ece4bdd52a1f")
WIRE_PRIV_PARAMETERS = bytes.fromhex("0102030405060709")
WIRE_CIPHERTEXT = bytes.fromhex(
    "66353a4ab546bf24204bdc4f75e0873fd262d49e721ea3"
    "036dce1050d671a696ce479b3e3a98aab13b95531025"
)

FIXED_TIME = 1700000000
FIXED_SALT = 0x0102030405060708


def rfc3414_hash_passphrase(passphrase, hash_factory):
    """Expand a pass-phrase into a master key per RFC 3414 A.2."""
    passphrase = passphrase.encode() if isinstance(passphrase, str) else passphrase
    ring_buffer = passphrase * (64 // len(passphrase) + 1)
    hasher = hash_factory()
    count, mark = 0, 0
    while count < 16384:
        end = mark + 64
        if end < len(ring_buffer):
            hasher.update(ring_buffer[mark:end])
            mark = end
        else:
            hasher.update(ring_buffer[mark:] + ring_buffer[: end - len(ring_buffer)])
            mark = end - len(ring_buffer)
        count += 1
    return hasher.digest()


def rfc3414_localize_key(master_key, engine_id, hash_factory):
    """Localize a master key with an engine ID per RFC 3414 A.2."""
    return hash_factory(master_key + engine_id + master_key).digest()


@pytest.fixture(autouse=True)
def frozen_time(monkeypatch):
    """Pin snmpEngineTime so wire vectors stay reproducible."""
    monkeypatch.setattr(time, "time", lambda: FIXED_TIME)


@pytest.fixture(autouse=True)
def fixed_aes_salt():
    """Pin the RFC 3826 salt of the shared AES-128 privacy service."""
    aes_service = service.SnmpUSMSecurityModel.PRIV_SERVICES[config.USM_PRIV_CFB128_AES]
    aes_service.local_int = FIXED_SALT
    yield
    aes_service.local_int = FIXED_SALT


def make_engine(engine_id):
    snmp_engine = engine.SnmpEngine(snmpEngineID=rfc1902.OctetString(engine_id))
    # SnmpEngine persists and bumps snmpEngineBoots for custom engine
    # IDs; pin it so the wire vectors stay reproducible
    (snmp_engine_boots,) = snmp_engine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots"
    )
    snmp_engine_boots.syntax = snmp_engine_boots.syntax.clone(1)
    return snmp_engine


def engine_id_syntax(snmp_engine, engine_id):
    (snmp_engine_id,) = snmp_engine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineID"
    )
    return snmp_engine_id.syntax.clone(engine_id)


def build_scoped_pdu(context_engine_id, pdu):
    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, context_engine_id)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)
    return scoped_pdu


def build_message(msg_flags):
    message = rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3)
    message.setComponentByPosition(1)
    header = message.getComponentByPosition(1)
    header.setComponentByPosition(0, 1)
    header.setComponentByPosition(1, 65507)
    header.setComponentByPosition(2, msg_flags)
    header.setComponentByPosition(3, 3)
    return message


def get_request_pdu():
    pdu = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_request_id(pdu, 1)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)])
    return pdu


def trap_pdu():
    pdu = v2c.SNMPv2TrapPDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_request_id(pdu, 1)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 3, 0), v2c.TimeTicks(123))])
    return pdu


def send_request(snmp_engine, security_engine_id, security_name, security_level, pdu, msg_flags):
    """Run the real USM outgoing-message path for a request/notification."""
    security_engine_id = engine_id_syntax(snmp_engine, security_engine_id)
    scoped_pdu = build_scoped_pdu(security_engine_id, pdu)
    message = build_message(msg_flags)
    _, whole_msg = snmp_engine.security_models[3].generate_request_message(
        snmp_engine,
        3,
        message,
        65507,
        3,
        security_engine_id,
        rfc1902.OctetString(security_name),
        security_level,
        scoped_pdu,
    )
    return whole_msg


def send_response(snmp_engine, security_state_reference, request_scoped_pdu, varbinds):
    """Run the real USM outgoing-message path for a response."""
    request_pdu = request_scoped_pdu.getComponentByPosition(2).getComponent()
    response_pdu = v2c.ResponsePDU()
    v2c.apiPDU.set_defaults(response_pdu)
    v2c.apiPDU.set_request_id(response_pdu, v2c.apiPDU.get_request_id(request_pdu))
    v2c.apiPDU.set_varbinds(response_pdu, varbinds)
    context_engine_id = request_scoped_pdu.getComponentByPosition(0)
    scoped_pdu = build_scoped_pdu(context_engine_id, response_pdu)
    message = build_message(b"\x03")
    _, whole_msg = snmp_engine.security_models[3].generate_response_message(
        snmp_engine, 3, message, 65507, 3, None, None, 3, scoped_pdu,
        security_state_reference, None,
    )
    return whole_msg


def receive_message(snmp_engine, whole_msg):
    """Run the real USM incoming-message path."""
    message, _ = decoder.decode(whole_msg, asn1Spec=rfc3412.SNMPv3Message())
    header = message.getComponentByPosition(1)
    (msg_flags,) = header.getComponentByPosition(2).asNumbers()
    security_parameters = message.getComponentByPosition(2)
    return snmp_engine.security_models[3].process_incoming_message(
        snmp_engine,
        3,
        65507,
        security_parameters,
        3,
        msg_flags & 0x03,
        whole_msg,
        message,
    )


def read_lcd_keys(snmp_engine, engine_id, user_name):
    """Read the pysnmpUsmKeyEntry columns of a configured USM user."""
    mib_builder = snmp_engine.get_mib_builder()
    (usm_user_entry,) = mib_builder.import_symbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )
    (usm_key_entry,) = mib_builder.import_symbols("PYSNMP-USM-MIB", "pysnmpUsmKeyEntry")
    tbl_idx = usm_user_entry.getInstIdFromIndices(
        engine_id_syntax(snmp_engine, engine_id), rfc1902.OctetString(user_name)
    )

    def read_column(column):
        try:
            return usm_key_entry.getNode(usm_key_entry.name + (column,) + tbl_idx).syntax.asOctets()
        except (NoSuchInstanceError, NoSuchObjectError):
            return None

    return {
        "local_auth": read_column(1),
        "local_priv": read_column(2),
        "master_auth": read_column(3),
        "master_priv": read_column(4),
    }


def usm_user_exists(snmp_engine, engine_id, user_name):
    mib_builder = snmp_engine.get_mib_builder()
    (usm_user_entry,) = mib_builder.import_symbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )
    tbl_idx = usm_user_entry.getInstIdFromIndices(
        engine_id_syntax(snmp_engine, engine_id), rfc1902.OctetString(user_name)
    )
    try:
        usm_user_entry.getNode(usm_user_entry.name + (13,) + tbl_idx)
        return True
    except (NoSuchInstanceError, NoSuchObjectError):
        return False


def add_interop_user(snmp_engine, engine_id, auth_key, priv_key, auth_key_type, priv_key_type):
    config.add_v3_user(
        snmp_engine,
        USER_NAME,
        config.USM_AUTH_HMAC192_SHA256,
        auth_key,
        config.USM_PRIV_CFB128_AES,
        priv_key,
        securityEngineId=engine_id,
        authKeyType=auth_key_type,
        privKeyType=priv_key_type,
    )


def run_round_trip(engine_a, engine_b):
    """Exchange trap, request and response between two engines.

    Returns the wire image of the GET request sent by *engine_a*.
    """
    # engine B is authoritative for its notifications: this message
    # also teaches engine A the boots/time timeline of engine B
    whole_trap = send_request(engine_b, ENGINE_B_ID, USER_NAME, 3, trap_pdu(), b"\x03")
    _, security_name, _, _, _ = receive_message(engine_a, whole_trap)
    assert security_name.asOctets() == USER_NAME.encode()

    # engine A sends a confirmed GET request to engine B
    whole_request = send_request(
        engine_a, ENGINE_B_ID, USER_NAME, 3, get_request_pdu(), b"\x07"
    )
    _, security_name, scoped_pdu, _, security_state_reference = receive_message(
        engine_b, whole_request
    )
    assert security_name.asOctets() == USER_NAME.encode()
    request_pdu = scoped_pdu.getComponentByPosition(2).getComponent()
    assert request_pdu.tagSet == v2c.GetRequestPDU.tagSet

    # engine B answers through the cached security state reference
    whole_response = send_response(
        engine_b,
        security_state_reference,
        scoped_pdu,
        [((1, 3, 6, 1, 2, 1, 1, 1, 0), v2c.OctetString("interop"))],
    )
    _, security_name, scoped_pdu, _, _ = receive_message(engine_a, whole_response)
    assert security_name.asOctets() == USER_NAME.encode()
    response_pdu = scoped_pdu.getComponentByPosition(2).getComponent()
    assert response_pdu.tagSet == v2c.ResponsePDU.tagSet

    return whole_request


def test_rfc3414_published_password_to_key_vectors():
    """RFC 3414 A.3 publishes these password-to-key sample results."""
    engine_id = bytes.fromhex("000000000000000000000002")

    assert localkey.hash_passphrase_md5("maplesyrup").asOctets() == bytes.fromhex(
        "9faf3283884e92834ebc9847d8edd963"
    )
    assert localkey.localize_key_md5(
        bytes.fromhex("9faf3283884e92834ebc9847d8edd963"), rfc1902.OctetString(engine_id)
    ).asOctets() == bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")

    assert localkey.hash_passphrase_sha("maplesyrup").asOctets() == bytes.fromhex(
        "9fb5cc0381497b3793528939ff788d5d79145211"
    )
    assert localkey.localize_key_sha(
        bytes.fromhex("9fb5cc0381497b3793528939ff788d5d79145211"), rfc1902.OctetString(engine_id)
    ).asOctets() == bytes.fromhex("6695febc9288e36282235fc7151f128497b38f3f")


def test_rfc7860_sha256_key_derivation_matches_independent_vectors():
    """RFC 7860 9.3 reuses the RFC 3414 A.2 algorithm with SHA-256.

    The expected values are produced by the independent implementation
    at the top of this file and pinned as constants.
    """
    assert rfc3414_hash_passphrase(AUTH_PASSWORD, hashlib.sha256) == MASTER_AUTH_KEY
    assert rfc3414_hash_passphrase(PRIV_PASSWORD, hashlib.sha256) == MASTER_PRIV_KEY
    assert rfc3414_localize_key(MASTER_AUTH_KEY, ENGINE_B_ID, hashlib.sha256) == LOCAL_AUTH_KEY_B
    assert rfc3414_localize_key(MASTER_PRIV_KEY, ENGINE_B_ID, hashlib.sha256)[:16] == LOCAL_PRIV_KEY_B

    # the pysnmp USM services must arrive at the same keys
    auth_service = service.SnmpUSMSecurityModel.AUTH_SERVICES[config.USM_AUTH_HMAC192_SHA256]
    assert auth_service.hash_passphrase(AUTH_PASSWORD).asOctets() == MASTER_AUTH_KEY
    assert (
        auth_service.localize_key(MASTER_AUTH_KEY, rfc1902.OctetString(ENGINE_B_ID)).asOctets()
        == LOCAL_AUTH_KEY_B
    )

    priv_service = service.SnmpUSMSecurityModel.PRIV_SERVICES[config.USM_PRIV_CFB128_AES]
    assert (
        priv_service.hash_passphrase(config.USM_AUTH_HMAC192_SHA256, PRIV_PASSWORD).asOctets()
        == MASTER_PRIV_KEY
    )
    assert (
        priv_service.localize_key(
            config.USM_AUTH_HMAC192_SHA256, MASTER_PRIV_KEY, rfc1902.OctetString(ENGINE_B_ID)
        ).asOctets()
        == LOCAL_PRIV_KEY_B
    )


@pytest.mark.parametrize(
    "key_type, auth_material, priv_material",
    [
        (config.USM_KEY_TYPE_PASSPHRASE, AUTH_PASSWORD, PRIV_PASSWORD),
        (config.USM_KEY_TYPE_MASTER, MASTER_AUTH_KEY, MASTER_PRIV_KEY),
        (config.USM_KEY_TYPE_LOCALIZED, LOCAL_AUTH_KEY_B, LOCAL_PRIV_KEY_B),
    ],
    ids=["passphrase", "master-key", "localized-key"],
)
def test_key_material_entry_points_produce_identical_wire_messages(
    key_type, auth_material, priv_material
):
    """Pass-phrase, master key and localized key are interchangeable.

    All three entry points must localize to the same per-engine keys in
    the LCD and emit the very same authenticated and encrypted messages
    over the real send/receive paths.
    """
    snmp_engine_a = make_engine(ENGINE_A_ID)
    snmp_engine_b = make_engine(ENGINE_B_ID)

    # engine B terminates the traffic, its user is keyed for its own ID
    add_interop_user(
        snmp_engine_b,
        None,
        auth_material,
        priv_material,
        key_type,
        key_type,
    )
    # engine A originates requests towards authoritative engine B
    add_interop_user(
        snmp_engine_a,
        ENGINE_B_ID,
        auth_material,
        priv_material,
        key_type,
        key_type,
    )

    for snmp_engine, engine_id in (
        (snmp_engine_a, ENGINE_B_ID),
        (snmp_engine_b, ENGINE_B_ID),
    ):
        lcd_keys = read_lcd_keys(snmp_engine, engine_id, USER_NAME)
        assert lcd_keys["local_auth"] == LOCAL_AUTH_KEY_B
        assert lcd_keys["local_priv"] == LOCAL_PRIV_KEY_B
        if key_type == config.USM_KEY_TYPE_LOCALIZED:
            # a localized entry keeps no master key: it cannot be
            # re-localized towards another engine
            assert lcd_keys["master_auth"] == b"\x00" * 8
            assert lcd_keys["master_priv"] == b"\x00" * 8
        else:
            # pass-phrase and master key entries stay re-localizable
            assert lcd_keys["master_auth"] == MASTER_AUTH_KEY
            assert lcd_keys["master_priv"] == MASTER_PRIV_KEY

    whole_request = run_round_trip(snmp_engine_a, snmp_engine_b)

    # the wire image is fully determined by the localized keys
    assert whole_request == WIRE_GET_REQUEST_B


def test_wire_vector_matches_independent_rfc7860_and_rfc3826_computation():
    """The pinned wire vector verifies against independent crypto."""
    message, _ = decoder.decode(WIRE_GET_REQUEST_B, asn1Spec=rfc3412.SNMPv3Message())
    security_parameters, _ = decoder.decode(
        message.getComponentByPosition(2).asOctets(),
        asn1Spec=service.UsmSecurityParameters(),
    )
    assert security_parameters.getComponentByPosition(0).asOctets() == ENGINE_B_ID
    assert int(security_parameters.getComponentByPosition(1)) == 1
    assert int(security_parameters.getComponentByPosition(2)) == 0
    assert security_parameters.getComponentByPosition(3).asOctets() == USER_NAME.encode()
    auth_parameters = security_parameters.getComponentByPosition(4).asOctets()
    priv_parameters = security_parameters.getComponentByPosition(5).asOctets()
    assert auth_parameters == WIRE_AUTH_PARAMETERS
    assert priv_parameters == WIRE_PRIV_PARAMETERS

    # RFC 7860 4: HMAC-SHA-256 over the message with a zeroed digest
    # field, truncated to 192 bits
    location = WIRE_GET_REQUEST_B.find(auth_parameters)
    assert location != -1
    zeroed_message = (
        WIRE_GET_REQUEST_B[:location] + b"\x00" * 24 + WIRE_GET_REQUEST_B[location + 24 :]
    )
    assert (
        hmac_module.new(LOCAL_AUTH_KEY_B, zeroed_message, hashlib.sha256).digest()[:24]
        == auth_parameters
    )

    # RFC 3826 3.2.4.2: IV is boots || time || salt, key is the first
    # 16 octets of the localized privacy key
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    ciphertext = message.getComponentByPosition(3).getComponentByPosition(1).asOctets()
    assert ciphertext == WIRE_CIPHERTEXT
    iv = (1).to_bytes(4, "big") + (0).to_bytes(4, "big") + priv_parameters
    decryptor = Cipher(algorithms.AES(LOCAL_PRIV_KEY_B), CFB(iv)).decryptor()
    scoped_pdu, _ = decoder.decode(
        decryptor.update(ciphertext) + decryptor.finalize(),
        asn1Spec=rfc3412.ScopedPDU(),
    )
    pdu = scoped_pdu.getComponentByPosition(2).getComponent()
    assert pdu.tagSet == v2c.GetRequestPDU.tagSet
    assert int(v2c.apiPDU.get_request_id(pdu)) == 1


def test_auth_and_priv_may_use_different_passwords_and_entry_points():
    """Auth and privacy key material are derived independently.

    The privacy password differs from the authentication password, and
    each may enter through a different entry point (pass-phrase for
    auth, master key for privacy). The privacy key is derived with the
    hash of the *authentication* protocol (SHA-256 here) per RFC 7860
    9.3, never with the privacy protocol itself.
    """
    snmp_engine_a = make_engine(ENGINE_A_ID)
    snmp_engine_b = make_engine(ENGINE_B_ID)

    for snmp_engine, engine_id in (
        (snmp_engine_a, ENGINE_B_ID),
        (snmp_engine_b, None),
    ):
        config.add_v3_user(
            snmp_engine,
            USER_NAME,
            config.USM_AUTH_HMAC192_SHA256,
            AUTH_PASSWORD,
            config.USM_PRIV_CFB128_AES,
            MASTER_PRIV_KEY,
            securityEngineId=engine_id,
            authKeyType=config.USM_KEY_TYPE_PASSPHRASE,
            privKeyType=config.USM_KEY_TYPE_MASTER,
        )
        lcd_keys = read_lcd_keys(snmp_engine, engine_id or ENGINE_B_ID, USER_NAME)
        assert lcd_keys["local_auth"] == LOCAL_AUTH_KEY_B
        assert lcd_keys["local_priv"] == LOCAL_PRIV_KEY_B

    whole_request = run_round_trip(snmp_engine_a, snmp_engine_b)
    assert whole_request == WIRE_GET_REQUEST_B


def test_binary_engine_id_drives_key_localization():
    """Engine identities are binary strings, not printable text.

    The same master key localized under the three binary engine IDs
    yields three distinct key sets; each is functional on its own
    engine only.
    """
    for engine_id in (ENGINE_A_ID, ENGINE_B_ID, ENGINE_C_ID):
        assert any(byte < 0x20 or byte > 0x7E for byte in engine_id)

    snmp_engine_a = make_engine(ENGINE_A_ID)
    snmp_engine_b = make_engine(ENGINE_B_ID)

    # engine A acts authoritatively (sends a notification) with keys
    # localized for its own binary engine ID
    add_interop_user(
        snmp_engine_a,
        None,
        MASTER_AUTH_KEY,
        MASTER_PRIV_KEY,
        config.USM_KEY_TYPE_MASTER,
        config.USM_KEY_TYPE_MASTER,
    )
    # engine B holds the peer entry keyed for engine A's identity
    add_interop_user(
        snmp_engine_b,
        ENGINE_A_ID,
        LOCAL_AUTH_KEY_A,
        LOCAL_PRIV_KEY_A,
        config.USM_KEY_TYPE_LOCALIZED,
        config.USM_KEY_TYPE_LOCALIZED,
    )

    assert read_lcd_keys(snmp_engine_a, ENGINE_A_ID, USER_NAME)["local_auth"] == LOCAL_AUTH_KEY_A
    assert read_lcd_keys(snmp_engine_a, ENGINE_A_ID, USER_NAME)["local_priv"] == LOCAL_PRIV_KEY_A
    assert LOCAL_AUTH_KEY_A != LOCAL_AUTH_KEY_B != LOCAL_AUTH_KEY_C

    whole_trap = send_request(snmp_engine_a, ENGINE_A_ID, USER_NAME, 3, trap_pdu(), b"\x03")
    _, security_name, _, _, _ = receive_message(snmp_engine_b, whole_trap)
    assert security_name.asOctets() == USER_NAME.encode()


def test_master_key_is_relocalizable_but_localized_key_is_not():
    """A master key serves any engine; a localized key only its own.

    The same master key configured for two engine identities yields
    different localized keys in each LCD row, while a localized entry
    point stores no master key and therefore cannot be re-localized.
    """
    snmp_engine = make_engine(ENGINE_A_ID)

    add_interop_user(
        snmp_engine,
        ENGINE_B_ID,
        MASTER_AUTH_KEY,
        MASTER_PRIV_KEY,
        config.USM_KEY_TYPE_MASTER,
        config.USM_KEY_TYPE_MASTER,
    )
    config.add_v3_user(
        snmp_engine,
        "usr-other",
        config.USM_AUTH_HMAC192_SHA256,
        MASTER_AUTH_KEY,
        config.USM_PRIV_CFB128_AES,
        MASTER_PRIV_KEY,
        securityEngineId=ENGINE_C_ID,
        authKeyType=config.USM_KEY_TYPE_MASTER,
        privKeyType=config.USM_KEY_TYPE_MASTER,
    )

    keys_for_b = read_lcd_keys(snmp_engine, ENGINE_B_ID, USER_NAME)
    keys_for_c = read_lcd_keys(snmp_engine, ENGINE_C_ID, "usr-other")
    assert keys_for_b["local_auth"] == LOCAL_AUTH_KEY_B
    assert keys_for_c["local_auth"] == LOCAL_AUTH_KEY_C
    assert keys_for_b["local_auth"] != keys_for_c["local_auth"]
    # both rows stay re-localizable: the master key is on record
    assert keys_for_b["master_auth"] == MASTER_AUTH_KEY
    assert keys_for_c["master_auth"] == MASTER_AUTH_KEY

    # a localized entry point leaves no master key behind
    config.add_v3_user(
        snmp_engine,
        "usr-local",
        config.USM_AUTH_HMAC192_SHA256,
        LOCAL_AUTH_KEY_B,
        config.USM_PRIV_CFB128_AES,
        LOCAL_PRIV_KEY_B,
        securityEngineId=ENGINE_B_ID,
        authKeyType=config.USM_KEY_TYPE_LOCALIZED,
        privKeyType=config.USM_KEY_TYPE_LOCALIZED,
    )
    keys_local = read_lcd_keys(snmp_engine, ENGINE_B_ID, "usr-local")
    assert keys_local["local_auth"] == LOCAL_AUTH_KEY_B
    assert keys_local["master_auth"] == b"\x00" * 8
    assert keys_local["master_priv"] == b"\x00" * 8


def test_localized_key_of_engine_a_is_not_accepted_at_engine_c():
    """A key localized for one engine must not serve another.

    Engine C is deliberately misconfigured with key material localized
    for engine B; the real receive path must reject engine B's traffic
    instead of authenticating it with the wrong localized key.
    """
    snmp_engine_b = make_engine(ENGINE_B_ID)
    snmp_engine_c = make_engine(ENGINE_C_ID)

    add_interop_user(
        snmp_engine_b,
        None,
        AUTH_PASSWORD,
        PRIV_PASSWORD,
        config.USM_KEY_TYPE_PASSPHRASE,
        config.USM_KEY_TYPE_PASSPHRASE,
    )
    # misconfiguration: B's localized keys registered at engine C
    add_interop_user(
        snmp_engine_c,
        ENGINE_B_ID,
        LOCAL_AUTH_KEY_B,
        LOCAL_PRIV_KEY_B,
        config.USM_KEY_TYPE_LOCALIZED,
        config.USM_KEY_TYPE_LOCALIZED,
    )

    # engine C's own correctly localized keys for the same passwords
    # differ, so accepting B's message would mean key confusion
    assert LOCAL_AUTH_KEY_B != LOCAL_AUTH_KEY_C

    whole_trap = send_request(snmp_engine_b, ENGINE_B_ID, USER_NAME, 3, trap_pdu(), b"\x03")

    # engine C does know B's localized keys, so this message verifies;
    # replace them with C-localized material and it must not
    _, security_name, _, _, _ = receive_message(snmp_engine_c, whole_trap)
    assert security_name.asOctets() == USER_NAME.encode()

    config.add_v3_user(
        snmp_engine_c,
        USER_NAME,
        config.USM_AUTH_HMAC192_SHA256,
        LOCAL_AUTH_KEY_C,
        config.USM_PRIV_CFB128_AES,
        LOCAL_PRIV_KEY_C,
        securityEngineId=ENGINE_B_ID,
        authKeyType=config.USM_KEY_TYPE_LOCALIZED,
        privKeyType=config.USM_KEY_TYPE_LOCALIZED,
    )
    with pytest.raises(error.StatusInformation) as raised:
        receive_message(snmp_engine_c, whole_trap)
    assert raised.value["errorIndication"] is errind.authenticationFailure


BAD_USER_KWARGS = {
    "unknown-auth-key-type": dict(authKeyType=5),
    "unknown-priv-key-type": dict(privKeyType=3),
    "short-localized-auth-key": dict(
        authKey=b"\x01" * 16, authKeyType=config.USM_KEY_TYPE_LOCALIZED
    ),
    "long-localized-auth-key": dict(
        authKey=b"\x01" * 20, authKeyType=config.USM_KEY_TYPE_LOCALIZED
    ),
    "short-master-auth-key": dict(
        authKey=b"\x01" * 16, authKeyType=config.USM_KEY_TYPE_MASTER
    ),
    "short-master-priv-key": dict(
        privKey=b"\x01" * 16, privKeyType=config.USM_KEY_TYPE_MASTER
    ),
    "short-localized-priv-key": dict(
        privKey=b"\x01" * 8, privKeyType=config.USM_KEY_TYPE_LOCALIZED
    ),
    "unknown-auth-protocol": dict(authProtocol=(1, 3, 6, 1, 4, 1, 99999, 1)),
    "unknown-priv-protocol": dict(privProtocol=(1, 3, 6, 1, 4, 1, 99999, 2)),
}


@pytest.mark.parametrize("bad_kwargs", BAD_USER_KWARGS.values(), ids=BAD_USER_KWARGS.keys())
def test_invalid_key_material_leaves_no_half_configured_user(bad_kwargs):
    """Wrong key type or length must not reach the LCD.

    A rejected attempt must leave no user row that only looks usable,
    and must not clobber a previously configured working user either.
    """
    snmp_engine = make_engine(ENGINE_B_ID)

    user_kwargs = dict(
        authProtocol=config.USM_AUTH_HMAC192_SHA256,
        authKey=AUTH_PASSWORD,
        privProtocol=config.USM_PRIV_CFB128_AES,
        privKey=PRIV_PASSWORD,
    )
    user_kwargs.update(bad_kwargs)

    with pytest.raises(pysnmp_error.PySnmpError):
        config.add_v3_user(snmp_engine, USER_NAME, **user_kwargs)
    assert not usm_user_exists(snmp_engine, ENGINE_B_ID, USER_NAME)

    # a working user survives a later failed reconfiguration attempt
    config.add_v3_user(
        snmp_engine,
        USER_NAME,
        config.USM_AUTH_HMAC192_SHA256,
        AUTH_PASSWORD,
        config.USM_PRIV_CFB128_AES,
        PRIV_PASSWORD,
    )
    with pytest.raises(pysnmp_error.PySnmpError):
        config.add_v3_user(snmp_engine, USER_NAME, **user_kwargs)
    assert usm_user_exists(snmp_engine, ENGINE_B_ID, USER_NAME)
    lcd_keys = read_lcd_keys(snmp_engine, ENGINE_B_ID, USER_NAME)
    assert lcd_keys["local_auth"] == LOCAL_AUTH_KEY_B
    assert lcd_keys["local_priv"] == LOCAL_PRIV_KEY_B
