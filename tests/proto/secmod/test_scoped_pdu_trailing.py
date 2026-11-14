"""Structured fuzz tests for encrypted SNMPv3 scopedPDU boundary handling.

A decrypted scopedPDU substrate must hold exactly one BER-encoded
ScopedPDU. Block ciphers (DES/3DES) may leave up to one padding block
behind; stream ciphers (AES CFB) leave nothing. Anything beyond that is
smuggled data, not padding, and must never reach management
applications.

Every sample here carries a valid HMAC produced with localized keys, so
the authentication layer never filters a sample out before the privacy
layer gets to judge it. Plaintext scopedPDUs are assembled independently
and encrypted through the stock DES/AES privacy backends.

Each sample records the actual consumption range of every layer:

* ciphertext length (privacy layer input)
* decrypted substrate length (privacy layer output)
* scopedPDU consumption (BER layer) and the trailing remainder
"""

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error
import pytest

from pysnmp.entity import config, engine
from pysnmp.proto import errind, error
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414 import service
from pysnmp.proto.secmod.rfc3414.auth import hmacsha
from pysnmp.proto.secmod.rfc3414.priv import des
from pysnmp.proto.secmod.rfc3826.priv import aes

AUTH_PASSPHRASE = b"authkey1"
PRIV_PASSPHRASE = b"privkey1"
USER_NAME = b"usr-sha-priv"
CONTEXT_ENGINE_ID = bytes.fromhex("80001f8801")

# Minimal sample: independently assembled plaintext scopedPDU carrying a
# GetRequest for sysDescr.0. Kept as a constant so the exact bytes under
# test are preserved and reviewable.
MINIMAL_SCOPED_PDU_HEX = (
    "3024"  # SEQUENCE, 36 octets
    "040580001f8801"  # contextEngineId
    "0400"  # contextName (empty)
    "a019"  # GetRequest-PDU, 25 octets
    "020101"  # request-id = 1
    "020100"  # error-status = 0
    "020100"  # error-index = 0
    "300e"  # variable-bindings, 14 octets
    "300c"  # VarBind, 12 octets
    "06082b06010201010100"  # 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    "0500"  # NULL
)
MINIMAL_SCOPED_PDU = bytes.fromhex(MINIMAL_SCOPED_PDU_HEX)

TWELVE_ZEROS = b"\x00" * 12


class Layers:
    """Actual consumption ranges of every processing layer."""

    def __init__(self, plaintext, decrypted_substrate, ciphertext):
        self.plaintext_length = len(plaintext)
        self.ciphertext_length = len(ciphertext)
        self.decrypted_length = len(decrypted_substrate)
        try:
            _, rest = decoder.decode(decrypted_substrate, asn1Spec=make_scoped_pdu())
        except PyAsn1Error:
            # BER layer refuses the substrate outright (e.g. truncation)
            self.scoped_pdu_consumed = None
            self.rest = None
        else:
            self.scoped_pdu_consumed = len(decrypted_substrate) - len(rest)
            self.rest = bytes(rest)


class ManagementCallback:
    """Stand-in for the management application callback (command responder)."""

    def __init__(self):
        self.received = []

    def __call__(self, scoped_pdu):
        self.received.append(scoped_pdu)


def make_scoped_pdu():
    """Assemble the minimal plaintext scopedPDU independently."""
    request = v2c.GetRequestPDU()
    request.setComponentByPosition(0, 1)  # request-id
    request.setComponentByPosition(1, 0)  # error-status
    request.setComponentByPosition(2, 0)  # error-index
    v2c.apiPDU.set_varbinds(request, [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)])

    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, CONTEXT_ENGINE_ID)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByPosition(0, request)
    return scoped_pdu


def make_second_scoped_pdu():
    """Assemble a different, fully valid scopedPDU to smuggle behind the first."""
    request = v2c.GetRequestPDU()
    request.setComponentByPosition(0, 2)
    request.setComponentByPosition(1, 0)
    request.setComponentByPosition(2, 0)
    v2c.apiPDU.set_varbinds(request, [((1, 3, 6, 1, 2, 1, 1, 2, 0), None)])

    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, CONTEXT_ENGINE_ID)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByPosition(0, request)
    return encoder.encode(scoped_pdu)


@pytest.fixture(params=["des", "aes"])
def cipher(request):
    return request.param


@pytest.fixture
def priv_handler(cipher):
    return {"des": des.Des, "aes": aes.Aes}[cipher]()


@pytest.fixture
def priv_protocol(cipher):
    return {
        "des": config.USM_PRIV_CBC56_DES,
        "aes": config.USM_PRIV_CFB128_AES,
    }[cipher]


@pytest.fixture
def snmp_engine(priv_protocol):
    snmp_engine = engine.SnmpEngine()
    config.add_v3_user(
        snmp_engine,
        USER_NAME.decode(),
        config.USM_AUTH_HMAC96_SHA,
        AUTH_PASSPHRASE.decode(),
        priv_protocol,
        PRIV_PASSPHRASE.decode(),
    )
    return snmp_engine


@pytest.fixture
def localized_keys(snmp_engine, priv_handler):
    """Derive localized keys exactly the way the LCD does, for valid MACs."""
    mib_builder = snmp_engine.get_mib_builder()
    (engine_id,) = mib_builder.import_symbols("__SNMP-FRAMEWORK-MIB", "snmpEngineID")
    auth_handler = hmacsha.HmacSha()
    auth_key = auth_handler.localize_key(
        auth_handler.hash_passphrase(AUTH_PASSPHRASE), engine_id.syntax
    )
    priv_key = priv_handler.localize_key(
        hmacsha.HmacSha.SERVICE_ID,
        priv_handler.hash_passphrase(
            hmacsha.HmacSha.SERVICE_ID, PRIV_PASSPHRASE
        ),
        engine_id.syntax,
    )
    return auth_key, priv_key


def build_message(snmp_engine, priv_handler, localized_keys, plaintext):
    """Encrypt *plaintext* and wrap it into a fully authenticated message.

    Returns the authenticated whole message plus the per-layer
    consumption record. The HMAC is computed over the final encoding, so
    authentication always succeeds and only the privacy/BER layers judge
    the sample.
    """
    auth_key, priv_key = localized_keys
    mib_builder = snmp_engine.get_mib_builder()
    engine_id, boots, time = mib_builder.import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineID", "snmpEngineBoots", "snmpEngineTime"
    )
    # snmpEngineTime.syntax is the boot base; clone() yields the elapsed
    # seconds the USM timeline check compares against
    engine_boots = int(boots.syntax)
    engine_time = int(time.syntax.clone())

    while True:
        ciphertext, priv_parameters = priv_handler.encrypt_data(
            priv_key,
            (engine_boots, engine_time, None),
            plaintext,
        )

        security_parameters = service.UsmSecurityParameters()
        security_parameters.setComponentByPosition(0, engine_id.syntax)
        security_parameters.setComponentByPosition(1, engine_boots)
        security_parameters.setComponentByPosition(2, engine_time)
        security_parameters.setComponentByPosition(3, USER_NAME)
        security_parameters.setComponentByPosition(4, TWELVE_ZEROS)
        security_parameters.setComponentByPosition(5, priv_parameters)

        message = rfc3412.SNMPv3Message()
        message.setComponentByPosition(0, 3)
        header = message.getComponentByPosition(1)
        header.setComponentByPosition(0, 1)
        header.setComponentByPosition(1, 65507)
        header.setComponentByPosition(2, b"\x07")  # reportable, auth, priv
        header.setComponentByPosition(3, 3)
        message.setComponentByPosition(2, encoder.encode(security_parameters))
        message.getComponentByPosition(3).setComponentByPosition(1, ciphertext)

        whole_msg = encoder.encode(message)
        # the MAC placeholder must be unique for authenticate_outgoing_message
        if whole_msg.count(TWELVE_ZEROS) == 1:
            break

    decrypted_substrate = priv_handler.decrypt_data(
        priv_key,
        (engine_boots, engine_time, priv_parameters),
        ciphertext,
    )
    layers = Layers(plaintext, decrypted_substrate, bytes(ciphertext))

    whole_msg = hmacsha.HmacSha().authenticate_outgoing_message(auth_key, whole_msg)
    return whole_msg, layers


def deliver(snmp_engine, whole_msg, callback):
    """Feed a message through USM and mimic mpMod dispatch to applications.

    Returns the StatusInformation on rejection, None when the scopedPDU
    was handed to the management callback.
    """
    msg, _ = decoder.decode(whole_msg, asn1Spec=rfc3412.SNMPv3Message())
    security_parameters = bytes(msg.getComponentByPosition(2))
    try:
        result = snmp_engine.security_models[3].process_incoming_message(
            snmp_engine, 3, 65507, security_parameters, 3, 3, whole_msg, msg
        )
    except error.StatusInformation as exc:
        return exc
    callback(result[2])  # scopedPDU dispatched to management applications
    return None


def read_length(data, offset):
    first = data[offset]
    assert first != 0x80, "indefinite length not used in these samples"
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), (
        offset + 1 + count
    )


def split_tlvs(data):
    tlvs = []
    offset = 0
    while offset < len(data):
        assert data[offset] & 0x1F != 0x1F, "single-octet tags only"
        length, content_offset = read_length(data, offset + 1)
        end = content_offset + length
        tlvs.append(data[offset:end])
        offset = end
    assert offset == len(data)
    return tlvs


def long_form_lengths(data):
    """Re-encode every TLV with long-form lengths, recursing into constructed."""
    tag = data[0]
    length, content_offset = read_length(data, 1)
    content = data[content_offset : content_offset + length]
    if tag & 0x20:
        content = b"".join(long_form_lengths(tlv) for tlv in split_tlvs(content))
    count = max(1, (len(content).bit_length() + 7) // 8)
    return bytes([tag, 0x80 | count]) + len(content).to_bytes(count, "big") + content


def inflate_inner_length(data, extra):
    """Inflate the declared length of the innermost PDU TLV by *extra*.

    The scopedPDU's third component is the PDUs choice; bumping its
    declared length without adding content makes the BER layer run past
    the actual substrate.
    """
    content_offset = 2  # outer SEQUENCE, short-form length
    tlvs = split_tlvs(data[content_offset:])
    pdu_tlv = tlvs[2]
    pdu_length, pdu_content_offset = read_length(pdu_tlv, 1)
    assert pdu_length < 0x80 - extra
    inflated = bytes([pdu_tlv[0], pdu_length + extra]) + pdu_tlv[pdu_content_offset:]
    return data[:content_offset] + tlvs[0] + tlvs[1] + inflated


def des_rest_length(plaintext_length):
    """Trailing octets the stock DES encryptor leaves after the scopedPDU."""
    return (plaintext_length // 8 + 1) * 8 - plaintext_length


# --- baseline -----------------------------------------------------------


def test_minimal_sample_encoding_is_preserved():
    assert encoder.encode(make_scoped_pdu()) == MINIMAL_SCOPED_PDU


def test_valid_message_is_accepted(snmp_engine, priv_handler, localized_keys, cipher):
    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU
    )

    # per-layer consumption ranges of the legitimate sample
    assert layers.scoped_pdu_consumed == len(MINIMAL_SCOPED_PDU)
    if cipher == "des":
        assert layers.ciphertext_length % 8 == 0
        assert 1 <= len(layers.rest) <= 8
        assert layers.rest == b"\x00" * len(layers.rest)
    else:
        assert layers.ciphertext_length == len(MINIMAL_SCOPED_PDU)
        assert layers.rest == b""

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is None
    assert len(callback.received) == 1
    assert encoder.encode(callback.received[0]) == MINIMAL_SCOPED_PDU


# --- trailing bytes -------------------------------------------------------


def test_trailing_garbage_is_rejected(
    snmp_engine, priv_handler, localized_keys, cipher
):
    garbage = b"\xde\xad\xbe\xef" * 4
    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU + garbage
    )
    # DES appends its own padding after the smuggled octets
    assert layers.rest.startswith(garbage)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is not None
    assert outcome["errorIndication"] is errind.decryptionError
    assert callback.received == []


def test_des_short_trailing_garbage_is_indistinguishable_from_padding(
    snmp_engine, priv_handler, localized_keys, cipher
):
    """DES padding is arbitrary octets: a smuggled tail that fits into the
    padding block cannot be told apart from legitimate padding. Pin this
    inherent DES-only ambiguity so it never goes unnoticed; AES must
    reject any tail."""
    extra = next(
        n
        for n in range(1, 17)
        if des_rest_length(len(MINIMAL_SCOPED_PDU) + n) <= 8
    )
    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU + b"\x00" * extra
    )

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    if cipher == "des":
        assert len(layers.rest) <= 8
        assert outcome is None
        assert len(callback.received) == 1
    else:
        assert outcome is not None
        assert outcome["errorIndication"] is errind.decryptionError
        assert callback.received == []


def test_appended_sneaky_pdu_is_rejected(
    snmp_engine, priv_handler, localized_keys, cipher
):
    """A whole second PDU appended to the plaintext is not block padding."""
    sneaky_pdu = make_second_scoped_pdu()
    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU + sneaky_pdu
    )
    assert layers.rest.startswith(sneaky_pdu)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is not None
    assert outcome["errorIndication"] is errind.decryptionError
    assert callback.received == []


def test_misacceptance_evidence_without_trailing_check(
    snmp_engine, priv_handler, localized_keys, cipher, monkeypatch
):
    """With the trailing-octet criterion removed, the smuggled-PDU sample
    is silently accepted and the first PDU reaches the management
    callback while the appended one goes unexamined."""
    handler = service.SnmpUSMSecurityModel.PRIV_SERVICES[priv_handler.SERVICE_ID]
    monkeypatch.setattr(handler, "PADDING_BLOCK_SIZE", 65536)

    sneaky_pdu = make_second_scoped_pdu()
    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU + sneaky_pdu
    )
    assert len(layers.rest) > 8

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    # mis-acceptance evidence: no error, first PDU dispatched as trusted
    assert outcome is None
    assert len(callback.received) == 1
    assert encoder.encode(callback.received[0]) == MINIMAL_SCOPED_PDU


# --- BER length encodings ---------------------------------------------------


def test_long_form_lengths_are_accepted(
    snmp_engine, priv_handler, localized_keys, cipher
):
    """BER long-form lengths (outer and nested) are legal and must pass."""
    plaintext = long_form_lengths(MINIMAL_SCOPED_PDU)
    assert plaintext != MINIMAL_SCOPED_PDU
    assert b"\x81" in plaintext or b"\x82" in plaintext

    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, plaintext
    )
    assert layers.scoped_pdu_consumed == len(plaintext)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is None
    assert len(callback.received) == 1
    assert encoder.encode(callback.received[0]) == MINIMAL_SCOPED_PDU


def test_nested_truncation_is_rejected(
    snmp_engine, priv_handler, localized_keys, cipher
):
    """An inner TLV declaring more than the substrate holds is not a
    complete management request."""
    plaintext = inflate_inner_length(MINIMAL_SCOPED_PDU, 4)
    whole_msg, _ = build_message(snmp_engine, priv_handler, localized_keys, plaintext)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is not None
    assert outcome["errorIndication"] is errind.decryptionError
    assert callback.received == []


def test_truncated_plaintext_is_rejected(
    snmp_engine, priv_handler, localized_keys, cipher
):
    cut = 8 if cipher == "des" else 1
    plaintext = MINIMAL_SCOPED_PDU[:-cut]
    whole_msg, _ = build_message(snmp_engine, priv_handler, localized_keys, plaintext)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is not None
    assert outcome["errorIndication"] is errind.decryptionError
    assert callback.received == []


# --- ciphertext-level samples -------------------------------------------


def test_empty_ciphertext_is_rejected(
    snmp_engine, priv_handler, localized_keys, cipher
):
    whole_msg, layers = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU
    )
    # replace the ciphertext with an empty OCTET STRING, re-attach valid MAC
    msg, _ = decoder.decode(whole_msg, asn1Spec=rfc3412.SNMPv3Message())
    msg.getComponentByPosition(3).setComponentByPosition(1, b"")
    security_parameters, _ = decoder.decode(
        bytes(msg.getComponentByPosition(2)),
        asn1Spec=service.UsmSecurityParameters(),
    )
    security_parameters.setComponentByPosition(4, TWELVE_ZEROS)
    msg.setComponentByPosition(2, encoder.encode(security_parameters))
    whole_msg = encoder.encode(msg)
    assert whole_msg.count(TWELVE_ZEROS) == 1
    auth_key, _ = localized_keys
    whole_msg = hmacsha.HmacSha().authenticate_outgoing_message(auth_key, whole_msg)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is not None
    assert outcome["errorIndication"] is errind.decryptionError
    assert callback.received == []


def test_des_ciphertext_not_block_aligned_is_rejected(
    snmp_engine, priv_handler, localized_keys, cipher
):
    if cipher != "des":
        pytest.skip("block alignment is a DES-only ciphertext rule")
    whole_msg, _ = build_message(
        snmp_engine, priv_handler, localized_keys, MINIMAL_SCOPED_PDU
    )
    msg, _ = decoder.decode(whole_msg, asn1Spec=rfc3412.SNMPv3Message())
    ciphertext = bytes(msg.getComponentByPosition(3).getComponentByPosition(1))
    msg.getComponentByPosition(3).setComponentByPosition(1, ciphertext + b"\x00")
    security_parameters, _ = decoder.decode(
        bytes(msg.getComponentByPosition(2)),
        asn1Spec=service.UsmSecurityParameters(),
    )
    security_parameters.setComponentByPosition(4, TWELVE_ZEROS)
    msg.setComponentByPosition(2, encoder.encode(security_parameters))
    whole_msg = encoder.encode(msg)
    assert whole_msg.count(TWELVE_ZEROS) == 1
    auth_key, _ = localized_keys
    whole_msg = hmacsha.HmacSha().authenticate_outgoing_message(auth_key, whole_msg)

    callback = ManagementCallback()
    outcome = deliver(snmp_engine, whole_msg, callback)

    assert outcome is not None
    assert outcome["errorIndication"] is errind.decryptionError
    assert callback.received == []
