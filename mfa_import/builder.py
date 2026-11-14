"""Constructors for RFC 6031 packages used by the demo and tests.

The backend normally receives packages from the wire; these helpers exist so
the demo can build representative material in-process.  They return fully
encoded, decodeable :class:`rfc6031.SymmetricKeyPackage` value objects.
"""

from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ, char, useful

from pyasn1_modules import rfc6031

from .planner import HOTP_ALGORITHM, PIN_ALGORITHM, TOTP_ALGORITHM


def _package_attr(oid, value):
    attr = rfc6031.SKeyPkgAttribute()
    attr["attrType"] = oid
    attr["attrValues"].setComponents(univ.Any(der_encode(value)))
    return attr


def _key_attr(oid, value):
    attr = rfc6031.SKeyAttribute()
    attr["attrType"] = oid
    attr["attrValues"].setComponents(univ.Any(der_encode(value)))
    return attr


def _utf8(oid, text):
    return _key_attr(oid, char.UTF8String(text))


def _integer(oid, number):
    return _key_attr(oid, univ.Integer(number))


def _time(oid, generalized_text):
    return _key_attr(oid, useful.GeneralizedTime(generalized_text))


def _response_format(encoding, length, check_digit=False):
    response = (
        rfc6031.PSKCAlgorithmParameters().componentType["responseFormat"]
        .asn1Object.clone())
    response["encoding"] = encoding
    response["length"] = length
    response["checkDigit"] = check_digit
    params = rfc6031.PSKCAlgorithmParameters()
    params["responseFormat"] = response
    return _key_attr(rfc6031.id_pskc_algorithmParameters, params)


def _challenge_format(encoding, minimum, maximum, check_digit=False):
    challenge = (
        rfc6031.PSKCAlgorithmParameters().componentType["challengeFormat"]
        .asn1Object.clone())
    challenge["encoding"] = encoding
    challenge["min"] = minimum
    challenge["max"] = maximum
    challenge["checkDigit"] = check_digit
    params = rfc6031.PSKCAlgorithmParameters()
    params["challengeFormat"] = challenge
    return _key_attr(rfc6031.id_pskc_algorithmParameters, params)


def _pin_policy(usage_mode, pin_key_id=None, min_length=None,
                max_length=None, pin_encoding=None):
    policy = rfc6031.PINPolicy()
    policy["pinUsageMode"] = usage_mode
    if pin_key_id is not None:
        policy["pinKeyId"] = pin_key_id
    if min_length is not None:
        policy["minLength"] = min_length
    if max_length is not None:
        policy["maxLength"] = max_length
    if pin_encoding is not None:
        policy["pinEncoding"] = pin_encoding
    return _key_attr(rfc6031.id_pskc_pinPolicy, policy)


def _key_usages(*usages):
    seq = rfc6031.PSKCKeyUsages()
    seq.setComponents(*[rfc6031.PSKCKeyUsage(usage) for usage in usages])
    return _key_attr(rfc6031.id_pskc_keyUsages, seq)


def make_key(*, key_id, algorithm, seed, counter=None, time_start=None,
             time_interval=None, time_drift=None, response_format=None,
             start_date=None, expiry_date=None, usages=("OTP",),
             pin_policy=None, issuer=None, friendly_name=None):
    attributes = []
    attributes.append(_utf8(rfc6031.id_pskc_keyId, key_id))
    attributes.append(_utf8(rfc6031.id_pskc_algorithm, algorithm))
    if issuer is not None:
        attributes.append(_utf8(rfc6031.id_pskc_issuer, issuer))
    if friendly_name is not None:
        friendly = rfc6031.FriendlyName()
        friendly["friendlyName"] = friendly_name
        attributes.append(_key_attr(rfc6031.id_pskc_friendlyName, friendly))
    if counter is not None:
        attributes.append(_integer(rfc6031.id_pskc_counter, counter))
    if time_start is not None:
        attributes.append(_integer(rfc6031.id_pskc_time, time_start))
    if time_interval is not None:
        attributes.append(_integer(rfc6031.id_pskc_timeInterval, time_interval))
    if time_drift is not None:
        attributes.append(_integer(rfc6031.id_pskc_timeDrift, time_drift))
    if response_format is not None:
        encoding, length, check_digit = response_format
        attributes.append(_response_format(encoding, length, check_digit))
    if start_date is not None:
        attributes.append(_time(rfc6031.id_pskc_keyStartDate, start_date))
    if expiry_date is not None:
        attributes.append(_time(rfc6031.id_pskc_keyExpiryDate, expiry_date))
    if usages is not None:
        attributes.append(_key_usages(*usages))
    if pin_policy is not None:
        attributes.append(pin_policy)

    skey_attrs = (
        rfc6031.OneSymmetricKey().componentType["sKeyAttrs"]
        .asn1Object.clone())
    skey_attrs.setComponents(*attributes)
    one_key = rfc6031.OneSymmetricKey()
    one_key.setComponents(skey_attrs, univ.OctetString(seed))
    return one_key


def make_package(keys, *, manufacturer=None, serial_number=None,
                 device_start=None, device_expiry=None):
    package_attributes = []
    if manufacturer is not None:
        package_attributes.append(
            _package_attr(rfc6031.id_pskc_manufacturer,
                          char.UTF8String(manufacturer)))
    if serial_number is not None:
        package_attributes.append(
            _package_attr(rfc6031.id_pskc_serialNo,
                          char.UTF8String(serial_number)))
    if device_start is not None:
        package_attributes.append(
            _package_attr(rfc6031.id_pskc_deviceStartDate,
                          useful.GeneralizedTime(device_start)))
    if device_expiry is not None:
        package_attributes.append(
            _package_attr(rfc6031.id_pskc_deviceExpiryDate,
                          useful.GeneralizedTime(device_expiry)))

    package = rfc6031.SymmetricKeyPackage()
    if package_attributes:
        pkg_attrs = (
            rfc6031.SymmetricKeyPackage().componentType["sKeyPkgAttrs"]
            .asn1Object.clone())
        pkg_attrs.setComponents(*package_attributes)
        package["sKeyPkgAttrs"] = pkg_attrs

    skeys = (
        rfc6031.SymmetricKeyPackage().componentType["sKeys"]
        .asn1Object.clone())
    skeys.setComponents(*keys)
    package["sKeys"] = skeys
    return package


# Deterministic demonstration material.  These are non-production, fixed test
# seeds; the demo output never prints them.
HOTP_SEED = bytes(range(1, 21))                  # 20-byte HMAC-SHA1 seed
TOTP_SEED = bytes(range(21, 53))                 # 32-byte HMAC-SHA256 seed
PIN_SEED = b"98765432"                           # 8-digit PIN material


def build_legal_package():
    hotp = make_key(
        key_id="hotp-0001",
        algorithm=HOTP_ALGORITHM,
        seed=HOTP_SEED,
        counter=42,
        response_format=("DECIMAL", 6, False),
        start_date="20260101000000Z",
        expiry_date="20301231235959Z",
        issuer="example-issuer",
        friendly_name="Login HOTP",
        pin_policy=_pin_policy("Local", min_length=4, max_length=8,
                               pin_encoding="DECIMAL"),
    )
    totp = make_key(
        key_id="totp-0001",
        algorithm=TOTP_ALGORITHM,
        seed=TOTP_SEED,
        time_start=0,
        time_interval=30,
        time_drift=0,
        response_format=("DECIMAL", 8, False),
        start_date="20260101000000Z",
        expiry_date="20301231235959Z",
        issuer="example-issuer",
        friendly_name="Login TOTP",
    )
    return make_package(
        [hotp, totp],
        manufacturer="Acme Token Corp",
        serial_number="SN-LEGAL-0001",
        device_start="20250101000000Z",
        device_expiry="20310101000000Z",
    )


def build_conflict_package():
    # First key is a sound HOTP credential.
    hotp = make_key(
        key_id="hotp-0002",
        algorithm=HOTP_ALGORITHM,
        seed=HOTP_SEED,
        counter=7,
        start_date="20260101000000Z",
        expiry_date="20290101000000Z",
    )
    # Second key declares HOTP but mixes in TOTP parameters, sets an
    # impossible validity window, and pairs a check digit with non-DECIMAL
    # encoding.  Any one of these alone blocks import; together they
    # demonstrate joint checking.
    broken = make_key(
        key_id="hotp-broken",
        algorithm=HOTP_ALGORITHM,
        seed=TOTP_SEED,
        counter=9,
        time_interval=30,                 # time parameter on HOTP
        response_format=("BASE64", 16, True),  # check digit requires DECIMAL
        start_date="20320101000000Z",     # starts after it expires and
        expiry_date="20260101000000Z",    # after the device expiry date
    )
    return make_package(
        [hotp, broken],
        manufacturer="Acme Token Corp",
        serial_number="SN-CONFLICT-0002",
        device_start="20250101000000Z",
        device_expiry="20300101000000Z",
    )


def build_cross_package_pin_reference():
    # This package contains two OTP keys but deliberately omits the PIN key.
    # The pinKeyId points at "pin-root", which only exists in a different
    # package, so the reference cannot resolve here.
    hotp = make_key(
        key_id="hotp-0003",
        algorithm=HOTP_ALGORITHM,
        seed=HOTP_SEED,
        counter=11,
        start_date="20260101000000Z",
        expiry_date="20301231235959Z",
        pin_policy=_pin_policy("Algorithmic", pin_key_id="pin-root"),
    )
    totp = make_key(
        key_id="totp-0003",
        algorithm=TOTP_ALGORITHM,
        seed=TOTP_SEED,
        time_start=0,
        time_interval=30,
        start_date="20260101000000Z",
        expiry_date="20301231235959Z",
        pin_policy=_pin_policy("Algorithmic", pin_key_id="pin-root"),
    )
    return make_package(
        [hotp, totp],
        manufacturer="Acme Token Corp",
        serial_number="SN-PINREF-0003",
        device_start="20250101000000Z",
        device_expiry="20310101000000Z",
    )


def build_pin_key(key_id="pin-root", seed=PIN_SEED):
    return make_key(
        key_id=key_id,
        algorithm=PIN_ALGORITHM,
        seed=seed,
        response_format=("DECIMAL", 8, False),
        start_date="20260101000000Z",
        expiry_date="20301231235959Z",
    )
