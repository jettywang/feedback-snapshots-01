"""Turn a decrypted, authenticated RFC 6031 symmetric key package into a plan.

The input is an already-decrypted and integrity-checked
:class:`pyasn1_modules.rfc6031.SymmetricKeyPackage`.  This module never
performs cryptographic protection itself; it performs a complete, all-or-
nothing validation and returns an immutable :class:`~mfa_import.model.ImportPlan`
that a caller may either persist (only when ``importable`` is true) or reject.

Validation covers, in one pass:

* package-level vs per-key attribute placement;
* required and intelligible critical parameters (key id, algorithm, seed);
* HOTP/TOTP parameter consistency and OTP format constraints;
* device and key validity windows, checked jointly;
* intended key usage;
* PIN policy references, which must resolve to a key inside this package;
* duplicate key ids and seed consistency for a repeated identity.

Any single failure marks the whole plan as not importable.
"""

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ, char

from pyasn1_modules import rfc5652
from pyasn1_modules import rfc6031

from .errors import ErrorCode
from .model import (
    CredentialEntry,
    DeviceInfo,
    ImportPlan,
    OtpParameters,
    PinPolicy,
    ValidationIssue,
)

# PSKC algorithm profile URIs (RFC 6030) this MFA backend understands.
HOTP_ALGORITHM = "urn:ietf:params:xml:ns:keyprov:pskc:hotp"
TOTP_ALGORITHM = "urn:ietf:params:xml:ns:keyprov:pskc:totp"
PIN_ALGORITHM = "urn:ietf:params:xml:ns:keyprov:pskc:pin"

_OTP_ALGORITHMS = frozenset((HOTP_ALGORITHM, TOTP_ALGORITHM))
_SUPPORTED_ALGORITHMS = frozenset((HOTP_ALGORITHM, TOTP_ALGORITHM, PIN_ALGORITHM))

# Every defined key attribute carries exactly one value except key usage.
_MULTI_VALUE_KEY_ATTRS = frozenset((rfc6031.id_pskc_keyUsages,))

# Attributes that only make sense on an OTP (HOTP/TOTP) key.
_OTP_ONLY_ATTRS = frozenset((
    rfc6031.id_pskc_counter,
    rfc6031.id_pskc_time,
    rfc6031.id_pskc_timeInterval,
    rfc6031.id_pskc_timeDrift,
))


class _IssueCollector:
    def __init__(self):
        self._issues = []

    def add(self, code, scope, key_id, detail):
        self._issues.append(ValidationIssue(code, scope, key_id, detail))

    @property
    def issues(self):
        return tuple(self._issues)


def _coerce_open_types(package):
    """Return a package whose open-type attribute values are decoded.

    Re-encoding and decoding with ``decodeOpenTypes`` lets the planner accept
    either an open-type-decoded value object or a freshly parsed package
    without mutating the caller's object graph.
    """
    decoded, _ = der_decode(
        der_encode(package),
        asn1Spec=rfc6031.SymmetricKeyPackage(),
        decodeOpenTypes=True,
    )
    return decoded


def _resolve_package(source):
    if isinstance(source, rfc6031.SymmetricKeyPackage):
        return _coerce_open_types(source)
    if isinstance(source, rfc5652.ContentInfo):
        content_type = source["contentType"]
        if content_type != rfc6031.id_ct_KP_sKeyPackage:
            from .errors import PlanError
            raise PlanError("content type is not an RFC 6031 symmetric key package")
        decoded, _ = der_decode(
            der_encode(source["content"]),
            asn1Spec=rfc6031.SymmetricKeyPackage(),
            decodeOpenTypes=True,
        )
        return decoded
    from .errors import PlanError
    raise PlanError("expected a SymmetricKeyPackage or its CMS ContentInfo wrapper")


def _single_value(attr, issues, scope, key_id):
    values = attr["attrValues"]
    if len(values) == 0:
        issues.add(
            ErrorCode.EMPTY_ATTRIBUTE_VALUES, scope, key_id,
            "attribute has no values",
        )
        return None
    if len(values) > 1:
        issues.add(
            ErrorCode.MULTIPLE_ATTRIBUTE_VALUES, scope, key_id,
            "single-valued attribute has more than one value",
        )
        return None
    return values[0]


def _text(value):
    """Return the Python text of a pyasn1 character string value."""
    if isinstance(value, char.AbstractCharacterString):
        return str(value)
    return str(value)


def _usage_texts(value):
    """Flatten a decoded PSKCKeyUsages (SEQUENCE OF PSKCKeyUsage) to text."""
    if isinstance(value, univ.SequenceOf):
        return tuple(str(member) for member in value)
    return (str(value),)


def _parse_generalized_time(value, issues, scope, key_id, code, label):
    try:
        return value.asDateTime
    except Exception:
        issues.add(code, scope, key_id, "%s is not a valid GeneralizedTime" % label)
        return None


def _read_device_attributes(package, issues):
    data = {
        "manufacturer": None,
        "serial_number": None,
        "model": None,
        "issue_number": None,
        "device_binding": None,
        "start_date": None,
        "expiry_date": None,
        "module_id": None,
        "device_user_id": None,
    }
    string_fields = {
        rfc6031.id_pskc_manufacturer: "manufacturer",
        rfc6031.id_pskc_serialNo: "serial_number",
        rfc6031.id_pskc_model: "model",
        rfc6031.id_pskc_issueNo: "issue_number",
        rfc6031.id_pskc_deviceBinding: "device_binding",
        rfc6031.id_pskc_moduleId: "module_id",
        rfc6031.id_pskc_deviceUserId: "device_user_id",
    }
    seen = set()
    for attr in package["sKeyPkgAttrs"] if package["sKeyPkgAttrs"].hasValue() else ():
        oid = attr["attrType"]
        if oid not in rfc6031.sKeyPkgAttributesMap:
            issues.add(
                ErrorCode.UNKNOWN_PACKAGE_ATTRIBUTE, "package", None,
                "package carries an attribute not defined at package level",
            )
            continue
        if oid in seen:
            issues.add(
                ErrorCode.DUPLICATE_ATTRIBUTE, "package", None,
                "package attribute appears more than once",
            )
            continue
        seen.add(oid)
        value = _single_value(attr, issues, "package", None)
        if value is None:
            continue
        if oid in string_fields:
            data[string_fields[oid]] = _text(value)
        elif oid == rfc6031.id_pskc_deviceStartDate:
            data["start_date"] = _parse_generalized_time(
                value, issues, "package", None,
                ErrorCode.MALFORMED_ATTRIBUTE, "device start date")
        elif oid == rfc6031.id_pskc_deviceExpiryDate:
            data["expiry_date"] = _parse_generalized_time(
                value, issues, "package", None,
                ErrorCode.MALFORMED_ATTRIBUTE, "device expiry date")

    device = DeviceInfo(**data)
    if device.start_date and device.expiry_date and device.start_date > device.expiry_date:
        issues.add(
            ErrorCode.DEVICE_WINDOW_INVERTED, "package", None,
            "device start date is later than device expiry date",
        )
    return device


def _read_otp_parameters(algorithm, attrs, key_id, issues):
    mode = "hotp" if algorithm == HOTP_ALGORITHM else "totp"
    params = OtpParameters(mode=mode)

    def scalar(oid):
        values = attrs.get(oid)
        return values[0] if values else None

    counter = scalar(rfc6031.id_pskc_counter)
    time_start = scalar(rfc6031.id_pskc_time)
    time_interval = scalar(rfc6031.id_pskc_timeInterval)
    time_drift = scalar(rfc6031.id_pskc_timeDrift)

    if mode == "hotp":
        if counter is None:
            issues.add(
                ErrorCode.HOTP_REQUIRES_COUNTER, "key", key_id,
                "HOTP key must carry an event counter",
            )
        if time_start is not None or time_interval is not None or time_drift is not None:
            issues.add(
                ErrorCode.HOTP_FORBIDS_TIME_PARAMETERS, "key", key_id,
                "HOTP key must not carry time-based parameters",
            )
    else:
        if counter is not None:
            issues.add(
                ErrorCode.TOTP_FORBIDS_COUNTER, "key", key_id,
                "TOTP key must not carry an event counter",
            )
        if time_interval is None:
            issues.add(
                ErrorCode.TOTP_REQUIRES_TIME_INTERVAL, "key", key_id,
                "TOTP key must carry a time interval",
            )
        elif int(time_interval) <= 0:
            issues.add(
                ErrorCode.TIME_INTERVAL_NOT_POSITIVE, "key", key_id,
                "TOTP time interval must be a positive number of seconds",
            )

    algo_params = scalar(rfc6031.id_pskc_algorithmParameters)
    suite = response = challenge = None
    if algo_params is not None:
        choice = algo_params
        try:
            chosen = choice.getName()
        except Exception:
            chosen = None
        if chosen == "suite":
            suite = _text(choice["suite"])
        elif chosen == "responseFormat":
            response = choice["responseFormat"]
        elif chosen == "challengeFormat":
            challenge = choice["challengeFormat"]
        else:
            issues.add(
                ErrorCode.UNINTELLIGIBLE_PARAMETER, "key", key_id,
                "algorithm parameters use an unrecognized alternative",
            )

    if response is not None:
        encoding = _text(response["encoding"])
        check_digit = bool(response["checkDigit"]) if response["checkDigit"].hasValue() else False
        if check_digit and encoding != "DECIMAL":
            issues.add(
                ErrorCode.CHECK_DIGIT_REQUIRES_DECIMAL, "key", key_id,
                "response check digit is only valid with DECIMAL encoding",
            )
        params = OtpParameters(
            mode=mode,
            counter=int(counter) if counter is not None else None,
            time_start=int(time_start) if time_start is not None else None,
            time_interval=int(time_interval) if time_interval is not None else None,
            time_drift=int(time_drift) if time_drift is not None else None,
            response_encoding=encoding,
            response_length=int(response["length"]),
            response_check_digit=check_digit,
            suite=suite,
        )
    elif challenge is not None:
        encoding = _text(challenge["encoding"])
        check_digit = bool(challenge["checkDigit"]) if challenge["checkDigit"].hasValue() else False
        if check_digit and encoding != "DECIMAL":
            issues.add(
                ErrorCode.CHECK_DIGIT_REQUIRES_DECIMAL, "key", key_id,
                "challenge check digit is only valid with DECIMAL encoding",
            )
        params = OtpParameters(
            mode=mode,
            counter=int(counter) if counter is not None else None,
            time_start=int(time_start) if time_start is not None else None,
            time_interval=int(time_interval) if time_interval is not None else None,
            time_drift=int(time_drift) if time_drift is not None else None,
            challenge_encoding=encoding,
            challenge_min=int(challenge["min"]),
            challenge_max=int(challenge["max"]),
            challenge_check_digit=check_digit,
            suite=suite,
        )
    else:
        params = OtpParameters(
            mode=mode,
            counter=int(counter) if counter is not None else None,
            time_start=int(time_start) if time_start is not None else None,
            time_interval=int(time_interval) if time_interval is not None else None,
            time_drift=int(time_drift) if time_drift is not None else None,
            suite=suite,
        )
    return params


def _read_pin_policy(value, key_id, issues):
    usage_mode = _text(value["pinUsageMode"])
    policy = PinPolicy(
        usage_mode=usage_mode,
        pin_key_id=_text(value["pinKeyId"]) if value["pinKeyId"].hasValue() else None,
        max_failed_attempts=(
            int(value["maxFailedAttempts"]) if value["maxFailedAttempts"].hasValue() else None),
        min_length=int(value["minLength"]) if value["minLength"].hasValue() else None,
        max_length=int(value["maxLength"]) if value["maxLength"].hasValue() else None,
        pin_encoding=_text(value["pinEncoding"]) if value["pinEncoding"].hasValue() else None,
    )
    if policy.min_length is not None and policy.max_length is not None:
        if policy.min_length > policy.max_length:
            issues.add(
                ErrorCode.UNINTELLIGIBLE_PARAMETER, "key", key_id,
                "PIN minimum length is greater than PIN maximum length",
            )
    return policy


def _collect_key_attributes(one_key, index, issues):
    attrs = {}
    if not one_key["sKeyAttrs"].hasValue():
        return attrs
    seen = set()
    for attr in one_key["sKeyAttrs"]:
        oid = attr["attrType"]
        if oid in rfc6031.sKeyPkgAttributesMap and oid not in rfc6031.sKeyAttributesMap:
            issues.add(
                ErrorCode.ATTRIBUTE_WRONG_SCOPE, "key", None,
                "package-level attribute was placed on a key",
            )
            continue
        if oid not in rfc6031.sKeyAttributesMap:
            issues.add(
                ErrorCode.UNKNOWN_KEY_ATTRIBUTE, "key", None,
                "key carries an undefined attribute that cannot be interpreted",
            )
            continue
        if oid in seen:
            issues.add(
                ErrorCode.DUPLICATE_ATTRIBUTE, "key", None,
                "key attribute appears more than once",
            )
            continue
        seen.add(oid)
        values = attr["attrValues"]
        if len(values) == 0:
            issues.add(ErrorCode.EMPTY_ATTRIBUTE_VALUES, "key", None,
                       "attribute has no values")
            continue
        if oid not in _MULTI_VALUE_KEY_ATTRS and len(values) > 1:
            issues.add(ErrorCode.MULTIPLE_ATTRIBUTE_VALUES, "key", None,
                       "single-valued attribute has more than one value")
            continue
        attrs[oid] = list(values)
    return attrs


def _build_entry(one_key, index, device, issues):
    attrs = _collect_key_attributes(one_key, index, issues)

    key_id_value = attrs.get(rfc6031.id_pskc_keyId)
    key_id = _text(key_id_value[0]) if key_id_value else None
    if key_id is None:
        issues.add(ErrorCode.MISSING_KEY_ID, "key", None,
                   "key is missing the required key identifier")

    algorithm_value = attrs.get(rfc6031.id_pskc_algorithm)
    algorithm = _text(algorithm_value[0]) if algorithm_value else None
    if algorithm is None:
        issues.add(ErrorCode.MISSING_ALGORITHM, "key", key_id,
                   "key is missing the required algorithm")

    seed = bytes(one_key["sKey"]) if one_key["sKey"].hasValue() else b""
    if not seed:
        issues.add(ErrorCode.MISSING_SEED, "key", key_id,
                   "key carries no symmetric key material")

    # Unknown/unintelligible algorithm: record it and skip profile-specific
    # interpretation so the rest of the package can still be examined.
    if algorithm is not None and algorithm not in _SUPPORTED_ALGORITHMS:
        issues.add(ErrorCode.UNSUPPORTED_ALGORITHM, "key", key_id,
                   "algorithm profile is not supported by this backend")

    start_date = expiry_date = None
    if rfc6031.id_pskc_keyStartDate in attrs:
        start_date = _parse_generalized_time(
            attrs[rfc6031.id_pskc_keyStartDate][0], issues, "key", key_id,
            ErrorCode.MALFORMED_ATTRIBUTE, "key start date")
    if rfc6031.id_pskc_keyExpiryDate in attrs:
        expiry_date = _parse_generalized_time(
            attrs[rfc6031.id_pskc_keyExpiryDate][0], issues, "key", key_id,
            ErrorCode.MALFORMED_ATTRIBUTE, "key expiry date")
    if start_date and expiry_date and start_date > expiry_date:
        issues.add(ErrorCode.KEY_WINDOW_INVERTED, "key", key_id,
                   "key start date is later than key expiry date")
    if device.start_date and start_date and start_date < device.start_date:
        issues.add(ErrorCode.KEY_OUTSIDE_DEVICE_WINDOW, "key", key_id,
                   "key starts before the device start date")
    if device.expiry_date and start_date and start_date > device.expiry_date:
        issues.add(ErrorCode.KEY_OUTSIDE_DEVICE_WINDOW, "key", key_id,
                   "key start date is after the device expiry date")
    if device.expiry_date and expiry_date and expiry_date > device.expiry_date:
        issues.add(ErrorCode.KEY_OUTSIDE_DEVICE_WINDOW, "key", key_id,
                   "key expires after the device expiry date")
    if device.start_date and expiry_date and expiry_date < device.start_date:
        issues.add(ErrorCode.KEY_OUTSIDE_DEVICE_WINDOW, "key", key_id,
                   "key expiry date is before the device start date")

    key_usages = frozenset()
    if rfc6031.id_pskc_keyUsages in attrs:
        usage_values = []
        for usage_container in attrs[rfc6031.id_pskc_keyUsages]:
            usage_values.extend(_usage_texts(usage_container))
        key_usages = frozenset(usage_values)

    otp_params = None
    pin_policy = None
    if algorithm in _OTP_ALGORITHMS:
        otp_params = _read_otp_parameters(algorithm, attrs, key_id, issues)
        if key_usages and "OTP" not in key_usages:
            issues.add(ErrorCode.KEY_USAGE_NOT_OTP, "key", key_id,
                       "OTP algorithm key does not include OTP usage")
    elif algorithm == PIN_ALGORITHM:
        for forbidden in _OTP_ONLY_ATTRS:
            if forbidden in attrs:
                issues.add(ErrorCode.UNINTELLIGIBLE_PARAMETER, "key", key_id,
                           "PIN key must not carry OTP transport parameters")
        if key_usages and "OTP" not in key_usages:
            issues.add(ErrorCode.KEY_USAGE_NOT_OTP, "key", key_id,
                       "PIN algorithm key does not include OTP usage")

    if rfc6031.id_pskc_pinPolicy in attrs:
        pin_policy = _read_pin_policy(attrs[rfc6031.id_pskc_pinPolicy][0],
                                      key_id, issues)

    def one(oid):
        values = attrs.get(oid)
        return _text(values[0]) if values else None

    friendly_name = None
    if rfc6031.id_pskc_friendlyName in attrs:
        friendly = attrs[rfc6031.id_pskc_friendlyName][0]
        friendly_name = _text(friendly["friendlyName"])

    entry = CredentialEntry(
        key_id=key_id if key_id is not None else "key[%d]" % index,
        algorithm=algorithm if algorithm is not None else "",
        key_usages=key_usages,
        seed=seed,
        issuer=one(rfc6031.id_pskc_issuer),
        key_profile_id=one(rfc6031.id_pskc_keyProfileId),
        key_reference=one(rfc6031.id_pskc_keyReference),
        friendly_name=friendly_name,
        key_user_id=one(rfc6031.id_pskc_keyUserId),
        start_date=start_date,
        expiry_date=expiry_date,
        number_of_transactions=(
            int(attrs[rfc6031.id_pskc_numberOfTransactions][0])
            if rfc6031.id_pskc_numberOfTransactions in attrs else None),
        otp=otp_params,
        pin_policy=pin_policy,
    )
    return entry, key_id


def _check_identity_and_pins(entries_by_index, raw_key_ids, issues):
    # Duplicate key ids and seed consistency for a repeated identity.
    seen_ids = {}
    for index, entry in entries_by_index:
        declared = raw_key_ids[index]
        if declared is None:
            continue
        if declared in seen_ids:
            issues.add(ErrorCode.DUPLICATE_KEY_ID, "key", declared,
                       "key identifier is used by more than one key")
            prior = seen_ids[declared]
            if prior.seed != entry.seed:
                issues.add(ErrorCode.SEED_MISMATCH_FOR_IDENTITY, "key", declared,
                           "same key identifier is bound to different key material")
        else:
            seen_ids[declared] = entry

    known_ids = set(seen_ids)
    # PIN references must resolve to another key carried in this package.
    for index, entry in entries_by_index:
        policy = entry.pin_policy
        if policy is None or policy.pin_key_id is None:
            continue
        target = policy.pin_key_id
        if target == entry.key_id:
            issues.add(ErrorCode.PIN_REFERENCES_SELF, "key", entry.key_id,
                       "PIN policy references its own key as the PIN key")
            continue
        if target not in known_ids:
            issues.add(ErrorCode.PIN_REFERENCE_MISSING, "key", entry.key_id,
                       "PIN policy references a key that is not in this package")
            continue
        target_entry = seen_ids[target]
        if target_entry.algorithm != PIN_ALGORITHM:
            issues.add(ErrorCode.PIN_REFERENCES_NON_PIN_KEY, "key", entry.key_id,
                       "PIN policy references a key that is not a PIN key")


def build_import_plan(source):
    """Validate a key package and build an immutable import plan.

    :param source: a :class:`rfc6031.SymmetricKeyPackage`, or the CMS
        :class:`rfc5652.ContentInfo` that wraps one.
    :returns: :class:`~mfa_import.model.ImportPlan`
    :raises PlanError: if ``source`` cannot be interpreted as a key package.
    """
    package = _resolve_package(source)
    issues = _IssueCollector()
    device = _read_device_attributes(package, issues)

    entries = []
    raw_key_ids = []
    for index, one_key in enumerate(package["sKeys"]):
        entry, declared_key_id = _build_entry(one_key, index, device, issues)
        entries.append((index, entry))
        raw_key_ids.append(declared_key_id)

    _check_identity_and_pins(entries, raw_key_ids, issues)

    plan = ImportPlan(
        importable=len(issues.issues) == 0,
        version=int(package["version"]),
        device=device,
        entries=tuple(entry for _, entry in entries),
        issues=issues.issues,
    )
    return plan
