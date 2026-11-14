"""Stable error codes for the MFA symmetric-key import planner.

The codes are part of the public API so callers can branch on them.  Their
text is deliberately generic: error messages never carry key material, PIN
material, or any other secret value from the source package.
"""


class ErrorCode:
    # Structural / decoding failures
    NOT_A_KEY_PACKAGE = "not_a_key_package"
    MALFORMED_ATTRIBUTE = "malformed_attribute"
    ATTRIBUTE_WRONG_SCOPE = "attribute_wrong_scope"
    UNKNOWN_PACKAGE_ATTRIBUTE = "unknown_package_attribute"
    UNKNOWN_KEY_ATTRIBUTE = "unknown_key_attribute"
    DUPLICATE_ATTRIBUTE = "duplicate_attribute"
    EMPTY_ATTRIBUTE_VALUES = "empty_attribute_values"
    MULTIPLE_ATTRIBUTE_VALUES = "multiple_attribute_values"

    # Required / understood critical parameters
    MISSING_KEY_ID = "missing_key_id"
    MISSING_ALGORITHM = "missing_algorithm"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    UNINTELLIGIBLE_PARAMETER = "unintelligible_parameter"
    MISSING_SEED = "missing_seed"

    # HOTP / TOTP parameter consistency
    HOTP_REQUIRES_COUNTER = "hotp_requires_counter"
    HOTP_FORBIDS_TIME_PARAMETERS = "hotp_forbids_time_parameters"
    TOTP_REQUIRES_TIME_INTERVAL = "totp_requires_time_interval"
    TOTP_FORBIDS_COUNTER = "totp_forbids_counter"
    TIME_INTERVAL_NOT_POSITIVE = "time_interval_not_positive"
    CHECK_DIGIT_REQUIRES_DECIMAL = "check_digit_requires_decimal"

    # Validity windows
    KEY_WINDOW_INVERTED = "key_window_inverted"
    DEVICE_WINDOW_INVERTED = "device_window_inverted"
    KEY_OUTSIDE_DEVICE_WINDOW = "key_outside_device_window"

    # Usage
    KEY_USAGE_NOT_OTP = "key_usage_not_otp"

    # PIN association
    PIN_REFERENCE_MISSING = "pin_reference_missing"
    PIN_REFERENCES_NON_PIN_KEY = "pin_references_non_pin_key"
    PIN_REFERENCES_SELF = "pin_references_self"

    # Identity / seed consistency
    DUPLICATE_KEY_ID = "duplicate_key_id"
    SEED_MISMATCH_FOR_IDENTITY = "seed_mismatch_for_identity"


class PlanError(Exception):
    """Raised only for inputs that cannot be interpreted as a key package."""


class ImportFailure(Exception):
    """Raised by the storage phase when a credential cannot be installed.

    The planner itself never installs anything and therefore never raises
    this; concrete :class:`~mfa_import.store.CredentialStore` implementations
    use it to trigger the all-or-nothing rollback.
    """
