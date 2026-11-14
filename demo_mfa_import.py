"""End-to-end demonstration of the RFC 6031 MFA import planner.

Run with the project virtualenv::

    .venv/bin/python demo_mfa_import.py

The output is safe to share: it never prints seed bytes, PIN values, or any
other key material.
"""

import json

from pyasn1.type import univ

from mfa_import import (
    ErrorCode,
    InMemoryCredentialStore,
    build_import_plan,
    install_plan,
)
from mfa_import.builder import (
    HOTP_SEED,
    PIN_SEED,
    TOTP_SEED,
    build_conflict_package,
    build_cross_package_pin_reference,
    build_legal_package,
    build_pin_key,
    make_package,
)
from mfa_import.errors import ImportFailure


SECRET_MARKERS = (HOTP_SEED, TOTP_SEED, PIN_SEED)


def _assert_no_secret_text(rendered):
    blob = rendered.encode("utf-8", "replace")
    for secret in SECRET_MARKERS:
        assert secret not in blob, "secret material leaked into output"
        assert secret.hex().encode() not in blob, "secret hex leaked into output"


def _print_plan(title, plan):
    print("=" * 72)
    print(title)
    print("-" * 72)
    rendered = json.dumps(plan.summary(), indent=2, sort_keys=True)
    _assert_no_secret_text(rendered)
    print(rendered)
    print("importable:", plan.importable)
    if plan.issues:
        print("issues:")
        for issue in plan.issues:
            line = "  - [%s] %s (%s)" % (issue.code, issue.detail,
                                         issue.key_id or issue.scope)
            _assert_no_secret_text(line)
            print(line)
    print()


def main():
    store = InMemoryCredentialStore()

    # 1. Legal two-key package: full validation succeeds and both credentials
    #    are installed together.
    legal_package = build_legal_package()
    legal_plan = build_import_plan(legal_package)
    _print_plan("SCENARIO 1 - legal two-key HOTP/TOTP package", legal_plan)
    assert legal_plan.importable
    installed = install_plan(legal_plan, store)
    print("installed credential ids:", store.installed_key_ids())
    assert installed == 2
    print()

    # 2. Second key violates HOTP/TOTP, format and validity constraints.
    #    The whole plan is rejected; the store must not gain either key.
    before = set(store.installed_key_ids())
    conflict_package = build_conflict_package()
    conflict_plan = build_import_plan(conflict_package)
    _print_plan("SCENARIO 2 - second key constraint conflict", conflict_plan)
    assert not conflict_plan.importable
    expected_codes = {
        ErrorCode.HOTP_FORBIDS_TIME_PARAMETERS,
        ErrorCode.CHECK_DIGIT_REQUIRES_DECIMAL,
        ErrorCode.KEY_WINDOW_INVERTED,
        ErrorCode.KEY_OUTSIDE_DEVICE_WINDOW,
    }
    found_codes = {issue.code for issue in conflict_plan.issues}
    assert expected_codes.issubset(found_codes), found_codes
    try:
        install_plan(conflict_plan, store)
    except ImportFailure as exc:
        print("storage refused:", str(exc))
    assert set(store.installed_key_ids()) == before, "partial install detected"
    print("installed credential ids after rejection:", store.installed_key_ids())
    print()

    # 3. Cross-package PIN reference: the referenced PIN key is absent.
    pin_ref_package = build_cross_package_pin_reference()
    pin_ref_plan = build_import_plan(pin_ref_package)
    _print_plan("SCENARIO 3 - cross-package PIN reference", pin_ref_plan)
    assert not pin_ref_plan.importable
    assert pin_ref_plan.issues_by_code(ErrorCode.PIN_REFERENCE_MISSING)
    before = set(store.installed_key_ids())
    try:
        install_plan(pin_ref_plan, store)
    except ImportFailure as exc:
        print("storage refused:", str(exc))
    assert set(store.installed_key_ids()) == before, "partial install detected"
    print()

    # The same reference succeeds once the PIN key travels in the same package.
    resolved_package = make_package(
        [build_pin_key(), pin_ref_package["sKeys"][0], pin_ref_package["sKeys"][1]],
        manufacturer="Acme Token Corp",
        serial_number="SN-PINREF-RESOLVED",
        device_start="20250101000000Z",
        device_expiry="20310101000000Z",
    )
    resolved_plan = build_import_plan(resolved_package)
    _print_plan("SCENARIO 3b - same keys with the PIN key present", resolved_plan)
    assert resolved_plan.importable

    # 4. A plan is an immutable snapshot: mutating the source ASN.1 object
    #    after planning does not change the accepted plan's meaning.
    original_summary = json.dumps(legal_plan.summary(), sort_keys=True)
    legal_package["sKeys"][0]["sKey"] = univ.OctetString(b"\xde\xad\xbe\xef")
    legal_package["sKeys"][0]["sKeyAttrs"][0]["attrValues"][0] = univ.Any(
        b"\x0c\x07changed")
    mutated_summary = json.dumps(legal_plan.summary(), sort_keys=True)
    assert mutated_summary == original_summary
    assert legal_plan.entries[0].seed_bytes() == HOTP_SEED
    print("=" * 72)
    print("SCENARIO 4 - source ASN.1 mutation after planning")
    print("plan unchanged after mutating the source object:", True)
    print("planned seed still matches the original material:", True)
    print()

    # 5. Secret hygiene across every rendered object.
    public_render = json.dumps(
        [legal_plan.summary(), conflict_plan.summary(), pin_ref_plan.summary()],
        sort_keys=True,
    )
    _assert_no_secret_text(public_render)
    print("=" * 72)
    print("SECRET HYGIENE")
    print("no seed or PIN material appears in summaries or error text:", True)
    print("credential repr example:", repr(legal_plan.entries[0]))
    print()
    print("all scenarios completed successfully")


if __name__ == "__main__":
    main()
