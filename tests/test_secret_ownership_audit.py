# SPDX-License-Identifier: MIT
"""
Reviewable ownership/lifecycle checks for secret handling.

These tests drive the controlled doubles in ``audit/ownership_audit.py``.  They
assert only object categories, lengths, and lifecycle transitions; they never
print secret contents and never scan process memory.
"""

from __future__ import annotations

import gc
import sys
import pathlib

import pytest

from _argon2_cffi_bindings import ffi as real_ffi
from _argon2_cffi_bindings import lib as real_lib

import argon2.low_level as low_level

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "audit"))

import ownership_audit as audit  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_binding():
    yield
    audit.restore_doubles()
    gc.collect()


def test_real_api_control_round_trip():
    record = audit.run_real_api_control()
    assert record["verify_ok"] is True
    assert record["raw_is_bytes"] and record["raw_len"] == audit.RAW_HASH_LEN
    assert record["native_default_flags"] == 0
    assert record["convenience_flags_parameter_exists"] is False


def test_high_level_success_has_no_binding_zeroization():
    record = audit.run_high_level_success()
    assert record["zeroized"] == []
    # Each hash allocates an encoded buffer plus pwd and salt C arrays.
    assert ("c-uint8-array", len(audit.SYNTHETIC_PASSWORD) + 1) in record["allocated"]
    assert record["native_entries"] == ["argon2_hash", "argon2_hash", "argon2_verify"]


def test_backend_failure_keeps_secret_array_observable_and_uncleared():
    record = audit.run_high_level_native_failure()
    assert record["raised"] == "HashingError"
    assert record["native_entries"] == ["argon2_hash"]
    assert record["zeroized"] == []
    assert ("c-uint8-array", len(audit.SYNTHETIC_PASSWORD) + 1) in record["allocated"]


def test_pre_native_allocation_failure_never_crosses_boundary():
    record = audit.run_high_level_alloc_failure()
    assert record["raised"] == "MemoryError"
    assert record["native_entries"] == []
    assert record["allocated"] == []


def test_low_level_native_failure_and_mismatch():
    raw_fail = audit.run_low_level_native_failure()
    assert raw_fail["raised"] == "HashingError"
    assert raw_fail["zeroized"] == []

    mismatch = audit.run_verify_mismatch()
    assert mismatch["raised"] == "VerifyMismatchError"
    assert mismatch["native_entries"] == ["argon2_verify"]


def test_returned_bytes_immutable_but_collectable():
    record = audit.run_caller_discards_result()
    obs = record["caller_observations"]
    assert obs["return_type"] == "bytes"
    assert obs["return_len"] == audit.RAW_HASH_LEN
    assert obs["bytes_inplace_zeroize"] == "TypeError"
    assert obs["bytearray_zeroized_len"] == audit.RAW_HASH_LEN
    assert obs["collected_after_drop"] == ["returned-raw-bytes"]


def test_library_cffi_temporaries_reclaimed_without_zeroization():
    record = audit.run_cffi_buffer_reclamation()
    assert record["zeroized"] == []
    reclaimed = {category for category, _length, cleared in
                 record["caller_observations"]["reclaimed_after_forced_gc"]}
    assert reclaimed == {"c-uint8-array"}
    assert all(cleared is False for _c, _l, cleared in
               record["caller_observations"]["reclaimed_after_forced_gc"])


def test_core_flags_zero_vs_clear_password():
    record = audit.run_core_caller_managed()
    assert record["flags_zero_pwd_buffer_unchanged"] is True
    assert record["clear_flag_pwd_zeroized"] is True
    assert record["clear_flag_events"] == [
        ("c-context-pwd", len(audit.SYNTHETIC_PASSWORD))
    ]


def test_core_failure_leaves_caller_owned_buffer_clearable():
    record = audit.run_core_native_failure()
    assert record["core_return_code"] != 0
    assert record["caller_pwd_present_after_failure"] is True
    assert record["caller_pwd_zeroized_after_failure"] is True


def test_full_invariant_set_holds():
    record = {fn.__name__: fn() for fn in audit.SCENARIOS}
    checks = audit.assert_invariants(record)
    assert len(checks) >= 20
    assert all(line.startswith("PASS") for line in checks)


def test_native_clear_flags_are_exposed_but_unused_by_convenience_api():
    # The constants reach Python through CFFI; only core() callers can set them.
    assert real_lib.ARGON2_DEFAULT_FLAGS == 0
    assert real_lib.ARGON2_FLAG_CLEAR_PASSWORD == 1
    assert real_lib.ARGON2_FLAG_CLEAR_SECRET == 2
    # core() is a pure pass-through with no binding-side buffer handling.
    audit.install_doubles()
    ctx, keep = audit._build_managed_context(audit.low_level.ffi, 0)
    try:
        assert low_level.core(ctx, audit.Type.ID.value) == real_lib.ARGON2_OK
    finally:
        audit.restore_doubles()
        del keep
