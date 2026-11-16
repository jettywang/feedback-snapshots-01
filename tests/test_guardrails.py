import io
import subprocess
import sys

import pytest

from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.guardrails import GUARD_CONFIG_STARTS, c_guardrails


def test_guard_config_start_size() -> None:
    """Test that all GUARD_CONFIG_STARTS have the same length."""
    sizes = map(len, GUARD_CONFIG_STARTS)
    assert len(set(sizes)) == 1


@pytest.mark.parametrize(
    "guard_option,settings_type,length",
    [
        (c_guardrails.GuardOption.GUARD_USER, c_guardrails.SettingsType.TYPE_SHORT, 2),
        (c_guardrails.GuardOption.GUARD_COMPUTER, c_guardrails.SettingsType.TYPE_SHORT, 2),
        (c_guardrails.GuardOption.GUARD_DOMAIN, c_guardrails.SettingsType.TYPE_SHORT, 2),
        (c_guardrails.GuardOption.GUARD_LOCAL_IP, c_guardrails.SettingsType.TYPE_INT, 4),
    ],
)
def test_guard_config_start_settings(guard_option, settings_type, length) -> None:
    """Test correctness of the known Guardrail start bytes by constructing the GuardrailSetting."""
    guard_option_user = c_guardrails.GuardrailSetting(
        option=guard_option,
        type=settings_type,
        length=length,
        value=b"",  # ignored
    ).dumps()
    assert guard_option_user in GUARD_CONFIG_STARTS


def test_beacon_dump_guardrails(guardrails_beacon_path):
    proc = subprocess.run(
        [sys.executable, "-m", "dissect.cobaltstrike.beacon", "-v", "-t", "normal", str(guardrails_beacon_path)],
        capture_output=True,
    )
    proc.check_returncode()
    stdout = proc.stdout
    stderr = proc.stderr

    assert b"Found guardrail payload xorkey: b'desktop-r4vgq8o'" in stderr
    assert b"guardrail payload xor key = b'desktop-r4vgq8o'" in stdout
    assert b"guardrail options = [<GuardOption.GUARD_COMPUTER: 6>, <GuardOption.GUARD_PAYLOAD_CHECKSUM: 9>]" in stdout


def test_beacon_guardrails_metadata(guardrails_beacon_file, beacon_x64_file):
    beacon = BeaconConfig.from_file(guardrails_beacon_file)
    assert beacon.guardrails is not None
    assert beacon.guardrails.payload_xor_key == b"desktop-r4vgq8o"
    assert beacon.guardrails.settings[0].option == c_guardrails.GuardOption.GUARD_COMPUTER
    assert beacon.guardrails.settings[1].option == c_guardrails.GuardOption.GUARD_PAYLOAD_CHECKSUM
    assert beacon.guardrails.checksum == 0xA5AD1
    assert beacon.guardrails.guardrail_xor_key == b"\x8a"

    beacon = BeaconConfig.from_file(beacon_x64_file)
    assert beacon.guardrails is None


def _guardrail_setting(option, setting_type, value):
    import struct

    return struct.pack(">HHH", int(option), int(setting_type), len(value)) + value


def _build_guardrails_payload(
    *,
    patch_size=0x1800,
    guardrail_xorkey=b"\x8a",
    payload_xorkey=b"desktop-r4vgq8o",
    checksum=None,
    prefix=b"\xaa" * 0x200,
    guard_patch_size=2048,
    guard_settings=None,
    nonzero=0x800,
):
    """Build a synthetic payload with one Guardrails block for behavioural tests."""
    from dissect.cobaltstrike.guardrails import GuardOption, payload_checksum
    from dissect.cobaltstrike.utils import xor

    plain = bytes(((i * 37 + 11) & 0xFF) for i in range(min(nonzero, patch_size)))
    plain += b"\x00" * (patch_size - len(plain))
    if checksum is None:
        checksum = payload_checksum(plain) + 1

    if guard_settings is None:
        guard_settings = _guardrail_setting(
            GuardOption.GUARD_COMPUTER, c_guardrails.SettingsType.TYPE_SHORT, b"\x00\x01"
        ) + _guardrail_setting(
            GuardOption.GUARD_PAYLOAD_CHECKSUM,
            c_guardrails.SettingsType.TYPE_INT,
            checksum.to_bytes(4, "big"),
        )
    unmasked_guard = guard_settings + b"\x00\x00"
    unmasked_guard += b"\x00" * (guard_patch_size - len(unmasked_guard))

    masked_beacon = xor(xor(plain, payload_xorkey), b"\x2e")
    masked_guard = xor(xor(unmasked_guard, masked_beacon[::-1]), guardrail_xorkey)
    return prefix + masked_beacon + masked_guard, plain, checksum


def test_guardrails_diagnostic_real_sample(guardrails_beacon_file):
    from dissect.cobaltstrike import guardrails

    report = guardrails.diagnose_guardrails(guardrails_beacon_file, source="sample")

    assert report.status == "confirmed"
    assert report.confirmed == ["guard@0x4e290/patch@0x1800"]
    assert report.ambiguous is False
    resolved = report.resolved_candidate()
    assert resolved is not None
    assert resolved.beacon_config_offset == 0x4CA90
    assert resolved.patch_size == 0x1800
    assert resolved.guard_config_signature_offset == 0x4E28A
    assert resolved.checksum == 0xA5AD1
    assert resolved.payload_checksum == 0xA5AD1
    assert resolved.payload_xor_key == b"desktop-r4vgq8o"

    by_id = {c.candidate_id: c for c in report.candidates}
    assert by_id["guard@0x4e290/patch@0x1000"].status == guardrails.CandidateStatus.CHECKSUM_MISMATCH


def test_guardrails_recompute_from_raw_interval(guardrails_beacon_file):
    from dissect.cobaltstrike import guardrails

    report = guardrails.diagnose_guardrails(guardrails_beacon_file)
    candidate = report.resolved_candidate()
    assert candidate is not None

    unmasked, checksum = guardrails.recompute_guardrail_checksum(
        candidate.masked_beacon_config, candidate.payload_xor_key, candidate.beacon_xor_key
    )
    assert checksum == candidate.checksum
    assert unmasked == candidate.unmasked_beacon_config
    assert guardrails.payload_checksum(unmasked) + 1 == candidate.checksum


def test_guardrails_order_independent(guardrails_beacon_file):
    from dissect.cobaltstrike import guardrails

    first = guardrails.diagnose_guardrails(guardrails_beacon_file)
    second = guardrails.correlate_guardrail_candidates(list(reversed(first.candidates)))

    assert first.confirmed == second.confirmed
    assert first.ambiguous == second.ambiguous
    assert first.resolved_candidate().candidate_id == second.resolved_candidate().candidate_id
    assert first.to_dict()["candidates"] == second.to_dict()["candidates"]


def test_guardrails_correlation_is_idempotent(guardrails_beacon_file):
    from dissect.cobaltstrike import guardrails

    report = guardrails.diagnose_guardrails(guardrails_beacon_file)
    once = report.to_dict()
    twice = guardrails.correlate_guardrail_candidates(report.candidates).to_dict()

    assert once["candidates"] == twice["candidates"]
    assert once["notes"] == twice["notes"]


def test_guardrails_wrong_guardrail_mask():
    from dissect.cobaltstrike import guardrails

    data, _, _ = _build_guardrails_payload()
    report = guardrails.diagnose_guardrails(io.BytesIO(data), xorkey=b"\x8b")

    assert report.candidates == []
    assert report.status == "no_association"


def test_guardrails_missing_interval():
    from dissect.cobaltstrike import guardrails
    from dissect.cobaltstrike.utils import xor

    # Place the guardrail block immediately after a 6-byte prefix, so the derived Beacon
    # interval for every supported patch size precedes the file start.
    settings = _guardrail_setting(
        guardrails.GuardOption.GUARD_COMPUTER, c_guardrails.SettingsType.TYPE_SHORT, b"\x00\x01"
    ) + _guardrail_setting(
        guardrails.GuardOption.GUARD_PAYLOAD_CHECKSUM,
        c_guardrails.SettingsType.TYPE_INT,
        (0xA5AD1).to_bytes(4, "big"),
    )
    unmasked_guard = (settings + b"\x00\x00").ljust(2048, b"\x00")
    prefix = b"\xaa" * 6
    masked_guard = bytearray(unmasked_guard)

    # The signature check compares the reversed 6 bytes before the guard block with its
    # first 6 bytes, so those bytes must be masked consistently with the chosen key.
    guard_key = b"\x8a"
    signature_mask = xor(xor(prefix[::-1], guard_key), unmasked_guard[:6])
    masked_guard[:6] = signature_mask
    data = prefix + bytes(masked_guard)

    report = guardrails.diagnose_guardrails(io.BytesIO(data))

    assert len(report.candidates) == 2
    assert all(c.status == guardrails.CandidateStatus.MISSING_INTERVAL for c in report.candidates)
    assert report.status == "unresolved"
    assert any("outside the payload" in note for note in report.notes)


def test_guardrails_truncated_adjacent_block():
    from dissect.cobaltstrike import guardrails

    data, _, _ = _build_guardrails_payload(guard_patch_size=16)
    report = guardrails.diagnose_guardrails(io.BytesIO(data))

    assert report.candidates
    assert all(c.status == guardrails.CandidateStatus.TRUNCATED_ADJACENT_BLOCK for c in report.candidates)


def test_guardrails_checksum_mismatch():
    from dissect.cobaltstrike import guardrails

    data, _, _ = _build_guardrails_payload(checksum=0x123456)
    report = guardrails.diagnose_guardrails(io.BytesIO(data))

    assert report.status == "unresolved"
    assert report.confirmed == []
    assert all(c.status == guardrails.CandidateStatus.CHECKSUM_MISMATCH for c in report.candidates)
    assert any("did not reproduce" in note for note in report.notes)


def test_guardrails_no_checksum():
    from dissect.cobaltstrike import guardrails

    settings = _guardrail_setting(
        guardrails.GuardOption.GUARD_COMPUTER, c_guardrails.SettingsType.TYPE_SHORT, b"\x00\x01"
    )
    data, _, _ = _build_guardrails_payload(guard_settings=settings)
    report = guardrails.diagnose_guardrails(io.BytesIO(data))

    assert report.confirmed == []
    assert all(c.status == guardrails.CandidateStatus.NO_CHECKSUM for c in report.candidates)


def test_guardrails_parse_error():
    from dissect.cobaltstrike import guardrails

    # Second setting declares a length larger than the remaining guardrail patch.
    settings = (
        _guardrail_setting(guardrails.GuardOption.GUARD_COMPUTER, c_guardrails.SettingsType.TYPE_SHORT, b"\x00\x01")
        + b"\x00\x09\x00\x02\xff\xff"
    )
    data, _, _ = _build_guardrails_payload(guard_settings=settings)
    report = guardrails.diagnose_guardrails(io.BytesIO(data))

    assert report.candidates
    assert all(c.status == guardrails.CandidateStatus.PARSE_ERROR for c in report.candidates)


def test_guardrails_multiple_intervals_ambiguous():
    from dissect.cobaltstrike import guardrails

    first, _, _ = _build_guardrails_payload(prefix=b"\xaa" * 0x200, payload_xorkey=b"key-one")
    second, _, _ = _build_guardrails_payload(prefix=b"\xbb" * 0x400, payload_xorkey=b"key-two", nonzero=0x700)

    first_report = guardrails.diagnose_guardrails(io.BytesIO(first))
    second_report = guardrails.diagnose_guardrails(io.BytesIO(second))
    candidates = first_report.candidates + second_report.candidates

    report = guardrails.correlate_guardrail_candidates(candidates)
    assert report.status == "ambiguous"
    assert report.ambiguous is True
    assert report.association_ambiguous is True
    assert len(report.confirmed) == 2
    assert report.resolved_candidate() is None

    reversed_report = guardrails.correlate_guardrail_candidates(list(reversed(candidates)))
    assert reversed_report.confirmed == report.confirmed
    assert reversed_report.to_dict()["candidates"] == report.to_dict()["candidates"]


def test_guardrails_json_report(guardrails_beacon_file):
    from dissect.cobaltstrike import guardrails

    report = guardrails.diagnose_guardrails(guardrails_beacon_file, source="sample")
    payload = report.to_dict()

    assert payload["source"] == "sample"
    assert payload["status"] == "confirmed"
    assert payload["resolved_candidate_id"] == "guard@0x4e290/patch@0x1800"
    assert payload["association_ambiguous"] is False
    candidate = payload["candidates"][0]
    assert len(candidate["decode_preview"]["masked_beacon_config"]) > 0


def test_guardrails_cli_json(guardrails_beacon_path):
    import json

    proc = subprocess.run(
        [sys.executable, "-m", "dissect.cobaltstrike.guardrails", "--format", "json", str(guardrails_beacon_path)],
        capture_output=True,
    )
    proc.check_returncode()
    payload = json.loads(proc.stdout)
    assert payload["status"] == "confirmed"
    assert payload["resolved_candidate_id"] == "guard@0x4e290/patch@0x1800"


def test_guardrails_cli_fail_on_error(beacon_x64_path):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "dissect.cobaltstrike.guardrails",
            "--fail-on-error",
            str(beacon_x64_path),
        ],
        capture_output=True,
    )
    assert proc.returncode == 1
    assert b"status: no_association" in proc.stdout
