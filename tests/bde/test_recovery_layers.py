"""Layered counterexamples for the BitLocker recovery password unlock path.

These tests drive the public :meth:`BDE.unlock_with_recovery_password` entry point against a
small, fully synthetic in-memory volume (see :mod:`tests.bde.recovery_volume`). Each
counterexample is pinned to the exact stage it reaches and to the final, readable state of
the volume.

The layers, from outermost to innermost, are:

1. Recovery password text format / group checksum validation.
2. Recovery VMK protector selection (explicit identifier vs. automatic selection).
3. AES-CCM authentication of the wrapped VMK.
4. AES-CCM authentication/unboxing of the wrapped FVEK key datum.

At least one counterexample keeps the recovery password text and its entire key derivation
valid and only mutates on-disk wrapping material, so not every failure stops at the outermost
format check. Logs and failure messages must never contain the recovery password or any
derived key.
"""

from __future__ import annotations

import logging

import pytest

from dissect.fve.bde import c_bde
from dissect.fve.bde.bde import BDE
from dissect.fve.bde.information import AesCcmEncryptedDatum, VmkInfoDatum
from tests.bde.recovery_volume import (
    DATA_SECTOR,
    KNOWN_PLAINTEXT,
    RECOVERY_IDENTIFIER,
    RECOVERY_PASSWORD,
    SECOND_RECOVERY_IDENTIFIER,
    SECTOR_SIZE,
    UNKNOWN_IDENTIFIER,
    build_volume,
)

WRAPPER_MESSAGE = "Unable to unlock with given recovery password"
SELECTION_CAUSE = "No compatible VMK found, incorrect key or identifier"
AUTH_CAUSE = "MAC check failed"


def _secret_fragments(secrets: dict[str, bytes | str]) -> list[str]:
    """All textual/hex forms that would constitute a secret leak."""
    fragments = [
        str(secrets["recovery_password"]),
        str(secrets["recovery_password"]).replace("-", ""),
        secrets["vmk"].hex(),
        secrets["fvek"].hex(),
        secrets["stretch_keys"].hex(),
    ]
    return [fragment for fragment in fragments if fragment]


def _assert_locked(bde_obj: BDE) -> None:
    """Assert a failed unlock leaves no usable key material and keeps the volume locked."""
    assert not bde_obj.unlocked
    assert bde_obj._fvek is None
    assert bde_obj._fvek_datum is None
    assert bde_obj._vmk is None
    assert bde_obj._vmk_datum is None
    with pytest.raises(ValueError, match="Volume is locked"):
        bde_obj.open()


def _assert_no_secret_leak(
    secrets: dict[str, bytes | str],
    caplog: pytest.LogCaptureFixture,
    error: BaseException | None = None,
) -> None:
    """Assert neither the emitted logs nor the full exception chain expose a secret."""
    logged = "\n".join(record.getMessage() for record in caplog.records)

    messages = [logged]
    cause = error
    while cause is not None:
        messages.append(str(cause))
        cause = cause.__cause__
    combined = "\n".join(messages)

    for fragment in _secret_fragments(secrets):
        assert fragment not in combined


class _CanaryLogFixture:
    """Minimal stand-in exposing the ``records`` attribute consumed by the leak guard."""

    def __init__(self: _CanaryLogFixture, message: str) -> None:
        self.records = [type("Record", (), {"getMessage": staticmethod(lambda: message)})()]


def test_secret_leak_guard_detects_canary() -> None:
    """The leak guard itself must fail when a secret reaches a log or an exception message."""
    volume, secrets = build_volume()
    BDE(volume)

    with pytest.raises(AssertionError):
        _assert_no_secret_leak(secrets, _CanaryLogFixture(secrets["recovery_password"]))  # type: ignore[arg-type]

    empty_caplog = _CanaryLogFixture("")
    with pytest.raises(AssertionError):
        _assert_no_secret_leak(secrets, empty_caplog, error=ValueError(secrets["fvek"].hex()))  # type: ignore[arg-type]


def test_recovery_password_happy_path_decrypts_known_bytes(caplog: pytest.LogCaptureFixture) -> None:
    """A valid recovery password reaches every layer and decrypts the known plaintext."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume()
    bde_obj = BDE(volume)

    assert bde_obj.has_recovery_password()
    assert not bde_obj.unlocked

    bde_obj.unlock_with_recovery_password(RECOVERY_PASSWORD)

    assert bde_obj.unlocked
    assert bde_obj._vmk == secrets["vmk"]
    assert bde_obj._fvek == secrets["fvek"]
    assert bde_obj.information.check_integrity(bde_obj._vmk)

    stream = bde_obj.open()
    stream.seek(DATA_SECTOR * SECTOR_SIZE)
    assert stream.read(SECTOR_SIZE) == KNOWN_PLAINTEXT

    _assert_no_secret_leak(secrets, caplog)


@pytest.mark.parametrize(
    ("bad_password", "expected_message"),
    [
        # Wrong number of groups: rejected before any key material is touched.
        ("284867-596541-514998-422114-660297-261613-215424", "invalid length"),
        # Non-numeric group.
        ("284867-596541-514998-422114-ABCDEF-261613-215424-199408", "non-numeric value"),
        # Eight numeric groups, but one is not divisible by 11.
        ("284867-596541-514998-422114-660298-261613-215424-199408", "not divisible by 11"),
        # Numeric, divisible by 11, but outside the allowed 16-bit range.
        ("284867-596541-514998-422114-720907-261613-215424-199408", "larger than 2 \\*\\* 16 \\* 11"),
    ],
)
def test_layer_1_text_format_and_group_checksum_failures(
    bad_password: str,
    expected_message: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Malformed recovery passwords stop at the outermost text/group validation stage."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume()
    bde_obj = BDE(volume)

    with pytest.raises(ValueError, match=expected_message) as exc_info:
        bde_obj.unlock_with_recovery_password(bad_password)

    # These are raw format errors, raised before the generic wrapper would translate them.
    assert WRAPPER_MESSAGE not in str(exc_info.value)
    assert bad_password not in str(exc_info.value)
    _assert_locked(bde_obj)
    _assert_no_secret_leak(secrets, caplog, exc_info.value)


def test_layer_2_unknown_identifier_skips_every_protector(caplog: pytest.LogCaptureFixture) -> None:
    """An explicit identifier matching no recovery VMK never attempts authentication."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume(recovery_protectors=2)
    bde_obj = BDE(volume)

    with pytest.raises(ValueError, match=WRAPPER_MESSAGE) as exc_info:
        bde_obj.unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=UNKNOWN_IDENTIFIER)

    assert SELECTION_CAUSE in str(exc_info.value.__cause__)
    _assert_locked(bde_obj)
    _assert_no_secret_leak(secrets, caplog, exc_info.value)


def test_layer_2_corrupted_target_protector_is_not_masked_by_healthy_protector(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Explicit and automatic selection follow the same identity rule.

    The first recovery protector's wrapping is corrupted while a second, healthy protector is
    present. Selecting the corrupted target explicitly must fail instead of silently succeeding
    through the other protector; automatic selection over both must still recover via the healthy
    one, proving the explicit failure is attributable to the named target.
    """
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume(recovery_protectors=2, corrupt_vmk_identifier=RECOVERY_IDENTIFIER)
    bde_obj = BDE(volume)

    # Explicitly naming the corrupted protector must fail at VMK authentication, not be hidden
    # by the healthy second protector.
    with pytest.raises(ValueError, match=WRAPPER_MESSAGE) as exc_info:
        bde_obj.unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=RECOVERY_IDENTIFIER)
    assert SELECTION_CAUSE in str(exc_info.value.__cause__)
    _assert_locked(bde_obj)

    # The same identifier rule on a fresh volume: automatic selection iterates every protector and
    # succeeds through the healthy one, confirming the explicit failure is target-specific.
    healthy_volume, healthy_secrets = build_volume(recovery_protectors=2)
    healthy_bde = BDE(healthy_volume)
    healthy_bde.unlock_with_recovery_password(RECOVERY_PASSWORD)
    assert healthy_bde.unlocked
    assert healthy_bde._fvek == healthy_secrets["fvek"]

    _assert_no_secret_leak(secrets, caplog, exc_info.value)
    _assert_no_secret_leak(healthy_secrets, caplog)


def test_layer_3_vmk_authentication_failure_with_fully_valid_password(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A valid password and derivation fail solely on the VMK AES-CCM authentication tag."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume(corrupt_vmk_identifier=RECOVERY_IDENTIFIER)
    bde_obj = BDE(volume)

    # Sanity: the password text itself is still well formed and derives a key; only the on-disk
    # authentication tag was mutated.
    assert bde_obj.has_recovery_password()
    assert bde_obj.identifiers == [RECOVERY_IDENTIFIER]

    with pytest.raises(ValueError, match=WRAPPER_MESSAGE) as exc_info:
        bde_obj.unlock_with_recovery_password(RECOVERY_PASSWORD)

    assert SELECTION_CAUSE in str(exc_info.value.__cause__)
    _assert_locked(bde_obj)
    _assert_no_secret_leak(secrets, caplog, exc_info.value)


def test_layer_4_fvek_datum_invalid_after_successful_vmk_authentication(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """VMK authentication succeeds, then the corrupted FVEK key datum fails to unbox."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume(corrupt_fvek_datum=True)
    bde_obj = BDE(volume)

    with pytest.raises(ValueError, match=WRAPPER_MESSAGE) as exc_info:
        bde_obj.unlock_with_recovery_password(RECOVERY_PASSWORD)

    # The VMK layer was passed cleanly; the failure is the FVEK AES-CCM verification.
    assert AUTH_CAUSE in str(exc_info.value.__cause__)
    assert SELECTION_CAUSE not in str(exc_info.value.__cause__)
    _assert_locked(bde_obj)
    _assert_no_secret_leak(secrets, caplog, exc_info.value)


def test_explicit_and_automatic_identifier_accept_healthy_target(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Both selection paths unlock the same healthy protector and yield identical key material."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    volume, secrets = build_volume(recovery_protectors=2)

    explicit_bde = BDE(volume)
    explicit_bde.unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=SECOND_RECOVERY_IDENTIFIER)
    assert explicit_bde.unlocked
    assert explicit_bde._vmk == secrets["vmk"]
    assert explicit_bde._fvek == secrets["fvek"]

    automatic_volume, _ = build_volume(recovery_protectors=2)
    automatic_bde = BDE(automatic_volume)
    automatic_bde.unlock_with_recovery_password(RECOVERY_PASSWORD)
    assert automatic_bde.unlocked
    assert automatic_bde._vmk == explicit_bde._vmk
    assert automatic_bde._fvek == explicit_bde._fvek

    _assert_no_secret_leak(secrets, caplog)


def test_identifier_accepts_uuid_and_string_forms(caplog: pytest.LogCaptureFixture) -> None:
    """The identifier argument is honoured identically as a UUID object or a string."""
    caplog.set_level(logging.DEBUG, logger="dissect.fve")
    for identifier in (RECOVERY_IDENTIFIER, str(RECOVERY_IDENTIFIER)):
        volume, secrets = build_volume()
        bde_obj = BDE(volume)
        bde_obj.unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=identifier)
        assert bde_obj.unlocked
        assert bde_obj._fvek == secrets["fvek"]
        _assert_no_secret_leak(secrets, caplog)


def test_layer_2_unknown_identifier_keeps_other_protector_usable() -> None:
    """A failed explicit lookup leaves a separately created volume's healthy path intact."""
    failed_volume, _ = build_volume(recovery_protectors=2)
    failed_bde = BDE(failed_volume)
    with pytest.raises(ValueError, match=WRAPPER_MESSAGE):
        failed_bde.unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=UNKNOWN_IDENTIFIER)
    assert not failed_bde.unlocked

    fresh_volume, secrets = build_volume(recovery_protectors=2)
    fresh_bde = BDE(fresh_volume)
    fresh_bde.unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=RECOVERY_IDENTIFIER)
    assert fresh_bde.unlocked
    assert fresh_bde._fvek == secrets["fvek"]


def test_each_counterexample_reaches_its_expected_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the exact depth of every failure by instrumenting the VMK-auth and FVEK-unbox boundaries.

    Stage markers:
        ``vmk_auth``  - a recovery protector's wrapped VMK AES-CCM unbox was attempted.
        ``fvek_unbox`` - the wrapped FVEK AES-CCM unbox was attempted (only after VMK success).
    """
    stages: list[str] = []

    real_vmk_decrypt = VmkInfoDatum.decrypt

    def tracked_vmk_decrypt(self: VmkInfoDatum, key: bytes) -> object:
        stages.append("vmk_auth")
        return real_vmk_decrypt(self, key)

    real_fvek_unbox = AesCcmEncryptedDatum.unbox

    def tracked_fvek_unbox(self: AesCcmEncryptedDatum, key: object) -> object:
        # The same unbox method wraps both VMK and FVEK; only count the FVEK role.
        if self.role == c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY:
            stages.append("fvek_unbox")
        return real_fvek_unbox(self, key)

    monkeypatch.setattr(VmkInfoDatum, "decrypt", tracked_vmk_decrypt)
    monkeypatch.setattr(AesCcmEncryptedDatum, "unbox", tracked_fvek_unbox)

    # Layer 1: malformed text never reaches any on-disk key operation.
    stages.clear()
    format_volume, _ = build_volume()
    with pytest.raises(ValueError, match="invalid length"):
        BDE(format_volume).unlock_with_recovery_password("000000-000000-000000")
    assert stages == []

    # Layer 2: unknown identifier filters every protector, so no authentication is attempted.
    stages.clear()
    selection_volume, _ = build_volume(recovery_protectors=2)
    with pytest.raises(ValueError, match=WRAPPER_MESSAGE):
        BDE(selection_volume).unlock_with_recovery_password(RECOVERY_PASSWORD, identifier=UNKNOWN_IDENTIFIER)
    assert stages == []

    # Layer 3: the protector is reached and its VMK authentication is attempted; FVEK is never touched.
    stages.clear()
    vmk_volume, _ = build_volume(corrupt_vmk_identifier=RECOVERY_IDENTIFIER)
    with pytest.raises(ValueError, match=WRAPPER_MESSAGE):
        BDE(vmk_volume).unlock_with_recovery_password(RECOVERY_PASSWORD)
    assert stages == ["vmk_auth"]
    assert "fvek_unbox" not in stages

    # Layer 4: VMK authentication succeeds and the FVEK datum unbox is reached before failing.
    stages.clear()
    fvek_volume, _ = build_volume(corrupt_fvek_datum=True)
    with pytest.raises(ValueError, match=WRAPPER_MESSAGE):
        BDE(fvek_volume).unlock_with_recovery_password(RECOVERY_PASSWORD)
    assert stages == ["vmk_auth", "fvek_unbox"]
