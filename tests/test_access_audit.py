from __future__ import annotations

import io
from uuid import UUID

import pytest
from dissect.util.sid import write_sid

from dissect.ntfs.access import (
    ACCESS_SYSTEM_SECURITY,
    MAXIMUM_ALLOWED,
    AceSpec,
    Decision,
    ObjectType,
    build_descriptor,
    build_empty_dacl_descriptor,
    build_null_dacl_descriptor,
    evaluate_descriptor,
    evaluate_descriptor_bytes,
    map_generic_access,
    mask_names,
)
from dissect.ntfs.c_ntfs import ACE_TYPE, c_ntfs
from dissect.ntfs.secure import SecurityDescriptor

USER = "S-1-5-21-10-20-30-1000"
ADMINS = "S-1-5-32-544"
OTHER = "S-1-5-21-10-20-30-1001"
TOKEN = [USER, "S-1-5-32-545", "S-1-5-11"]

FILE_ALL = 0x1F01FF
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000


def parse(blob: bytes) -> SecurityDescriptor:
    return SecurityDescriptor(io.BytesIO(blob))


class TestGenericMapping:
    def test_known_mappings(self) -> None:
        assert map_generic_access(GENERIC_READ, ObjectType.FILE) == 0x120089
        assert map_generic_access(GENERIC_WRITE, ObjectType.FILE) == 0x116
        assert map_generic_access(0x20000000, "directory") == 0x1200A0
        assert map_generic_access(0x10000000, ObjectType.DIRECTORY) == FILE_ALL

    def test_specific_bits_are_preserved(self) -> None:
        assert map_generic_access(GENERIC_READ | 0x10000, ObjectType.FILE) == 0x120089 | 0x10000

    def test_special_bits_pass_through(self) -> None:
        assert map_generic_access(MAXIMUM_ALLOWED, ObjectType.FILE) == MAXIMUM_ALLOWED
        assert map_generic_access(ACCESS_SYSTEM_SECURITY, ObjectType.FILE) == ACCESS_SYSTEM_SECURITY

    def test_unknown_object_type_rejected(self) -> None:
        with pytest.raises(ValueError):
            map_generic_access(GENERIC_READ, "registry_key")

    def test_mask_names(self) -> None:
        assert "DELETE" in mask_names(0x10000)
        assert mask_names(0) == []


class TestDaclStates:
    def test_null_dacl_allows_everything(self) -> None:
        decision = evaluate_descriptor_bytes(build_null_dacl_descriptor(owner=USER), TOKEN, FILE_ALL)
        assert decision.decision == Decision.ALLOW
        assert decision.dacl_state == "null"
        assert decision.granted_mask == FILE_ALL
        assert decision.remaining_mask == 0

    def test_empty_dacl_denies_everything(self) -> None:
        decision = evaluate_descriptor_bytes(build_empty_dacl_descriptor(owner=USER), TOKEN, FILE_ALL)
        assert decision.decision == Decision.DENY
        assert decision.dacl_state == "empty"
        assert decision.granted_mask == 0
        assert decision.denied_mask == FILE_ALL

    def test_same_sid_null_vs_empty_differ(self) -> None:
        null = evaluate_descriptor_bytes(build_null_dacl_descriptor(owner=USER), [USER], 0x1)
        empty = evaluate_descriptor_bytes(build_empty_dacl_descriptor(owner=USER), [USER], 0x1)
        assert null.decision == Decision.ALLOW
        assert empty.decision == Decision.DENY

    def test_null_dacl_maximum_allowed_returns_file_all(self) -> None:
        decision = evaluate_descriptor_bytes(build_null_dacl_descriptor(), TOKEN, MAXIMUM_ALLOWED)
        assert decision.decision == Decision.ALLOW
        assert decision.granted_mask == FILE_ALL

    def test_empty_dacl_maximum_allowed_is_zero_grant(self) -> None:
        decision = evaluate_descriptor_bytes(build_empty_dacl_descriptor(), TOKEN, MAXIMUM_ALLOWED)
        assert decision.decision == Decision.ALLOW
        assert decision.granted_mask == 0


class TestAllowDenyOrdering:
    def test_deny_first_blocks_bit_even_with_later_full_allow(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_DENIED", USER, 0x2),
                AceSpec("ACCESS_ALLOWED", USER, FILE_ALL),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, FILE_ALL)
        assert decision.decision == Decision.DENY
        assert decision.denied_mask == 0x2
        # The later allow must not restore the denied WRITE_DATA bit.
        assert decision.granted_mask == FILE_ALL & ~0x2

    def test_reordering_records_a_different_path_but_same_bit_set(self) -> None:
        allow_first = build_descriptor(
            [
                AceSpec("ACCESS_ALLOWED", USER, FILE_ALL),
                AceSpec("ACCESS_DENIED", USER, 0x2),
            ]
        )
        deny_first = build_descriptor(
            [
                AceSpec("ACCESS_DENIED", USER, 0x2),
                AceSpec("ACCESS_ALLOWED", USER, FILE_ALL),
            ]
        )
        first = evaluate_descriptor_bytes(allow_first, TOKEN, FILE_ALL)
        second = evaluate_descriptor_bytes(deny_first, TOKEN, FILE_ALL)
        # Plain allow/deny ACEs are order-independent for the final bit set:
        # Windows unions the grants and the denials across the whole DACL.
        assert first.decision == second.decision == Decision.DENY
        assert first.granted_mask == second.granted_mask == FILE_ALL & ~0x2
        assert first.denied_mask == second.denied_mask == 0x2
        # But the recorded, re-computable path reflects the stored order.
        assert first.trace[0].action == "allow"
        assert second.trace[0].action == "deny"

    def test_misordered_conditional_ace_is_never_silently_allowed(self) -> None:
        conditional_first = build_descriptor(
            [
                AceSpec("ACCESS_ALLOWED_CALLBACK", USER, 0x3, application_data=b"x"),
                AceSpec("ACCESS_DENIED", USER, 0x1),
            ]
        )
        deny_first = build_descriptor(
            [
                AceSpec("ACCESS_DENIED", USER, 0x1),
                AceSpec("ACCESS_ALLOWED_CALLBACK", USER, 0x3, application_data=b"x"),
            ]
        )
        # A hard deny still produces DENY in both orders; the conditional ACE
        # is recorded as undecided rather than skipped.
        for blob in (conditional_first, deny_first):
            decision = evaluate_descriptor_bytes(blob, TOKEN, 0x3)
            assert decision.decision == Decision.DENY
            assert any(entry.action == "undecided" for entry in decision.trace)

    def test_unrelated_sid_ace_does_not_apply(self) -> None:
        blob = build_descriptor([AceSpec("ACCESS_ALLOWED", OTHER, FILE_ALL)])
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.DENY
        assert decision.trace[0].action == "skip"


class TestInheritance:
    def test_inherit_only_ace_is_skipped(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_ALLOWED", USER, FILE_ALL, ace_flags=0x8),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.DENY
        assert decision.trace[0].action == "skip"

    def test_inherited_ace_still_applies_to_this_object(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_ALLOWED", USER, 0x1, ace_flags=0x10),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.ALLOW
        assert decision.trace[0].action == "allow"


class TestUndecidedSemantics:
    def test_callback_ace_with_data_is_undecided(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_ALLOWED_CALLBACK", USER, 0x1, application_data=b"cond"),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.UNDECIDED
        assert decision.trace[0].action == "undecided"

    def test_callback_ace_for_other_sid_is_not_applicable(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_DENIED_CALLBACK", OTHER, 0x1, application_data=b"cond"),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.DENY
        assert decision.trace[0].action == "skip"

    def test_hard_deny_overrides_undecided(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_DENIED", USER, 0x1),
                AceSpec("ACCESS_ALLOWED_CALLBACK", USER, FILE_ALL, application_data=b"x"),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, FILE_ALL)
        assert decision.decision == Decision.DENY
        assert decision.denied_mask & 0x1

    def test_access_system_security_is_undecided(self) -> None:
        blob = build_descriptor([AceSpec("ACCESS_ALLOWED", USER, FILE_ALL)])
        decision = evaluate_descriptor_bytes(blob, TOKEN, ACCESS_SYSTEM_SECURITY | 0x1)
        assert decision.decision == Decision.UNDECIDED
        assert decision.undecided_mask == ACCESS_SYSTEM_SECURITY


def _object_ace_blob(
    ace_type: str,
    sid: str,
    mask: int,
    *,
    object_guid: str | None = None,
) -> bytes:
    obj_flags = 0
    guids = b""
    if object_guid:
        obj_flags |= 1
        guids += UUID(object_guid).bytes_le
    body = c_ntfs.DWORD.dumps(mask) + c_ntfs.DWORD.dumps(obj_flags) + guids + write_sid(sid)
    header = c_ntfs._ACE_HEADER(
        AceType=ACE_TYPE[ace_type],
        AceFlags=c_ntfs.ACE_FLAGS(0),
        AceSize=len(c_ntfs._ACE_HEADER) + len(body),
    )
    ace_blob = header.dumps() + body
    acl = c_ntfs._ACL(AclRevision=2, Sbz1=0, AclSize=8 + len(ace_blob), AceCount=1, Sbz2=0).dumps() + ace_blob
    control = int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE) | int(
        c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT
    )
    sd_header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(
        Revision=1,
        Sbz1=0,
        Control=c_ntfs.SECURITY_DESCRIPTOR_CONTROL(control),
        Owner=0,
        Group=0,
        Sacl=0,
        Dacl=20,
    )
    return sd_header.dumps() + acl


class TestObjectAndCompoundAce:
    def test_scoped_object_ace_is_undecided(self) -> None:
        blob = _object_ace_blob(
            "ACCESS_ALLOWED_OBJECT",
            USER,
            0x1,
            object_guid="01234567-89ab-cdef-1111-111111111111",
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.UNDECIDED

    def test_unscoped_object_ace_is_plain_allow(self) -> None:
        blob = _object_ace_blob("ACCESS_ALLOWED_OBJECT", USER, 0x1)
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.ALLOW
        assert decision.granted_mask == 0x1

    def _compound_blob(self, client_sid: str, server_sid: str, mask: int) -> bytes:
        body = (
            c_ntfs.DWORD.dumps(mask)
            + c_ntfs.COMPOUND_ACE_TYPE.dumps(c_ntfs.COMPOUND_ACE_TYPE.COMPOUND_ACE_IMPERSONATION)
            + c_ntfs.USHORT.dumps(0)
            + write_sid(server_sid)
            + write_sid(client_sid)
        )
        header = c_ntfs._ACE_HEADER(
            AceType=ACE_TYPE.ACCESS_ALLOWED_COMPOUND,
            AceFlags=c_ntfs.ACE_FLAGS(0),
            AceSize=len(c_ntfs._ACE_HEADER) + len(body),
        )
        ace_blob = header.dumps() + body
        acl = c_ntfs._ACL(AclRevision=2, Sbz1=0, AclSize=8 + len(ace_blob), AceCount=1, Sbz2=0).dumps() + ace_blob
        control = int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE) | int(
            c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT
        )
        sd_header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(
            Revision=1,
            Sbz1=0,
            Control=c_ntfs.SECURITY_DESCRIPTOR_CONTROL(control),
            Owner=0,
            Group=0,
            Sacl=0,
            Dacl=20,
        )
        return sd_header.dumps() + acl

    def test_compound_ace_is_undecided_when_client_matches(self) -> None:
        blob = self._compound_blob(USER, "S-1-5-11", FILE_ALL)
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert decision.decision == Decision.UNDECIDED


class TestMaximumAllowed:
    def test_union_of_grants(self) -> None:
        blob = build_descriptor([AceSpec("ACCESS_ALLOWED", USER, 0x120089)])
        decision = evaluate_descriptor_bytes(blob, TOKEN, MAXIMUM_ALLOWED)
        assert decision.decision == Decision.ALLOW
        assert decision.maximum_allowed is True
        assert decision.granted_mask == 0x120089

    def test_deny_does_not_shrink_maximum_allowed_grant(self) -> None:
        blob = build_descriptor(
            [
                AceSpec("ACCESS_DENIED", USER, 0x1),
                AceSpec("ACCESS_ALLOWED", USER, 0x120089),
            ]
        )
        decision = evaluate_descriptor_bytes(blob, TOKEN, MAXIMUM_ALLOWED)
        assert decision.decision == Decision.ALLOW
        assert decision.granted_mask == 0x120089
        assert decision.denied_mask == 0


class TestOwner:
    def test_owner_implicit_rights(self) -> None:
        blob = build_descriptor([AceSpec("ACCESS_ALLOWED", "S-1-1-0", 0x1)], owner=USER)
        decision = evaluate_descriptor_bytes(blob, TOKEN, 0x40000)
        assert decision.decision == Decision.ALLOW
        assert decision.granted_mask & 0x40000

    def test_owner_rights_ace_constrains_owner(self) -> None:
        blob = build_descriptor([AceSpec("ACCESS_ALLOWED", "S-1-3-4", 0x1)], owner=USER)
        denied = evaluate_descriptor_bytes(blob, TOKEN, 0x40000)
        granted = evaluate_descriptor_bytes(blob, TOKEN, 0x1)
        assert denied.decision == Decision.DENY
        assert granted.decision == Decision.ALLOW


class TestRealDescriptors:
    def test_parsed_ntfs_descriptor(self, sds_bin) -> None:  # noqa: ANN001
        from dissect.ntfs.secure import Secure

        secure = Secure(sds=sds_bin)
        descriptor = secure.lookup(256)
        assert evaluate_descriptor(descriptor, ["S-1-5-18"], 0x120089).decision == Decision.ALLOW
        assert evaluate_descriptor(descriptor, ["S-1-5-21-9-9-9-9"], 0x1).decision == Decision.DENY
