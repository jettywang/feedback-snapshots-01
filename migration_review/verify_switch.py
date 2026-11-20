"""Local pre/post verification for migrating generic object permissions to
direct foreign-key tables.

Simulates the full switch runbook against guardian's own testapp:

  fixture (generic-only writes) -> preflight (stale content types) ->
  backfill -> enable direct models -> diff report -> rollback drill

Fixtures cover: UUID primary keys (incl. a legacy non-hyphenated object_pk),
a proxy model, and group grants. Run with:

    .venv/bin/python migration_review/verify_switch.py
"""

import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite://:memory:")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "guardian.testapp.testsettings")

import django

django.setup()

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection, models

call_command("migrate", run_syncdb=True, verbosity=0)

from guardian.core import ObjectPermissionChecker
from guardian.ctypes import get_content_type
from guardian.models import (
    GroupObjectPermission,
    GroupObjectPermissionBase,
    UserObjectPermission,
    UserObjectPermissionBase,
)
from guardian.shortcuts import assign_perm
from guardian.testapp.models import (
    CustomUser,
    Project,
    ProjectGroupObjectPermission,
    ProjectUserObjectPermission,
    UUIDPKModel,
)


# --- runtime direct models for the UUID-pk model (the "new tables") ---------
class UUIDPKUserObjectPermission(UserObjectPermissionBase):
    content_object = models.ForeignKey(UUIDPKModel, on_delete=models.CASCADE)
    enabled = False  # switch lever: reads stay on the generic table for now

    class Meta:
        app_label = "testapp"


class UUIDPKGroupObjectPermission(GroupObjectPermissionBase):
    content_object = models.ForeignKey(UUIDPKModel, on_delete=models.CASCADE)
    enabled = False

    class Meta:
        app_label = "testapp"


class ProjectProxy(Project):
    class Meta:
        proxy = True
        app_label = "testapp"


with connection.schema_editor() as editor:
    editor.create_model(UUIDPKUserObjectPermission)
    editor.create_model(UUIDPKGroupObjectPermission)

DIRECT_MODELS = [
    ProjectUserObjectPermission,
    ProjectGroupObjectPermission,
    UUIDPKUserObjectPermission,
    UUIDPKGroupObjectPermission,
]

BACKFILL_MAP = [  # (generic, direct, target)
    (UserObjectPermission, ProjectUserObjectPermission, Project),
    (GroupObjectPermission, ProjectGroupObjectPermission, Project),
    (UserObjectPermission, UUIDPKUserObjectPermission, UUIDPKModel),
    (GroupObjectPermission, UUIDPKGroupObjectPermission, UUIDPKModel),
]


def set_switch(on):
    for model in DIRECT_MODELS:
        model.enabled = on


# --- fixtures: all writes land in the generic tables -------------------------
set_switch(False)

alice = CustomUser.objects.create(username="alice")
bob = CustomUser.objects.create(username="bob")
editors = Group.objects.create(name="editors")
alice.groups.add(editors)

p1 = Project.objects.create(name="proj-1")
p2 = Project.objects.create(name="proj-2")
u1 = UUIDPKModel.objects.create()
u2 = UUIDPKModel.objects.create()

assign_perm("change_project", alice, p1)          # user grant, int pk
assign_perm("view_project", editors, p1)          # group grant
assign_perm("delete_project", editors, p2)        # group grant, second object
assign_perm("view_uuidpkmodel", bob, u1)          # user grant, UUID pk
assign_perm("view_uuidpkmodel", editors, u1)      # group grant, UUID pk

# legacy row: UUID stored without hyphens, as older imports produced
uuid_ct = get_content_type(UUIDPKModel)
view_uuid_perm = Permission.objects.get(content_type=uuid_ct, codename="view_uuidpkmodel")
UserObjectPermission.objects.bulk_create(
    [UserObjectPermission(user=alice, permission=view_uuid_perm,
                          content_type=uuid_ct, object_pk=u2.pk.hex)]
)

# stale row: content type whose model no longer exists ("missing content type")
ghost_ct = ContentType.objects.create(app_label="legacy", model="ghost")
UserObjectPermission.objects.bulk_create(
    [UserObjectPermission(user=bob, permission=view_uuid_perm,
                          content_type=ghost_ct, object_pk="1")]
)

OBJECTS = [
    ("project:p1", Project.objects.get(pk=p1.pk)),
    ("project:p2", Project.objects.get(pk=p2.pk)),
    ("project-proxy:p1", ProjectProxy.objects.get(pk=p1.pk)),
    ("uuid:u1", UUIDPKModel.objects.get(pk=u1.pk)),
    ("uuid:u2", UUIDPKModel.objects.get(pk=u2.pk)),
]
SUBJECTS = [("user:alice", alice), ("user:bob", bob), ("group:editors", editors)]


def snapshot():
    """Effective permissions per (subject, object): user grants + group grants."""
    snap = {}
    for subject_key, subject in SUBJECTS:
        checker = ObjectPermissionChecker(subject)
        for obj_key, obj in OBJECTS:
            snap[(subject_key, obj_key)] = frozenset(checker.get_perms(obj))
    return snap


def diff_report(before, after):
    """Permission delta caused by the switch: REMOVED = lost, ADDED = gained."""
    rows = []
    for key in before:
        for perm in sorted(before[key] - after[key]):
            rows.append(("REMOVED", key, perm))
        for perm in sorted(after[key] - before[key]):
            rows.append(("ADDED", key, perm))
    return rows


def print_report(title, rows):
    print(f"\n== {title} ==")
    if not rows:
        print("  (empty: no permission gained or lost)")
    for status, (subject, obj), perm in rows:
        print(f"  {status:8s} {subject:14s} {obj:16s} {perm}")
    return rows


def preflight_missing_ct():
    """Generic rows whose content type has no model class cannot be mapped to
    any direct table. Any hit must pause the switch."""
    problems = []
    for generic in (UserObjectPermission, GroupObjectPermission):
        for row in generic.objects.all():
            ct = row.content_type
            if ct.model_class() is None:
                problems.append((generic.__name__, row.pk, f"{ct.app_label}.{ct.model}",
                                 "content type has no model class"))
    return problems


def preflight_format_drift():
    """Generic rows whose object_pk is not the canonical str(pk) the read path
    queries with (e.g. UUID stored without hyphens). These rows are DEAD today
    (never matched); normalizing them during backfill would silently GRANT the
    permission. Any hit must pause the switch for an explicit decision."""
    drift = []
    for generic, _direct, target in BACKFILL_MAP:
        ct = get_content_type(target)
        pk_field = target._meta.pk
        for row in generic.objects.filter(content_type=ct):
            canonical = str(pk_field.to_python(row.object_pk))
            if canonical != row.object_pk:
                drift.append((generic.__name__, row.pk, row.object_pk, canonical))
    return drift


def backfill(skip=None):
    """Copy generic rows into the direct tables, normalizing object_pk through
    the target pk field (UUID hyphenation, int casting)."""
    migrated, unmappable = 0, []
    for generic, direct, target in BACKFILL_MAP:
        if (generic, target) in (skip or []):
            continue
        ct = get_content_type(target)
        owner_field = "user" if hasattr(direct, "user") else "group"
        pk_field = target._meta.pk
        for row in generic.objects.filter(content_type=ct):
            pk = pk_field.to_python(row.object_pk)  # normalization point
            if not target.objects.filter(pk=pk).exists():
                unmappable.append((direct.__name__, row.pk, row.object_pk))
                continue
            direct.objects.get_or_create(
                **{owner_field: getattr(row, owner_field),
                   "permission": row.permission, "content_object_id": pk})
            migrated += 1
    return migrated, unmappable


print("== preflight 1/2: missing content types ==")
problems = preflight_missing_ct()
for model_name, pk, ct_label, reason in problems:
    print(f"  PAUSE  {model_name} pk={pk} ct={ct_label}: {reason}")
if problems:
    print("  -> switch held: direct models stay enabled=False, reads unchanged")
    # remediation: remove the stale rows, then re-run preflight
    UserObjectPermission.objects.filter(content_type=ghost_ct).delete()
    GroupObjectPermission.objects.filter(content_type=ghost_ct).delete()
    assert preflight_missing_ct() == [], "preflight must be clean before switching"
    print("  -> stale rows remediated, preflight clean")

print("\n== preflight 2/2: object_pk format drift ==")
drift = preflight_format_drift()
for model_name, pk, stored, canonical in drift:
    print(f"  PAUSE  {model_name} pk={pk} object_pk={stored!r} canonical={canonical!r}")
if drift:
    print("  -> switch held: normalizing during backfill would GRANT a dead permission")
    # remediation: normalize the generic row in place, BEFORE the baseline
    # snapshot, so the grant is an explicit, audited data fix - not a side
    # effect of the migration.
    for model_name, pk, _stored, canonical in drift:
        UserObjectPermission.objects.filter(pk=pk).update(object_pk=canonical)
    assert preflight_format_drift() == []
    print("  -> drift rows normalized in place (audited grant), preflight clean")

# baseline is taken AFTER data fixes, immediately before the switch: it is the
# effective-permission state we commit to preserving.
before = snapshot()

# --- phase A: incomplete backfill (group table for UUID model forgotten) ----
print("\n-- phase A: switch with incomplete backfill --")
backfill(skip=[(GroupObjectPermission, UUIDPKModel)])
set_switch(True)
rows = print_report("diff report (detects the loss)", diff_report(before, snapshot()))
assert any(r[0] == "REMOVED" and r[1] == ("user:alice", "uuid:u1") for r in rows)

print("\n-- rollback: enabled=False, generic rows untouched --")
set_switch(False)
rows = print_report("diff after rollback", diff_report(before, snapshot()))
assert not rows

# --- phase B: complete backfill, then switch ---------------------------------
print("\n-- phase B: complete backfill, then switch --")
migrated, unmappable = backfill()
print(f"  backfilled {migrated} rows, unmappable: {unmappable}")
assert not unmappable
set_switch(True)
after = snapshot()
rows = print_report("diff report (final)", diff_report(before, after))
assert not rows

# proxy reads the same direct table; legacy hex UUID row survived normalization
checker = ObjectPermissionChecker(alice)
assert "change_project" in checker.get_perms(ProjectProxy.objects.get(pk=p1.pk))
assert "view_uuidpkmodel" in ObjectPermissionChecker(alice).get_perms(u2)
print("\n  proxy object and legacy non-hyphenated UUID row verified")

print("\nALL CHECKS PASSED")
