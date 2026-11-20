from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from guardian.exceptions import ObjectNotPersisted, StalePermissionStateError
from guardian.shortcuts import (
    assign_perm,
    get_perms,
    get_permission_snapshot,
    remove_perm,
    sync_object_permissions,
)
from guardian.testapp.models import CharPKModel, Post, Project

User = get_user_model()


class PermissionSnapshotTestCase(TestCase):
    def setUp(self):
        self.post = Post.objects.create(title="handover document")
        self.project = Project.objects.create(name="handover project")
        self.joe = User.objects.create_user("joe")
        self.jane = User.objects.create_user("jane")
        self.editors = Group.objects.create(name="editors")
        self.viewers = Group.objects.create(name="viewers")
        self.ctype = ContentType.objects.get_for_model(Post)
        self.post_permissions = sorted(
            Permission.objects.filter(content_type=self.ctype).values_list("codename", flat=True)
        )

    def empty_snapshot(self):
        return {"users": {}, "groups": {}}

    def test_snapshot_reports_users_and_groups_for_same_object(self):
        assign_perm("view_post", self.joe, self.post)
        assign_perm("change_post", self.editors, self.post)
        assign_perm("delete_post", self.editors, self.post)

        snapshot = get_permission_snapshot(self.post)

        self.assertEqual(snapshot["users"], {self.joe.pk: {"view_post"}})
        self.assertEqual(
            snapshot["groups"],
            {self.editors.pk: {"change_post", "delete_post"}},
        )
        self.assertEqual(snapshot["groups"].get(self.viewers.pk), None)

    def test_snapshot_does_not_leak_other_objects_or_global_perms(self):
        other_post = Post.objects.create(title="other document")
        assign_perm("view_post", self.joe, other_post)
        assign_perm("change_post", self.editors, other_post)
        global_perm = Permission.objects.filter(content_type__app_label="testapp").first()
        self.assertIsNotNone(global_perm)
        self.joe.user_permissions.add(global_perm)

        self.assertEqual(get_permission_snapshot(self.post), self.empty_snapshot())

    def test_sync_replaces_user_and_group_grants_atomically(self):
        assign_perm("view_post", self.joe, self.post)
        assign_perm("delete_post", self.editors, self.post)
        base = get_permission_snapshot(self.post)

        desired = {
            "users": {
                self.joe.pk: ["change_post", "view_post"],
                self.jane.pk: ["view_post"],
            },
            "groups": {
                self.viewers.pk: ["view_post"],
            },
        }
        result = sync_object_permissions(self.post, desired, expected=base)

        self.assertEqual(
            result,
            {
                "users": {
                    self.joe.pk: {"change_post", "view_post"},
                    self.jane.pk: {"view_post"},
                },
                "groups": {self.viewers.pk: {"view_post"}},
            },
        )
        self.assertEqual(get_permission_snapshot(self.post), result)
        self.assertEqual(set(get_perms(self.joe, self.post)), {"change_post", "view_post"})
        self.assertEqual(set(get_perms(self.jane, self.post)), {"view_post"})
        self.assertEqual(set(get_perms(self.viewers, self.post)), {"view_post"})
        self.assertEqual(get_perms(self.editors, self.post), [])

    def test_duplicate_submission_is_idempotent(self):
        first = sync_object_permissions(
            self.post,
            {"users": {self.joe.pk: ["view_post"]}, "groups": {self.editors.pk: ["view_post"]}},
            expected=self.empty_snapshot(),
        )

        base = get_permission_snapshot(self.post)
        second = sync_object_permissions(
            self.post,
            {"users": {self.joe.pk: ["view_post"]}, "groups": {self.editors.pk: ["view_post"]}},
            expected=base,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            get_permission_snapshot(self.post),
            {"users": {self.joe.pk: {"view_post"}}, "groups": {self.editors.pk: {"view_post"}}},
        )

    def test_stale_expected_snapshot_is_rejected_and_state_is_kept(self):
        sync_object_permissions(
            self.post,
            {"users": {self.joe.pk: ["view_post"]}, "groups": {}},
            expected=self.empty_snapshot(),
        )
        stale_base = self.empty_snapshot()

        with self.assertRaises(StalePermissionStateError):
            sync_object_permissions(
                self.post,
                {"users": {self.jane.pk: ["change_post"]}, "groups": {}},
                expected=stale_base,
            )

        self.assertEqual(
            get_permission_snapshot(self.post),
            {"users": {self.joe.pk: {"view_post"}}, "groups": {}},
        )
        self.assertEqual(get_perms(self.joe, self.post), ["view_post"])
        self.assertEqual(get_perms(self.jane, self.post), [])

    def test_failed_write_rolls_back_whole_snapshot(self):
        assign_perm("view_post", self.joe, self.post)
        assign_perm("view_post", self.editors, self.post)
        before = get_permission_snapshot(self.post)

        from guardian.utils import get_user_obj_perms_model

        manager_class = get_user_obj_perms_model(self.post).objects.__class__

        def failing_bulk_create(queryset, objs, *args, **kwargs):
            raise RuntimeError("simulated mid-transfer write rejection")

        with mock.patch.object(manager_class, "bulk_create", failing_bulk_create):
            with self.assertRaises(RuntimeError):
                sync_object_permissions(
                    self.post,
                    {
                        "users": {self.jane.pk: ["change_post", "delete_post"]},
                        "groups": {self.viewers.pk: ["view_post"]},
                    },
                )

        self.assertEqual(get_permission_snapshot(self.post), before)
        self.assertEqual(get_perms(self.joe, self.post), ["view_post"])
        self.assertEqual(get_perms(self.editors, self.post), ["view_post"])
        self.assertEqual(get_perms(self.jane, self.post), [])
        self.assertEqual(get_perms(self.viewers, self.post), [])

    def test_clearing_all_grants(self):
        assign_perm("view_post", self.joe, self.post)
        assign_perm("change_post", self.jane, self.post)
        assign_perm("view_post", self.editors, self.post)
        assign_perm("delete_post", self.viewers, self.post)
        base = get_permission_snapshot(self.post)

        result = sync_object_permissions(self.post, self.empty_snapshot(), expected=base)

        self.assertEqual(result, self.empty_snapshot())
        self.assertEqual(get_permission_snapshot(self.post), self.empty_snapshot())
        for identity in (self.joe, self.jane, self.editors, self.viewers):
            self.assertEqual(get_perms(identity, self.post), [])

    def test_identity_models_remain_independently_verifiable(self):
        assign_perm("view_post", self.joe, self.post)
        assign_perm("change_post", self.editors, self.post)

        snapshot = sync_object_permissions(
            self.post,
            {
                "users": {self.joe.pk: ["view_post", "delete_post"]},
                "groups": {self.editors.pk: ["change_post"]},
            },
            expected=get_permission_snapshot(self.post),
        )

        self.assertEqual(set(get_perms(self.joe, self.post)), {"view_post", "delete_post"})
        self.assertEqual(get_perms(self.editors, self.post), ["change_post"])
        self.assertEqual(
            snapshot,
            {
                "users": {self.joe.pk: {"view_post", "delete_post"}},
                "groups": {self.editors.pk: {"change_post"}},
            },
        )

    def test_sync_works_with_direct_foreign_key_permission_models(self):
        assign_perm("view_project", self.joe, self.project)
        base = get_permission_snapshot(self.project)

        result = sync_object_permissions(
            self.project,
            {
                "users": {self.jane.pk: ["change_project", "view_project"]},
                "groups": {self.editors.pk: ["delete_project"]},
            },
            expected=base,
        )

        self.assertEqual(
            result,
            {
                "users": {self.jane.pk: {"change_project", "view_project"}},
                "groups": {self.editors.pk: {"delete_project"}},
            },
        )
        self.assertEqual(get_perms(self.joe, self.project), [])
        self.assertEqual(set(get_perms(self.jane, self.project)), {"change_project", "view_project"})
        self.assertEqual(get_perms(self.editors, self.project), ["delete_project"])

    def test_accepts_identity_instances_and_permission_instances(self):
        view = Permission.objects.get(content_type=self.ctype, codename="view_post")
        change = Permission.objects.get(content_type=self.ctype, codename="change_post")

        result = sync_object_permissions(
            self.post,
            {"users": {self.joe: [view, change]}, "groups": {self.editors: [view]}},
        )

        self.assertEqual(
            result,
            {
                "users": {self.joe.pk: {"view_post", "change_post"}},
                "groups": {self.editors.pk: {"view_post"}},
            },
        )

    def test_unknown_permission_is_rejected_before_any_write(self):
        assign_perm("view_post", self.joe, self.post)
        before = get_permission_snapshot(self.post)

        with self.assertRaises(ValueError):
            sync_object_permissions(
                self.post,
                {"users": {self.jane.pk: ["not_a_real_perm"]}, "groups": {}},
            )

        self.assertEqual(get_permission_snapshot(self.post), before)

    def test_missing_section_is_rejected(self):
        with self.assertRaises(ValueError):
            sync_object_permissions(self.post, {"users": {}})

    def test_unsaved_object_is_rejected(self):
        unsaved = Post(title="not saved")
        with self.assertRaises(ObjectNotPersisted):
            get_permission_snapshot(unsaved)
        with self.assertRaises(ObjectNotPersisted):
            sync_object_permissions(unsaved, self.empty_snapshot())

    def test_expected_mismatch_after_external_change_keeps_independent_perms(self):
        assign_perm("view_post", self.joe, self.post)
        assign_perm("view_post", self.editors, self.post)
        base = get_permission_snapshot(self.post)

        remove_perm("view_post", self.editors, self.post)
        assign_perm("delete_post", self.viewers, self.post)

        with self.assertRaises(StalePermissionStateError):
            sync_object_permissions(
                self.post,
                {"users": {self.joe.pk: ["change_post"]}, "groups": {}},
                expected=base,
            )

        self.assertEqual(
            get_permission_snapshot(self.post),
            {
                "users": {self.joe.pk: {"view_post"}},
                "groups": {self.viewers.pk: {"delete_post"}},
            },
        )

    def test_supports_objects_with_non_integer_primary_keys(self):
        char_pk_object = CharPKModel.objects.create(char_pk="doc-handover-001")

        result = sync_object_permissions(
            char_pk_object,
            {"users": {self.joe.pk: ["view_charpkmodel"]}, "groups": {}},
        )

        self.assertEqual(get_permission_snapshot(char_pk_object), result)
        self.assertEqual(
            result,
            {"users": {self.joe.pk: {"view_charpkmodel"}}, "groups": {}},
        )

    def test_duplicate_codenames_and_dotted_names_are_normalized(self):
        result = sync_object_permissions(
            self.post,
            {
                "users": {self.joe.pk: ["view_post", "view_post", "testapp.view_post"]},
                "groups": {},
            },
        )

        self.assertEqual(result, {"users": {self.joe.pk: {"view_post"}}, "groups": {}})

    def test_expected_accepts_snapshot_round_trip_verbatim(self):
        sync_object_permissions(
            self.post,
            {"users": {self.joe.pk: ["view_post"]}, "groups": {self.editors.pk: ["view_post"]}},
        )
        snapshot = get_permission_snapshot(self.post)

        result = sync_object_permissions(
            self.post,
            {
                "users": {self.joe.pk: ["change_post"]},
                "groups": {self.editors.pk: ["view_post", "change_post"]},
            },
            expected=snapshot,
        )

        self.assertEqual(
            result,
            {
                "users": {self.joe.pk: {"change_post"}},
                "groups": {self.editors.pk: {"view_post", "change_post"}},
            },
        )
