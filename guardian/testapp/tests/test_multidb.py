"""
Tests for using django-guardian with multiple databases in one process.

Primary keys, content type ids and user ids are only unique within a single
database, so when an application switches between regional databases the same
ids get reused with different meaning. The object permission checker must
therefore resolve everything (content types, permission rows, group
memberships) against the database that owns the object being checked - even
when a single checker instance is reused across databases.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from guardian.core import ObjectPermissionChecker
from guardian.exceptions import ObjectDatabaseAmbiguityError
from guardian.models import UserObjectPermission
from guardian.shortcuts import assign_perm, get_perms
from guardian.testapp.models import Project, ProjectUserObjectPermission

User = get_user_model()


class MultiDatabaseTestCase(TestCase):
    """Base fixture: two databases holding mirror records with identical pks.

    ``default`` and ``secondary`` each get the same user, the same target
    objects (a Group for the generic permission models, a Project for the
    direct foreign key models) and the same team group - all created in the
    same order so their primary keys collide across databases. The grants are
    then set to opposite states per database.
    """

    databases = {"default", "secondary"}

    def setUp(self):
        super().setUp()
        ContentType.objects.clear_cache()

        # Same account id reused in both databases.
        self.user_default = User.objects.db_manager("default").create_user(username="region-user")
        self.user_secondary = User.objects.db_manager("secondary").create_user(username="region-user")
        self.assertEqual(self.user_default.pk, self.user_secondary.pk)

        # Generic-permission targets with colliding pks.
        self.group_default = Group.objects.using("default").create(name="shared-group")
        self.group_secondary = Group.objects.using("secondary").create(name="shared-group")
        self.assertEqual(self.group_default.pk, self.group_secondary.pk)

        # Direct-fk-permission targets with colliding pks.
        self.project_default = Project.objects.using("default").create(name="shared-project")
        self.project_secondary = Project.objects.using("secondary").create(name="shared-project")
        self.assertEqual(self.project_default.pk, self.project_secondary.pk)

        # Team membership in both databases, for group-based checks.
        self.team_default = Group.objects.using("default").create(name="team")
        self.team_secondary = Group.objects.using("secondary").create(name="team")
        self.user_default.groups.add(self.team_default)
        self.user_secondary.groups.add(self.team_secondary)

        # Make the content type id of auth.Group diverge between the
        # databases: delete it in "secondary" (cascading to its Permission
        # rows), insert a placeholder so the recreated row gets a fresh,
        # higher id than in "default".
        ContentType.objects.using("secondary").get(app_label="auth", model="group").delete()
        ContentType.objects.using("secondary").create(app_label="guardian_multidb", model="placeholder")
        ContentType.objects.clear_cache()
        self.ctype_group_default = ContentType.objects.db_manager("default").get_for_model(Group)
        self.ctype_group_secondary = ContentType.objects.db_manager("secondary").get_for_model(Group)
        self.assertNotEqual(self.ctype_group_default.id, self.ctype_group_secondary.id)

        # Recreate the Permission rows that were cascaded away in "secondary".
        self.perm_delete_group_secondary = Permission.objects.using("secondary").create(
            codename="delete_group", name="Can delete group", content_type=self.ctype_group_secondary
        )
        Permission.objects.using("secondary").create(
            codename="change_group", name="Can change group", content_type=self.ctype_group_secondary
        )

        # Opposite grant states per database, generic permission model:
        # "default" grants change_group, "secondary" grants delete_group.
        assign_perm("change_group", self.user_default, self.group_default)
        UserObjectPermission.objects.using("secondary").bulk_create(
            [
                UserObjectPermission(
                    user=self.user_secondary,
                    permission=self.perm_delete_group_secondary,
                    content_type=self.ctype_group_secondary,
                    object_pk=str(self.group_secondary.pk),
                )
            ]
        )

        # Group-based grant, only in "default".
        assign_perm("view_group", self.team_default, self.group_default)

        # Opposite grant states per database, direct foreign key model:
        # "default" grants change_project, "secondary" grants delete_project.
        assign_perm("change_project", self.user_default, self.project_default)
        perm_delete_project_secondary = Permission.objects.using("secondary").get(
            codename="delete_project", content_type__app_label="testapp", content_type__model="project"
        )
        ProjectUserObjectPermission.objects.using("secondary").create(
            user=self.user_secondary,
            permission=perm_delete_project_secondary,
            content_object=self.project_secondary,
        )


class SingleObjectMultiDatabaseTest(MultiDatabaseTestCase):
    def test_generic_model_checks_use_objects_database(self):
        checker = ObjectPermissionChecker(self.user_default)

        # One checker reused across databases: each answer must come from
        # the database the checked object lives in.
        self.assertTrue(checker.has_perm("change_group", self.group_default))
        self.assertFalse(checker.has_perm("change_group", self.group_secondary))
        self.assertFalse(checker.has_perm("delete_group", self.group_default))
        self.assertTrue(checker.has_perm("delete_group", self.group_secondary))

    def test_group_based_checks_use_objects_database(self):
        checker = ObjectPermissionChecker(self.user_default)

        self.assertTrue(checker.has_perm("view_group", self.group_default))
        self.assertFalse(checker.has_perm("view_group", self.group_secondary))

    def test_direct_fk_model_checks_use_objects_database(self):
        checker = ObjectPermissionChecker(self.user_default)

        self.assertTrue(checker.has_perm("change_project", self.project_default))
        self.assertFalse(checker.has_perm("change_project", self.project_secondary))
        self.assertFalse(checker.has_perm("delete_project", self.project_default))
        self.assertTrue(checker.has_perm("delete_project", self.project_secondary))

    def test_superuser_perms_come_from_objects_database(self):
        superuser = User.objects.db_manager("default").create_user(username="region-admin", is_superuser=True)
        checker = ObjectPermissionChecker(superuser)

        default_perms = checker.get_perms(self.group_default)
        secondary_perms = checker.get_perms(self.group_secondary)
        self.assertIn("view_group", default_perms)
        self.assertNotIn("view_group", secondary_perms)
        self.assertIn("delete_group", secondary_perms)

    def test_shortcuts_follow_objects_database(self):
        self.assertEqual(set(get_perms(self.user_default, self.group_default)), {"change_group", "view_group"})
        self.assertEqual(set(get_perms(self.user_default, self.group_secondary)), {"delete_group"})

    def test_unsaved_object_is_refused(self):
        checker = ObjectPermissionChecker(self.user_default)
        unsaved = Group(name="unsaved-group")

        with self.assertRaises(ObjectDatabaseAmbiguityError) as ctx:
            checker.has_perm("change_group", unsaved)
        message = str(ctx.exception)
        self.assertIn("auth.Group", message)
        self.assertIn("unknown", message)

        with self.assertRaises(ObjectDatabaseAmbiguityError):
            checker.get_perms(unsaved)


class PrefetchMultiDatabaseTest(MultiDatabaseTestCase):
    def test_prefetch_per_queryset_database(self):
        checker = ObjectPermissionChecker(self.user_default)

        self.assertTrue(checker.prefetch_perms(Group.objects.using("default").filter(name="shared-group")))
        self.assertTrue(checker.prefetch_perms(Group.objects.using("secondary").filter(name="shared-group")))

        self.assertTrue(checker.has_perm("change_group", self.group_default))
        self.assertFalse(checker.has_perm("change_group", self.group_secondary))
        self.assertFalse(checker.has_perm("delete_group", self.group_default))
        self.assertTrue(checker.has_perm("delete_group", self.group_secondary))

    def test_prefetch_list_uses_objects_database(self):
        checker = ObjectPermissionChecker(self.user_default)

        self.assertTrue(checker.prefetch_perms([self.project_default]))
        self.assertTrue(checker.prefetch_perms([self.project_secondary]))

        self.assertTrue(checker.has_perm("change_project", self.project_default))
        self.assertFalse(checker.has_perm("change_project", self.project_secondary))
        self.assertFalse(checker.has_perm("delete_project", self.project_default))
        self.assertTrue(checker.has_perm("delete_project", self.project_secondary))

    def test_prefetch_mixed_databases_is_refused(self):
        checker = ObjectPermissionChecker(self.user_default)

        with self.assertRaises(ObjectDatabaseAmbiguityError) as ctx:
            checker.prefetch_perms([self.group_default, self.group_secondary])
        message = str(ctx.exception)
        self.assertIn("default", message)
        self.assertIn("secondary", message)

    def test_prefetch_unsaved_object_is_refused(self):
        checker = ObjectPermissionChecker(self.user_default)

        with self.assertRaises(ObjectDatabaseAmbiguityError) as ctx:
            checker.prefetch_perms([Group(name="unsaved-group")])
        self.assertIn("auth.Group", str(ctx.exception))
