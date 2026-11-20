"""Executable contract for object-permission combination semantics.

These tests pin down how ``get_objects_for_user`` / ``get_objects_for_group``
combine permissions granted through different sources (direct user grants vs.
indirect group grants, which frequently overlap) so the behavior can be
verified before and after a Django upgrade.

The same fixtures are exercised twice: once against a model using direct
foreign-key permission models (``Project``) and once against a model using
generic-relation permission models (``Post``). For every scenario the
per-object boolean answers (``user.has_perm`` / ``ObjectPermissionChecker``)
must agree with the queryset answers.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from guardian.core import ObjectPermissionChecker
from guardian.shortcuts import assign_perm, get_objects_for_group, get_objects_for_user
from guardian.testapp.models import Post, Project

User = get_user_model()


class PermissionCombinationContractMixin:
    """Shared fixtures and contract assertions.

    Subclasses provide ``model`` (and ``object_kwarg`` used to build objects)
    so the identical contract runs against direct FK and generic relation
    permission models.
    """

    model = None
    object_kwarg = None

    def setUp(self):
        self.user = User.objects.create(username="contract-user")
        self.group = Group.objects.create(name="contract-group")
        self.user.groups.add(self.group)

        app_label = self.model._meta.app_label
        model_name = self.model._meta.model_name
        self.change_perm = f"{app_label}.change_{model_name}"
        self.delete_perm = f"{app_label}.delete_{model_name}"

        def make_obj(name):
            return self.model.objects.create(**{self.object_kwarg: name})

        # Each permission comes from a different source: change is granted
        # directly to the user, delete only indirectly via the group.
        self.obj_split = make_obj("split")
        assign_perm(self.change_perm, self.user, self.obj_split)
        assign_perm(self.delete_perm, self.group, self.obj_split)

        # Both permissions granted explicitly to the user.
        self.obj_user_both = make_obj("user-both")
        assign_perm(self.change_perm, self.user, self.obj_user_both)
        assign_perm(self.delete_perm, self.user, self.obj_user_both)

        # Both permissions granted indirectly via the group.
        self.obj_group_both = make_obj("group-both")
        assign_perm(self.change_perm, self.group, self.obj_group_both)
        assign_perm(self.delete_perm, self.group, self.obj_group_both)

        # The same permission granted both explicitly and indirectly.
        self.obj_overlap = make_obj("overlap")
        assign_perm(self.change_perm, self.user, self.obj_overlap)
        assign_perm(self.change_perm, self.group, self.obj_overlap)

        # No permissions at all.
        self.obj_none = make_obj("none")

        self.all_objects = [
            self.obj_split,
            self.obj_user_both,
            self.obj_group_both,
            self.obj_overlap,
            self.obj_none,
        ]
        self.queryset = self.model.objects.all()

    def assertSameObjects(self, queryset, expected):
        self.assertEqual(
            {obj.pk for obj in queryset},
            {obj.pk for obj in expected},
            f"queryset returned {[str(o) for o in queryset]}",
        )

    def assertMatchesPerObjectBooleans(self, queryset, expected_bool):
        """Every object's queryset membership must equal its boolean answer."""
        returned_pks = {obj.pk for obj in queryset}
        for obj in self.all_objects:
            self.assertEqual(
                obj.pk in returned_pks,
                expected_bool(obj),
                f"boolean/queryset mismatch for {obj}",
            )

    def user_has_all(self, obj):
        return self.user.has_perm(self.change_perm, obj) and self.user.has_perm(self.delete_perm, obj)

    def user_has_any(self, obj):
        return self.user.has_perm(self.change_perm, obj) or self.user.has_perm(self.delete_perm, obj)

    def group_checker(self):
        return ObjectPermissionChecker(self.group)

    # -- user entry point: intersection of multiple permissions ------------

    def test_user_intersection_requires_all_perms_from_any_source(self):
        objects = get_objects_for_user(self.user, [self.change_perm, self.delete_perm], self.queryset)
        expected = [self.obj_split, self.obj_user_both, self.obj_group_both]
        self.assertSameObjects(objects, expected)
        self.assertMatchesPerObjectBooleans(objects, self.user_has_all)

    def test_user_intersection_without_groups_excludes_indirect_grants(self):
        objects = get_objects_for_user(
            self.user,
            [self.change_perm, self.delete_perm],
            self.queryset,
            use_groups=False,
        )
        self.assertSameObjects(objects, [self.obj_user_both])

    def test_user_union_accepts_any_perm(self):
        objects = get_objects_for_user(
            self.user,
            [self.change_perm, self.delete_perm],
            self.queryset,
            any_perm=True,
        )
        expected = [self.obj_split, self.obj_user_both, self.obj_group_both, self.obj_overlap]
        self.assertSameObjects(objects, expected)
        self.assertMatchesPerObjectBooleans(objects, self.user_has_any)

    def test_user_single_perm_matches_per_object_booleans(self):
        change_objects = get_objects_for_user(self.user, self.change_perm, self.queryset)
        self.assertSameObjects(
            change_objects,
            [self.obj_split, self.obj_user_both, self.obj_group_both, self.obj_overlap],
        )
        self.assertMatchesPerObjectBooleans(
            change_objects, lambda obj: self.user.has_perm(self.change_perm, obj)
        )

        delete_objects = get_objects_for_user(self.user, self.delete_perm, self.queryset)
        self.assertSameObjects(delete_objects, [self.obj_split, self.obj_user_both, self.obj_group_both])
        self.assertMatchesPerObjectBooleans(
            delete_objects, lambda obj: self.user.has_perm(self.delete_perm, obj)
        )

    def test_user_overlapping_grants_do_not_duplicate_results(self):
        objects = get_objects_for_user(self.user, self.change_perm, self.queryset)
        self.assertEqual(list(objects).count(self.obj_overlap), 1)

    # -- group entry point: any-of and all-of ------------------------------

    def test_group_any_perm_matches_per_object_booleans(self):
        objects = get_objects_for_group(
            self.group,
            [self.change_perm, self.delete_perm],
            self.queryset,
            any_perm=True,
        )
        expected = [self.obj_split, self.obj_group_both, self.obj_overlap]
        self.assertSameObjects(objects, expected)
        checker = self.group_checker()
        self.assertMatchesPerObjectBooleans(
            objects,
            lambda obj: checker.has_perm(self.change_perm, obj) or checker.has_perm(self.delete_perm, obj),
        )

    def test_group_intersection_matches_per_object_booleans(self):
        objects = get_objects_for_group(self.group, [self.change_perm, self.delete_perm], self.queryset)
        self.assertSameObjects(objects, [self.obj_group_both])
        checker = self.group_checker()
        self.assertMatchesPerObjectBooleans(
            objects,
            lambda obj: checker.has_perm(self.change_perm, obj) and checker.has_perm(self.delete_perm, obj),
        )

    # -- empty permission set ----------------------------------------------

    def test_user_empty_perms_return_objects_holding_any_object_permission(self):
        objects = get_objects_for_user(self.user, [], self.queryset)
        self.assertSameObjects(
            objects,
            [self.obj_split, self.obj_user_both, self.obj_group_both, self.obj_overlap],
        )
        objects_any = get_objects_for_user(self.user, [], self.queryset, any_perm=True)
        self.assertSameObjects(objects_any, objects)

    def test_user_empty_perms_without_any_grants_return_nothing(self):
        stranger = User.objects.create(username="contract-stranger")
        self.assertSameObjects(get_objects_for_user(stranger, [], self.queryset), [])

    def test_group_empty_perms_return_objects_holding_any_group_permission(self):
        objects = get_objects_for_group(self.group, [], self.queryset)
        self.assertSameObjects(objects, [self.obj_split, self.obj_group_both, self.obj_overlap])

    def test_group_empty_perms_without_any_grants_return_nothing(self):
        other_group = Group.objects.create(name="contract-other-group")
        self.assertSameObjects(get_objects_for_group(other_group, [], self.queryset), [])


class DirectRelationContractTests(PermissionCombinationContractMixin, TestCase):
    """Contract against direct foreign-key permission models."""

    model = Project
    object_kwarg = "name"


class GenericRelationContractTests(PermissionCombinationContractMixin, TestCase):
    """Contract against generic-relation permission models."""

    model = Post
    object_kwarg = "title"
