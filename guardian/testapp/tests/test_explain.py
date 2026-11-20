from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from guardian.backends import ObjectPermissionBackend
from guardian.core import ObjectPermissionChecker
from guardian.shortcuts import assign_perm, get_objects_for_user
from guardian.testapp.models import Project

User = get_user_model()


class ExplainPermTests(TestCase):
    """Cross-check the optional explanation API against the list, checker
    and backend paths for the same user."""

    def setUp(self):
        self.user = User.objects.create_user("alice", "alice@example.com", "secret")
        self.group = Group.objects.create(name="editors")
        self.project = Project.objects.create(name="project-a")
        self.backend = ObjectPermissionBackend()

    def test_group_only_permission_consistent_across_paths(self):
        self.user.groups.add(self.group)
        assign_perm("change_project", self.group, self.project)

        checker = ObjectPermissionChecker(self.user)
        explanation = checker.explain_perm("change_project", self.project)

        self.assertTrue(explanation.allowed)
        self.assertEqual(explanation.perm, "testapp.change_project")
        self.assertEqual(explanation.sources, ["group:editors"])
        self.assertEqual(explanation.direct_perms, [])
        self.assertEqual(explanation.group_perms, {"editors": ["change_project"]})
        self.assertEqual(explanation.global_perms, [])

        # The same user reaches the same conclusion via checker, backend and list.
        self.assertTrue(checker.has_perm("change_project", self.project))
        self.assertTrue(self.backend.has_perm(self.user, "change_project", self.project))
        self.assertIn(self.project, get_objects_for_user(self.user, "testapp.change_project"))

        backend_explanation = self.backend.explain_perm(self.user, "testapp.change_project", self.project)
        self.assertEqual(backend_explanation.allowed, explanation.allowed)
        self.assertEqual(backend_explanation.sources, explanation.sources)
        self.assertEqual(backend_explanation.group_perms, explanation.group_perms)

    def test_global_permission_can_be_explicitly_excluded(self):
        assign_perm("testapp.change_project", self.user)  # global, obj=None

        checker = ObjectPermissionChecker(self.user)

        # Object-level boolean checks stay False: no object permission assigned.
        self.assertFalse(checker.has_perm("change_project", self.project))
        self.assertFalse(self.backend.has_perm(self.user, "change_project", self.project))

        included = checker.explain_perm("change_project", self.project)
        self.assertTrue(included.allowed)
        self.assertEqual(included.sources, ["global"])
        self.assertEqual(included.global_perms, ["change_project"])
        self.assertEqual(included.direct_perms, [])
        # Matches the list path when global perms are accepted (the default).
        self.assertIn(self.project, get_objects_for_user(self.user, "testapp.change_project"))

        excluded = checker.explain_perm("change_project", self.project, consider_global=False)
        self.assertFalse(excluded.allowed)
        self.assertEqual(excluded.sources, [])
        self.assertEqual(excluded.global_perms, [])
        self.assertIn("global permissions excluded", excluded.reason)
        # Matches the list path when global perms are explicitly excluded.
        self.assertNotIn(
            self.project,
            get_objects_for_user(self.user, "testapp.change_project", accept_global_perms=False),
        )

        backend_excluded = self.backend.explain_perm(
            self.user, "testapp.change_project", self.project, consider_global=False
        )
        self.assertFalse(backend_excluded.allowed)
        self.assertEqual(backend_excluded.sources, [])

    def test_inactive_user_denied_with_inert_evidence(self):
        assign_perm("change_project", self.user, self.project)
        self.user.is_active = False
        self.user.save()

        checker = ObjectPermissionChecker(self.user)
        explanation = checker.explain_perm("change_project", self.project)

        self.assertFalse(explanation.allowed)
        self.assertFalse(explanation.is_active)
        self.assertEqual(explanation.sources, [])
        # Grants are not reported as effective evidence for inactive users.
        self.assertEqual(explanation.direct_perms, [])
        self.assertEqual(explanation.group_perms, {})
        self.assertIn("inactive", explanation.reason)

        # Checker and backend reach the same conclusion for the same user.
        self.assertFalse(checker.has_perm("change_project", self.project))
        self.assertFalse(self.backend.has_perm(self.user, "change_project", self.project))
        backend_explanation = self.backend.explain_perm(self.user, "change_project", self.project)
        self.assertFalse(backend_explanation.allowed)
        self.assertEqual(backend_explanation.reason, explanation.reason)

        # Existing behavior: get_objects_for_user does not evaluate is_active,
        # so the object still shows up in the list path. The explanation is
        # what tells support why the grant is inert anyway.
        self.assertIn(self.project, get_objects_for_user(self.user, "testapp.change_project"))

    def test_evidence_comes_from_the_fresh_evaluation(self):
        checker = ObjectPermissionChecker(self.user)
        self.assertFalse(checker.has_perm("change_project", self.project))

        # Granting after the boolean check must not leak stale cache into the
        # explanation: its evidence comes only from its own evaluation.
        assign_perm("change_project", self.user, self.project)
        self.assertFalse(checker.has_perm("change_project", self.project))  # cached

        explanation = checker.explain_perm("change_project", self.project)
        self.assertTrue(explanation.allowed)
        self.assertEqual(explanation.sources, ["direct"])
        self.assertEqual(explanation.direct_perms, ["change_project"])
        self.assertEqual(explanation.group_perms, {})

    def test_superuser_source(self):
        self.user.is_superuser = True
        explanation = ObjectPermissionChecker(self.user).explain_perm("change_project", self.project)
        self.assertTrue(explanation.allowed)
        self.assertTrue(explanation.is_superuser)
        self.assertEqual(explanation.sources, ["superuser"])

    def test_backend_explain_unsupported_object(self):
        explanation = self.backend.explain_perm(self.user, "testapp.change_project", None)
        self.assertFalse(explanation.allowed)
        self.assertEqual(explanation.sources, [])
        self.assertIn("not supported", explanation.reason)

    def test_boolean_interfaces_unchanged(self):
        assign_perm("change_project", self.user, self.project)
        checker = ObjectPermissionChecker(self.user)
        self.assertTrue(checker.has_perm("change_project", self.project))
        self.assertTrue(checker.has_perm("testapp.change_project", self.project))
        self.assertTrue(self.backend.has_perm(self.user, "testapp.change_project", self.project))
        self.assertTrue(self.user.has_perm("testapp.change_project", self.project))
        self.assertEqual(checker.get_perms(self.project), ["change_project"])
