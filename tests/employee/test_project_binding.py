from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APITestCase

from tests.employee.models import EmployeeRecord, Project, ProjectMembership


class ProjectBindingPermissionTests(APITestCase):
    """
    Two approved projects and three pre-existing records:

      * project A: the test user is a *manager* (may browse and bind).
      * project B: the test user is only a *viewer* (may browse, may not bind).
      * record 1 -> A, record 2 -> B, record 3 -> unbound.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('employee', password='pw')
        cls.outside_user = User.objects.create_user('outsider', password='pw')

        cls.project_a = Project.objects.create(
            name='A', status=Project.STATUS_APPROVED
        )
        cls.project_b = Project.objects.create(
            name='B', status=Project.STATUS_APPROVED
        )

        ProjectMembership.objects.create(
            project=cls.project_a,
            user=cls.user,
            role=ProjectMembership.ROLE_MANAGER,
        )
        ProjectMembership.objects.create(
            project=cls.project_b,
            user=cls.user,
            role=ProjectMembership.ROLE_VIEWER,
        )

        cls.record_on_a = EmployeeRecord.objects.create(
            title='on-a', project=cls.project_a
        )
        cls.record_on_b = EmployeeRecord.objects.create(
            title='on-b', project=cls.project_b
        )
        cls.record_unbound = EmployeeRecord.objects.create(title='unbound')

        cls.records_url = '/employee/employee-records/'
        cls.projects_url = '/employee/projects/'

    def record_url(self, record):
        return '%s%d/' % (self.records_url, record.pk)

    def setUp(self):
        self.client.force_authenticate(self.user)

    # -- listing / browse permissions --------------------------------------

    def test_list_returns_every_visible_record(self):
        response = self.client.get(self.records_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item['id'] for item in response.data},
            {self.record_on_a.pk, self.record_on_b.pk, self.record_unbound.pk},
        )

    def test_projects_list_shows_browsable_but_not_bindability(self):
        response = self.client.get(self.projects_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item['id'] for item in response.data},
            {self.project_a.pk, self.project_b.pk},
        )

    def test_queryset_filtering_hides_other_members_records(self):
        self.client.force_authenticate(self.outside_user)
        response = self.client.get(self.records_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Only the unbound record leaks; records bound to invisible projects
        # are filtered out by the existing queryset rule.
        self.assertEqual(
            [item['id'] for item in response.data], [self.record_unbound.pk]
        )

        detail = self.client.get(self.record_url(self.record_on_a))
        self.assertEqual(detail.status_code, status.HTTP_404_NOT_FOUND)

    # -- selectable choices -------------------------------------------------

    def test_choices_only_include_bindable_projects(self):
        response = self.client.options(self.records_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        choices = response.data['actions']['POST']['project']['choices']
        self.assertEqual([choice['value'] for choice in choices], [self.project_a.pk])

    def test_detail_choices_stay_bindable_while_payload_keeps_legacy_value(self):
        response = self.client.options(self.record_url(self.record_on_b))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        choices = response.data['actions']['PUT']['project']['choices']
        self.assertEqual([choice['value'] for choice in choices], [self.project_a.pk])

        # The legacy association is still displayed in full.
        detail = self.client.get(self.record_url(self.record_on_b))
        self.assertEqual(detail.status_code, status.HTTP_200_OK)
        self.assertEqual(detail.data['project'], self.project_b.pk)

    # -- PATCH: unchanged legacy associations -------------------------------

    def test_patch_unrelated_field_keeps_legacy_association(self):
        response = self.client.patch(
            self.record_url(self.record_on_b), {'title': 'renamed'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_on_b.refresh_from_db()
        self.assertEqual(self.record_on_b.title, 'renamed')
        self.assertEqual(self.record_on_b.project_id, self.project_b.pk)

    def test_patch_resending_same_legacy_project_is_allowed(self):
        response = self.client.patch(
            self.record_url(self.record_on_b),
            {'title': 'again', 'project': self.project_b.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_on_b.refresh_from_db()
        self.assertEqual(self.record_on_b.project_id, self.project_b.pk)

    def test_explicit_unbind_does_not_require_binding_role(self):
        response = self.client.patch(
            self.record_url(self.record_on_b), {'project': None}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_on_b.refresh_from_db()
        self.assertIsNone(self.record_on_b.project_id)

    # -- PATCH: actual (re)binding ------------------------------------------

    def test_patch_rebind_to_view_only_project_is_denied(self):
        response = self.client.patch(
            self.record_url(self.record_unbound),
            {'project': self.project_b.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.record_unbound.refresh_from_db()
        self.assertIsNone(self.record_unbound.project_id)

        response = self.client.patch(
            self.record_url(self.record_on_a),
            {'project': self.project_b.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.record_on_a.refresh_from_db()
        self.assertEqual(self.record_on_a.project_id, self.project_a.pk)

    def test_patch_rebind_to_managed_project_succeeds(self):
        response = self.client.patch(
            self.record_url(self.record_unbound),
            {'project': self.project_a.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_unbound.refresh_from_db()
        self.assertEqual(self.record_unbound.project_id, self.project_a.pk)

    # -- new bindings via POST ----------------------------------------------

    def test_create_with_managed_project_succeeds(self):
        response = self.client.post(
            self.records_url,
            {'title': 'new-bound', 'project': self.project_a.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            EmployeeRecord.objects.get(pk=response.data['id']).project_id,
            self.project_a.pk,
        )

    def test_create_with_view_only_project_is_denied(self):
        response = self.client.post(
            self.records_url,
            {'title': 'new-rejected', 'project': self.project_b.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(EmployeeRecord.objects.filter(title='new-rejected').exists())

    def test_create_without_project_succeeds(self):
        response = self.client.post(
            self.records_url, {'title': 'new-unbound'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIsNone(EmployeeRecord.objects.get(pk=response.data['id']).project_id)

    # -- tightening / loosening the role condition --------------------------

    def test_tightening_role_keeps_confirmed_associations_usable(self):
        # Demote the user on project A: browsing stays, binding is removed.
        ProjectMembership.objects.filter(
            project=self.project_a, user=self.user
        ).update(role=ProjectMembership.ROLE_VIEWER)

        # Confirmed records remain readable and editable as long as the
        # association itself is untouched.
        response = self.client.patch(
            self.record_url(self.record_on_a), {'title': 'still-mine'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_on_a.refresh_from_db()
        self.assertEqual(self.record_on_a.project_id, self.project_a.pk)

        # A new binding to the now view-only project is refused.
        response = self.client.patch(
            self.record_url(self.record_unbound),
            {'project': self.project_a.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # The other confirmed project (B) is unaffected and still editable.
        response = self.client.patch(
            self.record_url(self.record_on_b), {'title': 'b-still-works'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_on_b.refresh_from_db()
        self.assertEqual(self.record_on_b.project_id, self.project_b.pk)

    def test_granting_manager_role_opens_binding(self):
        ProjectMembership.objects.filter(
            project=self.project_b, user=self.user
        ).update(role=ProjectMembership.ROLE_MANAGER)

        response = self.client.patch(
            self.record_url(self.record_unbound),
            {'project': self.project_b.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.record_unbound.refresh_from_db()
        self.assertEqual(self.record_unbound.project_id, self.project_b.pk)

    def test_draft_project_is_not_bindable_even_for_managers(self):
        Project.objects.filter(pk=self.project_a.pk).update(status=Project.STATUS_DRAFT)
        response = self.client.patch(
            self.record_url(self.record_unbound),
            {'project': self.project_a.pk},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # -- authentication -----------------------------------------------------

    def test_anonymous_request_is_rejected(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self.records_url)
        self.assertIn(response.status_code, (
            status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN
        ))
