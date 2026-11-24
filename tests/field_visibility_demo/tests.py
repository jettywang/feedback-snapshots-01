import csv
import io

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import CaseRecord
from .visibility import FieldVisibility


class FieldVisibilityContractTests(APITestCase):
    """
    End-to-end contract for one shared visibility policy.

    Two synthetic datasets (``alpha`` and ``beta``) hold rows that are
    identical on every public field and differ only on the staff-only fields.
    One extra row exists only in the sense that its distinguishing content is
    internal, letting us prove that hidden fields cannot drive membership.
    """

    @classmethod
    def setUpTestData(cls):
        cls.staff = User.objects.create_user(
            username='admin', password='x', is_staff=True)
        cls.member = User.objects.create_user(
            username='member', password='x', is_staff=False)

        # Dataset alpha: two rows identical publicly, different internally.
        CaseRecord.objects.create(
            dataset=CaseRecord.DATASET_ALPHA,
            name='Widget', category='hardware', status='open',
            internal_note='alpha secret A', risk_score=90)
        CaseRecord.objects.create(
            dataset=CaseRecord.DATASET_ALPHA,
            name='Widget', category='hardware', status='open',
            internal_note='alpha secret B', risk_score=10)
        # A row whose *only* distinguishing value lives in internal fields.
        CaseRecord.objects.create(
            dataset=CaseRecord.DATASET_ALPHA,
            name='Widget', category='hardware', status='open',
            internal_note='quarantine flag', risk_score=99)

        # Dataset beta: same public surface as alpha, different internals.
        CaseRecord.objects.create(
            dataset=CaseRecord.DATASET_BETA,
            name='Widget', category='hardware', status='open',
            internal_note='beta secret A', risk_score=50)
        CaseRecord.objects.create(
            dataset=CaseRecord.DATASET_BETA,
            name='Gadget', category='software', status='closed',
            internal_note='beta secret B', risk_score=20)

        cls.list_url = reverse('case-list')

    # -- representation --------------------------------------------------

    def test_public_representation_omits_internal_fields(self):
        self.client.force_authenticate(self.member)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = response.data['results'][0]
        self.assertEqual(set(row), set(FieldVisibility.PUBLIC_FIELDS))
        self.assertNotIn('internal_note', row)
        self.assertNotIn('risk_score', row)

    def test_staff_representation_includes_internal_fields(self):
        self.client.force_authenticate(self.staff)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = response.data['results'][0]
        self.assertEqual(set(row), set(FieldVisibility.all_fields()))

    def test_detail_uses_the_same_visibility_policy(self):
        record = CaseRecord.objects.first()
        url = reverse('case-detail', args=[record.pk])

        self.client.force_authenticate(self.member)
        public = self.client.get(url)
        self.assertEqual(set(public.data), set(FieldVisibility.PUBLIC_FIELDS))

        self.client.force_authenticate(self.staff)
        admin = self.client.get(url)
        self.assertEqual(set(admin.data), set(FieldVisibility.all_fields()))
        self.assertEqual(admin.data['internal_note'], record.internal_note)

    # -- hidden fields cannot decide membership --------------------------

    def test_hidden_filter_is_ignored_for_non_staff(self):
        self.client.force_authenticate(self.member)
        # risk_score=99 matches exactly one row for an admin...
        response = self.client.get(self.list_url, {'risk_score': 99})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # ...but a non-staff caller cannot use it, so all rows are returned.
        self.assertEqual(response.data['count'], CaseRecord.objects.count())

    def test_staff_can_filter_on_approved_internal_field(self):
        self.client.force_authenticate(self.staff)
        response = self.client.get(self.list_url, {'risk_score': 99})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['risk_score'], 99)

    def test_internal_search_term_cannot_narrow_public_results(self):
        self.client.force_authenticate(self.member)
        # 'quarantine' only appears in an internal note. Search is confined to
        # visible fields, so it behaves like any term with no public match and
        # cannot act as an oracle for hidden content.
        response = self.client.get(self.list_url, {'search': 'quarantine'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 0)
        # A genuinely non-existent term yields the same empty result, proving
        # internal values do not influence membership.
        other = self.client.get(self.list_url, {'search': 'no-such-token'})
        self.assertEqual(other.data['count'], response.data['count'])

    def test_staff_search_reaches_internal_fields(self):
        self.client.force_authenticate(self.staff)
        response = self.client.get(self.list_url, {'search': 'quarantine'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

    def test_public_search_still_works_on_visible_fields(self):
        self.client.force_authenticate(self.member)
        response = self.client.get(self.list_url, {'search': 'Gadget'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['name'], 'Gadget')

    # -- ordering --------------------------------------------------------

    def test_ordering_by_hidden_field_is_dropped_for_non_staff(self):
        self.client.force_authenticate(self.member)
        response = self.client.get(self.list_url, {'ordering': 'risk_score'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [row['id'] for row in response.data['results']]
        # Hidden ordering term removed -> stable default id ordering.
        self.assertEqual(ids, sorted(ids))

    def test_staff_ordering_by_internal_field_is_honoured(self):
        self.client.force_authenticate(self.staff)
        response = self.client.get(self.list_url, {'ordering': 'risk_score'})
        scores = [row['risk_score'] for row in response.data['results']]
        self.assertEqual(scores, sorted(scores))

    # -- pagination consistency -----------------------------------------

    def test_pagination_metadata_matches_effective_visibility(self):
        self.client.force_authenticate(self.member)
        response = self.client.get(self.list_url)
        body = response.data
        self.assertEqual(body['page_size'], 3)
        self.assertEqual(len(body['results']), 3)
        self.assertEqual(body['count'], CaseRecord.objects.count())
        self.assertEqual(body['visible_fields'],
                         list(FieldVisibility.PUBLIC_FIELDS))
        self.assertIsNotNone(body['next'])
        self.assertIsNone(body['previous'])

        page_two = self.client.get(self.list_url, {'page': 2})
        self.assertEqual(len(page_two.data['results']), 2)
        self.assertEqual(page_two.data['count'], body['count'])

    def test_pagination_count_unchanged_by_ignored_hidden_filter(self):
        self.client.force_authenticate(self.member)
        baseline = self.client.get(self.list_url).data['count']
        probed = self.client.get(
            self.list_url, {'internal_note': 'quarantine flag'}).data['count']
        self.assertEqual(baseline, probed)

    # -- export ----------------------------------------------------------

    def test_csv_export_columns_match_visible_fields(self):
        url = self.list_url
        self.client.force_authenticate(self.member)
        response = self.client.get(url, {'format': 'csv'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        reader = csv.DictReader(io.StringIO(response.content.decode()))
        self.assertEqual(reader.fieldnames,
                         list(FieldVisibility.PUBLIC_FIELDS))
        first = next(reader)
        self.assertNotIn('internal_note', first)
        self.assertNotIn('risk_score', first)

    def test_csv_export_for_staff_contains_internal_columns(self):
        self.client.force_authenticate(self.staff)
        response = self.client.get(self.list_url, {'format': 'csv'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        reader = csv.DictReader(io.StringIO(response.content.decode()))
        self.assertEqual(reader.fieldnames,
                         list(FieldVisibility.all_fields()))

    # -- unauthenticated -------------------------------------------------

    def test_anonymous_is_rejected(self):
        response = self.client.get(self.list_url)
        self.assertIn(response.status_code,
                      (status.HTTP_401_UNAUTHORIZED,
                       status.HTTP_403_FORBIDDEN))
