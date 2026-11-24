"""
End-to-end permission trace for the audited ReportViewSet.

Each test drives a real request through the router-bound URLconf and then
inspects two side-effect logs:

* PERMISSION_CALL_LOG -- every has_permission / has_object_permission call
  with the class name, layer, action and object pk involved.
* BUSINESS_CALL_LOG  -- which handler ran and whether it received an object.

Run with:
    .venv/bin/python -m pytest tests/permission_audit -v
"""
import pytest
from django.contrib.auth.models import User
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APIClient

from .models import Report
from .permissions import PERMISSION_CALL_LOG, reset_permission_log
from .views import BUSINESS_CALL_LOG, reset_business_log

pytestmark = pytest.mark.urls('tests.permission_audit.urls')


@pytest.fixture(autouse=True)
def _reset_logs():
    reset_permission_log()
    reset_business_log()
    yield
    reset_permission_log()
    reset_business_log()


@pytest.fixture
def report(db):
    return Report.objects.create(title='quarterly', body='data')


@pytest.fixture
def anon_client():
    return APIClient()


@pytest.fixture
def user_client(db):
    user = User.objects.create_user(username='clerk', password='pw')
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def staff_client(db):
    user = User.objects.create_user(username='boss', password='pw', is_staff=True)
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _perm_names(kind=None):
    return [
        entry['permission']
        for entry in PERMISSION_CALL_LOG
        if kind is None or entry['kind'] == kind
    ]


def _kinds():
    return [(entry['kind'], entry['permission'], entry['obj_pk'])
            for entry in PERMISSION_CALL_LOG]


# ---------------------------------------------------------------------------
# Router binding evidence: the exact patterns and method maps that get built.
# ---------------------------------------------------------------------------
def test_router_binds_one_pattern_for_get_and_post(report):
    from .urls import router

    patterns = {p.name: p for p in router.urls}

    # The shared collection route: one pattern, two HTTP-method bindings.
    list_route = patterns['report-list']
    assert list_route.callback.actions == {
        'get': 'list',
        'post': 'submit_report',
    }
    assert [cls.__name__ for cls in
            list_route.callback.initkwargs['permission_classes']] == [
        'TracingPublicReadAuthenticatedWrite'
    ]

    detail_route = patterns['report-detail']
    assert set(detail_route.callback.actions) == {
        'get', 'put', 'patch', 'delete'
    }
    # No @action override on the detail route: class default applies.
    assert 'permission_classes' not in detail_route.callback.initkwargs

    publish_route = patterns['report-publish']
    assert publish_route.callback.actions == {'post': 'publish'}
    assert [cls.__name__ for cls in
            publish_route.callback.initkwargs['permission_classes']] == [
        'TracingIsStaff'
    ]

    archive_route = patterns['report-archive']
    assert archive_route.callback.actions == {'post': 'archive'}


# ---------------------------------------------------------------------------
# Collection URL: public GET and restricted POST on the SAME url pattern.
# ---------------------------------------------------------------------------
def test_list_get_anonymous_is_public(report, anon_client):
    url = reverse('report-list')
    response = anon_client.get(url)

    assert response.status_code == status.HTTP_200_OK
    assert _perm_names() == ['TracingPublicReadAuthenticatedWrite']
    assert _kinds() == [
        ('has_permission', 'TracingPublicReadAuthenticatedWrite', None),
    ]
    assert BUSINESS_CALL_LOG == [{
        'handler': 'list', 'got_object': False, 'kwargs': {},
    }]


def test_list_post_anonymous_denied_without_reaching_handler(report, anon_client):
    url = reverse('report-list')
    response = anon_client.post(url, {'title': 'hack'}, format='json')

    assert response.status_code == status.HTTP_403_FORBIDDEN
    # Same policy class is consulted as for GET; it branches on the HTTP
    # method. The class default is never used on this merged route.
    assert _perm_names() == ['TracingPublicReadAuthenticatedWrite']
    assert all(entry['kind'] == 'has_permission' for entry in PERMISSION_CALL_LOG)
    assert BUSINESS_CALL_LOG == []


def test_list_post_authenticated_uses_same_action_policy(report, user_client):
    url = reverse('report-list')
    response = user_client.post(url, {'title': 'ok'}, format='json')

    assert response.status_code == status.HTTP_201_CREATED
    assert _perm_names() == ['TracingPublicReadAuthenticatedWrite']
    assert BUSINESS_CALL_LOG[0]['handler'] == 'submit_report'
    assert BUSINESS_CALL_LOG[0]['got_object'] is False


# ---------------------------------------------------------------------------
# Default-inherited detail route: class default policy, object check runs.
# ---------------------------------------------------------------------------
def test_retrieve_runs_request_and_object_permission_layers(report, anon_client):
    url = reverse('report-detail', args=[report.pk])
    response = anon_client.get(url)

    assert response.status_code == status.HTTP_200_OK
    assert _kinds() == [
        ('has_permission', 'TracingAllowAny', None),
        ('has_object_permission', 'TracingAllowAny', report.pk),
    ]
    assert BUSINESS_CALL_LOG == [{
        'handler': 'retrieve',
        'got_object': True,
        'obj_pk': report.pk,
        'kwargs': {'pk': str(report.pk)},
    }]


def test_partial_update_inherits_class_default(report, anon_client):
    url = reverse('report-detail', args=[report.pk])
    response = anon_client.patch(url, {'title': 'renamed'}, format='json')

    # Class default is AllowAny -> anonymous write succeeds today.
    # This is the gap the rollout checklist must close.
    assert response.status_code == status.HTTP_200_OK
    assert _kinds() == [
        ('has_permission', 'TracingAllowAny', None),
        ('has_object_permission', 'TracingAllowAny', report.pk),
    ]
    assert BUSINESS_CALL_LOG[0]['handler'] == 'partial_update'
    assert BUSINESS_CALL_LOG[0]['got_object'] is True


def test_destroy_inherits_class_default_and_gets_object(report, anon_client):
    url = reverse('report-detail', args=[report.pk])
    response = anon_client.delete(url)

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert _kinds() == [
        ('has_permission', 'TracingAllowAny', None),
        ('has_object_permission', 'TracingAllowAny', report.pk),
    ]
    assert BUSINESS_CALL_LOG[0]['handler'] == 'destroy'
    assert not Report.objects.filter(pk=report.pk).exists()


# ---------------------------------------------------------------------------
# Self-loading detail action: request check only, object check skipped.
# ---------------------------------------------------------------------------
def test_publish_anonymous_blocked_at_request_layer(report, anon_client):
    url = reverse('report-publish', args=[report.pk])
    response = anon_client.post(url)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert _kinds() == [('has_permission', 'TracingIsStaff', None)]
    assert BUSINESS_CALL_LOG == []


def test_publish_non_staff_blocked_at_request_layer(report, user_client):
    url = reverse('report-publish', args=[report.pk])
    response = user_client.post(url)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert _kinds() == [('has_permission', 'TracingIsStaff', None)]
    assert BUSINESS_CALL_LOG == []


def test_publish_staff_skips_object_permission_despite_policy(report, staff_client):
    url = reverse('report-publish', args=[report.pk])
    response = staff_client.post(url)

    assert response.status_code == status.HTTP_200_OK
    # Only the request layer ran. TracingIsStaff.has_object_permission is
    # never consulted because the handler loads via get_object_or_404().
    assert _kinds() == [('has_permission', 'TracingIsStaff', None)]
    assert BUSINESS_CALL_LOG == [{
        'handler': 'publish',
        'got_object': True,
        'obj_pk': report.pk,
        'loaded_via': 'get_object_or_404',
        'kwargs': {'pk': str(report.pk)},
    }]


def test_archive_staff_runs_both_layers_via_get_object(report, staff_client):
    url = reverse('report-archive', args=[report.pk])
    response = staff_client.post(url)

    assert response.status_code == status.HTTP_200_OK
    # Control case: self.get_object() triggers the object-level check.
    assert _kinds() == [
        ('has_permission', 'TracingIsStaff', None),
        ('has_object_permission', 'TracingIsStaff', report.pk),
    ]
    assert BUSINESS_CALL_LOG[0]['handler'] == 'archive'
    assert BUSINESS_CALL_LOG[0]['loaded_via'] == 'self.get_object'
