"""
Regression cover for the approval-policy serializer contract.

A policy belongs to an organization, and ``(organization, alias)`` is unique.
The organization is never accepted from input: it is a ``HiddenField`` whose
default is resolved from the authenticated request, and only on create.  The
same stored target can be reached through both PUT and PATCH.

Every scenario records three separate phases:

* ``default``   - when (and whether) the request-derived default was evaluated
* ``query.*``   - the exact lookup keys the uniqueness validator used
* ``save.*``    - the validated payload handed to ``create()`` / ``update()``

Two deliberately wrong stand-ins apply the default early and persist a change
early, so the phase criteria can be shown to fail at the right stage.
"""
from django.contrib.auth.models import User
from django.db import models
from django.test import TestCase

from rest_framework import generics, permissions, serializers, status
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.validators import UniqueTogetherValidator

factory = APIRequestFactory()


# Miniature dataset
# -----------------

class Organization(models.Model):
    name = models.CharField(max_length=50)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='approval_profile')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)


class ApprovalPolicy(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='policies')
    alias = models.CharField(max_length=50)
    description = models.CharField(max_length=200, blank=True, default='')

    class Meta:
        unique_together = ('organization', 'alias')


# Phase recording
# ---------------

def _plain(value):
    if isinstance(value, models.Model):
        return value.pk
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


class PhaseRecord:
    """Ordered record of the default, validator and save phases."""

    STAGE_OF_KIND = {
        'default': 'default',
        'query.filter': 'validation',
        'query.exclude': 'validation',
        'query.exists': 'validation',
        'save.create': 'save',
        'save.update': 'save',
        'save.eager': 'save',
    }

    def __init__(self):
        self.events = []

    def record(self, kind, value=None):
        self.events.append((kind, _plain(value)))

    def kind(self, kind):
        return [value for event_kind, value in self.events if event_kind == kind]

    def divergent_stages(self, expected):
        """Stages whose recorded events differ from ``expected``."""
        failures = []
        for stage in ('default', 'validation', 'save'):
            actual_stage = [
                event for event in self.events
                if self.STAGE_OF_KIND[event[0]] == stage
            ]
            expected_stage = [
                event for event in expected
                if self.STAGE_OF_KIND[event[0]] == stage
            ]
            if actual_stage != expected_stage:
                failures.append(stage)
        return failures


class RequestOrganizationDefault:
    """Resolve the organization from the authenticated request."""

    requires_context = True

    def __call__(self, field):
        organization = field.context['request'].user.approval_profile.organization
        field.context['record'].record('default', organization)
        return organization


class RecordedQuerySet:
    """Queryset proxy that records the keys the validator actually queries."""

    def __init__(self, queryset, record):
        self._queryset = queryset
        self._record = record

    def filter(self, **kwargs):
        self._record.record('query.filter', kwargs)
        return RecordedQuerySet(self._queryset.filter(**kwargs), self._record)

    def exclude(self, **kwargs):
        self._record.record('query.exclude', kwargs)
        return RecordedQuerySet(self._queryset.exclude(**kwargs), self._record)

    def exists(self):
        result = self._queryset.exists()
        self._record.record('query.exists', result)
        return result

    def __getattr__(self, name):
        return getattr(self._queryset, name)


# Serializer under test
# ---------------------

def make_serializer_classes(record):
    class ApprovalPolicySerializer(serializers.ModelSerializer):
        organization = serializers.HiddenField(
            default=serializers.CreateOnlyDefault(RequestOrganizationDefault())
        )

        class Meta:
            model = ApprovalPolicy
            fields = ('id', 'organization', 'alias', 'description')
            validators = [
                UniqueTogetherValidator(
                    queryset=RecordedQuerySet(ApprovalPolicy.objects.all(), record),
                    fields=('organization', 'alias'),
                )
            ]

        def create(self, validated_data):
            record.record('save.create', validated_data)
            return super().create(validated_data)

        def update(self, instance, validated_data):
            record.record('save.update', validated_data)
            return super().update(instance, validated_data)

    # Stand-in 1: resolve the request default before normal validation, even
    # for partial updates.  The value is dropped again on update, so the only
    # observable deviation is the default-evaluation phase.
    class EagerDefaultHiddenField(serializers.HiddenField):
        def get_value(self, dictionary):
            return RequestOrganizationDefault()(self)

    class EagerDefaultSerializer(ApprovalPolicySerializer):
        organization = EagerDefaultHiddenField(
            default=serializers.CreateOnlyDefault(RequestOrganizationDefault())
        )

        def validate(self, attrs):
            if self.instance is not None:
                attrs.pop('organization', None)
            return attrs

    # Stand-in 2: persist the submitted change before the uniqueness validator
    # runs, so an invalid update still lands in the database.
    class EagerSaveSerializer(ApprovalPolicySerializer):
        def to_internal_value(self, data):
            validated = super().to_internal_value(data)
            if self.instance is not None and 'description' in validated:
                ApprovalPolicy.objects.filter(pk=self.instance.pk).update(
                    description=validated['description'])
                self.instance.description = validated['description']
                record.record('save.eager', {'description': validated['description']})
            return validated

    return {
        'correct': ApprovalPolicySerializer,
        'early_default': EagerDefaultSerializer,
        'early_save': EagerSaveSerializer,
    }


# Permission gate
# ---------------

class SameOrganization(permissions.BasePermission):
    message = 'You may only modify policies in your organization.'

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        profile = getattr(request.user, 'approval_profile', None)
        return profile is not None and obj.organization_id == profile.organization_id


def detail_view(serializer_class):
    class ApprovalPolicyDetailView(generics.RetrieveUpdateAPIView):
        queryset = ApprovalPolicy.objects.all()
        permission_classes = [SameOrganization]

        def get_serializer_class(self):
            return serializer_class

    return ApprovalPolicyDetailView.as_view()


# Fixture shared by the create, PATCH and PUT scenarios
# -----------------------------------------------------

class ApprovalPolicyPhaseTests(TestCase):
    def setUp(self):
        self.record = PhaseRecord()
        self.serializers = make_serializer_classes(self.record)

        self.org_a = Organization.objects.create(name='Alpha')
        self.org_b = Organization.objects.create(name='Beta')
        self.user = User.objects.create_user('alice', password='pw')
        UserProfile.objects.create(user=self.user, organization=self.org_a)
        self.target = ApprovalPolicy.objects.create(
            organization=self.org_a, alias='travel', description='old')
        ApprovalPolicy.objects.create(
            organization=self.org_a, alias='taken', description='other')
        request = factory.get('/')
        force_authenticate(request, user=self.user)
        self.request = Request(request)

    def serializer(self, *args, variant='correct', **kwargs):
        kwargs.setdefault('context', {'request': self.request, 'record': self.record})
        return self.serializers[variant](*args, **kwargs)

    def snapshot(self):
        self.target.refresh_from_db()
        return (
            self.target.organization_id,
            self.target.alias,
            self.target.description,
        )

    def assert_stages(self, expected, expect_failures=()):
        failures = self.record.divergent_stages(expected)
        if failures != list(expect_failures):
            self.fail(
                'phase criteria failed at {} (expected {}); recorded {}'.format(
                    failures, list(expect_failures), self.record.events)
            )
        if not expect_failures:
            self.assertEqual(self.record.events, list(expected))

    # Create: the client omits the organization; it must come from the request.

    def test_create_uses_request_organization(self):
        serializer = self.serializer(data={'alias': 'fresh', 'description': 'new'})
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data == {
            'organization': self.org_a,
            'alias': 'fresh',
            'description': 'new',
        }
        policy = serializer.save()
        assert policy.organization_id == self.org_a.pk
        assert ApprovalPolicy.objects.filter(alias='fresh').count() == 1
        self.assert_stages([
            ('default', self.org_a.pk),
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'fresh'}),
            ('query.exists', False),
            ('save.create', {
                'organization': self.org_a.pk,
                'alias': 'fresh',
                'description': 'new',
            }),
        ])

    # PATCH: only the alias changes.  The organization is read from the
    # instance for the validator keys, and a submitted organization is ignored.

    def test_patch_alias_only_reuses_original_organization(self):
        serializer = self.serializer(
            self.target,
            data={'alias': 'travel-2026', 'organization': self.org_b.pk},
            partial=True,
        )
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data == {'alias': 'travel-2026'}
        serializer.save()
        assert self.snapshot() == (self.org_a.pk, 'travel-2026', 'old')
        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'travel-2026'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('query.exists', False),
            ('save.update', {'alias': 'travel-2026'}),
        ])

    # PUT: the full representation explicitly submits another organization.
    # It is still ignored, and the validator reuses the stored organization.
    # The alias is unchanged, so no duplicate probe runs.

    def test_put_with_explicit_organization_ignores_input(self):
        serializer = self.serializer(
            self.target,
            data={
                'organization': self.org_b.pk,
                'alias': 'travel',
                'description': 'new',
            },
        )
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data == {'alias': 'travel', 'description': 'new'}
        serializer.save()
        assert self.snapshot() == (self.org_a.pk, 'travel', 'new')
        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'travel'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('save.update', {'alias': 'travel', 'description': 'new'}),
        ])

    # PUT that omits the organization: the validator still reads it from the
    # instance, and the saved payload contains only the supplied fields.

    def test_put_without_organization_uses_instance_organization(self):
        serializer = self.serializer(
            self.target,
            data={'alias': 'travel-2026', 'description': 'new'},
        )
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data == {'alias': 'travel-2026', 'description': 'new'}
        serializer.save()
        assert self.snapshot() == (self.org_a.pk, 'travel-2026', 'new')
        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'travel-2026'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('query.exists', False),
            ('save.update', {'alias': 'travel-2026', 'description': 'new'}),
        ])

    # The same stored target goes through PUT and then PATCH; the organization
    # survives both, and the validator keys follow the stored organization.

    def test_same_target_survives_put_then_patch(self):
        put = self.serializer(
            self.target,
            data={
                'organization': self.org_b.pk,
                'alias': 'travel',
                'description': 'put',
            },
        )
        assert put.is_valid(), put.errors
        put.save()
        assert self.snapshot() == (self.org_a.pk, 'travel', 'put')

        patch = self.serializer(self.target, data={'alias': 'travel-2026'}, partial=True)
        assert patch.is_valid(), patch.errors
        patch.save()
        assert self.snapshot() == (self.org_a.pk, 'travel-2026', 'put')

        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'travel'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('save.update', {'alias': 'travel', 'description': 'put'}),
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'travel-2026'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('query.exists', False),
            ('save.update', {'alias': 'travel-2026'}),
        ])

    # A duplicate alias in the same organization is reported, and nothing is
    # written.

    def test_duplicate_alias_is_rejected_before_save(self):
        before = self.snapshot()
        serializer = self.serializer(
            self.target, data={'alias': 'taken'}, partial=True)
        assert not serializer.is_valid()
        assert serializer.errors == {
            'non_field_errors': ['The fields organization, alias must make a unique set.']
        }
        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'taken'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('query.exists', True),
        ])
        assert self.snapshot() == before

    # Permission denial happens before the serializer exists, so the protected
    # target is neither written nor probed for duplicates.  The same request is
    # issued with a duplicate and a non-duplicate alias; identical responses
    # show the denial does not leak uniqueness information.

    def test_permission_denied_target_is_not_written_or_probed(self):
        foreign = ApprovalPolicy.objects.create(
            organization=self.org_b, alias='travel', description='foreign')
        ApprovalPolicy.objects.create(
            organization=self.org_b, alias='taken', description='foreign-dup')

        view = detail_view(self.serializers['correct'])
        responses = []
        for alias in ('taken', 'not-taken'):
            request = factory.patch(
                '/policies/{}/'.format(foreign.pk),
                {'alias': alias, 'description': 'hijack'},
                format='json',
            )
            force_authenticate(request, user=self.user)
            responses.append(view(request, pk=foreign.pk))

        for response in responses:
            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert response.data == {
                'detail': 'You may only modify policies in your organization.'
            }
        assert responses[0].data == responses[1].data
        assert self.record.events == []
        foreign.refresh_from_db()
        assert (foreign.alias, foreign.description) == ('travel', 'foreign')

    # Contrast: for a target the user may modify, the duplicate is reported as
    # a validation error, and still nothing is written.

    def test_allowed_target_reports_duplicate_without_writing(self):
        request = factory.patch(
            '/policies/{}/'.format(self.target.pk),
            {'alias': 'taken'},
            format='json',
        )
        force_authenticate(request, user=self.user)
        response = detail_view(self.serializers['correct'])(request, pk=self.target.pk)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'must make a unique set' in str(response.data)
        assert self.record.kind('save.update') == []
        assert self.record.kind('save.create') == []
        assert self.snapshot() == (self.org_a.pk, 'travel', 'old')

    # The early-default stand-in evaluates the request default during PATCH.
    # Only the default-stage criterion should flag it; the validator keys and
    # the saved payload still match the correct run.

    def test_early_default_is_caught_at_default_stage(self):
        serializer = self.serializer(
            self.target, data={'alias': 'travel-2026'}, partial=True,
            variant='early_default',
        )
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data == {'alias': 'travel-2026'}
        assert self.record.kind('default') == [self.org_a.pk]
        serializer.save()
        assert self.snapshot() == (self.org_a.pk, 'travel-2026', 'old')
        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'travel-2026'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('query.exists', False),
            ('save.update', {'alias': 'travel-2026'}),
        ], expect_failures=['default'])

    # The early-save stand-in writes the description during to_internal_value,
    # before uniqueness validation.  Only the save-stage criterion should flag
    # it; the validator keys match the correct duplicate run.

    def test_early_save_is_caught_at_save_stage(self):
        before = self.snapshot()
        serializer = self.serializer(
            self.target,
            data={'alias': 'taken', 'description': 'eager'},
            partial=True,
            variant='early_save',
        )
        assert not serializer.is_valid()
        self.target.refresh_from_db()
        assert self.target.description == 'eager'
        assert self.snapshot()[0:2] == before[0:2]
        assert self.record.kind('save.eager') == [{'description': 'eager'}]
        assert self.record.kind('save.update') == []
        self.assert_stages([
            ('query.filter', {'organization': self.org_a.pk, 'alias': 'taken'}),
            ('query.exclude', {'pk': self.target.pk}),
            ('query.exists', True),
        ], expect_failures=['save'])
