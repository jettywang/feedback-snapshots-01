from django.shortcuts import get_object_or_404

from rest_framework import permissions, serializers, status
from rest_framework.admissions import AdmissionDenied, AdmissionTarget
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase
from rest_framework.views import APIView
from tests.models import TargetAdmissionCommit, TargetAdmissionLibrary


class LockedCommitPermission(permissions.BasePermission):
    message = 'Locked commits cannot be modified.'
    code = 'commit_locked'

    def has_object_permission(self, request, view, obj):
        if isinstance(obj, TargetAdmissionLibrary):
            return True
        return not obj.locked


class CommitListSerializer(serializers.TargetAdmissionListSerializer):
    def update(self, library, validated_data):
        updated = []
        for index, attrs in enumerate(validated_data):
            commit = library.commits.get(pk=attrs['id'])
            self.check_write_target(
                commit,
                location=('commits', index),
            )
            updated.append(self.child.update(commit, attrs))
        return updated


class CommitSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()

    class Meta:
        model = TargetAdmissionCommit
        fields = ('id', 'sha', 'message', 'locked')
        read_only_fields = ('sha', 'locked')
        list_serializer_class = CommitListSerializer


class LibrarySerializer(serializers.ModelSerializer):
    commits = CommitSerializer(many=True)

    class Meta:
        model = TargetAdmissionLibrary
        fields = ('id', 'key', 'name', 'commits')

    def _resolve_commits(self, instance, commits_data):
        resolved = []
        targets = [AdmissionTarget(instance, location='library')]
        for index, attrs in enumerate(commits_data):
            commit = instance.commits.get(pk=attrs['id'])
            resolved.append((index, commit, attrs))
            targets.append(
                AdmissionTarget(commit, location=('commits', index))
            )
        return resolved, targets

    def update(self, instance, validated_data):
        commits_data = validated_data.pop('commits', [])
        commits_serializer = self.fields['commits']
        resolved, targets = self._resolve_commits(instance, commits_data)

        # Confirm every actual parent and child target before any write.
        commits_serializer.admit_targets(targets)

        # One transaction boundary for the complete nested/bulk write.
        with commits_serializer.admission_boundary():
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            instance.save()

            for index, commit, attrs in resolved:
                # Point-of-write recheck closes the validation-to-save gap.
                commits_serializer.check_write_target(
                    commit,
                    location=('commits', index),
                )
                for attr, value in attrs.items():
                    setattr(commit, attr, value)
                commit.save()

        return instance


class LateRevocationLibrarySerializer(LibrarySerializer):
    """Simulates revocation after preflight but before the second write."""

    def update(self, instance, validated_data):
        commits_data = validated_data.pop('commits', [])
        commits_serializer = self.fields['commits']
        resolved, targets = self._resolve_commits(instance, commits_data)
        commits_serializer.admit_targets(targets)

        with commits_serializer.admission_boundary():
            instance.name = validated_data.get('name', instance.name)
            instance.save()

            for index, commit, attrs in resolved:
                if index == 1:
                    TargetAdmissionCommit.objects.filter(pk=commit.pk).update(
                        locked=True
                    )
                    commit.refresh_from_db()

                commits_serializer.check_write_target(
                    commit,
                    location=('commits', index),
                )
                for attr, value in attrs.items():
                    setattr(commit, attr, value)
                commit.save()

        return instance


class LibraryCommitsView(APIView):
    permission_classes = [LockedCommitPermission]

    def patch(self, request, pk):
        library = get_object_or_404(TargetAdmissionLibrary, pk=pk)
        self.check_object_permissions(request, library)
        serializer = LibrarySerializer(
            library,
            data=request.data,
            partial=True,
            context={'request': request, 'view': self},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(LibrarySerializer(library).data)


class RowCommitListSerializer(serializers.ListSerializer):
    admission_permission_classes = [LockedCommitPermission]

    def get_write_targets(self):
        return list(enumerate(self.instance))

    def update(self, instance, validated_data):
        return [
            self.child.update(obj, attrs)
            for obj, attrs in zip(instance, validated_data)
        ]


class TargetAdmissionTests(APITestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.library = TargetAdmissionLibrary.objects.create(
            key='drf-test-library',
            name='Original library',
        )
        self.first = TargetAdmissionCommit.objects.create(
            library=self.library,
            sha='a' * 40,
            message='first message',
        )
        self.second = TargetAdmissionCommit.objects.create(
            library=self.library,
            sha='b' * 40,
            message='second message',
        )
        self.payload = {
            'name': 'Reviewed library',
            'commits': [
                {'id': self.first.pk, 'message': 'first reviewed'},
                {'id': self.second.pk, 'message': 'second reviewed'},
            ],
        }

    def _context(self):
        request = self.factory.patch('/libraries/1/', self.payload, format='json')
        view = LibraryCommitsView()
        view.request = request
        view.format_kwarg = None
        return {'request': request, 'view': view}

    def test_fixture_has_expected_actual_fields_and_records(self):
        library_fields = {
            field.name for field in TargetAdmissionLibrary._meta.get_fields()
        }
        commit_fields = {
            field.name for field in TargetAdmissionCommit._meta.get_fields()
        }

        self.assertEqual(
            {'id', 'key', 'name', 'commits'},
            {'id', 'key', 'name', 'commits'} & library_fields,
        )
        self.assertEqual(
            {'id', 'library', 'sha', 'message', 'locked'},
            {'id', 'library', 'sha', 'message', 'locked'} & commit_fields,
        )
        self.assertEqual(
            list(
                TargetAdmissionCommit.objects.order_by('pk')
                .values_list('sha', 'message', 'locked')
            ),
            [
                ('a' * 40, 'first message', False),
                ('b' * 40, 'second message', False),
            ],
        )

    def test_top_level_list_preflight_locates_denied_row(self):
        serializer = RowCommitListSerializer(
            [self.first, self.second],
            data=[
                {'id': self.first.pk, 'message': 'row one'},
                {'id': self.second.pk, 'message': 'row two'},
            ],
            child=CommitSerializer(),
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)

        TargetAdmissionCommit.objects.filter(pk=self.second.pk).update(
            locked=True
        )
        self.second.refresh_from_db()

        with self.assertRaises(AdmissionDenied) as exc_info:
            serializer.save()

        self.assertEqual(exc_info.exception.denied_indexes, [1])
        self.assertEqual(
            exc_info.exception.detail[1]['non_field_errors'][0].code,
            'commit_locked',
        )
        self.first.refresh_from_db()
        self.second.refresh_from_db()
        self.assertEqual(self.first.message, 'first message')
        self.assertEqual(self.second.message, 'second message')

    def test_all_targets_permitted_update_succeeds(self):
        request = self.factory.patch(
            f'/libraries/{self.library.pk}/',
            self.payload,
            format='json',
        )

        response = LibraryCommitsView.as_view()(
            request,
            pk=self.library.pk,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.library.refresh_from_db()
        self.first.refresh_from_db()
        self.second.refresh_from_db()
        self.assertEqual(self.library.name, 'Reviewed library')
        self.assertEqual(self.first.message, 'first reviewed')
        self.assertEqual(self.second.message, 'second reviewed')

    def test_target_revoked_after_validation_is_located_and_not_saved(self):
        serializer = LibrarySerializer(
            self.library,
            data=self.payload,
            partial=True,
            context=self._context(),
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)

        # Policy changes only after validation has accepted the rows.
        TargetAdmissionCommit.objects.filter(pk=self.second.pk).update(
            locked=True
        )
        self.second.refresh_from_db()

        with self.assertRaises(AdmissionDenied) as exc_info:
            serializer.save()

        exc = exc_info.exception
        self.assertEqual(exc.denied_indexes, [1])
        self.assertEqual(exc.failures[0].obj.pk, self.second.pk)
        self.assertEqual(exc.failures[0].location, ('commits', 1))
        row_error = exc.detail['commits'][1]['non_field_errors'][0]
        self.assertEqual(row_error.code, 'commit_locked')
        self.assertIn('Locked commits', str(row_error))

        view = LibraryCommitsView()
        view.request = self._context()['request']
        view.format_kwarg = None
        response = view.handle_exception(exc)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data['commits'][1]['non_field_errors'][0].code,
            'commit_locked',
        )
        rendered = JSONRenderer().render(response.data)
        self.assertIn(b'"commits":{"1":{"non_field_errors"', rendered)

        self.library.refresh_from_db()
        self.first.refresh_from_db()
        self.second.refresh_from_db()
        self.assertEqual(self.library.name, 'Original library')
        self.assertEqual(self.first.message, 'first message')
        self.assertEqual(self.second.message, 'second message')
        self.assertTrue(self.second.locked)

    def test_late_denial_rolls_back_already_written_rows(self):
        serializer = LateRevocationLibrarySerializer(
            self.library,
            data=self.payload,
            partial=True,
            context=self._context(),
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)

        with self.assertRaises(AdmissionDenied):
            serializer.save()

        self.library.refresh_from_db()
        self.first.refresh_from_db()
        self.second.refresh_from_db()
        self.assertEqual(self.library.name, 'Original library')
        self.assertEqual(self.first.message, 'first message')
        self.assertEqual(self.second.message, 'second message')
        self.assertFalse(self.second.locked)
