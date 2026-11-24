from django.test import RequestFactory, TestCase, override_settings
from django.utils import translation
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, status
from rest_framework.decorators import api_view
from rest_framework.exceptions import (
    APIException, ErrorDetail, Throttled, ValidationError, _get_error_details,
    bad_request, get_error_paths, project_bulk_errors, server_error
)
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.utils import json
from rest_framework.views import APIView


class ExceptionTestCase(TestCase):

    def test_get_error_details(self):

        example = "string"
        lazy_example = _(example)

        assert _get_error_details(lazy_example) == example

        assert isinstance(
            _get_error_details(lazy_example),
            ErrorDetail
        )

        assert _get_error_details({'nested': lazy_example})['nested'] == example

        assert isinstance(
            _get_error_details({'nested': lazy_example})['nested'],
            ErrorDetail
        )

        assert _get_error_details([[lazy_example]])[0][0] == example

        assert isinstance(
            _get_error_details([[lazy_example]])[0][0],
            ErrorDetail
        )

    def test_get_full_details_with_throttling(self):
        exception = Throttled()
        assert exception.get_full_details() == {
            'message': 'Request was throttled.', 'code': 'throttled'}

        exception = Throttled(wait=2)
        assert exception.get_full_details() == {
            'message': f'Request was throttled. Expected available in {2} seconds.',
            'code': 'throttled'}

        exception = Throttled(wait=2, detail='Slow down!')
        assert exception.get_full_details() == {
            'message': f'Slow down! Expected available in {2} seconds.',
            'code': 'throttled'}


class ErrorDetailTests(TestCase):

    def test_eq(self):
        assert ErrorDetail('msg') == ErrorDetail('msg')
        assert ErrorDetail('msg', 'code') == ErrorDetail('msg', code='code')

        assert ErrorDetail('msg') == 'msg'
        assert ErrorDetail('msg', 'code') == 'msg'

    def test_ne(self):
        assert ErrorDetail('msg1') != ErrorDetail('msg2')
        assert ErrorDetail('msg') != ErrorDetail('msg', code='invalid')

        assert ErrorDetail('msg1') != 'msg2'
        assert ErrorDetail('msg1', 'code') != 'msg2'

    def test_repr(self):
        assert repr(ErrorDetail('msg1')) == \
            'ErrorDetail(string={!r}, code=None)'.format('msg1')
        assert repr(ErrorDetail('msg1', 'code')) == \
            'ErrorDetail(string={!r}, code={!r})'.format('msg1', 'code')

    def test_str(self):
        assert str(ErrorDetail('msg1')) == 'msg1'
        assert str(ErrorDetail('msg1', 'code')) == 'msg1'

    def test_hash(self):
        assert hash(ErrorDetail('msg')) == hash('msg')
        assert hash(ErrorDetail('msg', 'code')) == hash('msg')


class TranslationTests(TestCase):

    @translation.override('fr')
    def test_message(self):
        # this test largely acts as a sanity test to ensure the translation files are present.
        self.assertEqual(_('A server error occurred.'), 'Une erreur du serveur est survenue.')
        self.assertEqual(str(APIException()), 'Une erreur du serveur est survenue.')


def test_server_error():
    request = RequestFactory().get('/')
    response = server_error(request)
    assert response.status_code == 500
    assert response["content-type"] == 'application/json'


def test_bad_request():
    request = RequestFactory().get('/')
    exception = Exception('Something went wrong — Not used')
    response = bad_request(request, exception)
    assert response.status_code == 400
    assert response["content-type"] == 'application/json'


class TestBulkErrorProjection(TestCase):
    """
    The projected structure is renderer-agnostic and identifies submitted
    positions rather than internal error-tree shapes.
    """

    def test_returns_none_for_non_bulk_details(self):
        assert project_bulk_errors({'sku': ['required']}) is None
        assert project_bulk_errors(['required']) is None
        assert project_bulk_errors(ErrorDetail('invalid')) is None

    def test_public_errors_include_row_field_pointer_and_code(self):
        detail = {
            1: {
                'sku': [ErrorDetail('This field may not be blank.', code='blank')],
                'lines': {
                    0: {'qty': [ErrorDetail('A valid integer is required.', code='invalid')]}
                },
            },
        }
        assert project_bulk_errors(detail) == {
            'errors': [
                {
                    'row': 1,
                    'field': 'lines[0].qty',
                    'pointer': '/1/lines/0/qty',
                    'code': 'invalid',
                    'message': 'A valid integer is required.',
                },
                {
                    'row': 1,
                    'field': 'sku',
                    'pointer': '/1/sku',
                    'code': 'blank',
                    'message': 'This field may not be blank.',
                },
            ]
        }

    def test_internal_errors_are_collapsed_to_a_stable_row_position(self):
        detail = {
            0: {'rule': [ErrorDetail('duplicate in batch', code='batch_duplicate')]},
            1: {
                'sku': [ErrorDetail('This field may not be blank.', code='blank')],
                'rule': [ErrorDetail('duplicate in batch', code='batch_duplicate')],
            },
        }
        projected = project_bulk_errors(detail)
        assert projected == {
            'errors': [
                {
                    'row': 0,
                    'field': None,
                    'pointer': '/0',
                    'code': 'internal',
                    'message': (
                        'This row failed an internal validation rule and '
                        'cannot be corrected from the submitted data.'
                    ),
                },
                {
                    'row': 1,
                    'field': None,
                    'pointer': '/1',
                    'code': 'internal',
                    'message': (
                        'This row failed an internal validation rule and '
                        'cannot be corrected from the submitted data.'
                    ),
                },
                {
                    'row': 1,
                    'field': 'sku',
                    'pointer': '/1/sku',
                    'code': 'blank',
                    'message': 'This field may not be blank.',
                },
            ]
        }

    def test_adding_internal_nodes_does_not_move_public_positions(self):
        public_only = {
            1: {'sku': [ErrorDetail('This field may not be blank.', code='blank')]},
        }
        with_internal = {
            1: {
                'sku': [ErrorDetail('This field may not be blank.', code='blank')],
                'extra': {'deeper': [ErrorDetail('hidden', code='rule_42')]},
            },
        }
        public_errors = [
            error for error in project_bulk_errors(public_only)['errors']
            if error['code'] != 'internal'
        ]
        assert public_errors == [
            error for error in project_bulk_errors(with_internal)['errors']
            if error['code'] != 'internal'
        ]

    def test_nested_container_path_is_preserved(self):
        detail = {
            'items': {
                2: {'sku': [ErrorDetail('This field may not be blank.', code='blank')]}
            }
        }
        assert project_bulk_errors(detail)['errors'][0]['pointer'] == '/items/2/sku'
        assert project_bulk_errors(detail)['errors'][0]['field'] == 'sku'

    def test_non_field_errors_belong_to_the_row(self):
        detail = {
            1: {
                'non_field_errors': [ErrorDetail('duplicate row', code='unique')],
                'sku': [ErrorDetail('This field may not be blank.', code='blank')],
            }
        }
        projected = project_bulk_errors(detail)['errors']
        by_code = {error['code']: error for error in projected}
        assert by_code['unique']['field'] is None
        assert by_code['unique']['pointer'] == '/1'
        assert by_code['blank']['pointer'] == '/1/sku'

    def test_custom_public_codes_can_be_supplied(self):
        detail = {0: {'sku': [ErrorDetail('bad', code='partner_fixable')]}}
        assert project_bulk_errors(detail) == {
            'errors': [{
                'row': 0, 'field': None, 'pointer': '/0', 'code': 'internal',
                'message': (
                    'This row failed an internal validation rule and '
                    'cannot be corrected from the submitted data.'
                ),
            }]
        }
        projected = project_bulk_errors(detail, public_codes={'partner_fixable'})
        assert projected['errors'] == [{
            'row': 0,
            'field': 'sku',
            'pointer': '/0/sku',
            'code': 'partner_fixable',
            'message': 'bad',
        }]

    def test_legacy_list_format_is_supported(self):
        detail = [{}, {'num': [ErrorDetail('Must be a valid boolean.', code='invalid')]}]
        assert project_bulk_errors(detail) == {
            'errors': [{
                'row': 1,
                'field': 'num',
                'pointer': '/1/num',
                'code': 'invalid',
                'message': 'Must be a valid boolean.',
            }]
        }

    def test_get_error_paths_keep_internal_diagnostics(self):
        detail = {
            0: {'rule': [ErrorDetail('duplicate in batch', code='batch_duplicate')]},
            1: {'sku': [ErrorDetail('This field may not be blank.', code='blank')]},
        }
        assert get_error_paths(detail) == [
            {
                'row': 0, 'pointer': '/0/rule', 'code': 'batch_duplicate',
                'message': 'duplicate in batch',
            },
            {
                'row': 1, 'pointer': '/1/sku', 'code': 'blank',
                'message': 'This field may not be blank.',
            },
        ]

    def test_exception_helpers_expose_the_same_diagnostics(self):
        exc = ValidationError({
            0: {'rule': [ErrorDetail('duplicate in batch', code='batch_duplicate')]},
            1: {'sku': [ErrorDetail('This field may not be blank.', code='blank')]},
        })
        assert exc.get_error_paths() == get_error_paths(exc.detail)
        assert exc.get_full_details()[0]['rule'][0]['code'] == 'batch_duplicate'
        assert [error['code'] for error in exc.get_bulk_errors()['errors']] == [
            'internal', 'blank',
        ]


INTERNAL_SKUS = {'A-100'}


class BulkImportRowSerializer(serializers.Serializer):
    sku = serializers.CharField()
    quantity = serializers.IntegerField()
    warehouse = serializers.DictField(child=serializers.CharField())

    def validate(self, attrs):
        # Internal, service-owned rule: this SKU was retired on the service
        # side. A partner cannot fix this by editing the row.
        if attrs['sku'] in INTERNAL_SKUS:
            raise serializers.ValidationError(
                ErrorDetail('SKU is no longer accepted', code='retired_sku')
            )
        return attrs


class BulkImportSerializer(serializers.Serializer):
    items = BulkImportRowSerializer(many=True)


class BulkImportView(APIView):
    bulk_error_projection = True
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer]

    def post(self, request):
        serializer = BulkImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {'imported': len(serializer.validated_data['items'])},
            status=status.HTTP_201_CREATED,
        )


bulk_import_view = BulkImportView.as_view()

factory = APIRequestFactory()


def bulk_payload(first_sku='A-100'):
    """
    Three synthetic rows:
    0. fails only an internal, service-owned rule,
    1. has two public errors at different depths,
    2. is valid.
    """
    return {
        'items': [
            {'sku': first_sku, 'quantity': 1, 'warehouse': {'code': 'WH-1'}},
            {'sku': 'B-200', 'quantity': 'many', 'warehouse': {'code': ''}},
            {'sku': 'C-300', 'quantity': 3, 'warehouse': {'code': 'WH-3'}},
        ]
    }


class TestBulkErrorProjectionIntegration(TestCase):

    def _post(self, data, fmt=None):
        suffix = '?format=%s' % fmt if fmt else ''
        request = factory.post(
            '/' + suffix, data, format='json',
            HTTP_ACCEPT=(
                'text/html' if fmt == 'api' else 'application/json'
            )
        )
        return bulk_import_view(request)

    def test_json_and_html_consume_the_same_public_structure(self):
        data = bulk_payload()

        json_response = self._post(data)
        assert json_response.status_code == status.HTTP_400_BAD_REQUEST
        public = json_response.data

        html_response = self._post(data, fmt='api')
        assert html_response.status_code == status.HTTP_400_BAD_REQUEST
        html = html_response.rendered_content.decode()

        expected = {
            'errors': [
                {
                    'row': 0,
                    'field': None,
                    'pointer': '/items/0',
                    'code': 'internal',
                    'message': (
                        'This row failed an internal validation rule and '
                        'cannot be corrected from the submitted data.'
                    ),
                },
                {
                    'row': 1,
                    'field': 'quantity',
                    'pointer': '/items/1/quantity',
                    'code': 'invalid',
                    'message': 'A valid integer is required.',
                },
                {
                    'row': 1,
                    'field': 'warehouse.code',
                    'pointer': '/items/1/warehouse/code',
                    'code': 'blank',
                    'message': 'This field may not be blank.',
                },
            ]
        }
        assert public == expected

        # The browsable API renders the same JSON payload from the same
        # response data, including field pointers and public codes. The
        # second prettyprint block is the response body.
        embedded = html.split('<pre class="prettyprint">', 2)[2]
        embedded = embedded.split('</pre>', 1)[0]
        embedded = embedded.split('</span>', 1)[1]
        embedded = embedded.replace('&quot;', '"')
        start = embedded.index('{')
        end = embedded.rindex('}') + 1
        assert json.loads(embedded[start:end]) == expected

    def test_row_positions_map_back_to_original_input(self):
        response = self._post(bulk_payload())
        errors = response.data['errors']
        submitted = bulk_payload()['items']

        for error in errors:
            pointer = error['pointer']
            assert pointer.startswith('/items/%d' % error['row'])
            if error['field'] is not None:
                # Walk the actual submitted row to prove the field exists.
                target = submitted[error['row']]
                for part in error['field'].replace('[', '.').replace(']', '').split('.'):
                    target = target[int(part)] if part.isdigit() else target[part]

        # Row 1 carries two public errors at different depths: a top-level
        # field and a nested dictionary field.
        row_one = [error for error in errors if error['code'] != 'internal']
        assert {
            (error['field'], error['pointer']) for error in row_one
        } == {
            ('quantity', '/items/1/quantity'),
            ('warehouse.code', '/items/1/warehouse/code'),
        }
        assert row_one[0]['row'] == row_one[1]['row'] == 1

    def test_internal_only_row_keeps_its_row_and_no_field(self):
        response = self._post(bulk_payload())
        internal = [
            error for error in response.data['errors']
            if error['code'] == 'internal'
        ]
        assert internal == [{
            'row': 0,
            'field': None,
            'pointer': '/items/0',
            'code': 'internal',
            'message': (
                'This row failed an internal validation rule and '
                'cannot be corrected from the submitted data.'
            ),
        }]

    def test_support_diagnostics_retain_the_full_internal_path(self):
        serializer = BulkImportSerializer(data=bulk_payload())
        assert not serializer.is_valid()
        exc = ValidationError(serializer.errors)

        assert exc.get_error_paths() == [
            {'row': 0, 'pointer': '/items/0', 'code': 'retired_sku',
             'message': 'SKU is no longer accepted'},
            {'row': 1, 'pointer': '/items/1/quantity', 'code': 'invalid',
             'message': 'A valid integer is required.'},
            {'row': 1, 'pointer': '/items/1/warehouse/code', 'code': 'blank',
             'message': 'This field may not be blank.'},
        ]
        # The exception handler's full diagnostics are untouched by the
        # external projection.
        assert exc.get_full_details()['items'][0]['non_field_errors'] == [
            {'message': 'SKU is no longer accepted', 'code': 'retired_sku'}
        ]

    def test_changing_an_internal_error_does_not_move_public_errors(self):
        first = self._post(bulk_payload())

        # Re-send after changing only the internal rule's message/code.
        class AdjustedRowSerializer(BulkImportRowSerializer):
            def validate(self, attrs):
                if attrs['sku'] in INTERNAL_SKUS:
                    raise serializers.ValidationError(
                        ErrorDetail('row already consumed', code='row_consumed')
                    )
                return attrs

        class AdjustedSerializer(BulkImportSerializer):
            items = AdjustedRowSerializer(many=True)

        class AdjustedView(BulkImportView):
            def post(self, request):
                serializer = AdjustedSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                return Response({'imported': 3}, status=201)

        second = AdjustedView.as_view()(factory.post('/', bulk_payload(), format='json'))
        assert second.status_code == status.HTTP_400_BAD_REQUEST

        def public_positions(response):
            return [
                (error['row'], error['field'], error['pointer'], error['code'])
                for error in response.data['errors']
                if error['code'] != 'internal'
            ]

        assert public_positions(first) == public_positions(second)
        assert [error['row'] for error in first.data['errors']] == [0, 1, 1]
        assert [error['row'] for error in second.data['errors']] == [0, 1, 1]

    @override_settings(REST_FRAMEWORK={'BULK_ERROR_PROJECTION': True})
    def test_global_setting_projects_function_based_views_too(self):
        data = bulk_payload()

        @api_view(['POST'])
        def bulk_view(request):
            serializer = BulkImportSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            return Response({'imported': 3})

        response = bulk_view(factory.post('/', data, format='json'))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['errors'] == [
            {
                'row': 0,
                'field': None,
                'pointer': '/items/0',
                'code': 'internal',
                'message': (
                    'This row failed an internal validation rule and '
                    'cannot be corrected from the submitted data.'
                ),
            },
            {
                'row': 1,
                'field': 'quantity',
                'pointer': '/items/1/quantity',
                'code': 'invalid',
                'message': 'A valid integer is required.',
            },
            {
                'row': 1,
                'field': 'warehouse.code',
                'pointer': '/items/1/warehouse/code',
                'code': 'blank',
                'message': 'This field may not be blank.',
            },
        ]

    def test_projection_is_opt_in(self):
        class DefaultView(APIView):
            def post(self, request):
                BulkImportSerializer(data=request.data).is_valid(raise_exception=True)
                return Response({'imported': 3})

        response = DefaultView.as_view()(factory.post('/', bulk_payload(), format='json'))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'errors' not in response.data
        assert list(response.data) == ['items']

    def test_non_bulk_validation_errors_keep_the_full_detail_shape(self):
        @api_view(['POST'])
        def simple_view(request):
            serializer = BulkImportRowSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            return Response({}, status=201)

        response = simple_view(factory.post('/', {'sku': '', 'quantity': 1}, format='json'))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        # Global projection is off by default; even with a per-view opt-in,
        # non-list details are left untouched.
        assert response.data == {
            'sku': [ErrorDetail('This field may not be blank.', code='blank')],
            'warehouse': [ErrorDetail('This field is required.', code='required')],
        }

        class ProjectedView(APIView):
            bulk_error_projection = True

            def post(self, request):
                serializer = BulkImportRowSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                return Response({}, status=201)

        response = ProjectedView.as_view()(
            factory.post('/', {'sku': '', 'quantity': 1}, format='json')
        )
        assert response.data == {
            'sku': [ErrorDetail('This field may not be blank.', code='blank')],
            'warehouse': [ErrorDetail('This field is required.', code='required')],
        }
