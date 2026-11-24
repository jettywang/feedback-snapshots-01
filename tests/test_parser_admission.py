"""
Tests for the optional parser admission contract.

The admission policy restricts which of a view's parsers a given client may
use, before the request body reaches a parser or a business serializer. It
is resolved once per request, so a read performed by an authentication class
and a later read performed by the view always observe the same admitted
parser set and the same selected parser.
"""
from unittest import mock
from urllib.parse import urlencode

from django.test import TestCase, override_settings

from rest_framework import serializers, status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import (
    MediaTypeNotAdmitted, UnsupportedMediaType
)
from rest_framework.parsers import (
    AllowAllParserAdmission, BaseParserAdmission, FormParser, JSONParser,
    MediaTypeParserAdmission, MultiPartParser
)
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView


factory = APIRequestFactory()

FORM_BODY = urlencode({'name': 'value'}).encode()
JSON_BODY = b'{"name": "value"}'


class CountingJSONParser(JSONParser):
    """JSONParser that records how many times it actually parses a body."""

    parse_calls = 0

    def parse(self, stream, media_type=None, parser_context=None):
        type(self).parse_calls += 1
        return super().parse(stream, media_type, parser_context)


class CountingFormParser(FormParser):
    """FormParser that records how many times it actually parses a body."""

    parse_calls = 0

    def parse(self, stream, media_type=None, parser_context=None):
        type(self).parse_calls += 1
        return super().parse(stream, media_type, parser_context)


class RecordingAuthentication(BaseAuthentication):
    """
    An authentication class that reads the request body during authentication,
    recording what it observes. Mirrors real authenticators that need
    `request.data` before the view runs.
    """

    seen_data = None
    seen_parser = None

    def authenticate(self, request):
        RecordingAuthentication.seen_data = request.data
        RecordingAuthentication.seen_parser = request.accepted_parser
        return None


class ExampleSerializer(serializers.Serializer):
    name = serializers.CharField()


class AdmissionTestMixin:
    def reset_counters(self):
        CountingJSONParser.parse_calls = 0
        CountingFormParser.parse_calls = 0
        RecordingAuthentication.seen_data = None
        RecordingAuthentication.seen_parser = None

    def setUp(self):
        super().setUp()
        self.reset_counters()


class JsonOnlyAdmission(BaseParserAdmission):
    """Admit JSON clients only; form submissions are refused."""

    def get_admitted_parsers(self, request, parsers, parser_context=None):
        return [
            parser for parser in parsers
            if isinstance(parser, JSONParser)
        ]


def form_request():
    return factory.post(
        '/', FORM_BODY,
        content_type='application/x-www-form-urlencoded'
    )


def json_request():
    return factory.post('/', JSON_BODY, content_type='application/json')


class TestParserAdmissionContract(TestCase):
    def test_allow_all_admission_returns_every_parser(self):
        admission = AllowAllParserAdmission()
        parsers = [JSONParser(), FormParser()]
        assert admission.get_admitted_parsers(None, parsers) == parsers

    def test_media_type_admission_filters_parsers(self):
        admission = MediaTypeParserAdmission(
            allowed_media_types=['application/json']
        )
        parsers = [JSONParser(), FormParser(), MultiPartParser()]
        admitted = admission.get_admitted_parsers(None, parsers)
        assert [type(parser) for parser in admitted] == [JSONParser]

    def test_media_type_admission_supports_wildcard_matching(self):
        admission = MediaTypeParserAdmission(
            allowed_media_types=['multipart/*']
        )
        parsers = [JSONParser(), MultiPartParser()]
        admitted = admission.get_admitted_parsers(None, parsers)
        assert [type(parser) for parser in admitted] == [MultiPartParser]

    def test_media_type_admission_requires_an_allow_list(self):
        with self.assertRaises(AssertionError):
            MediaTypeParserAdmission()

    def test_base_contract_must_be_implemented(self):
        with self.assertRaises(NotImplementedError):
            BaseParserAdmission().get_admitted_parsers(None, [])


class TestRequestLevelAdmission(AdmissionTestMixin, TestCase):
    def build_request(self, http_request, parsers, admissions=None):
        return Request(
            http_request,
            parsers=parsers,
            parser_admissions=admissions or []
        )

    def test_admitted_media_type_parses_normally(self):
        request = self.build_request(
            json_request(),
            [CountingJSONParser(), CountingFormParser()],
            admissions=[JsonOnlyAdmission()]
        )
        assert request.data == {'name': 'value'}
        assert isinstance(request.accepted_parser, CountingJSONParser)
        assert CountingJSONParser.parse_calls == 1

    def test_refused_media_type_raises_distinguishable_error(self):
        request = self.build_request(
            form_request(),
            [CountingJSONParser(), CountingFormParser()],
            admissions=[JsonOnlyAdmission()]
        )
        with self.assertRaises(MediaTypeNotAdmitted) as ctx:
            request.data
        assert ctx.exception.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        assert ctx.exception.get_codes() == 'media_type_not_admitted'
        # The view supports the form parser, so admission - not negotiation -
        # is what refused the request.
        assert request._admission_denied is True
        assert CountingFormParser.parse_calls == 0

    def test_unknown_media_type_still_raises_plain_unsupported_error(self):
        request = self.build_request(
            factory.post('/', b'plain text', content_type='text/plain'),
            [CountingJSONParser(), CountingFormParser()],
            admissions=[JsonOnlyAdmission()]
        )
        with self.assertRaises(UnsupportedMediaType) as ctx:
            request.data
        assert not isinstance(ctx.exception, MediaTypeNotAdmitted)
        assert ctx.exception.get_codes() == 'unsupported_media_type'
        assert request._admission_denied is False

    def test_admission_is_evaluated_once_across_repeated_reads(self):
        admission = JsonOnlyAdmission()
        request = self.build_request(
            json_request(),
            [CountingJSONParser(), CountingFormParser()],
            admissions=[admission]
        )
        with mock.patch.object(
            JsonOnlyAdmission, 'get_admitted_parsers',
            wraps=admission.get_admitted_parsers
        ) as admission_call:
            first = request.data
            second = request.data
        assert first == second == {'name': 'value'}
        assert admission_call.call_count == 1
        assert CountingJSONParser.parse_calls == 1

    def test_repeated_read_after_refusal_keeps_same_error(self):
        request = self.build_request(
            form_request(),
            [CountingJSONParser(), CountingFormParser()],
            admissions=[JsonOnlyAdmission()]
        )
        for _ in range(2):
            with self.assertRaises(MediaTypeNotAdmitted):
                request.data
        assert request.accepted_parser is None
        assert request._admission_denied is True

    def test_admission_still_applies_when_middleware_read_post_first(self):
        """
        If Django's `request.POST` is touched before DRF parses the body
        (e.g. by middleware), the exhausted-stream recovery path must still
        enforce the admission contract rather than silently returning data.
        """
        multipart_request = factory.post('/', {'name': 'value'})
        # Force Django to consume and cache the multipart body first.
        _ = multipart_request.POST
        request = self.build_request(
            multipart_request,
            [CountingJSONParser(), CountingFormParser(), MultiPartParser()],
            admissions=[JsonOnlyAdmission()]
        )
        with self.assertRaises(MediaTypeNotAdmitted):
            request.data
        assert request._admission_denied is True


class TestViewLevelAdmission(AdmissionTestMixin, TestCase):
    def build_view(self, admission_classes, auth_classes=None):
        class AdmissionView(APIView):
            parser_classes = [CountingJSONParser, CountingFormParser]
            parser_admission_classes = admission_classes
            authentication_classes = auth_classes or []

            def post(self, request, *args, **kwargs):
                serializer = ExampleSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                return Response(
                    {
                        'data': serializer.validated_data,
                        'parser': type(request.accepted_parser).__name__,
                    },
                    status=status.HTTP_200_OK,
                )

        return AdmissionView.as_view()

    def test_admitted_form_is_parsed_once_when_authenticator_reads_first(self):
        """
        The authentication class reads `request.data` first, then the view
        reads the same legal form body. Both stages must share the one
        selected parser, the body must be parsed a single time, and the
        serializer must run on the parsed data.
        """
        view = self.build_view(
            admission_classes=[AllowAllParserAdmission],
            auth_classes=[RecordingAuthentication],
        )
        response = view(form_request())

        assert response.status_code == status.HTTP_200_OK
        assert response.data['parser'] == 'CountingFormParser'
        assert response.data['data'] == {'name': 'value'}

        # The authenticator and the view observed the same parser instance.
        assert isinstance(
            RecordingAuthentication.seen_parser, CountingFormParser
        )
        assert dict(RecordingAuthentication.seen_data) == {'name': ['value']}

        # One admission decision, one parser selection, one body parse.
        assert CountingFormParser.parse_calls == 1
        assert CountingJSONParser.parse_calls == 0

    def test_refused_form_never_reaches_serializer(self):
        class RefusedSerializer(ExampleSerializer):
            run_count = 0

            def is_valid(self, *args, **kwargs):
                type(self).run_count += 1
                return super().is_valid(*args, **kwargs)

        class RefusedView(APIView):
            parser_classes = [CountingJSONParser, CountingFormParser]
            parser_admission_classes = [JsonOnlyAdmission]

            def post(self, request, *args, **kwargs):
                serializer = RefusedSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.validated_data)

        response = RefusedView.as_view()(form_request())
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        assert response.data['detail'].code == 'media_type_not_admitted'
        assert RefusedSerializer.run_count == 0
        assert CountingFormParser.parse_calls == 0

    def test_admitted_json_body_is_parsed_once_with_auth_first_read(self):
        view = self.build_view(
            admission_classes=[JsonOnlyAdmission],
            auth_classes=[RecordingAuthentication],
        )
        response = view(json_request())

        assert response.status_code == status.HTTP_200_OK
        assert response.data['parser'] == 'CountingJSONParser'
        assert isinstance(
            RecordingAuthentication.seen_parser, CountingJSONParser
        )
        assert CountingJSONParser.parse_calls == 1
        assert CountingFormParser.parse_calls == 0

    def test_default_view_has_no_admission_restriction(self):
        class DefaultView(APIView):
            parser_classes = [CountingJSONParser, CountingFormParser]

            def post(self, request, *args, **kwargs):
                data = request.data
                return Response({
                    'parser': type(request.accepted_parser).__name__,
                    'data': data,
                })

        response = DefaultView.as_view()(form_request())
        assert response.status_code == status.HTTP_200_OK
        assert response.data['parser'] == 'CountingFormParser'


class TestFunctionViewAdmission(AdmissionTestMixin, TestCase):
    def test_api_view_decorator_applies_admission_policy(self):
        from rest_framework.decorators import (
            api_view, parser_admission_classes, parser_classes
        )

        @api_view(['POST'])
        @parser_admission_classes([JsonOnlyAdmission])
        @parser_classes([CountingJSONParser, CountingFormParser])
        def admission_view(request):
            data = request.data
            return Response({
                'parser': type(request.accepted_parser).__name__,
                'data': data,
            })

        refused = admission_view(form_request())
        assert refused.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        assert refused.data['detail'].code == 'media_type_not_admitted'

        accepted = admission_view(json_request())
        assert accepted.status_code == status.HTTP_200_OK
        assert accepted.data['parser'] == 'CountingJSONParser'


class TestGlobalAdmissionSetting(AdmissionTestMixin, TestCase):
    def test_default_global_setting_admits_everything(self):
        from rest_framework.settings import api_settings
        assert api_settings.DEFAULT_PARSER_ADMISSION_CLASSES == [
            AllowAllParserAdmission
        ]

    def test_global_setting_restricts_all_views(self):
        from rest_framework.settings import api_settings

        class GlobalJsonOnlyView(APIView):
            parser_classes = [CountingJSONParser, CountingFormParser]

            # Read the global policy lazily so an `override_settings` change
            # is picked up the same way it is for the default API policy.
            @property
            def parser_admission_classes(self):
                return api_settings.DEFAULT_PARSER_ADMISSION_CLASSES

            def post(self, request, *args, **kwargs):
                data = request.data
                return Response({
                    'parser': type(request.accepted_parser).__name__,
                    'data': data,
                })

        with override_settings(REST_FRAMEWORK={
            'DEFAULT_PARSER_ADMISSION_CLASSES': [
                'tests.test_parser_admission.JsonOnlyAdmission'
            ]
        }):
            response = GlobalJsonOnlyView.as_view()(form_request())
            assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
            assert response.data['detail'].code == 'media_type_not_admitted'
