"""
Parsers are used to parse the content of incoming HTTP requests.

They give us a generic way of being able to handle various media types
on the request, such as form content or json encoded data.
"""

import codecs
import contextlib

from django.conf import settings
from django.core.files.uploadhandler import StopFutureHandlers
from django.http import QueryDict
from django.http.multipartparser import ChunkIter
from django.http.multipartparser import (
    MultiPartParser as DjangoMultiPartParser
)
from django.http.multipartparser import MultiPartParserError
from django.utils.http import parse_header_parameters

from rest_framework import renderers
from rest_framework.exceptions import ParseError
from rest_framework.settings import api_settings
from rest_framework.utils import json
from rest_framework.utils.mediatypes import media_type_matches


def get_encoding(parser_context):
    """
    Return the charset to decode the request body with: the one named in the
    request's `Content-Type` header, or `settings.DEFAULT_CHARSET`.

    Django accepts any charset that `codecs.lookup()` resolves, which includes
    bytes-to-bytes codecs such as `bz2_codec`. Decoding through one of those
    decompresses the body after `DATA_UPLOAD_MAX_MEMORY_SIZE` has already been
    checked against the compressed size, so a tiny request can expand without
    bound. Only text encodings are accepted here.
    """
    encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)
    try:
        # Unlike `codecs.getreader()`, `str.encode()` rejects non-text codecs.
        ''.encode(encoding)
    except (LookupError, UnicodeError):
        raise ParseError(
            'Unsupported charset "%s" in request Content-Type header.' % encoding
        )
    return encoding


class DataAndFiles:
    def __init__(self, data, files):
        self.data = data
        self.files = files


class BaseParser:
    """
    All parsers should extend `BaseParser`, specifying a `media_type`
    attribute, and overriding the `.parse()` method.
    """
    media_type = None

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Given a stream to read from, return the parsed representation.
        Should return parsed data, or a `DataAndFiles` object consisting of the
        parsed data and files.
        """
        raise NotImplementedError(".parse() must be overridden.")


class BaseParserAdmission:
    """
    Optional policy that decides which of a view's parsers a given request is
    allowed to use, before the request body is handed to a parser (and thus
    before any business serializer runs).

    An admission policy is consulted once per request, the first time the
    request body is read. The parser set it admits and the parser selected
    from it are reused for every later read (for example a read performed by
    an authentication class followed by the view), so the same policy and
    parser apply regardless of which stage reads first.
    """

    def get_admitted_parsers(self, request, parsers, parser_context=None):
        """
        Return the subset of `parsers` this request may use.

        Returning every parser admits the request unchanged, while returning
        an empty sequence refuses every input form. The default policy admits
        all of the view's configured parsers.
        """
        raise NotImplementedError(
            '.get_admitted_parsers() must be overridden.'
        )


class AllowAllParserAdmission(BaseParserAdmission):
    """
    Default admission policy: every configured parser remains available.
    """

    def get_admitted_parsers(self, request, parsers, parser_context=None):
        return parsers


class MediaTypeParserAdmission(BaseParserAdmission):
    """
    Admission policy that limits a request to an explicit set of media types.

    Subclasses (or instances built with `allowed_media_types`) only admit
    parsers whose `media_type` is in the allow list. This makes it possible
    to restrict some clients to, for example, JSON while still allowing form
    submissions from others.
    """
    allowed_media_types = None

    def __init__(self, allowed_media_types=None):
        if allowed_media_types is not None:
            self.allowed_media_types = allowed_media_types
        assert self.allowed_media_types is not None, (
            '`MediaTypeParserAdmission` subclasses must define an '
            '`allowed_media_types` attribute, or pass one to the constructor.'
        )

    def get_admitted_parsers(self, request, parsers, parser_context=None):
        return [
            parser for parser in parsers
            if any(
                media_type_matches(allowed, parser.media_type)
                for allowed in self.allowed_media_types
            )
        ]


class JSONParser(BaseParser):
    """
    Parses JSON-serialized data.
    """
    media_type = 'application/json'
    renderer_class = renderers.JSONRenderer
    strict = api_settings.STRICT_JSON

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Parses the incoming bytestream as JSON and returns the resulting data.
        """
        parser_context = parser_context or {}
        encoding = get_encoding(parser_context)

        try:
            decoded_stream = codecs.getreader(encoding)(stream)
            parse_constant = json.strict_constant if self.strict else None
            return json.load(decoded_stream, parse_constant=parse_constant)
        except ValueError as exc:
            raise ParseError('JSON parse error - %s' % str(exc))


class FormParser(BaseParser):
    """
    Parser for form data.
    """
    media_type = 'application/x-www-form-urlencoded'

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Parses the incoming bytestream as a URL encoded form,
        and returns the resulting QueryDict.
        """
        parser_context = parser_context or {}
        encoding = get_encoding(parser_context)
        return QueryDict(stream.read(), encoding=encoding)


class MultiPartParser(BaseParser):
    """
    Parser for multipart form data, which may include file data.
    """
    media_type = 'multipart/form-data'

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Parses the incoming bytestream as a multipart encoded form,
        and returns a DataAndFiles object.

        `.data` will be a `QueryDict` containing all the form parameters.
        `.files` will be a `QueryDict` containing all the form files.
        """
        parser_context = parser_context or {}
        request = parser_context['request']
        encoding = get_encoding(parser_context)
        meta = request.META.copy()
        meta['CONTENT_TYPE'] = media_type
        upload_handlers = request.upload_handlers

        try:
            parser = DjangoMultiPartParser(meta, stream, upload_handlers, encoding)
            data, files = parser.parse()
            return DataAndFiles(data, files)
        except MultiPartParserError as exc:
            raise ParseError('Multipart form parse error - %s' % str(exc))


class FileUploadParser(BaseParser):
    """
    Parser for file upload data.
    """
    media_type = '*/*'
    errors = {
        'unhandled': 'FileUpload parse error - none of upload handlers can handle the stream',
        'no_filename': 'Missing filename. Request should include a Content-Disposition header with a filename parameter.',
    }

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Treats the incoming bytestream as a raw file upload and returns
        a `DataAndFiles` object.

        `.data` will be None (we expect request body to be a file content).
        `.files` will be a `QueryDict` containing one 'file' element.
        """
        parser_context = parser_context or {}
        request = parser_context['request']
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)
        meta = request.META
        upload_handlers = request.upload_handlers
        filename = self.get_filename(stream, media_type, parser_context)

        if not filename:
            raise ParseError(self.errors['no_filename'])

        # Note that this code is extracted from Django's handling of
        # file uploads in MultiPartParser.
        content_type = meta.get('HTTP_CONTENT_TYPE',
                                meta.get('CONTENT_TYPE', ''))
        try:
            content_length = int(meta.get('HTTP_CONTENT_LENGTH',
                                          meta.get('CONTENT_LENGTH', 0)))
        except (ValueError, TypeError):
            content_length = None

        # See if the handler will want to take care of the parsing.
        for handler in upload_handlers:
            result = handler.handle_raw_input(stream,
                                              meta,
                                              content_length,
                                              None,
                                              encoding)
            if result is not None:
                return DataAndFiles({}, {'file': result[1]})

        # This is the standard case.
        possible_sizes = [x.chunk_size for x in upload_handlers if x.chunk_size]
        chunk_size = min([2 ** 31 - 4] + possible_sizes)
        chunks = ChunkIter(stream, chunk_size)
        counters = [0] * len(upload_handlers)

        for index, handler in enumerate(upload_handlers):
            try:
                handler.new_file(None, filename, content_type,
                                 content_length, encoding)
            except StopFutureHandlers:
                upload_handlers = upload_handlers[:index + 1]
                break

        for chunk in chunks:
            for index, handler in enumerate(upload_handlers):
                chunk_length = len(chunk)
                chunk = handler.receive_data_chunk(chunk, counters[index])
                counters[index] += chunk_length
                if chunk is None:
                    break

        for index, handler in enumerate(upload_handlers):
            file_obj = handler.file_complete(counters[index])
            if file_obj is not None:
                return DataAndFiles({}, {'file': file_obj})

        raise ParseError(self.errors['unhandled'])

    def get_filename(self, stream, media_type, parser_context):
        """
        Detects the uploaded file name. First searches a 'filename' url kwarg.
        Then tries to parse Content-Disposition header.
        """
        with contextlib.suppress(KeyError):
            return parser_context['kwargs']['filename']

        with contextlib.suppress(AttributeError, KeyError, ValueError):
            meta = parser_context['request'].META
            disposition, params = parse_header_parameters(meta['HTTP_CONTENT_DISPOSITION'])
            if 'filename*' in params:
                return params['filename*']
            return params['filename']
