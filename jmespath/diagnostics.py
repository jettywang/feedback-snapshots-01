"""Scoped, two-audience error reporting for JMESPath.

The default behaviour of the library is unchanged: the original exception is
raised and no reporting happens.  Applications that expose JMESPath errors to
less trusted observers (for example a tenant facing query editor) can opt in
to diagnostics by constructing :class:`Diagnostics` and passing it through
:class:`jmespath.Options`.

Two audiences are produced for a single failure:

``InternalEvent``
    Contains the original exception, the expression and the precise source
    location.  This is for trusted logs/metrics handlers and is never
    serialized into the public report.

``PublicErrorReport``
    Contains only an approved category, a fixed human readable message, a
    character span (if one can be determined) and a correlation identifier.

Both views share the same correlation identifier, which is a random token
that contains no business values.  It lets trusted code join the public
receipt back to the internal event without exposing the expression, field
names, data values or extension exceptions.
"""

import logging
import uuid
import weakref

from jmespath import exceptions
from jmespath.spans import CharacterSpan


# The original exception is kept out of the public exception object entirely.
# Trusted in-process code can still recover it through the ``internal_error``
# property; a weak mapping avoids both leaking it into ``vars(exc)`` and
# keeping it alive beyond the exception's own lifetime.
_internal_origins = weakref.WeakKeyDictionary()


LOCATION_EXACT = 'exact'
LOCATION_CALL_SITE = 'call_site'
LOCATION_UNKNOWN = 'unknown'

_PUBLIC_MESSAGES = {
    'lexer.empty_expression': 'The expression is empty.',
    'lexer.unknown_token': 'The expression contains an invalid token.',
    'lexer.unterminated_token': 'The expression contains an unterminated token.',
    'lexer.invalid_literal': 'The expression contains an invalid literal.',
    'lexer.error': 'The expression could not be tokenized.',
    'parser.incomplete_expression': 'The expression ends before it is complete.',
    'parser.unexpected_token': 'The expression contains unexpected syntax.',
    'parser.invalid_function_name': 'The expression contains an invalid function name.',
    'parser.error': 'The expression is not valid JMESPath syntax.',
    'evaluation.unknown_function': 'The expression references an unavailable function.',
    'evaluation.invalid_arity': 'A function was called with the wrong number of arguments.',
    'evaluation.invalid_type': 'A function received a value of an invalid type.',
    'evaluation.extension_error': 'The expression could not be evaluated.',
    'evaluation.error': 'The expression could not be evaluated.',
}


def _new_correlation_id():
    # A random opaque token.  It is intentionally unrelated to the expression,
    # the data or the exception, so it cannot be used to recover business
    # values from a public receipt.
    return uuid.uuid4().hex


def _span_to_dict(span):
    if span is None:
        return None
    return span.to_dict()


def _safe_exception_text(exc):
    try:
        return str(exc)
    except Exception:
        return ''


class DiagnosticView(object):
    """Mapping-style access to a diagnostic payload."""

    _fields = ()

    def __getitem__(self, name):
        if name not in self._fields:
            raise KeyError(name)
        return getattr(self, name)

    def get(self, name, default=None):
        if name not in self._fields:
            return default
        return getattr(self, name, default)

    def keys(self):
        return list(self._fields)

    def items(self):
        return [(name, getattr(self, name)) for name in self._fields]

    def __iter__(self):
        return iter(self._fields)

    def to_dict(self):
        return dict(self.items())


class InternalEvent(DiagnosticView):
    """Trusted diagnostic view for one failed expression evaluation.

    This object may contain the original expression and exception.  Do not
    log or serialize it for an untrusted audience; use the accompanying
    :class:`PublicErrorReport` instead.
    """

    _fields = (
        'correlation_id', 'phase', 'code', 'location', 'span',
        'expression', 'exception', 'exception_type', 'exception_message',
        'function_name',
    )

    def __init__(self, correlation_id, phase, code, location, span,
                 expression, exception, function_name=None):
        self.correlation_id = correlation_id
        self.phase = phase
        self.code = code
        self.location = location
        self.span = span
        self.expression = expression
        self.exception = exception
        self.exception_type = type(exception).__name__
        self.exception_message = _safe_exception_text(exception)
        self.function_name = function_name

    def __repr__(self):
        return (
            'InternalEvent(correlation_id=%r, phase=%r, code=%r, '
            'location=%r, span=%r, exception_type=%r)' % (
                self.correlation_id, self.phase, self.code, self.location,
                self.span, self.exception_type))


class PublicErrorReport(DiagnosticView):
    """Approved, tenant-safe view of a failed expression."""

    _fields = (
        'correlation_id', 'phase', 'code', 'message', 'span', 'location',
    )

    def __init__(self, correlation_id, phase, code, message, span, location):
        self.correlation_id = correlation_id
        self.phase = phase
        self.code = code
        self.message = message
        self.span = span
        self.location = location

    def _render(self):
        location = ''
        if self.span is not None:
            location = ' at characters %s:%s' % (self.span.start, self.span.end)
        return '%s [%s]%s' % (self.message, self.correlation_id, location)

    # Mapping-style access mirrors ``InternalEvent`` for handlers that treat
    # both views uniformly, while ``to_dict`` stays the serialization API.
    __getitem__ = DiagnosticView.__getitem__
    get = DiagnosticView.get
    keys = DiagnosticView.keys
    items = DiagnosticView.items

    def __str__(self):
        return self._render()

    def __repr__(self):
        return 'PublicErrorReport(%r, %r, %r, %r, %r)' % (
            self.correlation_id, self.phase, self.code, self.message,
            self.span)

    def to_dict(self):
        return {
            'correlation_id': self.correlation_id,
            'phase': self.phase,
            'code': self.code,
            'message': self.message,
            'span': _span_to_dict(self.span),
            'location': self.location,
        }


class PublicJMESPathError(exceptions.JMESPathError):
    """A redacted exception safe to show to an untrusted observer.

    The exception's ``args``, ``str``, ``repr``, ``__cause__`` and
    ``__context__`` contain only approved information.  Trusted code that
    needs the original failure should use the matching internal event, or
    the :attr:`internal_error` attribute which is deliberately not included
    in any string or traceback rendering.
    """

    def __init__(self, report, internal_error=None):
        self.report = report
        self.correlation_id = report.correlation_id
        self.phase = report.phase
        self.code = report.code
        self.span = report.span
        self.location = report.location
        super(PublicJMESPathError, self).__init__(report.message)
        self.__cause__ = None
        self.__context__ = None
        self.__suppress_context__ = True
        if internal_error is not None:
            try:
                _internal_origins[self] = internal_error
            except TypeError:
                # Exotic subclass with __slots__ and no __weakref__; the
                # public view still works, only the trusted side channel is
                # unavailable.
                pass

    @property
    def internal_error(self):
        """The original exception, for trusted in-process handlers only.

        This value is stored out of band: it is absent from ``args``,
        ``str()``, ``repr()``, ``vars()``, the exception chain and any
        standard traceback formatting.
        """
        return _internal_origins.get(self)

    def to_dict(self):
        return self.report.to_dict()

    def __str__(self):
        return self.report._render()

    def __repr__(self):
        return 'PublicJMESPathError(%s)' % self.report._render()

    # A copied exception must not become a back door to private state.
    def __reduce__(self):
        return (
            _rebuild_public_error,
            (self.report.to_dict(),),
        )


def _rebuild_public_error(payload):
    report = PublicErrorReport(
        correlation_id=payload['correlation_id'],
        phase=payload['phase'],
        code=payload['code'],
        message=payload['message'],
        span=_span_from_dict(payload['span']),
        location=payload['location'],
    )
    return PublicJMESPathError(report)


def _span_from_dict(payload):
    if payload is None:
        return None
    return CharacterSpan(payload['start'], payload['end'])


class Diagnostics(object):
    """Opt-in scoped error reporting.

    Parameters
    ----------
    public:
        When true, a :class:`PublicJMESPathError` is raised instead of the
        original exception.  The original exception is still delivered to
        ``internal_sink`` and is available through
        ``PublicJMESPathError.internal_error``.
    internal_sink:
        Callable receiving one :class:`InternalEvent` per failure.  It sees
        the original exception and expression; keep it in trusted code only.
    public_sink:
        Callable receiving one :class:`PublicErrorReport` per failure.  The
        report contains only approved fields.
    public_exception:
        When true (the default), failures are raised as
        :class:`PublicJMESPathError` instances.  Set to false to keep raising
        the original exception while still emitting both diagnostic views.
    logger:
        Optional :class:`logging.Logger`.  Public reports are logged at
        ``level`` using a lazy format string.  Internal events are never
        logged automatically.
    correlation_id_factory:
        Callable returning a new opaque identifier.  The default uses
        UUID4; override only if your tracing infrastructure requires a
        particular random/opaque token format.
    """

    def __init__(self, public=False, internal_sink=None, public_sink=None,
                 logger=None, level=logging.WARNING,
                 correlation_id_factory=None, public_exception=None):
        self.public = bool(public)
        if public_exception is None:
            public_exception = self.public
        self.public_exception = bool(public_exception)
        self.internal_sink = internal_sink
        self.public_sink = public_sink
        self.logger = logger
        self.level = level
        self.correlation_id_factory = (
            correlation_id_factory or _new_correlation_id)

    @property
    def enabled(self):
        return bool(self.public or self.internal_sink or self.public_sink or
                    self.logger)

    def record(self, exception, expression=None):
        """Emit diagnostics for ``exception`` and return the safe report."""
        correlation_id = self.correlation_id_factory()
        phase, code = _classify(exception)
        span, location, function_name = _extract_location(
            exception, expression, phase)
        message = _PUBLIC_MESSAGES.get(
            code, _PUBLIC_MESSAGES['%s.error' % phase])
        internal = InternalEvent(
            correlation_id=correlation_id, phase=phase, code=code,
            location=location, span=span, expression=expression,
            exception=exception, function_name=function_name)
        report = PublicErrorReport(
            correlation_id=correlation_id, phase=phase, code=code,
            message=message, span=span, location=location)
        self._emit_internal(internal)
        self._emit_public(report)
        return report

    def public_error(self, exception, expression=None):
        """Return a redacted exception without emitting any sinks."""
        correlation_id = self.correlation_id_factory()
        phase, code = _classify(exception)
        span, location, function_name = _extract_location(
            exception, expression, phase)
        message = _PUBLIC_MESSAGES.get(
            code, _PUBLIC_MESSAGES['%s.error' % phase])
        if expression is not None and not isinstance(expression, str):
            expression = None
        report = PublicErrorReport(
            correlation_id=correlation_id, phase=phase, code=code,
            message=message, span=span, location=location)
        return PublicJMESPathError(report, internal_error=exception)

    def _emit_internal(self, event):
        if self.internal_sink is None:
            return
        try:
            self.internal_sink(event)
        except Exception:
            # A broken observer must not mask the query failure.
            pass

    def _emit_public(self, report):
        if self.public_sink is not None:
            try:
                self.public_sink(report)
            except Exception:
                pass
        if self.logger is not None:
            try:
                self.logger.log(self.level, '%s', report)
            except Exception:
                pass


def _classify(exc):
    if not isinstance(exc, BaseException):
        return exceptions.PHASE_EVALUATION, 'evaluation.error'
    phase = _phase_of(exc)
    if isinstance(exc, exceptions.EmptyExpressionError):
        return phase, 'lexer.empty_expression'
    if isinstance(exc, exceptions.LexerError):
        message = getattr(exc, 'message', '') or ''
        if message.startswith('Unclosed'):
            return phase, 'lexer.unterminated_token'
        if message.startswith('Bad token'):
            return phase, 'lexer.invalid_literal'
        if message.startswith('Unknown token'):
            return phase, 'lexer.unknown_token'
        return phase, 'lexer.error'
    if isinstance(exc, exceptions.IncompleteExpressionError):
        return phase, 'parser.incomplete_expression'
    if isinstance(exc, exceptions.VariadictArityError):
        return exceptions.PHASE_EVALUATION, 'evaluation.invalid_arity'
    if isinstance(exc, exceptions.ArityError):
        return exceptions.PHASE_EVALUATION, 'evaluation.invalid_arity'
    if isinstance(exc, exceptions.JMESPathTypeError):
        return exceptions.PHASE_EVALUATION, 'evaluation.invalid_type'
    if isinstance(exc, exceptions.UnknownFunctionError):
        return exceptions.PHASE_EVALUATION, 'evaluation.unknown_function'
    if isinstance(exc, exceptions.ParseError):
        message = getattr(exc, 'msg', '') or ''
        if message.startswith('Quoted identifier not allowed'):
            return phase, 'parser.invalid_function_name'
        if message.startswith('Invalid function name'):
            return phase, 'parser.invalid_function_name'
        if message.startswith('Unexpected token') or \
                message.startswith('Expecting:'):
            return phase, 'parser.unexpected_token'
        return phase, 'parser.error'
    return exceptions.PHASE_EVALUATION, 'evaluation.extension_error'


def _phase_of(exc):
    if isinstance(exc, exceptions.LexerError):
        return exceptions.PHASE_LEXER
    if isinstance(exc, exceptions.IncompleteExpressionError):
        return exceptions.PHASE_PARSER
    if isinstance(exc, exceptions.ParseError):
        # ArityError still subclasses ParseError for compatibility, but it is
        # raised by the evaluator.
        if isinstance(exc, exceptions.ArityError):
            return exceptions.PHASE_EVALUATION
        return exceptions.PHASE_PARSER
    phase = getattr(exc, 'phase', None)
    if phase in (exceptions.PHASE_LEXER, exceptions.PHASE_PARSER,
                 exceptions.PHASE_EVALUATION):
        return phase
    return exceptions.PHASE_EVALUATION


def _span_from_exception(exc):
    span = getattr(exc, 'span', None)
    if isinstance(span, CharacterSpan):
        return span
    span = getattr(exc, '_jmespath_span', None)
    if isinstance(span, CharacterSpan):
        return span
    return None


def _location_from_exception(exc, span):
    location = getattr(exc, '_jmespath_location', None)
    if location in (LOCATION_EXACT, LOCATION_CALL_SITE, LOCATION_UNKNOWN):
        return location
    if span is None:
        return LOCATION_UNKNOWN
    phase = _phase_of(exc)
    if phase in (exceptions.PHASE_LEXER, exceptions.PHASE_PARSER):
        return LOCATION_EXACT
    return LOCATION_CALL_SITE


def _extract_location(exc, expression, phase):
    if expression is not None and not isinstance(expression, str):
        expression = None
    span = _span_from_exception(exc)
    location = _location_from_exception(exc, span)
    function_name = getattr(exc, '_jmespath_function', None)
    if function_name is None:
        function_name = getattr(exc, 'function_name', None)
    if span is None and isinstance(exc, exceptions.EmptyExpressionError):
        span = CharacterSpan(0, 0)
        location = LOCATION_EXACT
    if span is None and phase == exceptions.PHASE_EVALUATION:
        # Opaque extension failures give us no source position.  Say so
        # explicitly rather than inventing one.
        location = LOCATION_UNKNOWN
    return span, location, function_name


def from_options(options):
    if options is None:
        return None
    diagnostics = getattr(options, 'diagnostics', None)
    if isinstance(diagnostics, Diagnostics):
        return diagnostics
    return None
