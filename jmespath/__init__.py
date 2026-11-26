from jmespath import parser
from jmespath import diagnostics as _diagnostics
from jmespath.diagnostics import Diagnostics, PublicJMESPathError
from jmespath.spans import CharacterSpan
from jmespath.visitor import Options

__version__ = '1.1.0'

__all__ = [
    'compile', 'search', 'Options', 'Diagnostics', 'PublicJMESPathError',
    'CharacterSpan', 'diagnostics',
]


def compile(expression, options=None):
    reporter = _diagnostics.from_options(options)
    if reporter is None or not reporter.enabled:
        return parser.Parser().parse(expression)
    public_error = None
    try:
        parsed = parser.Parser().parse(expression)
    except Exception as exc:
        report = reporter.record(exc, expression)
        if reporter.public_exception:
            public_error = _diagnostics.PublicJMESPathError(
                report, internal_error=exc)
        else:
            raise
    # Raise outside the ``except`` block so Python does not implicitly
    # chain the original (private) exception as ``__context__``.
    if public_error is not None:
        raise public_error from None
    return parsed


def search(expression, data, options=None):
    reporter = _diagnostics.from_options(options)
    if reporter is None or not reporter.enabled:
        return parser.Parser().parse(expression).search(data, options=options)
    public_error = None
    try:
        parsed = parser.Parser().parse(expression)
    except Exception as exc:
        report = reporter.record(exc, expression)
        if reporter.public_exception:
            public_error = _diagnostics.PublicJMESPathError(
                report, internal_error=exc)
        else:
            raise
    # Raise outside the ``except`` block so Python does not implicitly
    # chain the original (private) exception as ``__context__``.
    if public_error is not None:
        raise public_error from None
    return parsed.search(data, options=options)
