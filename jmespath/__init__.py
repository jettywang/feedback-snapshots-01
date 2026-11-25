from jmespath import parser
from jmespath.visitor import Options
from jmespath.observation import (
    Decision,
    EvaluationTrace,
    ExecutionStatus,
    MissingJudgment,
    MissingType,
    Observation,
    ObservationResult,
    ObservationTrace,
    ObservedResult,
    ObservedTreeInterpreter,
    Observer,
    Presence,
    Trace,
    TraceEvent,
    observe_expression,
    observe_many,
    search_with_trace,
)

__version__ = '1.1.0'


def compile(expression):
    return parser.Parser().parse(expression)


def search(expression, data, options=None, **kwargs):
    return parser.Parser().parse(expression).search(
        data, options=options, **kwargs)


def observe(expression, data, options=None):
    """Evaluate ``expression`` and return its value plus an observation trace."""
    return parser.Parser().parse(expression).observe(data, options=options)


def explain(expression, data, options=None):
    """Return a human-readable observation trace for an evaluation."""
    return observe(expression, data, options=options).explain()


evaluate = observe
audit = observe


def trace(expression, data, options=None):
    """Evaluate ``expression`` and return only its observation trace."""
    return observe(expression, data, options=options).trace
