"""Compatibility namespace for callers using trace terminology."""
from jmespath.observation import *  # noqa: F401,F403
from jmespath.observation import (  # noqa: F401
    EvaluationTrace,
    ObservationResult,
    ObservedResult,
    Trace,
    TraceEvent,
    search_with_trace,
)
