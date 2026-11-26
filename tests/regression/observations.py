"""Instrumented evaluation used by the regression harness.

Nothing in the library is changed.  Two observers are layered on top of
the public interpreter:

* `TracingInterpreter` logs every *field access* (name and order) plus the
  visited node types (for diagnostics only);
* `RecordingFunctions` logs the ordered calls of the local extension
  functions `probe()` / `pick()`.

That separation matters: an expression can visit a different node type
without touching any more data, and it can evaluate one extra argument
without changing its JSON value.  The call log catches the latter.
"""

import jmespath

from jmespath import functions
from jmespath import visitor


class RecordingFunctions(functions.Functions):
    """Local, record-only extension functions.

    `probe(label, value)` returns `value` unchanged after logging.
    `pick(first, second)` matches `a || b` value-for-value but always
    evaluates both arguments, so it is a stand-in for an over-eager
    implementation that touches an extra branch.
    """

    def __init__(self):
        self.calls = []

    @functions.signature({'types': []}, {'types': []})
    def _func_probe(self, label, value):
        self.calls.append(("probe", label, freeze(value)))
        return value

    @functions.signature({'types': []}, {'types': []})
    def _func_pick(self, first, second):
        self.calls.append(("pick", freeze(first), freeze(second)))
        # JMESPath truthiness, independent of the interpreter instance.
        falsey = (first is None or first is False or first == "" or
                  first == [] or first == {})
        return second if falsey else first


def freeze(value):
    """Convert a result into a hashable, comparable form."""
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    if isinstance(value, dict):
        return tuple(sorted((key, freeze(val)) for key, val in value.items()))
    return value


class TracingInterpreter(visitor.TreeInterpreter):
    def __init__(self, options=None):
        super(TracingInterpreter, self).__init__(options)
        self.field_accesses = []
        self.node_types = []

    def visit(self, node, *args, **kwargs):
        self.node_types.append(node["type"])
        if node["type"] == "field":
            self.field_accesses.append(node["value"])
        return super(TracingInterpreter, self).visit(node, *args, **kwargs)


class Observation(object):
    """One evaluation of one expression against one document."""

    def __init__(self, value, fields, calls, nodes):
        self.value = value
        self.fields = tuple(fields)
        self.calls = tuple(calls)
        self.nodes = tuple(nodes)

    @property
    def value_key(self):
        return freeze(self.value)

    @property
    def accesses(self):
        """(field accesses, function calls) -- what data was touched."""
        return (self.fields, self.calls)

    def __eq__(self, other):
        return (isinstance(other, Observation) and
                self.value_key == other.value_key and
                self.fields == other.fields and
                self.calls == other.calls)

    def __hash__(self):
        return hash((self.value_key, self.fields, self.calls))

    def __repr__(self):
        return ("Observation(value=%r, fields=%r, calls=%r, nodes=%r)" % (
            self.value, self.fields, self.calls, self.nodes))


def observe(expr, data):
    """Evaluate `expr` on `data` with full instrumentation.

    `expr` may be a source string (parsed now) or an already-parsed object
    (`jmespath.compile(...)`) to exercise parse reuse.
    """
    recorder = RecordingFunctions()
    options = visitor.Options(custom_functions=recorder)
    parsed = expr if hasattr(expr, "parsed") else jmespath.compile(expr)
    interpreter = TracingInterpreter(options)
    value = interpreter.visit(parsed.parsed, data)
    return Observation(value, interpreter.field_accesses,
                       recorder.calls, interpreter.node_types)
