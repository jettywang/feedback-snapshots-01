"""Independent call-order criterion for local recording functions.

Value equality is not enough: two expressions can produce the same JSON
while one of them evaluates an extra short-circuit branch.  The call log
of the recording extension functions is therefore checked as its own
criterion, separately from the returned value.
"""


def call_sequence(observation):
    """Return the ordered (kind, label, frozen_value) log as a tuple."""
    return tuple(observation.calls)


def probe_labels(observation):
    return tuple(call[1] for call in observation.calls
                 if call[0] == "probe")


def assert_call_order(observation, expected, note=""):
    actual = call_sequence(observation)
    assert actual == tuple(expected), (
        "%s\nexpected call order: %r\nactual call order:   %r" % (
            note or "call order mismatch", tuple(expected), actual))


def assert_same_call_order(left, right, note=""):
    assert call_sequence(left) == call_sequence(right), (
        "%s\nexpected: %r\nactual:   %r" % (
            note or "call order mismatch",
            call_sequence(left), call_sequence(right)))
