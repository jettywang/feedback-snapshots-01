"""Three independent equivalence criteria.

1. ``value``   -- the returned JSON value.
2. ``branch``  -- the set of data accesses (field reads, as a multiset)
   plus the ordered log of local extension-function calls.  Reordering the
   same reads still counts as the same branch set, but an *extra* read or
   call does not.
3. ``order``   -- the exact order of those field reads.

`strict` = value + branch set + read order + call order.
`equivalent` = value + branch set + call order (argument swaps allowed).
Anything that differs in value or branch set is not equivalent.
"""

from collections import Counter


class EquivalenceReport(object):
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.value_equal = left.value_key == right.value_key
        self.branch_set_equal = (
            Counter(left.fields) == Counter(right.fields) and
            left.calls == right.calls)
        self.access_order_equal = left.fields == right.fields
        self.call_order_equal = left.calls == right.calls

    @property
    def strict_equal(self):
        return (self.value_equal and self.access_order_equal and
                self.call_order_equal)

    @property
    def equivalent(self):
        return self.value_equal and self.branch_set_equal

    def failures(self):
        names = []
        if not self.value_equal:
            names.append("value")
        if Counter(self.left.fields) != Counter(self.right.fields):
            names.append("branch-access")
        if not self.call_order_equal:
            names.append("call-order")
        if (self.value_equal and self.call_order_equal and
                not self.access_order_equal):
            names.append("access-order-only")
        return names

    def describe(self):
        if self.strict_equal:
            return "strictly equivalent"
        if self.equivalent:
            return "equivalent with differing access order"
        return "not equivalent (%s)" % ", ".join(self.failures())


def compare(left, right):
    return EquivalenceReport(left, right)


def _message(note, report, left, right):
    return "%s\n%s\nleft:  %r\nright: %r" % (
        note, report.describe(), left, right)


def assert_strict(left, right, note=""):
    report = compare(left, right)
    assert report.strict_equal, _message(
        note or "not strictly equivalent", report, left, right)
    return report


def assert_equivalent(left, right, note=""):
    report = compare(left, right)
    assert report.equivalent, _message(
        note or "expressions are not equivalent", report, left, right)
    return report


def assert_not_equivalent(left, right, note=""):
    report = compare(left, right)
    assert not report.equivalent, _message(
        note or "expressions unexpectedly equivalent", report, left, right)
    return report


def assert_same_value_but_extra_branch(left, right, note=""):
    """Values match, yet one expression executed an extra branch."""
    report = compare(left, right)
    assert report.value_equal, _message(
        note or "values differ", report, left, right)
    assert (Counter(left.fields) != Counter(right.fields) or
            not report.call_order_equal), _message(
        note or "no extra branch detected", report, left, right)
    return report
