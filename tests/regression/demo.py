"""Executable demonstrations: one pass, one intentional failure, contrasts.

Run as a module::

    python -m tests.regression.demo
    python -m tests.regression.demo --mutant   # intentional failure

The first mode exits 0 on success.  `--mutant` deliberately swaps the
second short-circuit branch for an extension function that evaluates an
extra branch, and asserts that the harness *fails* even though both
expressions return the same JSON.  A non-zero exit from that mode is the
proof that the extra branch was detected.
"""

import sys

from tests.regression.calls import call_sequence, probe_labels
from tests.regression.criteria import (
    assert_equivalent,
    assert_not_equivalent,
    assert_same_value_but_extra_branch,
)
from tests.regression.generator import corpus
from tests.regression.observations import observe


def _first(family_name):
    return corpus(family_name, count=1)[0]


def demonstrate_pass():
    print("== passing rewrite: `a || b` -> `not_null(a, b)` (a is null) ==")
    fixture = _first("or-to-not-null")
    left = observe(fixture.left, fixture.document)
    right = observe(fixture.right, fixture.document)
    assert_equivalent(left, right)
    print("  seed %d document %r" % (fixture.seed, fixture.document))
    print("  fields: %r calls: %r" % (left.fields, call_sequence(left)))

    print("== passing rewrite: projection -> map (no nulls in items) ==")
    fixture = _first("projection-to-map")
    left = observe(fixture.left, fixture.document)
    right = observe(fixture.right, fixture.document)
    assert_equivalent(left, right)
    print("  seed %d document %r" % (fixture.seed, fixture.document))

    print("== passing rewrite: `items[0].a` -> `items[0] | a` ==")
    fixture = _first("index-expression-pipe")
    assert_equivalent(observe(fixture.left, fixture.document),
                      observe(fixture.right, fixture.document))
    print("  seed %d document %r" % (fixture.seed, fixture.document))

    print("== contrast: expressions that really differ stay different ==")
    for family_name in ("contrast-or-and",
                        "contrast-projection-map-nulls"):
        fixture = _first(family_name)
        left = observe(fixture.left, fixture.document)
        right = observe(fixture.right, fixture.document)
        assert_not_equivalent(left, right)
        print("  %-32s %r vs %r -> %r vs %r" % (
            family_name, fixture.left, fixture.right,
            left.value, right.value))


def demonstrate_mutant():
    print("== intentional failure: extra short-circuit branch ==")
    fixture = _first("extra-branch-not-null")
    # This pair returns the same JSON but `not_null` evaluates both probes
    # while `||` stops after the first truthy value.
    left = observe(fixture.left, fixture.document)
    right = observe(fixture.right, fixture.document)
    print("  document %r" % (fixture.document,))
    print("  left  value=%r calls=%r" % (left.value, call_sequence(left)))
    print("  right value=%r calls=%r" % (right.value, call_sequence(right)))
    report = assert_same_value_but_extra_branch(left, right)  # must pass
    print("  values equal, branches differ: %s" % report.describe())
    print("  probe labels left=%r right=%r" % (
        probe_labels(left), probe_labels(right)))
    # Deliberately assert *strict* equivalence for a pair that cannot have
    # it; this raises and is caught below to prove the harness notices.
    try:
        from tests.regression.criteria import assert_strict
        assert_strict(left, right, note="intentional mutant")
    except AssertionError as exc:
        print("  caught the expected failure:")
        for line in str(exc).splitlines():
            print("    " + line)
        return 0
    print("ERROR: mutant was not detected")
    return 1


def main(argv):
    if "--mutant" in argv:
        return demonstrate_mutant()
    demonstrate_pass()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
