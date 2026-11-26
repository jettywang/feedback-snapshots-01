"""Harness-level checks: applicability gating, mutants, reproducibility."""

import os
import subprocess
import sys

import pytest

from tests.regression.criteria import (
    assert_not_equivalent,
    assert_same_value_but_extra_branch,
    compare,
)
from tests.regression.families import FAMILIES
from tests.regression.generator import family
from tests.regression.generator import (
    build_fixture,
    corpus,
    minimal_seed,
)
from tests.regression.observations import observe

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_generator_refuses_projection_to_map_with_nulls():
    """The rule owns its precondition: null/missing `a` blocks generation."""
    trap = {"items": [{"a": 1}, {"a": None}, {}]}
    safe = {"items": [{"a": 1}, {"a": 2}]}
    projection_to_map = family("projection-to-map")
    assert not projection_to_map.applicable(trap)
    assert projection_to_map.applicable(safe)


def test_trap_document_diverges_at_runtime():
    """And if the rule were ignored, the harness does catch the divergence."""
    trap = {"items": [{"a": 1}, {"a": None}, {}]}
    left = observe("items[*].a", trap)
    right = observe("map(&a, items)", trap)
    report = compare(left, right)
    assert not report.equivalent
    assert report.failures()


def test_pick_helper_models_over_eager_branch():
    """A test double that always evaluates both arguments is detected."""
    document = {"a": 2, "b": "x"}
    fast = observe("probe('L', a) || probe('R', b)", document)
    eager = observe("pick(probe('L', a), probe('R', b))", document)
    # Same JSON value...
    assert fast.value == eager.value == 2
    # ...but the eager helper ran an extra probe.
    report = assert_same_value_but_extra_branch(fast, eager)
    assert "call-order" in report.failures()


def test_control_family_value_collision_is_still_rejected():
    """or/and can return the same JSON yet read different branches."""
    same_value = {"a": 1, "b": 1}
    left = observe("a || b", same_value)
    right = observe("a && b", same_value)
    assert left.value == right.value == 1
    assert_not_equivalent(left, right)


def test_control_family_divergence_is_not_equivalence():
    for fixture in corpus("contrast-projection-map-nulls", count=6):
        left = observe(fixture.left, fixture.document)
        right = observe(fixture.right, fixture.document)
        report = compare(left, right)
        assert not report.equivalent, (fixture, report.describe())


def _fingerprint(hash_seed):
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = str(hash_seed)
    env["PYTHONPATH"] = REPO_ROOT
    output = subprocess.check_output(
        [sys.executable, "-m", "tests.regression.fingerprint"],
        cwd=REPO_ROOT, env=env, stderr=subprocess.STDOUT)
    return output.decode("utf-8")


@pytest.mark.parametrize("hash_seed", [0, 1, 4242])
def test_same_seed_reproduces_across_fresh_interpreters(hash_seed):
    assert _fingerprint(hash_seed) == _fingerprint(7), (
        "different interpreters/hash seeds produced different fixtures")


@pytest.mark.parametrize("family_name", [fam.name for fam in FAMILIES])
def test_minimal_seed_is_stable(family_name):
    seed = minimal_seed(family_name)
    fixture = build_fixture(family_name, seed)
    assert fixture.key() == build_fixture(family_name, seed).key()
    if seed > 0:
        with pytest.raises(ValueError):
            build_fixture(family_name, seed - 1)


def test_demo_pass_and_mutant_exit_codes():
    ok = subprocess.run(
        [sys.executable, "-m", "tests.regression.demo"],
        cwd=REPO_ROOT, env=dict(os.environ, PYTHONPATH=REPO_ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    mutant = subprocess.run(
        [sys.executable, "-m", "tests.regression.demo", "--mutant"],
        cwd=REPO_ROOT, env=dict(os.environ, PYTHONPATH=REPO_ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert mutant.returncode == 0, mutant.stdout + mutant.stderr
    assert b"caught the expected failure" in mutant.stdout
