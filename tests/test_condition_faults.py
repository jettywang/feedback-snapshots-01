# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Regression tests for application callbacks used inside Casbin rules.

A rule may call back into application code: a role link condition decides whether
an inherited role is active, and a matcher may call a function registered with
add_function() to look at request attributes. Either callback can say yes, say no,
or fail to reach a conclusion at all (returning None, a string, a number or an
arbitrary object). Only a real True may grant access. Everything else has to end
in a denial, while an exception raised by the callback itself must keep
propagating instead of being flattened into a denial.

The tests count callback invocations so they can tell apart three situations that
otherwise look the same in the final decision:

* the callback was never reached because an earlier operand already decided;
* the callback ran and returned a plain boolean;
* the callback ran but raised, and the error is still the caller's to see.

They also pin the existing effectors and the enforce_ex() explanation contract, so
a fix for the fail-closed behaviour does not quietly change which rules are
reported as the reason for a decision.
"""

from unittest import TestCase

import casbin
from casbin.persist.adapters.string_adapter import StringAdapter

ALLOW_OVERRIDE = "some(where (p.eft == allow))"
DENY_OVERRIDE = "!some(where (p.eft == deny))"
ALLOW_AND_DENY = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"
PRIORITY = "priority(p.eft) || deny"

EFFECTS = {
    "allow_override": ALLOW_OVERRIDE,
    "deny_override": DENY_OVERRIDE,
    "allow_and_deny": ALLOW_AND_DENY,
    "priority": PRIORITY,
}

ROLE_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _, (_, _)

[policy_effect]
e = {effect}

[matchers]
m = {matcher}
"""

ATTRIBUTE_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = {matcher}
"""

DOMAIN_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act, eft

[role_definition]
g = _, _, (_, _)

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


class Stopwatch:
    """A link condition or matcher callback that records every invocation.

    ``result`` is returned verbatim so a test can hand back None, a truthy string
    or another stand-in. When ``error`` is set the callback raises it instead.
    """

    def __init__(self, result=True, error=None):
        self.calls = 0
        self.args = []
        self.result = result
        self.error = error

    def __call__(self, *args):
        self.calls += 1
        self.args.append(args)
        if self.error is not None:
            raise self.error
        return self.result


def role_enforcer(effect, policy, matcher="g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"):
    model = casbin.Model()
    model.load_model_from_text(ROLE_MODEL.format(effect=effect, matcher=matcher))
    return casbin.Enforcer(model, StringAdapter(policy))


def attribute_enforcer(matcher, policy=""):
    model = casbin.Model()
    model.load_model_from_text(ATTRIBUTE_MODEL.format(matcher=matcher))
    enforcer = casbin.Enforcer(model, StringAdapter(policy) if policy else None)
    enforcer.enable_auto_save(False)
    return enforcer


def domain_enforcer(policy):
    model = casbin.Model()
    model.load_model_from_text(DOMAIN_MODEL)
    return casbin.Enforcer(model, StringAdapter(policy))


def bind_role_condition(enforcer, user, role, condition, *params):
    enforcer.add_named_link_condition_func("g", user, role, condition)
    enforcer.set_named_link_condition_func_params("g", user, role, *(params or ("_", "_")))


class TestRoleConditionFailClosed(TestCase):
    """A role link condition that does not answer True must not open the link."""

    def test_truthy_non_booleans_do_not_grant_access(self):
        for name, effect in EFFECTS.items():
            for result in ("yes", [0], object(), 1, 1.0):
                with self.subTest(effect=name, result=repr(result)):
                    enforcer = role_enforcer(effect, "p, admin, data1, read, allow\ng, alice, admin, _, _")
                    condition = Stopwatch(result)
                    bind_role_condition(enforcer, "alice", "admin", condition)

                    allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                    # allow_override says no because the only rule never matched;
                    # deny_override has no deny rule, so its default is an allow.
                    self.assertEqual(allowed, effect == DENY_OVERRIDE)
                    self.assertEqual(explanation, [])
                    self.assertEqual(condition.calls, 1, "the condition must still be consulted once")

    def test_none_from_a_condition_is_a_denial_not_a_grant(self):
        for name, effect in EFFECTS.items():
            with self.subTest(effect=name):
                enforcer = role_enforcer(effect, "p, admin, data1, read, allow\ng, alice, admin, _, _")
                condition = Stopwatch(None)
                bind_role_condition(enforcer, "alice", "admin", condition)

                allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                self.assertEqual(allowed, effect == DENY_OVERRIDE)
                self.assertEqual(explanation, [])
                self.assertEqual(condition.calls, 1)

    def test_true_still_grants_and_names_the_rule(self):
        for name, effect in EFFECTS.items():
            with self.subTest(effect=name):
                enforcer = role_enforcer(effect, "p, admin, data1, read, allow\ng, alice, admin, _, _")
                condition = Stopwatch(True)
                bind_role_condition(enforcer, "alice", "admin", condition, "2020-01-01 00:00:00", "_")

                allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                self.assertTrue(allowed)
                # A deny-override model explains an allow by having no deny rule to
                # name; the other effectors name the allow rule that matched.
                self.assertEqual(explanation, [] if effect == DENY_OVERRIDE else ["admin", "data1", "read", "allow"])
                self.assertEqual(condition.calls, 1)
                self.assertEqual(condition.args, [("2020-01-01 00:00:00", "_")])

    def test_false_is_a_plain_denial_without_an_explanation(self):
        for name, effect in EFFECTS.items():
            with self.subTest(effect=name):
                enforcer = role_enforcer(effect, "p, admin, data1, read, allow\ng, alice, admin, _, _")
                condition = Stopwatch(False)
                bind_role_condition(enforcer, "alice", "admin", condition)

                allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                self.assertEqual(allowed, effect == DENY_OVERRIDE)
                self.assertEqual(explanation, [])
                self.assertEqual(condition.calls, 1)

    def test_condition_errors_keep_their_own_type(self):
        for error in (ValueError("bad attribute"), KeyError("missing key"), ZeroDivisionError("1/0")):
            with self.subTest(error=type(error).__name__):
                enforcer = role_enforcer(ALLOW_OVERRIDE, "p, admin, data1, read, allow\ng, alice, admin, _, _")
                condition = Stopwatch(error=error)
                bind_role_condition(enforcer, "alice", "admin", condition)

                with self.assertRaises(type(error)) as raised:
                    enforcer.enforce_ex("alice", "data1", "read")

                self.assertEqual(raised.exception.args, error.args)
                self.assertEqual(condition.calls, 1)

    def test_condition_is_not_called_when_the_matcher_cannot_reach_it(self):
        # The condition belongs to g(), which the matcher only evaluates after the
        # request attributes line up. A request for another object never gets there.
        enforcer = role_enforcer(
            ALLOW_OVERRIDE,
            "p, admin, data2, read, allow\ng, alice, admin, _, _",
            matcher="r.obj == p.obj && r.act == p.act && g(r.sub, p.sub)",
        )
        condition = Stopwatch(True)
        bind_role_condition(enforcer, "alice", "admin", condition)

        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

        self.assertFalse(allowed)
        self.assertEqual(explanation, [])
        # The object check failed first, so the link condition was never evaluated.
        self.assertEqual(condition.calls, 0)

        allowed, explanation = enforcer.enforce_ex("alice", "data2", "read")
        self.assertTrue(allowed)
        self.assertEqual(explanation, ["admin", "data2", "read", "allow"])
        self.assertEqual(condition.calls, 1)

    def test_a_decided_allow_short_circuits_later_policy_rows(self):
        # p, alice, ... is checked before p, bob, ...; the first rule grants, so the
        # second rule's matcher (and its callback) never runs.
        enforcer = attribute_enforcer(
            "app(r.sub) && r.obj == p.obj && r.act == p.act",
            "p, alice, data1, read\np, bob, data1, read",
        )
        callback = Stopwatch(True)
        enforcer.add_function("app", callback)

        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

        self.assertTrue(allowed)
        self.assertEqual(explanation, ["alice", "data1", "read"])
        self.assertEqual(callback.calls, 1)


class TestExplicitDenyStillRuns(TestCase):
    """An inconclusive allow must not skip a deny that is already in the policy."""

    def test_inconclusive_allow_does_not_mask_an_explicit_deny(self):
        enforcer = role_enforcer(
            ALLOW_AND_DENY,
            "p, admin, data1, read, allow\np, banned, data1, read, deny\n"
            "g, alice, admin, _, _\ng, alice, banned, _, _",
        )
        admin = Stopwatch(None)
        banned = Stopwatch(True)
        bind_role_condition(enforcer, "alice", "admin", admin)
        bind_role_condition(enforcer, "alice", "banned", banned)

        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

        self.assertFalse(allowed)
        self.assertEqual(explanation, ["banned", "data1", "read", "deny"])
        # Both links are inspected, so the deny is actually reached.
        self.assertGreater(admin.calls, 0)
        self.assertGreater(banned.calls, 0)

    def test_priority_deny_still_runs_after_an_inconclusive_allow(self):
        enforcer = role_enforcer(
            PRIORITY,
            "p, admin, data1, read, allow\np, banned, data1, read, deny\n"
            "g, alice, admin, _, _\ng, alice, banned, _, _",
        )
        admin = Stopwatch("truthy but not bool")
        banned = Stopwatch(True)
        bind_role_condition(enforcer, "alice", "admin", admin)
        bind_role_condition(enforcer, "alice", "banned", banned)

        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

        self.assertFalse(allowed)
        self.assertEqual(explanation, ["banned", "data1", "read", "deny"])

    def test_a_direct_deny_rule_is_still_reached(self):
        # The inherited link is inconclusive; the user's own deny row must still run.
        for effect in (ALLOW_AND_DENY, PRIORITY):
            with self.subTest(effect=effect):
                enforcer = role_enforcer(
                    effect,
                    "p, admin, data1, read, allow\np, alice, data1, read, deny\n"
                    "g, alice, admin, _, _",
                )
                admin = Stopwatch(None)
                bind_role_condition(enforcer, "alice", "admin", admin)

                allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                self.assertFalse(allowed)
                self.assertEqual(explanation, ["alice", "data1", "read", "deny"])

    def test_a_direct_allow_rule_is_not_overridden_by_an_inconclusive_link(self):
        # An inconclusive inherited link is just a missing role; it must not veto a
        # rule that names the user directly.
        for effect in (ALLOW_OVERRIDE, ALLOW_AND_DENY, PRIORITY):
            with self.subTest(effect=effect):
                enforcer = role_enforcer(
                    effect,
                    "p, admin, data1, read, allow\np, alice, data1, read, allow\n"
                    "g, alice, admin, _, _",
                )
                admin = Stopwatch(None)
                bind_role_condition(enforcer, "alice", "admin", admin)

                allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                self.assertTrue(allowed)
                self.assertEqual(explanation, ["alice", "data1", "read", "allow"])


class TestMatcherCallbackFailClosed(TestCase):
    """A function registered with add_function() must also return a real bool."""

    def test_truthy_non_boolean_is_not_a_grant_inside_a_conjunction(self):
        for matcher in (
            "app(r.sub) && r.obj == p.obj && r.act == p.act",
            "r.obj == p.obj && r.act == p.act && app(r.sub)",
        ):
            for result in ("yes", [0], object(), 1):
                with self.subTest(matcher=matcher, result=repr(result)):
                    enforcer = attribute_enforcer(matcher, "p, alice, data1, read")
                    callback = Stopwatch(result)
                    enforcer.add_function("app", callback)

                    allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                    self.assertFalse(allowed)
                    self.assertEqual(explanation, [])
                    self.assertEqual(callback.calls, 1)

    def test_non_boolean_at_the_top_level_keeps_the_error_interface(self):
        for result in (None, "yes", [0], object(), 1):
            with self.subTest(result=repr(result)):
                enforcer = attribute_enforcer("app(r.sub)", "p, alice, data1, read")
                callback = Stopwatch(result)
                enforcer.add_function("app", callback)

                with self.assertRaisesRegex(RuntimeError, "matcher result should be bool, int or float"):
                    enforcer.enforce_ex("alice", "data1", "read")

                self.assertEqual(callback.calls, 1)

    def test_a_callback_error_is_not_reported_as_a_denial(self):
        enforcer = attribute_enforcer("app(r.sub) && r.obj == p.obj && r.act == p.act", "p, alice, data1, read")
        callback = Stopwatch(error=ValueError("attribute lookup failed"))
        enforcer.add_function("app", callback)

        with self.assertRaisesRegex(ValueError, "attribute lookup failed"):
            enforcer.enforce_ex("alice", "data1", "read")
        self.assertEqual(callback.calls, 1)

    def test_true_and_false_still_decide_normally(self):
        enforcer = attribute_enforcer("r.obj == p.obj && r.act == p.act && app(r.sub)", "p, alice, data1, read")
        allowed_callback = Stopwatch(True)
        enforcer.add_function("app", allowed_callback)

        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")
        self.assertTrue(allowed)
        self.assertEqual(explanation, ["alice", "data1", "read"])
        self.assertEqual(allowed_callback.calls, 1)

        denied_callback = Stopwatch(False)
        enforcer.add_function("app", denied_callback)
        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")
        self.assertFalse(allowed)
        self.assertEqual(explanation, [])
        self.assertEqual(denied_callback.calls, 1)

    def test_callback_is_skipped_when_an_earlier_operand_already_failed(self):
        enforcer = attribute_enforcer("r.obj == p.obj && r.act == p.act && app(r.sub)", "p, alice, data1, read")
        callback = Stopwatch(True)
        enforcer.add_function("app", callback)

        allowed, explanation = enforcer.enforce_ex("alice", "data2", "read")

        self.assertFalse(allowed)
        self.assertEqual(explanation, [])
        self.assertEqual(callback.calls, 0)

    def test_negation_does_not_turn_an_inconclusive_value_into_a_grant(self):
        for matcher in ("not app(r.sub)", "!(app(r.sub))"):
            for result in ("", object(), [0]):
                with self.subTest(matcher=matcher, result=repr(result)):
                    enforcer = attribute_enforcer(matcher, "p, alice, data1, read")
                    callback = Stopwatch(result)
                    enforcer.add_function("app", callback)

                    allowed, _ = enforcer.enforce_ex("alice", "data1", "read")

                    self.assertFalse(allowed)
                    self.assertEqual(callback.calls, 1)

    def test_no_policy_rules_still_respect_a_boolean_result(self):
        enforcer = attribute_enforcer("app(r.sub)")
        callback = Stopwatch(True)
        enforcer.add_function("app", callback)
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))

        callback.result = False
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))

        callback.result = "yes"
        with self.assertRaisesRegex(RuntimeError, "matcher result should be bool, int or float"):
            enforcer.enforce("alice", "data1", "read")


class TestDomainRoleConditionFailClosed(TestCase):
    """The same rule holds for a conditional role bound to a domain."""

    POLICY = "p, admin, domain1, data1, read, allow\ng, alice, admin, domain1, _, _"

    def bind(self, enforcer, condition, *params):
        enforcer.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", condition)
        enforcer.set_named_domain_link_condition_func_params(
            "g", "alice", "admin", "domain1", *(params or ("_", "_"))
        )

    def test_only_a_real_true_opens_a_domain_link(self):
        for result, expected in ((True, True), (False, False), (None, False), ("yes", False), (1, False)):
            with self.subTest(result=repr(result)):
                enforcer = domain_enforcer(self.POLICY)
                condition = Stopwatch(result)
                self.bind(enforcer, condition)

                allowed, explanation = enforcer.enforce_ex("alice", "domain1", "data1", "read")

                self.assertEqual(allowed, expected)
                self.assertEqual(explanation, ["admin", "domain1", "data1", "read", "allow"] if expected else [])
                self.assertEqual(condition.calls, 1)

    def test_domain_condition_errors_keep_their_own_type(self):
        error = LookupError("domain attribute missing")
        enforcer = domain_enforcer(self.POLICY)
        condition = Stopwatch(error=error)
        self.bind(enforcer, condition)

        with self.assertRaises(LookupError) as raised:
            enforcer.enforce_ex("alice", "domain1", "data1", "read")

        self.assertEqual(raised.exception.args, error.args)
        self.assertEqual(condition.calls, 1)


class TestExplanationsMatchDecisions(TestCase):
    """enforce_ex() must not name a rule that contradicts the returned decision."""

    def test_allowed_decision_names_an_allow_rule(self):
        enforcer = role_enforcer(ALLOW_OVERRIDE, "p, admin, data1, read, allow\ng, alice, admin, _, _")
        bind_role_condition(enforcer, "alice", "admin", Stopwatch(True))

        allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

        self.assertTrue(allowed)
        self.assertEqual(explanation, ["admin", "data1", "read", "allow"])

    def test_denied_decision_names_a_deny_rule_or_nothing(self):
        cases = (
            (ALLOW_OVERRIDE, "p, admin, data1, read, allow\ng, alice, admin, _, _", Stopwatch(False), []),
            (
                ALLOW_AND_DENY,
                "p, admin, data1, read, allow\np, banned, data1, read, deny\n"
                "g, alice, admin, _, _\ng, alice, banned, _, _",
                Stopwatch(True),
                ["banned", "data1", "read", "deny"],
            ),
        )
        for effect, policy, condition, expected in cases:
            with self.subTest(effect=effect, condition=repr(condition.result)):
                enforcer = role_enforcer(effect, policy)
                bind_role_condition(enforcer, "alice", "admin", condition)
                if effect == ALLOW_AND_DENY:
                    bind_role_condition(enforcer, "alice", "banned", Stopwatch(True))

                allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")

                self.assertFalse(allowed)
                self.assertEqual(explanation, expected)

    def test_changing_a_condition_result_changes_both_decision_and_explanation(self):
        enforcer = role_enforcer(ALLOW_OVERRIDE, "p, admin, data1, read, allow\ng, alice, admin, _, _")
        condition = Stopwatch(True)
        bind_role_condition(enforcer, "alice", "admin", condition)

        self.assertEqual(enforcer.enforce_ex("alice", "data1", "read"), (True, ["admin", "data1", "read", "allow"]))

        condition.result = None
        self.assertEqual(enforcer.enforce_ex("alice", "data1", "read"), (False, []))

        condition.result = True
        self.assertEqual(enforcer.enforce_ex("alice", "data1", "read"), (True, ["admin", "data1", "read", "allow"]))
