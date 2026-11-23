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

"""One consistent request-attribute view per authorization decision."""

from unittest import TestCase

import asyncio

import casbin
from casbin import AttributeView
from casbin.core_enforcer import EnforceContext


def abac_model(matcher="r.sub == p.sub && r.sub == r.obj.Owner && r.act == p.act"):
    result = casbin.Model()
    result.load_model_from_text(
        """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = """
        + matcher
    )
    return result


def multi_matcher_model():
    result = casbin.Model()
    result.load_model_from_text(
        """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.sub == r.obj.Owner && r.act == p.act
m2 = r.sub == p.sub && r.obj.Owner == r.sub && r.act == p.act
"""
    )
    return result


def deny_model():
    result = casbin.Model()
    result.load_model_from_text(
        """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = owner(r.obj) == p.sub && r.act == p.act
"""
    )
    return result


class Document:
    """a mutable business object, like a row an application loads and updates."""

    def __init__(self, owner):
        self.Owner = owner

    def __repr__(self):
        return "Document(Owner={!r})".format(self.Owner)


class Principal:
    """a mutable subject that compares and hashes like its current name.

    This makes the FastEnforcer filter key depend on the attribute value, so a
    fast path that reads the live object instead of the captured view would be
    visible in the decision.
    """

    def __init__(self, name):
        self.name = name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, str):
            return self.name == other
        return isinstance(other, Principal) and self.name == other.name

    def __repr__(self):
        return "Principal({!r})".format(self.name)


def new_enforcer(cls=casbin.Enforcer, cache_key_order=None):
    enforcer = cls(abac_model(), cache_key_order=cache_key_order) if cache_key_order else cls(abac_model())
    enforcer.enable_auto_save(False)
    enforcer.add_policy("alice", "data1", "read")
    enforcer.add_policy("bob", "data1", "read")
    return enforcer


class TestAttributeView(TestCase):
    def test_default_entry_keeps_using_live_request_objects(self):
        enforcer = new_enforcer()
        document = Document("alice")

        self.assertTrue(enforcer.enforce("alice", document, "read"))
        self.assertTupleEqual(enforcer.enforce_ex("alice", document, "read"), (True, ["alice", "data1", "read"]))

        document.Owner = "bob"
        self.assertFalse(enforcer.enforce("alice", document, "read"))
        self.assertTupleEqual(enforcer.enforce_ex("alice", document, "read"), (False, []))

    def test_a_held_view_keeps_deciding_on_the_captured_version(self):
        enforcer = new_enforcer()
        document = Document("alice")

        view = AttributeView.capture("alice", document, "read")
        document.Owner = "bob"

        decision = enforcer.enforce_ex_with_attributes(view)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.rule, ["alice", "data1", "read"])
        self.assertEqual(decision.attributes.version, view.version)
        self.assertEqual(decision.attributes["r_obj"].Owner, "alice")

        # The same held view keeps working after more changes.
        document.Owner = "carol"
        self.assertTrue(enforcer.enforce_with_attributes(view))

        # A new decision captures the current version and sees the update.
        self.assertFalse(enforcer.enforce_with_attributes("alice", document, "read"))

    def test_the_entry_point_captures_when_no_view_is_supplied(self):
        enforcer = new_enforcer()
        document = Document("alice")

        decision = enforcer.enforce_ex_with_attributes("alice", document, "read")
        self.assertTrue(decision.allowed)

        document.Owner = "bob"
        self.assertFalse(enforcer.enforce_with_attributes("alice", document, "read"))
        self.assertTrue(enforcer.enforce_with_attributes(decision.attributes))

    def test_explicit_mapping_view_binds_by_token_name(self):
        enforcer = new_enforcer()
        document = Document("alice")

        view = AttributeView.from_mapping({"act": "read", "obj": document, "sub": "alice"})
        document.Owner = "bob"
        decision = enforcer.enforce_ex_with_attributes(attributes=view)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.attributes.as_dict()["r_sub"], "alice")
        self.assertEqual(decision.attributes["r.act"], "read")
        self.assertEqual(decision.attributes["r.obj"].Owner, "alice")

    def test_live_view_opts_out_of_isolation(self):
        enforcer = new_enforcer()
        document = Document("alice")

        view = AttributeView.live("alice", document, "read")
        self.assertFalse(view.isolated)
        document.Owner = "bob"
        self.assertFalse(enforcer.enforce_with_attributes(view))

    def test_a_view_can_be_copied_for_a_new_decision(self):
        enforcer = new_enforcer()
        document = Document("alice")

        original = AttributeView.capture("alice", document, "read")
        duplicate = original.copy()

        self.assertNotEqual(duplicate.version, original.version)
        self.assertEqual(duplicate.tokens, original.tokens)
        document.Owner = "bob"
        decision = enforcer.enforce_ex_with_attributes(duplicate)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.attributes["r.obj"].Owner, "alice")

    def test_unsupported_attribute_argument_is_rejected(self):
        enforcer = new_enforcer()
        with self.assertRaises(TypeError):
            enforcer.enforce_with_attributes("alice", Document("alice"), "read", attributes=object())

    def test_old_plain_requests_still_work_through_the_default_entry(self):
        # Keeping the previous calling convention is part of the contract: the
        # default entry point does not wrap, copy or require a view.
        enforcer = new_enforcer()
        document = Document("alice")
        old_request = ("alice", document, "read")

        self.assertTrue(enforcer.enforce(*old_request))
        self.assertTupleEqual(enforcer.enforce_ex(*old_request), (True, ["alice", "data1", "read"]))

    def test_multiple_matchers_see_the_same_version(self):
        enforcer = casbin.Enforcer(multi_matcher_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read")

        # Both named matchers are evaluated against the view captured once.
        for mtype in ("m", "m2"):
            context = EnforceContext(rtype="r", ptype="p", etype="e", mtype=mtype)
            with self.subTest(matcher=mtype):
                document = Document("alice")
                view = AttributeView.capture("alice", document, "read")
                document.Owner = "bob"
                decision = enforcer.enforce_ex_with_attributes(context, view)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.attributes["r_obj"].Owner, "alice")


class TestOneDecisionOneVersion(TestCase):
    def test_enforce_context_and_view_can_arrive_in_either_order(self):
        enforcer = new_enforcer()
        document = Document("alice")
        context = EnforceContext(rtype="r", ptype="p", etype="e", mtype="m")

        first = AttributeView.capture("alice", document, "read")
        second = AttributeView.capture("alice", document, "read")
        document.Owner = "bob"

        for arguments in ((context, first), (second, context)):
            with self.subTest(order=type(arguments[0]).__name__):
                self.assertTrue(enforcer.enforce_with_attributes(*arguments))

    def test_a_view_must_match_the_request_size(self):
        enforcer = new_enforcer()
        view = AttributeView.capture("alice", "data1")
        with self.assertRaises(RuntimeError):
            enforcer.enforce_with_attributes(view, "read")

    def test_custom_function_cannot_drift_between_policy_rows(self):
        enforcer = casbin.Enforcer(deny_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read", "allow")
        enforcer.add_policy("bob", "data1", "read", "deny")

        seen_versions = []

        def owner(document):
            # A deliberately hostile callback: it records the view, reads the
            # attribute and then mutates the object.  The decision must keep
            # reading the captured version, not the mutation.
            seen_versions.append(getattr(casbin.current_attribute_view(), "version", None))
            current = document.Owner
            document.Owner = "bob"
            return current

        enforcer.add_function("owner", owner)
        document = Document("alice")

        decision = enforcer.enforce_ex_with_attributes("alice", document, "read")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.rule, ["alice", "data1", "read", "allow"])

        # Every row and every callback saw the same captured version.
        view = decision.attributes
        self.assertGreaterEqual(len(seen_versions), 2)
        self.assertEqual(set(seen_versions), {view.version})

        # The caller's object was not left holding a value written by the
        # callback: the callback worked on the decision's copy.
        self.assertEqual(document.Owner, "alice")

    def test_a_function_installed_on_the_map_is_detected_too(self):
        enforcer = casbin.Enforcer(deny_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read", "allow")
        enforcer.add_policy("bob", "data1", "read", "deny")

        def owner(document):
            current = document.Owner
            document.Owner = "bob"
            return current

        # Not through add_function(): the attribute-view path must still notice
        # that the map was customised and isolate the rows.
        enforcer.fm.add_function("owner", owner)
        document = Document("alice")

        decision = enforcer.enforce_ex_with_attributes("alice", document, "read")
        self.assertTrue(decision.allowed)
        self.assertEqual(document.Owner, "alice")

    def test_mutations_are_visible_on_the_legacy_path(self):
        enforcer = casbin.Enforcer(deny_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read", "allow")
        enforcer.add_policy("bob", "data1", "read", "deny")

        def owner(document):
            current = document.Owner
            document.Owner = "bob"
            return current

        enforcer.add_function("owner", owner)
        document = Document("alice")

        # The historical entry point passes the caller's object through, so a
        # mutating callback is visible on the next row and the deny matches.
        self.assertFalse(enforcer.enforce("alice", document, "read"))
        self.assertEqual(document.Owner, "bob")

    def test_custom_function_signature_is_unchanged(self):
        # Existing add_function() callbacks keep their parameters; they only
        # receive the captured value instead of the live one in this path.
        received = []

        def check(owner, expected):
            received.append(owner)
            return owner == expected

        enforcer = casbin.Enforcer(abac_model("check(r.obj.Owner, p.sub) && r.act == p.act"))
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read")
        enforcer.add_function("check", check)

        document = Document("alice")
        view = AttributeView.capture("alice", document, "read")
        document.Owner = "bob"

        self.assertTrue(enforcer.enforce_with_attributes(view))
        self.assertEqual(received, ["alice"])

    def test_current_view_is_only_published_for_the_new_entry_point(self):
        enforcer = casbin.Enforcer(abac_model("observe() && r.sub == p.sub && r.act == p.act"))
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read")
        observed = []
        enforcer.add_function("observe", lambda: observed.append(casbin.current_attribute_view()) or True)

        enforcer.enforce("alice", "data1", "read")
        self.assertEqual(observed, [None])

        decision = enforcer.enforce_ex_with_attributes("alice", "data1", "read")
        self.assertEqual(len(observed), 2)
        self.assertIs(observed[-1], decision.attributes)


class TestFastEnforcerAttributeView(TestCase):
    def model(self):
        return abac_model("r.sub.name == p.sub && r.obj == p.obj && r.act == p.act")

    def new_enforcers(self):
        plain = casbin.Enforcer(self.model())
        fast_model = casbin.FastModel([0, 1])
        fast_model.load_model_from_text(self.model().to_text())
        fast = casbin.FastEnforcer(fast_model, cache_key_order=[0, 1])
        for enforcer in (plain, fast):
            enforcer.enable_auto_save(False)
            enforcer.add_policy("alice", "data1", "read")
            enforcer.add_policy("bob", "data1", "read")
            enforcer.add_policy("alice", "data1", "write")
        return plain, fast

    def test_action_decisions_and_explanations_match(self):
        plain, fast = self.new_enforcers()
        principal = Principal("alice")

        for enforcer in (plain, fast):
            self.assertTrue(enforcer.enforce(principal, "data1", "read"), type(enforcer).__name__)

        view = AttributeView.capture(principal, "data1", "read")
        principal.name = "bob"

        expected = plain.enforce_ex_with_attributes(view)
        actual = fast.enforce_ex_with_attributes(view)
        self.assertTrue(actual.allowed)
        self.assertEqual(actual.rule, expected.rule)
        self.assertEqual(actual.rule, ["alice", "data1", "read"])
        self.assertEqual(actual.attribute_version, view.version)

        # The old object through the default entry is still governed by its
        # current value, on both enforcers.
        self.assertTrue(fast.enforce(principal, "data1", "read"))
        self.assertTrue(plain.enforce(principal, "data1", "read"))

        # A fresh decision captures the updated value as well.
        principal.name = "carol"
        self.assertFalse(fast.enforce_with_attributes(principal, "data1", "read"))
        self.assertFalse(plain.enforce_with_attributes(principal, "data1", "read"))

    def test_fast_filter_uses_the_captured_key(self):
        plain, fast = self.new_enforcers()
        principal = Principal("alice")
        view = AttributeView.capture(principal, "data1", "read")

        # The live object no longer matches any policy row, but the captured
        # view still does.  A filter derived from the live object would return
        # an empty policy and deny this request.
        principal.name = "nobody"
        self.assertTrue(fast.enforce_with_attributes(view))
        self.assertTrue(plain.enforce_with_attributes(view))

    def test_held_view_through_enforce_uses_the_attribute_path(self):
        plain, fast = self.new_enforcers()
        principal = Principal("alice")
        view = AttributeView.capture(principal, "data1", "read")
        principal.name = "nobody"

        self.assertTrue(fast.enforce(view))
        self.assertTrue(plain.enforce(view))

    def test_legacy_fast_path_is_unchanged(self):
        _, fast = self.new_enforcers()
        principal = Principal("alice")

        self.assertTrue(fast.enforce(principal, "data1", "read"))
        self.assertFalse(fast.enforce(principal, "data1", "delete"))
        self.assertTupleEqual(fast.enforce_ex(principal, "data1", "read"), (True, ["alice", "data1", "read"]))


class TestAttributeViewsAcrossEnforcers(TestCase):
    def test_async_enforcer_exposes_the_entry_point(self):
        model = abac_model()

        async def run():
            enforcer = casbin.AsyncEnforcer(model)
            enforcer.enable_auto_save(False)
            await enforcer.add_policy("alice", "data1", "read")
            document = Document("alice")
            view = AttributeView.capture("alice", document, "read")
            document.Owner = "bob"

            self.assertTrue(enforcer.enforce_with_attributes(view))
            decision = enforcer.enforce_ex_with_attributes(view)
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.rule, ["alice", "data1", "read"])
            self.assertFalse(enforcer.enforce_with_attributes("alice", document, "read"))

        asyncio.run(run())

    def test_the_caller_object_is_not_copied_twice_or_left_mutated(self):
        # The view is a version, not a transaction: the caller's live object
        # must be untouched, and a second decision must capture a new copy.
        enforcer = new_enforcer()
        document = Document("alice")

        decision = enforcer.enforce_ex_with_attributes("alice", document, "read")
        self.assertIsNot(decision.attributes["r.obj"], document)
        self.assertEqual(document.Owner, "alice")

        document.Owner = "bob"
        self.assertFalse(enforcer.enforce_with_attributes("alice", document, "read"))
        self.assertTrue(enforcer.enforce_with_attributes(decision.attributes))

    def test_a_value_that_cannot_be_copied_is_reported(self):
        class Uncopyable:
            def __init__(self, owner):
                self.Owner = owner

            def __deepcopy__(self, memo):
                raise TypeError("this value cannot be copied")

        enforcer = new_enforcer()
        document = Uncopyable("alice")

        view = AttributeView.capture("alice", document, "read")
        self.assertFalse(view.isolated)
        self.assertFalse(view.is_fully_isolated)
        self.assertEqual(view.fallbacks, (1,))
        # A shallow copy still preserves the top-level Owner version.
        document.Owner = "bob"
        self.assertTrue(enforcer.enforce_with_attributes(view))


class TestAttributeEntryAcrossEnforcers(TestCase):
    def test_cached_enforcer_does_not_reuse_a_view_decision(self):
        enforcer = casbin.CachedEnforcer(abac_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read")
        document = Document("alice")

        self.assertTrue(enforcer.enforce_with_attributes("alice", document, "read"))
        self.assertEqual(len(enforcer.get_cache()), 0)

        document.Owner = "bob"
        self.assertFalse(enforcer.enforce_with_attributes("alice", document, "read"))

    def test_cached_default_entry_with_a_view_stays_uncached(self):
        enforcer = casbin.CachedEnforcer(abac_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read")
        document = Document("alice")

        view = AttributeView.capture("alice", document, "read")
        document.Owner = "bob"

        self.assertTrue(enforcer.enforce(view))
        self.assertEqual(len(enforcer.get_cache()), 0)
        allowed, explanation = enforcer.enforce_ex(view)
        self.assertTrue(allowed)
        self.assertEqual(explanation.attributes["r.obj"].Owner, "alice")
        self.assertEqual(len(enforcer.get_cache()), 0)

    def test_synced_enforcer_exposes_the_entry_point(self):
        enforcer = casbin.SyncedEnforcer(abac_model())
        enforcer.enable_auto_save(False)
        enforcer.add_policy("alice", "data1", "read")
        document = Document("alice")

        view = AttributeView.capture("alice", document, "read")
        document.Owner = "bob"

        self.assertTrue(enforcer.enforce_with_attributes(view))
        decision = enforcer.enforce_ex_with_attributes(view)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.attribute_version, view.version)
        self.assertFalse(enforcer.enforce_with_attributes("alice", document, "read"))
