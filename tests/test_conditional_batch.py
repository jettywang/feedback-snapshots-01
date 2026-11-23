# Copyright 2026 The casbin Authors. All Rights Reserved.
#
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

"""Batch semantics for conditional (temporary) role edges."""

import os
from unittest import TestCase

import casbin
from casbin import util
from casbin.persist.adapters import StringAdapter


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


DOMAIN_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _, (_, _)

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


def _policy_with_domain_window(start, end, domain="domain1"):
    return (
        "p, admin, {0}, data1, read\n"
        "g, alice, admin, {0}, {1}, {2}\n"
    ).format(domain, start, end)


def _enforcer(policy, matcher=None):
    model = DOMAIN_MODEL
    if matcher is not None:
        model = DOMAIN_MODEL.replace(
            "m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act",
            "m = " + matcher,
        )
    m = casbin.Model()
    m.load_model_from_text(model)
    return casbin.Enforcer(m, StringAdapter(policy))


class TestBatchUsesOneTimeBasis(TestCase):
    def test_every_request_in_a_batch_shares_the_evaluated_at(self):
        e = _enforcer(_policy_with_domain_window("2000-01-01 00:00:00", "2100-01-01 00:00:00"))
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", util.time_match_func)

        results = e.batch_enforce_ex(
            [("alice", "domain1", "data1", "read")] * 3,
            at="2026-11-24 02:00:00",
        )
        self.assertEqual([r.allowed for r in results], [True, True, True])
        self.assertEqual({r.evaluated_at.strftime("%Y-%m-%d %H:%M:%S") for r in results}, {"2026-11-24 02:00:00"})

    def test_explicit_instant_changes_the_decision(self):
        e = _enforcer(_policy_with_domain_window("2000-01-01 00:00:00", "2030-01-01 00:00:00"))
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", util.time_match_func)

        with_condition = e.enforce_ex_at("2025-01-01 00:00:00", "alice", "domain1", "data1", "read")
        after_expiry = e.enforce_ex_at("2040-01-01 00:00:00", "alice", "domain1", "data1", "read")

        self.assertTrue(with_condition.allowed)
        self.assertFalse(after_expiry.allowed)
        self.assertEqual(
            with_condition.role_edges[0].rule,
            ["alice", "admin", "domain1", "2000-01-01 00:00:00", "2030-01-01 00:00:00"],
        )
        self.assertEqual(after_expiry.role_edges, [])

    def test_result_unpacks_like_enforce_ex(self):
        e = _enforcer("p, alice, domain1, data1, read\n")
        allowed, explanation = e.enforce_ex_at("2025-01-01 00:00:00", "alice", "domain1", "data1", "read")
        self.assertTrue(allowed)
        self.assertEqual(explanation, ["alice", "domain1", "data1", "read"])

        allowed, explanation = e.batch_enforce_ex(
            [("alice", "domain1", "data1", "read")], at="2025-01-01 00:00:00"
        )[0]
        self.assertTrue(allowed)
        self.assertEqual(explanation, ["alice", "domain1", "data1", "read"])


class TestParametersDoNotChangeMidBatch(TestCase):
    def test_parameters_changed_half_way_do_not_split_the_batch(self):
        e = _enforcer(_policy_with_domain_window("2000-01-01 00:00:00", "2100-01-01 00:00:00"))
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", util.time_match_func)

        requests = [("alice", "domain1", "data1", "read")] * 2
        results = e.batch_enforce_ex(requests, at="2026-11-24 02:00:00")
        # Change the window after the batch's first evaluation would have run.
        e.set_named_domain_link_condition_func_params(
            "g", "alice", "admin", "domain1", "2000-01-01 00:00:00", "2000-01-02 00:00:00"
        )
        later = e.batch_enforce_ex(requests, at="2026-11-24 02:00:00")

        self.assertEqual([r.allowed for r in results], [True, True])
        self.assertEqual([r.allowed for r in later], [False, False])
        # A separate call sees the update immediately.
        self.assertFalse(e.enforce_ex_at("2026-11-24 02:00:00", "alice", "domain1", "data1", "read").allowed)

    def test_batch_enforce_without_explanations_shares_the_view(self):
        calls = []

        def condition(*args):
            calls.append(args)
            return True

        e = _enforcer("p, admin, domain1, data1, read\ng, alice, admin, domain1, _, _\n")
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", condition)

        self.assertEqual(e.batch_enforce([("alice", "domain1", "data1", "read")] * 3), [True, True, True])
        self.assertEqual(len(calls), 1)


class TestExpiryDuringBatch(TestCase):
    def test_expiry_half_way_through_the_batch_keeps_later_requests_consistent(self):
        clock = iter(
            [
                "2026-11-24 01:59:59",  # role valid at the start of the batch
                "2026-11-24 02:00:05",  # expired by the time the second request is checked
            ]
        )
        expired = {"value": False}
        seen_at = []

        def expiring(*_args):
            # Each call advances a private clock; the first call is the batch
            # start, the second would flip the decision if it were consulted.
            moment = next(clock, "2026-11-24 03:00:00")
            seen_at.append(moment)
            return moment < "2026-11-24 02:00:00"

        e = _enforcer("p, admin, domain1, data1, read\ng, alice, admin, domain1, _, _\n")
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", expiring)

        results = e.batch_enforce_ex(
            [("alice", "domain1", "data1", "read"), ("alice", "domain1", "data1", "read")],
            at="2026-11-24 01:59:59",
        )

        self.assertEqual([r.allowed for r in results], [True, True])
        self.assertEqual(seen_at, ["2026-11-24 01:59:59"])
        self.assertEqual(results[1].role_edges, results[0].role_edges)

        # A fresh call sees the current decision.
        expired["value"] = True
        self.assertFalse(e.enforce("alice", "domain1", "data1", "read"))


class TestExplanationPath(TestCase):
    def test_a_multi_hop_explanation_lists_every_edge_on_the_path(self):
        policy = (
            "p, admin, domain1, data1, read\n"
            "g, alice, viewer, domain1, _, _\n"
            "g, viewer, editor, domain1, _, _\n"
            "g, editor, admin, domain1, 2000-01-01 00:00:00, 2030-01-01 00:00:00\n"
        )
        e = _enforcer(policy)
        e.add_named_domain_link_condition_func("g", "editor", "admin", "domain1", util.time_match_func)

        result = e.enforce_at(("alice", "domain1", "data1", "read"), at="2026-11-24 02:00:00")
        self.assertTrue(result.allowed)
        self.assertEqual(
            [edge.rule for edge in result.role_edges],
            [
                ["alice", "viewer", "domain1", "_", "_"],
                ["viewer", "editor", "domain1", "_", "_"],
                ["editor", "admin", "domain1", "2000-01-01 00:00:00", "2030-01-01 00:00:00"],
            ],
        )

        expired = e.enforce_at(("alice", "domain1", "data1", "read"), at="2040-01-01 00:00:00")
        self.assertFalse(expired.allowed)
        self.assertEqual(expired.role_edges, [])


class TestSameRoleNameInTwoDomains(TestCase):
    def get_enforcer(self):
        policy = (
            "p, admin, acme, data1, read\n"
            "p, admin, beta, data1, read\n"
            "g, alice, admin, acme, 2000-01-01 00:00:00, 2100-01-01 00:00:00\n"
            "g, alice, admin, beta, 2000-01-01 00:00:00, 2100-01-01 00:00:00\n"
        )
        e = _enforcer(policy)
        for domain in ("acme", "beta"):
            e.add_named_domain_link_condition_func("g", "alice", "admin", domain, util.time_match_func)
        return e

    def test_each_of_two_same_named_role_domains_is_consistent(self):
        e = self.get_enforcer()
        results = e.batch_enforce_ex(
            [("alice", "acme", "data1", "read"), ("alice", "beta", "data1", "read")],
            at="2026-11-24 02:00:00",
        )
        self.assertEqual([r.allowed for r in results], [True, True])
        self.assertEqual(len(results[0].role_edges), 1)
        self.assertEqual(len(results[1].role_edges), 1)
        self.assertNotEqual(results[0].role_edges[0].rule, results[1].role_edges[0].rule)
        self.assertEqual(results[0].role_edges[0].domain, "acme")
        self.assertEqual(results[1].role_edges[0].domain, "beta")

    def test_a_domain_pattern_condition_points_back_to_the_policy_edge(self):
        policy = (
            "p, admin, acme@eu, data1, read\n"
            "g, alice, admin, acme, 2000-01-01 00:00:00, 2100-01-01 00:00:00\n"
        )
        e = _enforcer(policy)
        e.add_named_domain_link_condition_func("g", "alice", "admin", "acme", util.time_match_func)
        e.add_named_domain_matching_func(
            "g", lambda request_domain, policy_domain: request_domain.split("@")[0] == policy_domain
        )

        result = e.enforce_ex_at("2026-11-24 02:00:00", "alice", "acme@eu", "data1", "read")
        self.assertTrue(result.allowed)
        self.assertEqual(
            result.role_edges[0].rule,
            ["alice", "admin", "acme", "2000-01-01 00:00:00", "2100-01-01 00:00:00"],
        )
        after = e.enforce_ex_at("2200-01-01 00:00:00", "alice", "acme@eu", "data1", "read")
        self.assertFalse(after.allowed)
        self.assertEqual(after.role_edges, [])


class TestExplanationsAreDetached(TestCase):
    def test_editing_a_returned_edge_does_not_affect_later_results(self):
        e = _enforcer(_policy_with_domain_window("2000-01-01 00:00:00", "2100-01-01 00:00:00"))
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", util.time_match_func)

        first = e.enforce_at(("alice", "domain1", "data1", "read"), at="2026-11-24 02:00:00")
        first.role_edges[0].params = ("tampered",)
        first.role_edges[0][-1] = "2099-01-01 00:00:00"

        second = e.enforce_at(("alice", "domain1", "data1", "read"), at="2026-11-24 02:00:00")
        self.assertEqual(
            second.role_edges[0].rule,
            ["alice", "admin", "domain1", "2000-01-01 00:00:00", "2100-01-01 00:00:00"],
        )

    def test_a_cached_conditional_result_is_still_detached(self):
        e = casbin.CachedEnforcer(
            get_examples("rbac_with_temporal_roles_model.conf"),
            get_examples("rbac_with_temporal_roles_policy.csv"),
        )
        e.add_named_link_condition_func("g", "alice", "data2_admin", util.time_match_func)
        e.set_expire_time(30)

        e.set_named_link_condition_func_params(
            "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"
        )
        first = e.enforce_ex("alice", "data2", "read")
        self.assertTrue(first[0])
        self.assertEqual(
            first[1].role_edges[0].rule,
            ["alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"],
        )

        first[1].role_edges[0].params = ("tampered",)
        first[1].role_edges[0][-1] = "2000-01-02 00:00:00"
        second = e.enforce_ex("alice", "data2", "read")
        self.assertTrue(second[0])
        self.assertEqual(
            second[1].role_edges[0].rule,
            ["alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"],
        )


class TestSingleRequestEntry(TestCase):
    def test_sequence_entry_reports_the_same_edges_as_the_batch(self):
        e = _enforcer(_policy_with_domain_window("2000-01-01 00:00:00", "2100-01-01 00:00:00"))
        e.add_named_domain_link_condition_func("g", "alice", "admin", "domain1", util.time_match_func)

        single = e.enforce_at(("alice", "domain1", "data1", "read"), at="2026-11-24 02:00:00")
        batch = e.batch_enforce_ex([("alice", "domain1", "data1", "read")], at="2026-11-24 02:00:00")[0]

        self.assertTrue(single.allowed)
        self.assertEqual(single.to_dict(), batch.to_dict())

    def test_and_enforce_ex_at_take_requests_in_different_shapes(self):
        e = _enforcer("p, alice, domain1, data1, read\n")
        first = e.enforce_at(("alice", "domain1", "data1", "read"), at="2025-01-01 00:00:00")
        second = e.enforce_ex_at("2025-01-01 00:00:00", "alice", "domain1", "data1", "read")
        self.assertEqual(first.to_dict()["rule"], second.to_dict()["rule"])

    def test_synced_enforcer_delegates_both_entries(self):
        e = casbin.SyncedEnforcer(
            get_examples("rbac_with_domain_temporal_roles_model.conf"),
            get_examples("rbac_with_domain_temporal_roles_policy.csv"),
        )
        e.add_named_domain_link_condition_func("g", "alice", "data2_admin", "domain2", util.time_match_func)
        result = e.enforce_at(("alice", "domain2", "data2", "read"), at="2026-11-24 02:00:00")
        self.assertFalse(result.allowed)
        batch = e.batch_enforce_ex([("alice", "domain2", "data2", "read")], at="2026-11-24 02:00:00")
        self.assertFalse(batch[0].allowed)


class TestTemporalExamples(TestCase):
    def test_existing_temporal_example_is_unchanged_for_a_separate_call(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_domain_temporal_roles_model.conf"),
            get_examples("rbac_with_domain_temporal_roles_policy.csv"),
        )
        for index in range(2, 9):
            e.add_named_domain_link_condition_func(
                "g", "alice", "data{}_admin".format(index), "domain{}".format(index), util.time_match_func
            )

        results = e.batch_enforce_ex(
            [
                ("alice", "domain{}".format(index), "data{}".format(index), "read")
                for index in range(1, 9)
            ],
            at="2026-11-24 02:00:00",
        )
        self.assertEqual([r.allowed for r in results], [True, False, True, True, True, False, True, False])
        for result in results[1:]:
            if result.allowed:
                self.assertEqual(len(result.role_edges), 1)
                self.assertEqual(result.role_edges[0].user, "alice")
