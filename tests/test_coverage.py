# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import TestCase

import casbin
from casbin.persist.adapter import load_policy_line
from casbin.persist.adapter_filtered import FilteredAdapter

MODEL_TEXT = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = priority, sub, dom, obj, act, eft

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


def make_pages():
    return {
        "domain1": {
            "lines": [
                "p, 1, alice, domain1, data1, read, allow",
                "p, 2, data1_admin, domain1, data1, write, allow",
                "p, 3, alice, domain1, data2, read, allow",
                "g, bob, data1_admin, domain1",
            ],
            "p_domains": {"domain1"},
            "g_domains": {"domain1"},
        },
        "domain1-deny": {
            "lines": [
                "p, 0, alice, domain1, data2, read, deny",
            ],
            "p_domains": {"domain1"},
            "g_domains": set(),
        },
        "domain1-extra": {
            "lines": [
                "p, 4, carol, domain1, data9, read, allow",
            ],
            "p_domains": {"domain1"},
            "g_domains": set(),
        },
        "domain2": {
            "lines": [
                "p, 1, alice, domain2, data3, read, allow",
            ],
            "p_domains": {"domain2"},
            "g_domains": {"domain2"},
        },
    }


class PagedMemoryAdapter(FilteredAdapter):
    """In-memory filtered adapter that serves the policy in domain-scoped pages."""

    def __init__(self, pages):
        self.pages = pages
        self.loaded_pages = []

    def is_filtered(self):
        return len(self.loaded_pages) < len(self.pages)

    def load_policy(self, model):
        for page_id in self.pages:
            self._load_page(model, page_id)
        self.loaded_pages = list(self.pages)

    def load_filtered_policy(self, model, filter):
        for page_id in filter:
            if page_id not in self.loaded_pages:
                self._load_page(model, page_id)
                self.loaded_pages.append(page_id)

    def _load_page(self, model, page_id):
        for line in self.pages[page_id]["lines"]:
            load_policy_line(line, model)

    def coverage(self):
        # a domain is fully known only when every page that may carry
        # rules for it has been loaded
        missing_pages = [p for p in self.pages if p not in self.loaded_pages]
        p_domains = {
            d
            for d in self._all_domains("p_domains")
            if all(d not in self.pages[p]["p_domains"] for p in missing_pages)
        }
        g_domains = {
            d
            for d in self._all_domains("g_domains")
            if all(d not in self.pages[p]["g_domains"] for p in missing_pages)
        }
        missing = tuple("page '%s' not loaded" % p for p in missing_pages)
        return casbin.CoverageSnapshot(
            complete=not missing,
            policy_domains=frozenset(p_domains),
            role_domains=frozenset(g_domains),
            missing=missing,
        )

    def _all_domains(self, key):
        domains = set()
        for page in self.pages.values():
            domains |= page[key]
        return domains

    def save_policy(self, model):
        raise RuntimeError("not implemented")

    def add_policy(self, sec, ptype, rule):
        raise RuntimeError("not implemented")

    def remove_policy(self, sec, ptype, rule):
        raise RuntimeError("not implemented")


def new_enforcer():
    m = casbin.model.Model()
    m.load_model_from_text(MODEL_TEXT)
    return casbin.Enforcer(m, PagedMemoryAdapter(make_pages()))


class TestCoverageDecision(TestCase):
    def test_missing_page_makes_other_domain_indeterminate(self):
        e = new_enforcer()
        e.load_filtered_policy(["domain1"])
        e.load_increment_filtered_policy(["domain1-deny"])
        e.load_increment_filtered_policy(["domain1-extra"])

        # every page that may carry domain1 rules is loaded: definite answers.
        d = e.enforce_with_coverage("alice", "domain1", "data1", "read")
        self.assertEqual(casbin.Decision.ALLOW, d.decision)
        self.assertTrue(d.allowed)
        self.assertFalse(d.evidence.complete)
        self.assertTrue(d.evidence.policy_known)
        self.assertTrue(d.evidence.role_links_known)
        self.assertTrue(d.evidence.priority_known)

        # role links loaded with the page take part in the decision.
        d = e.enforce_with_coverage("bob", "domain1", "data1", "write")
        self.assertEqual(casbin.Decision.ALLOW, d.decision)

        # the loaded deny rule decides domain1 data2 for good.
        d = e.enforce_with_coverage("alice", "domain1", "data2", "read")
        self.assertEqual(casbin.Decision.DENY, d.decision)
        self.assertEqual(("0", "alice", "domain1", "data2", "read", "deny"), d.explain)

        # domain2 page is missing: the answer cannot be final.
        d = e.enforce_with_coverage("alice", "domain2", "data3", "read")
        self.assertEqual(casbin.Decision.INDETERMINATE, d.decision)
        self.assertFalse(d.allowed)
        self.assertFalse(d.evidence.policy_known)
        self.assertFalse(d.evidence.priority_known)
        self.assertIn("page 'domain2' not loaded", d.evidence.missing)
        self.assertIn("policy rules for domain 'domain2' not fully loaded", d.evidence.missing)

    def test_deferred_deny_turns_indeterminate_into_definite_deny(self):
        e = new_enforcer()
        e.load_filtered_policy(["domain1"])

        # the allow rule is loaded but the deny page is deferred:
        # raw result is allow, yet the decision is not final.
        d = e.enforce_with_coverage("alice", "domain1", "data2", "read")
        self.assertEqual(casbin.Decision.INDETERMINATE, d.decision)
        self.assertTrue(d.allowed)
        self.assertIn("page 'domain1-deny' not loaded", d.evidence.missing)

        # top up the deferred deny page: deny under allow-and-deny is final
        # even though other domain1 pages are still missing.
        e.load_increment_filtered_policy(["domain1-deny"])
        d = e.enforce_with_coverage("alice", "domain1", "data2", "read")
        self.assertEqual(casbin.Decision.DENY, d.decision)
        self.assertFalse(d.allowed)
        self.assertEqual(("0", "alice", "domain1", "data2", "read", "deny"), d.explain)
        self.assertFalse(d.evidence.complete)
        self.assertFalse(d.evidence.policy_known)

        # an allow under the same incomplete scope stays non-final.
        d = e.enforce_with_coverage("alice", "domain1", "data1", "read")
        self.assertEqual(casbin.Decision.INDETERMINATE, d.decision)
        self.assertTrue(d.allowed)

    def test_topping_up_all_pages_completes_the_scope(self):
        e = new_enforcer()
        e.load_filtered_policy(["domain1"])
        self.assertEqual(1, len(e.enforce_with_coverage("alice", "domain1", "data1", "read").evidence.loaded_batches))

        e.load_increment_filtered_policy(["domain1-deny"])
        e.load_increment_filtered_policy(["domain1-extra"])
        e.load_increment_filtered_policy(["domain2"])

        d = e.enforce_with_coverage("alice", "domain2", "data3", "read")
        self.assertEqual(casbin.Decision.ALLOW, d.decision)
        self.assertTrue(d.evidence.complete)
        self.assertEqual((), d.evidence.missing)
        self.assertEqual(4, len(d.evidence.loaded_batches))

        d = e.enforce_with_coverage("alice", "domain1", "data2", "read")
        self.assertEqual(casbin.Decision.DENY, d.decision)
        self.assertTrue(d.evidence.complete)

    def test_full_policy_callers_keep_definite_behavior(self):
        e = new_enforcer()
        e.load_policy()

        for request, expected in [
            (("alice", "domain1", "data1", "read"), True),
            (("bob", "domain1", "data1", "write"), True),
            (("alice", "domain1", "data2", "read"), False),
            (("alice", "domain2", "data3", "read"), True),
            (("alice", "domain2", "data3", "write"), False),
        ]:
            d = e.enforce_with_coverage(*request)
            self.assertEqual(expected, d.allowed)
            self.assertEqual(casbin.Decision.ALLOW if expected else casbin.Decision.DENY, d.decision)
            self.assertEqual(expected, e.enforce(*request))
            self.assertTrue(d.evidence.complete)
            self.assertEqual((), d.evidence.missing)
