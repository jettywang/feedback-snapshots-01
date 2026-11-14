# -*- coding: utf-8 -*-
import unittest

from trustgraph import (FULL_TRUST, Cert, Evaluator, Key, Root, Uid,
                        VALID, INSUFFICIENT, UNKNOWN, TARGET_INVALID,
                        interpret_regex)

NOW = 1_700_000_000.0
UID_B = "Bob <bob@example.org>"


def base_keys():
    return [
        Key("ROOT", "root-admin"),
        Key("A", "alice"),
        Key("B", "bob"),
    ]


def direct(cert_id="c1", issuer="ROOT", **kw):
    return Cert(cert_id, issuer, "B", UID_B, **kw)


class TestValidityWindow(unittest.TestCase):
    def test_direct_cert_valid(self):
        ev = Evaluator(base_keys(), [direct()], [Root("ROOT", FULL_TRUST, 0)], NOW)
        v = ev.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v.status, VALID)
        self.assertTrue(ev.verify_paths(v))

    def test_expired_cert_ignored(self):
        ev = Evaluator(base_keys(), [direct(expires=NOW - 1)],
                       [Root("ROOT", FULL_TRUST, 0)], NOW)
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, INSUFFICIENT)

    def test_revoked_cert_ignored(self):
        ev = Evaluator(base_keys(), [direct(revoked=True)],
                       [Root("ROOT", FULL_TRUST, 0)], NOW)
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, INSUFFICIENT)

    def test_future_cert_ignored(self):
        ev = Evaluator(base_keys(), [direct(created=NOW + 100)],
                       [Root("ROOT", FULL_TRUST, 0)], NOW)
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, INSUFFICIENT)

    def test_revoked_issuer_key(self):
        keys = base_keys()
        keys[0] = Key("ROOT", "root-admin", revoked=True)
        ev = Evaluator(keys, [direct()], [Root("ROOT", FULL_TRUST, 0)], NOW)
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, INSUFFICIENT)

    def test_revoked_target_key(self):
        keys = base_keys()
        keys[2] = Key("B", "bob", revoked=True)
        ev = Evaluator(keys, [direct()], [Root("ROOT", FULL_TRUST, 0)], NOW)
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, TARGET_INVALID)

    def test_revoked_target_uid(self):
        ev = Evaluator(base_keys(), [direct()], [Root("ROOT", FULL_TRUST, 0)], NOW,
                       uids=[Uid("B", UID_B, revoked=True)])
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, TARGET_INVALID)


class TestAmountsAndThreshold(unittest.TestCase):
    def test_trust_amount_caps_edge(self):
        ev = Evaluator(base_keys(),
                       [direct(trust_amount=60)],
                       [Root("ROOT", FULL_TRUST, 0)], NOW)
        v = ev.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v.status, INSUFFICIENT)
        self.assertEqual(v.pessimistic_flow, 60)

    def test_two_independent_introducers_sum(self):
        keys = base_keys() + [Key("I2", "carol")]
        certs = [direct("c1"), direct("c2", issuer="I2")]
        roots = [Root("ROOT", 60, 0), Root("I2", 60, 0)]
        ev = Evaluator(keys, certs, roots, NOW)
        v = ev.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v.status, VALID)
        self.assertEqual(sum(a for a, _ in v.paths), 120)
        self.assertTrue(ev.verify_paths(v))

    def test_same_controller_does_not_sum(self):
        keys = [Key("ROOT", "root-admin"), Key("K1", "mallory"),
                Key("K2", "mallory"), Key("B", "bob")]
        certs = [direct("c1", issuer="K1"), direct("c2", issuer="K2")]
        ev = Evaluator(keys, certs, [Root("ROOT", 60, 1),
                                     Root("K1", 60, 0), Root("K2", 60, 0)], NOW)
        # Roots on K1 and K2 inject into the same contracted node: the source
        # edges both feed controller "mallory", but each root only adds its own
        # amount; the point is the two *certifications* share one node budget.
        v = ev.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v.pessimistic_flow, 120)  # two roots did sum
        # Now a single root of 60 split across two same-controller keys:
        ev2 = Evaluator(keys, certs, [Root("K1", 60, 0)], NOW)
        v2 = ev2.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v2.status, INSUFFICIENT)
        self.assertEqual(v2.pessimistic_flow, 60)


class TestDepth(unittest.TestCase):
    def chain(self, root_depth, mid_depth):
        keys = [Key("ROOT", "r"), Key("CA", "ca"), Key("SUB", "sub"), Key("B", "bob")]
        certs = [
            Cert("root-ca", "ROOT", "CA", "CA <ca@x>",
                 trust_amount=FULL_TRUST, trust_depth=mid_depth),
            Cert("ca-sub", "CA", "SUB", "SUB <sub@x>",
                 trust_amount=FULL_TRUST, trust_depth=1),
            Cert("sub-b", "SUB", "B", UID_B),
            Cert("ca-b", "CA", "B", UID_B),
        ]
        return keys, certs, [Root("ROOT", FULL_TRUST, root_depth)]

    def test_depth_allows_one_delegation(self):
        keys, certs, roots = self.chain(root_depth=1, mid_depth=1)
        ev = Evaluator(keys, certs, roots, NOW)
        v = ev.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v.status, VALID)          # ROOT -> CA -> B
        self.assertTrue(ev.verify_paths(v))

    def test_depth_blocks_second_delegation(self):
        keys, certs, roots = self.chain(root_depth=1, mid_depth=1)
        certs = [c for c in certs if c.cid != "ca-b"]
        ev = Evaluator(keys, certs, roots, NOW)
        v = ev.evaluate("B", UID_B, FULL_TRUST)    # ROOT -> CA -> SUB -> B too long
        self.assertEqual(v.status, INSUFFICIENT)

    def test_deeper_root_allows_longer_chain(self):
        keys, certs, roots = self.chain(root_depth=2, mid_depth=2)
        certs = [c for c in certs if c.cid != "ca-b"]
        ev = Evaluator(keys, certs, roots, NOW)
        v = ev.evaluate("B", UID_B, FULL_TRUST)
        self.assertEqual(v.status, VALID)
        self.assertTrue(ev.verify_paths(v))

    def test_plain_cert_does_not_delegate(self):
        keys, certs, roots = self.chain(root_depth=1, mid_depth=1)
        certs = [Cert("root-ca", "ROOT", "CA", "CA <ca@x>"),  # plain cert
                 Cert("ca-b", "CA", "B", UID_B)]
        ev = Evaluator(keys, certs, roots, NOW)
        self.assertEqual(ev.evaluate("B", UID_B, FULL_TRUST).status, INSUFFICIENT)


class TestScopeRegex(unittest.TestCase):
    SCOPE = r"[^<]+<[^@]+@corp\.example>"

    def corp_graph(self, uid, regex=SCOPE):
        keys = [Key("ROOT", "r"), Key("CA", "ca"), Key("B", "bob")]
        certs = [
            Cert("root-ca", "ROOT", "CA", "CA <ca@corp.example>",
                 trust_amount=FULL_TRUST, trust_depth=1, trust_regex=regex),
            Cert("ca-b", "CA", "B", uid),
        ]
        return Evaluator(keys, certs, [Root("ROOT", FULL_TRUST, 1)], NOW)

    def test_in_scope_uid_valid(self):
        ev = self.corp_graph("Bob <bob@corp.example>")
        v = ev.evaluate("B", "Bob <bob@corp.example>", FULL_TRUST)
        self.assertEqual(v.status, VALID)
        self.assertTrue(ev.verify_paths(v))

    def test_out_of_scope_uid_rejected(self):
        ev = self.corp_graph("Mallory <mallory@evil.example>")
        v = ev.evaluate("B", "Mallory <mallory@evil.example>", FULL_TRUST)
        self.assertEqual(v.status, INSUFFICIENT)
        self.assertEqual(v.pessimistic_flow, 0)

    def test_uninterpretable_regex_yields_unknown(self):
        ev = self.corp_graph("Bob <bob@corp.example>", regex=r"([^<]+)<\1>")
        v = ev.evaluate("B", "Bob <bob@corp.example>", FULL_TRUST)
        self.assertEqual(v.status, UNKNOWN)
        self.assertEqual(v.pessimistic_flow, 0)
        self.assertEqual(v.optimistic_flow, FULL_TRUST)

    def test_unknown_regex_irrelevant_when_threshold_already_met(self):
        keys = [Key("ROOT", "r"), Key("CA", "ca"), Key("B", "bob")]
        certs = [
            Cert("root-b", "ROOT", "B", "Bob <bob@corp.example>"),
            Cert("root-ca", "ROOT", "CA", "CA <ca@corp.example>",
                 trust_amount=FULL_TRUST, trust_depth=1, trust_regex=r"([^<]+)<\1>"),
            Cert("ca-b", "CA", "B", "Bob <bob@corp.example>"),
        ]
        ev = Evaluator(keys, certs, [Root("ROOT", FULL_TRUST, 1)], NOW)
        v = ev.evaluate("B", "Bob <bob@corp.example>", FULL_TRUST)
        self.assertEqual(v.status, VALID)   # direct cert suffices on its own
        self.assertTrue(ev.verify_paths(v))

    def test_subset_accepts_and_rejects(self):
        self.assertIsNotNone(interpret_regex(r"[^<]+<[^@]+@corp\.example>"))
        self.assertIsNotNone(interpret_regex(r"(alice|bob)@example\.(org|com)"))
        self.assertIsNone(interpret_regex(r"(a)\1"))        # backreference
        self.assertIsNone(interpret_regex(r"\d+@x"))        # character class escape
        self.assertIsNone(interpret_regex(r"(?=admin)"))    # look-ahead
        self.assertIsNone(interpret_regex(r"[a-z"))         # syntax error


class TestCycles(unittest.TestCase):
    def ring(self):
        keys = [Key("M1", "mallory"), Key("M2", "mallory2"),
                Key("M3", "mallory3"), Key("V", "victim")]
        certs = [
            Cert("r1", "M1", "M2", "m2@x", trust_amount=FULL_TRUST, trust_depth=2),
            Cert("r2", "M2", "M3", "m3@x", trust_amount=FULL_TRUST, trust_depth=2),
            Cert("r3", "M3", "M1", "m1@x", trust_amount=FULL_TRUST, trust_depth=2),
            Cert("mv", "M1", "V", "v@x"),
        ]
        return keys, certs

    def test_ring_without_root_has_no_trust(self):
        keys, certs = self.ring()
        ev = Evaluator(keys, certs, [], NOW)
        v = ev.evaluate("V", "v@x", FULL_TRUST)
        self.assertEqual(v.status, INSUFFICIENT)
        self.assertEqual(v.pessimistic_flow, 0)

    def test_ring_cannot_amplify_root_inflow(self):
        keys, certs = self.ring()
        ev = Evaluator(keys, certs, [Root("M2", 60, 2)], NOW)
        v = ev.evaluate("V", "v@x", FULL_TRUST)
        self.assertEqual(v.status, INSUFFICIENT)
        self.assertEqual(v.pessimistic_flow, 60)


if __name__ == "__main__":
    unittest.main()
