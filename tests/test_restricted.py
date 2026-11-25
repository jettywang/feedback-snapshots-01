"""Tests for the field-visibility restricted query entry point.

The security model is checked with two fixtures, ``data_alpha`` and
``data_beta``, which share identical structure, ordering, nulls and public
fields and differ *only* in the values of the sensitive fields.  A correct
restricted entry point must return deeply equal external results for both, so
that a restricted value can never be inferred from which rows appear, their
order, null handling or the surrounding structure.
"""
import copy
import unittest
from collections import OrderedDict

import jmespath
from jmespath import (
    VisibilityPolicy,
    compile_restricted,
    redact,
    restricted_search,
)
from jmespath import exceptions


RESTRICTED_FIELDS = (
    "employees.salary",
    "employees.ssn",
    "employees.dept.budget",
)

# Expressions whose value must be identical for both fixtures.  They exercise
# renaming, projection, merge, filtering and sorting on restricted fields, plus
# null/structure preservation.
EQUIVALENT_EXPRESSIONS = [
    # Rename + projection keeps the public part and nulls the restricted one.
    "employees[*].{who: name, pay: salary, team: dept.code}",
    "employees[*].{id: id, secret: ssn, money: dept.budget}",
    # A restricted field used in a filter must not affect membership.
    "employees[?salary > `100000`].name",
    "employees[?salary == `2000`].name",
    'employees[?ssn == `"111-AA"`].name',
    "employees[?!salary].name",
    "employees[?salary].name",
    # Ordering by a public key is unaffected and stays stable.
    "sort_by(employees, &id)[*].name",
    # Merging objects still carries redacted restricted values.
    "merge(employees[0], employees[1])",
    # Field names / cardinality are structure, not sensitive values.
    "keys(employees[0])",
    "length(employees[0])",
    "values(employees[0])",
    # Restricted leaves project away under normal JMESPath null semantics.
    "employees[*].ssn",
    "employees[*].dept.budget",
    # Nested object keeps public child, nulls the restricted child.
    "employees[0].dept",
    # type()/length() on a redacted field are constant.
    "type(employees[0].salary)",
    "employees[*].{n: name, s: salary} | length(@)",
]


def _employee(emp_id, name, code, salary, ssn, budget):
    return {
        "id": emp_id,
        "name": name,
        "salary": salary,
        "ssn": ssn,
        "dept": {"code": code, "budget": budget},
    }


def _payload(employees):
    return {"company": "acme", "employees": employees}


# Public fields, ordering and the genuine null on bob.ssn are identical; only
# the sensitive values (and even their types) differ between the fixtures.
data_alpha = _payload([
    _employee(1, "ada", "eng", 150000, "111-AA", 900),
    _employee(2, "bob", "sales", 40000, None, 100),
    _employee(3, "cy", "eng", 75000, "444-DD", 450),
])

data_beta = _payload([
    _employee(1, "ada", "eng", 2000, "222-BB", 7),
    _employee(2, "bob", "sales", 999999, "333-CC", 555),
    _employee(3, "cy", "eng", None, ["blocked"], "hidden"),
])


class VisibilityPolicyTests(unittest.TestCase):
    def test_accepts_single_string_and_iterable(self):
        single = VisibilityPolicy("employees.salary")
        multi = VisibilityPolicy(["employees.salary"])
        self.assertEqual(single.restricted_paths(),
                         multi.restricted_paths())
        self.assertEqual(single.restricted_paths(),
                         [("employees", "salary")])

    def test_rejects_empty_or_blank_path(self):
        for bad in ("", "   ", "employees..salary", ".employees",
                    "employees."):
            with self.assertRaises(ValueError):
                VisibilityPolicy(bad)

    def test_parent_path_denies_whole_subtree(self):
        policy = VisibilityPolicy(["employees.dept",
                                   "employees.dept.budget"])
        redacted = redact(data_alpha, policy)
        # Denying "dept" hides the entire object, including public "code".
        self.assertIsNone(redacted["employees"][0]["dept"])

    def test_redact_does_not_mutate_input(self):
        policy = VisibilityPolicy(RESTRICTED_FIELDS)
        snapshot = copy.deepcopy(data_alpha)
        redact(data_alpha, policy)
        self.assertEqual(data_alpha, snapshot)

    def test_redact_preserves_structure_order_and_nulls(self):
        policy = VisibilityPolicy(RESTRICTED_FIELDS)
        redacted = redact(data_alpha, policy)
        first = redacted["employees"][0]
        self.assertEqual(list(first.keys()),
                         ["id", "name", "salary", "ssn", "dept"])
        self.assertIsNone(first["salary"])
        self.assertIsNone(first["ssn"])
        self.assertIsNone(first["dept"]["budget"])
        # Public fields and genuine nulls survive unchanged.
        self.assertEqual(first["name"], "ada")
        self.assertEqual(first["dept"]["code"], "eng")
        self.assertIsNone(redacted["employees"][1]["ssn"])

    def test_redact_applies_implicitly_to_every_list_element(self):
        policy = VisibilityPolicy(RESTRICTED_FIELDS)
        redacted = redact(data_alpha, policy)
        self.assertTrue(
            all(row["salary"] is None for row in redacted["employees"]))

    def test_top_level_list_input(self):
        policy = VisibilityPolicy(["salary"])
        rows = data_alpha["employees"]
        redacted = redact(rows, policy)
        self.assertTrue(all(row["salary"] is None for row in redacted))
        self.assertEqual([row["name"] for row in redacted],
                         ["ada", "bob", "cy"])

    def test_redact_requires_policy_type(self):
        with self.assertRaises(TypeError):
            redact(data_alpha, ["employees.salary"])

    def test_dict_subclass_and_key_order_preserved(self):
        policy = VisibilityPolicy(["a.secret"])
        source = OrderedDict([
            ("a", OrderedDict([("secret", 1), ("ok", 2)]))])
        redacted = redact(source, policy)
        self.assertIsInstance(redacted, OrderedDict)
        self.assertIsInstance(redacted["a"], OrderedDict)
        self.assertEqual(list(redacted["a"].keys()), ["secret", "ok"])
        self.assertIsNone(redacted["a"]["secret"])
        self.assertEqual(redacted["a"]["ok"], 2)

    def test_scalars_and_empty_containers_are_passthrough(self):
        policy = VisibilityPolicy(["a.secret"])
        for scalar in ("text", 42, 3.14, True, None):
            self.assertIs(redact(scalar, policy), scalar)
        self.assertEqual(redact({}, policy), {})
        self.assertEqual(redact([], policy), [])

    def test_unknown_restricted_path_is_harmless(self):
        policy = VisibilityPolicy(["does.not.exist"])
        self.assertEqual(redact({"x": 1}, policy), {"x": 1})


class RestrictedEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = VisibilityPolicy(RESTRICTED_FIELDS)

    def test_fixtures_differ_only_in_sensitive_fields(self):
        # Guard against accidentally making the fixtures identical: prove the
        # sensitive inputs really do differ, including by type.
        self.assertNotEqual(data_alpha["employees"][0]["salary"],
                            data_beta["employees"][0]["salary"])
        self.assertNotEqual(
            type(data_alpha["employees"][2]["dept"]["budget"]),
            type(data_beta["employees"][2]["dept"]["budget"]))

    def test_redacted_inputs_are_deeply_equal(self):
        # The substitution collapses every sensitive difference away.
        self.assertEqual(redact(data_alpha, self.policy),
                         redact(data_beta, self.policy))

    def test_external_results_are_equivalent_across_fixtures(self):
        for expression in EQUIVALENT_EXPRESSIONS:
            alpha_result = restricted_search(
                expression, data_alpha, self.policy)
            beta_result = restricted_search(
                expression, data_beta, self.policy)
            self.assertEqual(
                alpha_result, beta_result,
                msg="sensitive value leaked through: %s" % expression)

    def test_restricted_field_filter_cannot_select_rows(self):
        # Real salaries straddle 100000 in different directions per fixture;
        # a redacted filter must return the same (empty) membership for both.
        expression = "employees[?salary > `100000`].id"
        self.assertEqual(
            restricted_search(expression, data_alpha, self.policy),
            restricted_search(expression, data_beta, self.policy))
        self.assertEqual(
            restricted_search(expression, data_alpha, self.policy), [])

    def test_sorting_on_restricted_key_fails_identically(self):
        # A null sort key is rejected by JMESPath the same way for both
        # fixtures, so ordering cannot encode a restricted value either.
        expression = "sort_by(employees, &salary)[*].name"
        for data in (data_alpha, data_beta):
            with self.assertRaises(exceptions.JMESPathTypeError):
                restricted_search(expression, data, self.policy)

    def test_compiled_expression_is_reusable_and_equivalent(self):
        compiled = compile_restricted(
            "employees[*].{who: name, pay: salary}", self.policy)
        self.assertEqual(compiled.search(data_alpha),
                         compiled.search(data_beta))

    def test_compile_requires_policy_type(self):
        with self.assertRaises(TypeError):
            compile_restricted("employees", VisibilityPolicy)


class PublicBehaviorParityTests(unittest.TestCase):
    def setUp(self):
        self.policy = VisibilityPolicy(RESTRICTED_FIELDS)

    PUBLIC_EXPRESSIONS = [
        "company",
        "employees[*].name",
        "employees[*].{who: name, team: dept.code}",
        "sort_by(employees, &id)[*].id",
        'employees[?dept.code == `"eng"`].name',
        "length(employees)",
        "employees[0].id",
    ]

    def test_public_only_expressions_match_stock_search(self):
        for expression in self.PUBLIC_EXPRESSIONS:
            self.assertEqual(
                restricted_search(expression, data_alpha, self.policy),
                jmespath.search(expression, data_alpha),
                msg="public expression changed behavior: %s" % expression)

    def test_empty_policy_is_equivalent_to_stock_search(self):
        permissive = VisibilityPolicy()
        for expression in self.PUBLIC_EXPRESSIONS:
            self.assertEqual(
                restricted_search(expression, data_alpha, permissive),
                jmespath.search(expression, data_alpha))

    def test_jmespath_options_are_passed_through(self):
        options = jmespath.Options(dict_cls=OrderedDict)
        result = restricted_search(
            "employees[0].{who: name, pay: salary}",
            data_alpha, self.policy, options=options)
        self.assertIsInstance(result, OrderedDict)
        self.assertEqual(result, OrderedDict([("who", "ada"),
                                              ("pay", None)]))
