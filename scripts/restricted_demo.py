#!/usr/bin/env python
"""Local demonstration of the restricted JMESPath entry point.

It builds two fake documents that differ ONLY in their sensitive fields
(salary / ssn / dept.budget), then runs the same business-authored JMESPath
views through ``jmespath.restricted_search`` and prints them side by side.

Run from the repository root:

    .venv/bin/python scripts/restricted_demo.py
"""
import json

import jmespath
from jmespath import VisibilityPolicy, restricted_search


RESTRICTED = VisibilityPolicy([
    "employees.salary",
    "employees.ssn",
    "employees.dept.budget",
])

# Public fields, ordering and the genuine null (bob.ssn) are identical.
# Only the sensitive values, and sometimes their types, differ.
alpha = {
    "company": "acme",
    "employees": [
        {"id": 1, "name": "ada", "salary": 150000, "ssn": "111-AA",
         "dept": {"code": "eng", "budget": 900}},
        {"id": 2, "name": "bob", "salary": 40000, "ssn": None,
         "dept": {"code": "sales", "budget": 100}},
        {"id": 3, "name": "cy", "salary": 75000, "ssn": "444-DD",
         "dept": {"code": "eng", "budget": 450}},
    ],
}

beta = {
    "company": "acme",
    "employees": [
        {"id": 1, "name": "ada", "salary": 2000, "ssn": "222-BB",
         "dept": {"code": "eng", "budget": 7}},
        {"id": 2, "name": "bob", "salary": 999999, "ssn": "333-CC",
         "dept": {"code": "sales", "budget": 555}},
        {"id": 3, "name": "cy", "salary": None, "ssn": ["blocked"],
         "dept": {"code": "eng", "budget": "hidden"}},
    ],
}

# Each view is a normal JMESPath expression a reporting user might write.
VIEWS = [
    ("rename + project",
     "employees[*].{who: name, pay: salary, team: dept.code}"),
    ("filter on restricted field",
     "employees[?salary > `100000`].name"),
    ("negated filter on restricted field",
     "employees[?!salary].name"),
    ("public sort order preserved",
     "sort_by(employees, &id)[*].{who: name, pay: salary}"),
    ("merge keeps public + redacted parts",
     "merge(employees[0], employees[1])"),
    ("nested structure and real null",
     "employees[*].{who: name, s: ssn, b: dept.budget, code: dept.code}"),
    ("structure only (keys/length)",
     "{keys: keys(employees[0]), size: length(employees[0])}"),
]


def _dumps(value):
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


def main():
    all_equivalent = True
    for title, expression in VIEWS:
        out_alpha = restricted_search(expression, alpha, RESTRICTED)
        out_beta = restricted_search(expression, beta, RESTRICTED)
        equivalent = out_alpha == out_beta
        all_equivalent = all_equivalent and equivalent
        print("=" * 72)
        print("%s\n  expression: %s" % (title, expression))
        print("  alpha (sensitive set A): %s" % _dumps(out_alpha))
        print("  beta  (sensitive set B): %s" % _dumps(out_beta))
        print("  externally equivalent: %s"
              % ("YES" if equivalent else "NO <<< LEAK"))

    print("=" * 72)
    # Fully public expression must match the stock, unrestricted entry point.
    public_expr = "employees[*].{who: name, team: dept.code}"
    parity = (
        restricted_search(public_expr, alpha, RESTRICTED)
        == jmespath.search(public_expr, alpha)
    )
    print("public-only view matches stock jmespath.search: %s"
          % ("YES" if parity else "NO"))
    print("ALL VIEWS EQUIVALENT ACROSS SENSITIVE FIXTURES: %s"
          % ("YES" if all_equivalent and parity else "NO"))


if __name__ == "__main__":
    main()
