"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
"""Offline acceptance for the "real new access" release gate.

Run from the repository root:

    python -m cfn_policy_validator.tests.policy_analysis_tests.acceptance

It parses real templates through the real parser and policy analysis, replacing
only the AWS client boundary with one semantic analyzer double. Every scenario
prints the full template path of the evidence it used.

Exit code is 0 only when every scenario matches its expected outcome.
"""
import json
import os
import sys

from cfn_policy_validator.tests.policy_analysis_tests.release_gate import (
    finding_evidence,
    run_release_gate,
)
from cfn_policy_validator.tests.policy_analysis_tests.semantic_access_analyzer import SemanticAccessAnalyzer


THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
FIXTURES = os.path.join(THIS_DIRECTORY, 'fixtures')


SCENARIOS = [
    ('legacy approved template', 'legacy_approved_template.yaml', 'approved_reference_policy.json', 0),
    ('equivalent reorder', 'reordered_equivalent_template.yaml', 'approved_reference_policy.json', 0),
    ('redirected to another resource', 'redirected_resource_template.yaml', 'approved_reference_policy.json', 1),
]


def run():
    failures = []
    for name, template, reference, expected_blocking in SCENARIOS:
        analyzer = SemanticAccessAnalyzer()
        result = run_release_gate(
            os.path.join(FIXTURES, template),
            os.path.join(FIXTURES, reference),
            analyzer,
        )
        report = result['report']
        blocking = len(report.blocking_findings)

        print(f'[{"PASS" if blocking == expected_blocking else "FAIL"}] {name}: blocking findings={blocking} expected={expected_blocking}')

        for evidence in finding_evidence(report, result['evaluatedDocuments'], result['policyDocumentsByOwner']):
            print(f'    evidence: {evidence["statementPath"]}')
            print(f'      action:   {", ".join(evidence["actions"])}')
            print(f'      resource: {", ".join(evidence["resources"])}')
            print(f'      resourceName={evidence["resourceName"]} policyName={evidence["policyName"]}')

        if blocking != expected_blocking:
            failures.append(name)

    return failures


def main():
    failures = run()
    if failures:
        print(f'FAILED: {", ".join(failures)}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
