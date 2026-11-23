"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import unittest

from cfn_policy_validator.tests.policy_analysis_tests.release_gate import (
    finding_evidence,
    run_release_gate,
)
from cfn_policy_validator.tests.policy_analysis_tests.semantic_access_analyzer import (
    SemanticAccessAnalyzer,
    allow_grants,
)


this_files_directory = os.path.dirname(os.path.realpath(__file__))
fixtures_directory = os.path.join(this_files_directory, 'fixtures')

LEGACY_TEMPLATE = os.path.join(fixtures_directory, 'legacy_approved_template.yaml')
REORDERED_TEMPLATE = os.path.join(fixtures_directory, 'reordered_equivalent_template.yaml')
REDIRECTED_TEMPLATE = os.path.join(fixtures_directory, 'redirected_resource_template.yaml')
REFERENCE_POLICY = os.path.join(fixtures_directory, 'approved_reference_policy.json')


def grants_as_set(policy):
    return {(grant.action, grant.resource, grant.condition) for grant in allow_grants(policy)}


class WhenComparingPolicySemantics(unittest.TestCase):
    def test_statement_and_action_order_does_not_change_the_grant_set(self):
        first = {
            'Version': '2012-10-17',
            'Statement': [
                {'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:PutObject'], 'Resource': ['arn:aws:s3:::b/*']},
                {'Effect': 'Allow', 'Action': 'sns:Publish', 'Resource': 'arn:aws:sns:us-east-2:111222333444:t'},
            ],
        }
        second = {
            'Version': '2012-10-17',
            'Statement': [
                {'Resource': 'arn:aws:sns:us-east-2:111222333444:t', 'Action': 'sns:Publish', 'Effect': 'Allow'},
                {'Resource': ['arn:aws:s3:::b/*'], 'Action': ['s3:PutObject', 's3:GetObject'], 'Effect': 'Allow'},
            ],
        }

        self.assertEqual(grants_as_set(first), grants_as_set(second))

    def test_same_action_name_on_a_different_resource_is_a_new_grant(self):
        reference = {
            'Statement': [{'Effect': 'Allow', 'Action': 's3:PutObject', 'Resource': 'arn:aws:s3:::prod-app-data/write/*'}]
        }
        new = {
            'Statement': [{'Effect': 'Allow', 'Action': 's3:PutObject', 'Resource': 'arn:aws:s3:::prod-audit-data/write/*'}]
        }

        analyzer = SemanticAccessAnalyzer()
        response = analyzer.check_no_new_access(
            policyType='IDENTITY_POLICY',
            existingPolicyDocument=reference,
            newPolicyDocument=new,
        )

        self.assertEqual('FAIL', response['result'])
        self.assertEqual('arn:aws:s3:::prod-audit-data/write/*', response['reasons'][0]['resources'][0])

    def test_action_wildcard_in_reference_covers_specific_action(self):
        reference = {
            'Statement': [{'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': 'arn:aws:s3:::prod-app-data/*'}]
        }
        new = {
            'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::prod-app-data/read/*'}]
        }

        analyzer = SemanticAccessAnalyzer()
        response = analyzer.check_no_new_access(
            policyType='IDENTITY_POLICY',
            existingPolicyDocument=reference,
            newPolicyDocument=new,
        )

        self.assertEqual('PASS', response['result'])

    def test_deny_statements_do_not_add_grants(self):
        policy = {
            'Statement': [
                {'Effect': 'Deny', 'Action': '*', 'Resource': '*'},
                {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::b/*'},
            ]
        }

        self.assertEqual(
            {('s3:GetObject', 'arn:aws:s3:::b/*', ())},
            grants_as_set(policy),
        )


class WhenRunningTheReleaseGate(unittest.TestCase):
    def run_gate(self, template_path):
        analyzer = SemanticAccessAnalyzer()
        result = run_release_gate(template_path, REFERENCE_POLICY, analyzer)
        return analyzer, result

    def test_legacy_template_is_accepted(self):
        analyzer, result = self.run_gate(LEGACY_TEMPLATE)

        self.assertEqual(0, len(result['report'].blocking_findings))
        self.assertEqual(['PASS'], [call['result'] for call in analyzer.calls])

    def test_reordered_template_is_accepted(self):
        analyzer, result = self.run_gate(REORDERED_TEMPLATE)

        self.assertEqual(0, len(result['report'].blocking_findings))
        self.assertEqual(['PASS'], [call['result'] for call in analyzer.calls])

    def test_reordered_template_has_the_same_semantics_as_the_legacy_template(self):
        _, legacy = self.run_gate(LEGACY_TEMPLATE)
        _, reordered = self.run_gate(REORDERED_TEMPLATE)

        legacy_policy = next(
            document['policy'] for document in legacy['evaluatedDocuments']
            if document['templatePath'] == 'Resources.WorkerRole.Properties.Policies[0].PolicyDocument'
        )
        reordered_policy = next(
            document['policy'] for document in reordered['evaluatedDocuments']
            if document['templatePath'] == 'Resources.WorkerRole.Properties.Policies[0].PolicyDocument'
        )

        self.assertEqual(grants_as_set(legacy_policy), grants_as_set(reordered_policy))

    def test_redirecting_the_conditional_write_is_blocked_with_full_path_evidence(self):
        analyzer, result = self.run_gate(REDIRECTED_TEMPLATE)
        report = result['report']

        self.assertEqual(1, len(report.blocking_findings))
        self.assertEqual(['FAIL'], [call['result'] for call in analyzer.calls])

        finding = report.blocking_findings[0]
        self.assertEqual('WorkerRole', finding.resourceName)
        self.assertEqual('DataAccess', finding.policyName)

        evidence = finding_evidence(report, result['evaluatedDocuments'], result['policyDocumentsByOwner'])
        self.assertTrue(evidence, 'Expected evidence pointing at the changed statement.')

        changed = {
            (item['statementPath'], item['actions'][0], item['resources'][0])
            for item in evidence
        }
        self.assertIn(
            (
                'Resources.WorkerRole.Properties.Policies[0].PolicyDocument.Statement[2]',
                's3:PutObject',
                'arn:aws:s3:::prod-audit-data/write/*',
            ),
            changed,
        )
        self.assertIn(
            (
                'Resources.WorkerRole.Properties.Policies[0].PolicyDocument.Statement[2]',
                's3:PutObjectAcl',
                'arn:aws:s3:::prod-audit-data/write/*',
            ),
            changed,
        )

    def test_release_gate_only_builds_the_clients_the_parser_and_analyzer_need(self):
        analyzer, result = self.run_gate(LEGACY_TEMPLATE)

        services = [service for service, _ in result['awsClients'].calls]
        self.assertIn('accessanalyzer', services)
        self.assertEqual(1, len(analyzer.calls))
        self.assertNotIn('boto3', services)


class WhenTheReleaseGateMustNotBeFooled(unittest.TestCase):
    """Negative controls for the two ways this check could silently pass."""

    def run_gate(self, template_path):
        analyzer = SemanticAccessAnalyzer()
        result = run_release_gate(template_path, REFERENCE_POLICY, analyzer)
        return analyzer, result

    def test_the_redirect_change_is_not_just_an_action_name_check(self):
        _, result = self.run_gate(REDIRECTED_TEMPLATE)
        policies = {
            document['templatePath']: document['policy']
            for document in result['evaluatedDocuments']
        }

        approved_grants = {
            (grant.action, grant.resource)
            for grant in allow_grants(json.load(open(REFERENCE_POLICY)))
        }
        redirected_grants = {
            (grant.action, grant.resource)
            for grant in allow_grants(
                policies['Resources.WorkerRole.Properties.Policies[0].PolicyDocument']
            )
        }

        # The two write actions are unchanged by name, but their concrete target moved
        # from the approved bucket to the audit bucket. An action-name-only check
        # would see s3:PutObject and s3:PutObjectAcl in both and wrongly pass.
        self.assertEqual(
            {('s3:PutObject', 'arn:aws:s3:::prod-app-data/write/*'),
             ('s3:PutObjectAcl', 'arn:aws:s3:::prod-app-data/write/*')},
            approved_grants - redirected_grants,
        )
        self.assertEqual(
            {('s3:PutObject', 'arn:aws:s3:::prod-audit-data/write/*'),
             ('s3:PutObjectAcl', 'arn:aws:s3:::prod-audit-data/write/*')},
            redirected_grants - approved_grants,
        )

        # Both versions keep the same action names; only the targets differ.
        self.assertTrue(
            {'s3:PutObject', 's3:PutObjectAcl'}.issubset(
                {action for action, _ in approved_grants} &
                {action for action, _ in redirected_grants}
            )
        )

    def test_dropping_a_condition_that_restricts_access_is_a_new_grant(self):
        reference = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::prod-app-data/read/*',
                'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-12345'}},
            }]
        }
        new = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::prod-app-data/read/*',
            }]
        }

        analyzer = SemanticAccessAnalyzer()
        response = analyzer.check_no_new_access(
            policyType='IDENTITY_POLICY',
            existingPolicyDocument=reference,
            newPolicyDocument=new,
        )

        self.assertEqual('FAIL', response['result'])

    def test_adding_a_condition_does_not_widen_access(self):
        reference = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::prod-app-data/read/*',
            }]
        }
        new = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::prod-app-data/read/*',
                'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-12345'}},
            }]
        }

        analyzer = SemanticAccessAnalyzer()
        response = analyzer.check_no_new_access(
            policyType='IDENTITY_POLICY',
            existingPolicyDocument=reference,
            newPolicyDocument=new,
        )

        self.assertEqual('PASS', response['result'])


class WhenParsingTheReleaseGateFixtures(unittest.TestCase):
    """Prove the fixtures exercise Ref, conditions and generated ARNs."""

    def evaluated_policy(self, template_path):
        result = run_release_gate(template_path, REFERENCE_POLICY, SemanticAccessAnalyzer())
        return next(
            document['policy'] for document in result['evaluatedDocuments']
            if document['templatePath'] == 'Resources.WorkerRole.Properties.Policies[0].PolicyDocument'
        )

    def test_ref_to_an_sns_topic_is_resolved_to_a_generated_arn(self):
        policy = self.evaluated_policy(LEGACY_TEMPLATE)
        publish = next(statement for statement in policy['Statement'] if statement['Sid'] == 'PublishNotifications')

        self.assertEqual(
            'arn:aws:sns:us-east-2:111222333444:Notifications',
            publish['Resource'],
        )

    def test_getatt_and_sub_are_resolved_to_bucket_arns(self):
        policy = self.evaluated_policy(LEGACY_TEMPLATE)
        read = next(statement for statement in policy['Statement'] if statement['Sid'] == 'ReadData')

        self.assertEqual(
            [
                'arn:aws:s3:::prod-app-data/read/*',
                'arn:aws:s3:::prod-app-data/cache/*',
            ],
            read['Resource'],
        )

    def test_the_condition_selects_the_production_branch(self):
        policy = self.evaluated_policy(LEGACY_TEMPLATE)
        write = next(statement for statement in policy['Statement'] if statement['Sid'] == 'ConditionalWrite')

        self.assertEqual('arn:aws:s3:::prod-app-data/write/*', write['Resource'])

    def test_the_redirected_fixture_differs_only_in_the_conditional_target(self):
        legacy = self.evaluated_policy(LEGACY_TEMPLATE)
        redirected = self.evaluated_policy(REDIRECTED_TEMPLATE)

        legacy_statements = {statement['Sid']: statement for statement in legacy['Statement']}
        redirected_statements = {statement['Sid']: statement for statement in redirected['Statement']}

        self.assertEqual(
            'arn:aws:s3:::prod-app-data/write/*',
            legacy_statements['ConditionalWrite']['Resource'],
        )
        self.assertEqual(
            'arn:aws:s3:::prod-audit-data/write/*',
            redirected_statements['ConditionalWrite']['Resource'],
        )
        for sid in ('ReadData', 'PublishNotifications'):
            self.assertEqual(legacy_statements[sid], redirected_statements[sid])
