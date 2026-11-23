"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import os
import unittest

from cfn_policy_validator.tests.policy_analysis_tests.release_gate import (
    run_release_gate,
    template_policy_documents,
)
from cfn_policy_validator.tests.policy_analysis_tests.semantic_access_analyzer import SemanticAccessAnalyzer


this_files_directory = os.path.dirname(os.path.realpath(__file__))
fixtures_directory = os.path.join(this_files_directory, 'fixtures')

HISTORICAL_TEMPLATE = os.path.join(fixtures_directory, 'historical_pipeline_template.json')
HISTORICAL_REFERENCE = os.path.join(fixtures_directory, 'historical_reference_policy.json')

PARAMETERS = {
    'EnvironmentName': 'prod',
    'CodestarConnectionArn': 'arn:aws:codestar-connections:us-east-2:111222333444:connection/abc',
}


class WhenRunningTheReleaseGateOnAHistoricalTemplate(unittest.TestCase):
    """The historical pipeline template is the approved baseline for the fixture.

    It exercises Ref (CodestarConnectionArn and SNS topic), Fn::GetAtt ARNs
    (SQS queue), Fn::Join, Fn::Sub, Mappings, managed policies from IAM, and
    resource policies. Its reference policy is the exact policy that template
    produced before this change, so it must keep passing.
    """

    def run_gate(self):
        analyzer = SemanticAccessAnalyzer()
        result = run_release_gate(
            HISTORICAL_TEMPLATE,
            HISTORICAL_REFERENCE,
            analyzer,
            parameters=PARAMETERS,
        )
        return analyzer, result

    def test_historical_template_still_passes_the_release_gate(self):
        analyzer, result = self.run_gate()

        self.assertEqual([], result['report'].blocking_findings)
        self.assertTrue(all(call['result'] == 'PASS' for call in analyzer.calls))

    def test_historical_template_policies_are_evaluated_before_comparison(self):
        _, result = self.run_gate()

        documents = {
            document['templatePath']: document['policy']
            for document in result['evaluatedDocuments']
        }

        # Fn::Sub resolving a Ref to a bucket name.
        bucket_policy = documents['Resources.ArtifactBucketPolicy.Properties.PolicyDocument']
        self.assertEqual(
            'arn:aws:s3:::prod-app-artifacts/*',
            bucket_policy['Statement'][0]['Resource'],
        )

        # Fn::GetAtt to a generated SQS ARN.
        queue_policy = documents['Resources.MyQueuePolicy.Properties.PolicyDocument']
        self.assertEqual(
            'arn:aws:sqs:us-east-2:111222333444:MyQueue',
            queue_policy['Statement'][0]['Resource'],
        )

    def test_historical_template_contains_the_expected_policy_paths(self):
        _, result = self.run_gate()

        paths = [document['templatePath'] for document in result['evaluatedDocuments']]
        self.assertIn('Resources.CodePipelineServiceRole.Properties.Policies[0].PolicyDocument', paths)
        self.assertIn('Resources.MyQueuePolicy.Properties.PolicyDocument', paths)
        self.assertIn('Resources.ArtifactBucketAccessPoint.Properties.Policy', paths)

    def test_historical_template_is_offline(self):
        analyzer, result = self.run_gate()

        services = {service for service, _ in result['awsClients'].calls}
        self.assertEqual({'accessanalyzer', 'iam', 'ssm', 'cloudformation'}, services)
        self.assertGreaterEqual(len(analyzer.calls), 1)
