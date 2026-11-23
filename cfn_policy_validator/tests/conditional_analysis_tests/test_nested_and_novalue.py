"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.conditional_analysis.analyzer import analyze_conditions
from cfn_policy_validator.conditional_analysis.unknown_value import UnknownValue, collect_unknown_parameters, \
	contains_unknown

REGION = 'us-east-2'
ACCOUNT_ID = '111222333444'
PARTITION = 'aws'

NESTED_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ExternalAccount:
    Type: String
  FeatureEnabled:
    Type: String
Conditions:
  HasExternalAccount:
    Fn::Not:
      - Fn::Equals:
          - !Ref ExternalAccount
          - ""
  FeatureOn:
    Fn::Equals:
      - !Ref FeatureEnabled
      - "true"
  Both:
    Fn::And:
      - Condition: HasExternalAccount
      - Condition: FeatureOn
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue
  QueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref Queue
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Fn::If:
              - Both
              - Sid: conditionalGrant
                Effect: Allow
                Principal:
                  AWS: !Sub "arn:aws:iam::${ExternalAccount}:root"
                Action: sqs:SendMessage
                Resource: "*"
              - !Ref AWS::NoValue
"""


class WhenConditionsAreNested(unittest.TestCase):
	def setUp(self):
		self.report = analyze_conditions(NESTED_TEMPLATE, REGION, ACCOUNT_ID, PARTITION, {})

	def test_all_related_conditions_are_undecidable(self):
		self.assertEqual(
			sorted(['Both', 'FeatureOn', 'HasExternalAccount']),
			sorted(self.report['UndecidableConditions'])
		)

	def test_novalue_branch_grants_nothing(self):
		policy = self.report['Policies'][0]
		self.assertEqual('CONDITIONAL', policy['Status'])
		self.assertEqual(['Both'], policy['AffectingConditions'])
		self.assertTrue(policy['Scenarios']['if_true']['present'])
		self.assertFalse(policy['Scenarios']['if_false']['present'])

	def test_sub_embedded_unknown_parameter_is_tracked(self):
		policy = self.report['Policies'][0]
		self.assertEqual(
			['ExternalAccount'],
			policy['Scenarios']['if_true']['unresolvedParameters']
		)
		self.assertTrue(policy['Scenarios']['if_true']['hasUnresolvedValue'])


class WhenUnknownValueIsEmbeddedInString(unittest.TestCase):
	def test_detects_placeholder_inside_larger_string(self):
		document = {
			'Statement': [{
				'Resource': 'arn:aws:s3:::bucket/${UnknownParameter}:Prefix/*'
			}]
		}
		self.assertTrue(contains_unknown(document))
		self.assertEqual(['Prefix'], collect_unknown_parameters(document))

	def test_direct_marker_is_still_recognised(self):
		marker = UnknownValue('DirectParam')
		self.assertIsInstance(marker, str)
		self.assertTrue(contains_unknown({'Principal': marker}))
		self.assertEqual(['DirectParam'], collect_unknown_parameters(marker))


if __name__ == '__main__':
	unittest.main()
