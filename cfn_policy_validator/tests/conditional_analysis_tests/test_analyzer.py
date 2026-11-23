"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

import cfn_policy_validator
from cfn_policy_validator.conditional_analysis.analyzer import analyze_conditions
from cfn_policy_validator.conditional_analysis.report import STATUS_CONDITIONAL, STATUS_KNOWN

REGION = 'us-east-2'
ACCOUNT_ID = '111222333444'
PARTITION = 'aws'


def template_with_conditional_bucket_policy():
	return """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketAccess:
    Type: String
    Default: restricted
  RoleNameParam:
    Type: String
Conditions:
  IsPublic:
    Fn::Equals:
      - !Ref BucketAccess
      - public
Resources:
  FixedRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleNameParam
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: bounded
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: s3:GetObject
                Resource: arn:aws:s3:::data/*
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: data-bucket
  DataBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref DataBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Fn::If:
              - IsPublic
              - Effect: Allow
                Principal: "*"
                Action: s3:GetObject
                Resource: arn:aws:s3:::data-bucket/*
              - Effect: Allow
                Principal:
                  AWS: arn:aws:iam::111222333444:root
                Action: s3:GetObject
                Resource: arn:aws:s3:::data-bucket/*
"""


def policies_by_key(report):
	return {policy['Key']: policy for policy in report['Policies']}


class WhenAParameterIsUnresolved(unittest.TestCase):
	def setUp(self):
		# RoleNameParam is supplied; BucketAccess is deliberately left unresolved
		self.report = analyze_conditions(
			template_with_conditional_bucket_policy(),
			REGION, ACCOUNT_ID, PARTITION,
			{'RoleNameParam': 'my-role'}
		)

	def test_reports_unknown_parameter_without_defaulting_it(self):
		self.assertEqual(['BucketAccess'], self.report['UnknownParameters'])
		self.assertEqual(['IsPublic'], self.report['UndecidableConditions'])

	def test_only_the_affected_resource_policy_is_conditional(self):
		by_key = policies_by_key(self.report)
		bucket_policy = by_key['RESOURCE_POLICY::DataBucketPolicy::BucketPolicy']
		self.assertEqual(STATUS_CONDITIONAL, bucket_policy['Status'])
		self.assertEqual(['IsPublic'], bucket_policy['AffectingConditions'])

	def test_unrelated_role_keeps_deterministic_result(self):
		by_key = policies_by_key(self.report)
		role_policy = by_key['ROLE_POLICY::my-role::bounded']
		trust_policy = by_key['ROLE_TRUST::my-role::TrustPolicy']
		self.assertEqual(STATUS_KNOWN, role_policy['Status'])
		self.assertEqual(STATUS_KNOWN, trust_policy['Status'])
		self.assertEqual([], role_policy['AffectingConditions'])

	def test_three_scenarios_are_present_and_comparable(self):
		bucket_policy = policies_by_key(self.report)['RESOURCE_POLICY::DataBucketPolicy::BucketPolicy']
		scenarios = bucket_policy['Scenarios']
		self.assertTrue(scenarios['unresolved']['present'])
		self.assertTrue(scenarios['if_true']['present'])
		self.assertTrue(scenarios['if_false']['present'])

		true_codes = [f['code'] for f in scenarios['if_true']['findings']]
		false_codes = [f['code'] for f in scenarios['if_false']['findings']]
		self.assertIn('PUBLIC_PRINCIPAL', true_codes)
		self.assertNotIn('PUBLIC_PRINCIPAL', false_codes)

	def test_summary_counts_match(self):
		self.assertEqual(1, self.report['StatusSummary'][STATUS_CONDITIONAL])
		self.assertEqual(2, self.report['StatusSummary'][STATUS_KNOWN])


class WhenAllParametersAreResolved(unittest.TestCase):
	def test_public_value_returns_single_deterministic_conclusion(self):
		report = analyze_conditions(
			template_with_conditional_bucket_policy(),
			REGION, ACCOUNT_ID, PARTITION,
			{'RoleNameParam': 'my-role', 'BucketAccess': 'public'}
		)

		self.assertEqual([], report['UnknownParameters'])
		self.assertEqual([], report['UndecidableConditions'])
		self.assertEqual(0, report['StatusSummary'][STATUS_CONDITIONAL])

		bucket_policy = policies_by_key(report)['RESOURCE_POLICY::DataBucketPolicy::BucketPolicy']
		self.assertEqual(STATUS_KNOWN, bucket_policy['Status'])
		codes = [f['code'] for f in bucket_policy['Scenarios']['if_true']['findings']]
		self.assertIn('PUBLIC_PRINCIPAL', codes)

	def test_restricted_value_returns_clean_deterministic_conclusion(self):
		report = analyze_conditions(
			template_with_conditional_bucket_policy(),
			REGION, ACCOUNT_ID, PARTITION,
			{'RoleNameParam': 'my-role', 'BucketAccess': 'restricted'}
		)

		bucket_policy = policies_by_key(report)['RESOURCE_POLICY::DataBucketPolicy::BucketPolicy']
		self.assertEqual(STATUS_KNOWN, bucket_policy['Status'])
		for scenario in bucket_policy['Scenarios'].values():
			self.assertEqual([], scenario['findings'])


class WhenUsingTheLibraryEntryPoint(unittest.TestCase):
	def test_package_level_function_matches_analyzer(self):
		report = cfn_policy_validator.analyze_conditions(
			template_with_conditional_bucket_policy(),
			REGION, ACCOUNT_ID, PARTITION,
			{'RoleNameParam': 'my-role'}
		)
		self.assertIn('StatusSummary', report)
		self.assertIn('Policies', report)


if __name__ == '__main__':
	unittest.main()
