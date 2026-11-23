"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cfn_policy_validator import main as main_module
from cfn_policy_validator.tests.utils import captured_output, ignore_warnings

TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Access:
    Type: String
Conditions:
  IsPublic:
    Fn::Equals:
      - !Ref Access
      - public
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: data-bucket
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
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


class WhenRunningAnalyzeConditionsFromCLI(unittest.TestCase):
	def setUp(self):
		ignore_warnings()
		self.temp = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
		self.temp.write(TEMPLATE)
		self.temp.close()

	def tearDown(self):
		os.unlink(self.temp.name)

	def test_runs_offline_and_prints_three_scenario_report(self):
		args = [
			'analyze-conditions',
			'--template-path', self.temp.name,
			'--region', 'us-east-2'
		]

		with patch('cfn_policy_validator.main.validate_credentials') as validate_credentials, \
				captured_output() as (out, _):
			try:
				main_module.main(args)
			except SystemExit as exit_error:
				self.assertEqual(0, exit_error.code)

		# the offline command must never validate live credentials
		validate_credentials.assert_not_called()

		report = json.loads(out.getvalue())
		self.assertEqual(['Access'], report['UnknownParameters'])
		self.assertEqual(['IsPublic'], report['UndecidableConditions'])
		self.assertEqual(1, report['StatusSummary']['CONDITIONAL'])

		bucket_policy = next(
			policy for policy in report['Policies']
			if policy['Key'] == 'RESOURCE_POLICY::BucketPolicy::BucketPolicy'
		)
		self.assertIn('unresolved', bucket_policy['Scenarios'])
		self.assertIn('if_true', bucket_policy['Scenarios'])
		self.assertIn('if_false', bucket_policy['Scenarios'])


if __name__ == '__main__':
	unittest.main()
