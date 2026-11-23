"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import json

from cfn_policy_validator.tests.boto_mocks import BotoResponse, BotoClientError


# A single customer managed policy ARN that holds both an old (v1) and a reviewed new (v2)
# version.  The two phases of the migration differ only in which version is the default.
POLICY_ARN = 'arn:aws:iam::111222333444:policy/BatchDataAccess'
POLICY_NAME = 'BatchDataAccess'
OLD_VERSION = 'v1'
NEW_VERSION = 'v2'

old_policy_document = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': ['s3:GetObject', 's3:PutObject'],
			'Resource': 'arn:aws:s3:::legacy-bucket/*'
		}
	]
}

new_policy_document = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': ['s3:GetObject'],
			'Resource': 'arn:aws:s3:::approved-bucket/*'
		}
	]
}

assume_role_policy_doc = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Principal': {'Service': 'batch.amazonaws.com'},
			'Action': 'sts:AssumeRole'
		}
	]
}


def get_policy_response(version_id, policy_arn=POLICY_ARN, policy_name=POLICY_NAME, path='/'):
	return BotoResponse(
		method='get_policy',
		service_response={
			'Policy': {
				'PolicyName': policy_name,
				'DefaultVersionId': version_id,
				'Path': path
			}
		},
		expected_params={'PolicyArn': policy_arn}
	)


def get_policy_version_response(version_id, document, policy_arn=POLICY_ARN):
	return BotoResponse(
		method='get_policy_version',
		service_response={
			'PolicyVersion': {
				'Document': json.dumps(copy.deepcopy(document)),
				'VersionId': version_id,
				'IsDefaultVersion': version_id == NEW_VERSION
			}
		},
		expected_params={'PolicyArn': policy_arn, 'VersionId': version_id}
	)


def default_version_read_error(version_id, policy_arn=POLICY_ARN):
	return BotoClientError(
		method='get_policy_version',
		service_error_code='NoSuchEntity',
		expected_params={'PolicyArn': policy_arn, 'VersionId': version_id}
	)


def build_approval_report(policy_arn=POLICY_ARN, approved_version_id=NEW_VERSION):
	"""
	The reviewed approval evidence: the new version (v2) of the policy ARN is the only one approved.
	"""
	return {
		'ManagedPolicies': [
			{
				'Arn': policy_arn,
				'ApprovedVersionId': approved_version_id
			}
		]
	}


def build_role_template(policy_arn=POLICY_ARN, role_name='BatchRole'):
	return {
		'Resources': {
			role_name: {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'RoleName': role_name,
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'ManagedPolicyArns': [policy_arn]
				}
			}
		}
	}


# Phase 1: the policy still defaults to the old version. get_policy returns v1 and reading the v1
# document succeeds, so the old policy is usable and can still be reviewed.
phase_one_mocks = [
	get_policy_response(OLD_VERSION),
	get_policy_version_response(OLD_VERSION, old_policy_document)
]

# Phase 2: the reviewed new version is now the default. get_policy returns v2 and reading v2
# succeeds, so the role can be confirmed against the approval report.
phase_two_mocks = [
	get_policy_response(NEW_VERSION),
	get_policy_version_response(NEW_VERSION, new_policy_document)
]

# Failure path: get_policy advertises a default version whose document cannot be read.
default_version_read_error_mocks = [
	get_policy_response(NEW_VERSION),
	default_version_read_error(NEW_VERSION)
]
