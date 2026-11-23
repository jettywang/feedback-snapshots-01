"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging

from botocore.exceptions import ClientError

from cfn_policy_validator import client
from cfn_policy_validator.release.models import ManagedPolicyState

LOGGER = logging.getLogger("cfn-policy-validator")


class PolicyVersionResolver:
	"""
	Resolves the version of a managed policy ARN that a role actually uses.

	IAM managed policies are versioned: an ARN identifies the policy while DefaultVersionId
	identifies which document is in effect.  The same ARN therefore has to be resolved to a
	concrete version id before it can be compared against the approval report.
	"""

	def __init__(self, region, iam_client=None):
		self.region = region
		self._client = iam_client
		# cache resolved ARNs so multiple roles sharing a managed policy do not repeat calls
		self._cache = {}

	@property
	def client(self):
		if self._client is None:
			self._client = client.build('iam', self.region)
		return self._client

	def resolve_default_version(self, arn):
		"""
		Return the ManagedPolicyState for the policy's currently effective (default) version.
		"""
		if arn in self._cache:
			return self._cache[arn]

		state = self._read_default_version(arn)
		self._cache[arn] = state
		return state

	def _read_default_version(self, arn):
		try:
			policy_response = self.client.get_policy(PolicyArn=arn)
		except ClientError as error:
			if error.response['Error']['Code'] == 'NoSuchEntity':
				return self._build_read_error(arn, None,
											  f'Could not find managed policy with {arn} in template or in environment.')
			raise

		policy = policy_response['Policy']
		name = policy.get('PolicyName')
		default_version_id = policy['DefaultVersionId']

		try:
			version_response = self.client.get_policy_version(PolicyArn=arn, VersionId=default_version_id)
		except ClientError as error:
			if error.response['Error']['Code'] in ('NoSuchEntity', 'InvalidInput'):
				return self._build_read_error(
					arn, default_version_id,
					f'Could not read version {default_version_id} of managed policy {arn}.')
			raise

		document = version_response['PolicyVersion']['Document']
		document = self._normalize_document(document)

		LOGGER.info(f'Resolved managed policy {arn} to default version {default_version_id}')
		return ManagedPolicyState(arn=arn, version_id=default_version_id, name=name, document=document)

	@staticmethod
	def _build_read_error(arn, version_id, detail):
		LOGGER.info(detail)
		return ManagedPolicyState(arn=arn, version_id=version_id, read_error=detail)

	@staticmethod
	def _normalize_document(document):
		# IAM may return the policy document as a URL-encoded JSON string; the parser path also
		# stores decoded dictionaries, so decode a string into a dictionary for consistent comparison.
		if isinstance(document, str):
			try:
				return json.loads(document)
			except json.JSONDecodeError:
				return document
		return document
