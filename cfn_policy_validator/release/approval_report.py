"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.release.models import ApprovalBasis

LOGGER = logging.getLogger("cfn-policy-validator")


class ApprovalReport:
	"""
	The reviewed, version-pinned approval evidence for a managed policy migration.

	Each entry pins a managed policy ARN to the exact version id that was reviewed and approved.
	Roles whose managed policy resolves to a different version are not allowed to inherit the
	approval, even when they reference the same ARN.
	"""

	def __init__(self, bases=None):
		# keyed by ARN so that lookup is independent of how many roles reference the policy
		self._bases = {} if bases is None else {basis.arn: basis for basis in bases}

	@classmethod
	def from_dict(cls, report_as_dict):
		if not isinstance(report_as_dict, dict):
			raise ApplicationError('Approval report must be a JSON object containing a "ManagedPolicies" list.')

		entries = report_as_dict.get('ManagedPolicies')
		if entries is None:
			raise ApplicationError('Approval report is missing the required "ManagedPolicies" list.')

		if not isinstance(entries, list):
			raise ApplicationError('Approval report property "ManagedPolicies" must be a list.')

		bases = []
		for index, entry in enumerate(entries):
			if not isinstance(entry, dict):
				raise ApplicationError(
					f'Approval report entry at ManagedPolicies.{index} must be an object.')

			arn = entry.get('Arn')
			if arn is None:
				raise ApplicationError(
					f'Approval report entry at ManagedPolicies.{index} is missing required property "Arn".')

			approved_version_id = entry.get('ApprovedVersionId')
			if approved_version_id is None:
				raise ApplicationError(
					f'Approval report entry at ManagedPolicies.{index} is missing required property "ApprovedVersionId".')

			bases.append(ApprovalBasis(arn, approved_version_id))

		return cls(bases)

	@classmethod
	def load(cls, file_path):
		try:
			with open(file_path, 'r') as stream:
				contents = stream.read()
		except FileNotFoundError:
			raise ApplicationError(f'Approval report not found: {file_path}')

		try:
			report_as_dict = json.loads(contents)
		except json.JSONDecodeError:
			raise ApplicationError(f'Unable to parse approval report. Invalid JSON detected: {file_path}')

		return cls.from_dict(report_as_dict)

	def get_basis_for(self, arn):
		return self._bases.get(arn)

	def __contains__(self, arn):
		return arn in self._bases

	def __len__(self):
		return len(self._bases)
