"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""


class ManagedPolicyState:
	"""
	The state of a single managed policy version that a role actually resolves to.

	The same managed policy ARN can hold multiple versions, so the ARN alone cannot identify
	which policy document a role is using.  The version id is therefore tracked alongside the
	ARN and each (ARN, version) pair is judged independently.
	"""

	def __init__(self, arn, version_id, name=None, document=None, read_error=None):
		self.arn = arn
		self.version_id = version_id
		self.name = name
		self.document = document
		# read_error is set when the default version of the policy cannot be read (for example
		# get_policy_version fails).  A policy in this state can never be treated as confirmed.
		self.read_error = read_error

	@property
	def could_not_read(self):
		return self.read_error is not None

	def __eq__(self, other):
		if not isinstance(other, ManagedPolicyState):
			return False

		return self.arn == other.arn and self.version_id == other.version_id

	def __hash__(self):
		return hash((self.arn, self.version_id))

	def custom_to_json(self):
		as_dict = {
			'arn': self.arn,
			'versionId': self.version_id
		}
		if self.name is not None:
			as_dict['name'] = self.name
		if self.read_error is not None:
			as_dict['readError'] = self.read_error
		return as_dict


class ApprovalBasis:
	"""
	The version of a managed policy ARN that has been reviewed and approved.

	Validation pins the approval to a specific version id so that a later change to the policy's
	default version cannot silently be treated as approved.
	"""

	def __init__(self, arn, approved_version_id):
		self.arn = arn
		self.approved_version_id = approved_version_id

	def __eq__(self, other):
		if not isinstance(other, ApprovalBasis):
			return False

		return self.arn == other.arn and self.approved_version_id == other.approved_version_id

	def __hash__(self):
		return hash((self.arn, self.approved_version_id))

	def custom_to_json(self):
		return {
			'arn': self.arn,
			'approvedVersionId': self.approved_version_id
		}


class PolicyEvaluation:
	"""
	The judgment for one managed policy (ARN + resolved version) attached to a role.
	"""

	# the role resolves the policy to the exact version that the approval report pins
	CONFIRMED = 'CONFIRMED'
	# the role still resolves an older version that the report does not approve; the old policy
	# document remains available for validation, but the migration is not finished
	ON_OLD_VERSION = 'ON_OLD_VERSION'
	# the role resolves a version that is neither the approved one nor a known prior version
	UNEXPECTED_VERSION = 'UNEXPECTED_VERSION'
	# the policy ARN has no entry in the approval report, so the deployment evidence is missing
	MISSING_APPROVAL = 'MISSING_APPROVAL'
	# the policy's default version could not be read from the environment
	READ_ERROR = 'READ_ERROR'

	_BLOCKING_STATUSES = (ON_OLD_VERSION, UNEXPECTED_VERSION, MISSING_APPROVAL, READ_ERROR)

	def __init__(self, role_name, arn, resolved_version_id, approved_version_id=None, status=None,
				 document=None, detail=None):
		self.role_name = role_name
		self.arn = arn
		self.resolved_version_id = resolved_version_id
		self.approved_version_id = approved_version_id
		self.status = status
		self.document = document
		self.detail = detail

	@property
	def is_confirmed(self):
		return self.status == self.CONFIRMED

	@property
	def is_blocking(self):
		return self.status in self._BLOCKING_STATUSES

	def custom_to_json(self):
		as_dict = {
			'roleName': self.role_name,
			'arn': self.arn,
			'resolvedVersionId': self.resolved_version_id,
			'status': self.status
		}
		if self.approved_version_id is not None:
			as_dict['approvedVersionId'] = self.approved_version_id
		if self.detail is not None:
			as_dict['detail'] = self.detail
		return as_dict


class RoleReleaseEvaluation:
	"""
	All of the per-policy judgments for a single role.
	"""

	def __init__(self, role_name, policy_evaluations=None):
		self.role_name = role_name
		self.policy_evaluations = [] if policy_evaluations is None else policy_evaluations

	def add(self, policy_evaluation):
		self.policy_evaluations.append(policy_evaluation)

	@property
	def is_confirmed(self):
		# a role with no external managed policies has nothing to migrate and is trivially confirmed
		if len(self.policy_evaluations) == 0:
			return True

		return all(evaluation.is_confirmed for evaluation in self.policy_evaluations)

	@property
	def blocking_evaluations(self):
		return [evaluation for evaluation in self.policy_evaluations if evaluation.is_blocking]

	@property
	def requires_confirmation(self):
		return len(self.blocking_evaluations) > 0

	def custom_to_json(self):
		return {
			'roleName': self.role_name,
			'confirmed': self.is_confirmed,
			'policies': [evaluation.custom_to_json() for evaluation in self.policy_evaluations]
		}
