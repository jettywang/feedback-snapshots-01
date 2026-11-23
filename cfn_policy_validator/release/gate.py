"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging

from cfn_policy_validator.release.models import PolicyEvaluation, RoleReleaseEvaluation

LOGGER = logging.getLogger("cfn-policy-validator")


class ReleaseGate:
	"""
	Decides whether a set of roles is ready to be published during a managed policy migration.

	A role is only confirmed when every managed policy it uses resolves to the exact version that
	the approval report pins for that ARN.  The judgment uses both:

	  * the role's actually resolved default version (what the role will use when it runs), and
	  * the approval basis recorded in the report (which version was reviewed).

	The same ARN with different versions is therefore judged independently, and a role that has not
	migrated keeps resolving its old policy version instead of being marked complete.
	"""

	def __init__(self, approval_report, resolver):
		self.approval_report = approval_report
		self.resolver = resolver

	def evaluate(self, roles):
		evaluations = []
		for role in roles:
			evaluations.append(self._evaluate_role(role))
		return ReleaseGateReport(evaluations)

	def _evaluate_role(self, role):
		role_evaluation = RoleReleaseEvaluation(role.RoleName)

		for policy in role.Policies:
			# policies defined inside the template (and inline policies) have no external ARN and
			# are not part of the managed policy migration
			if not getattr(policy, 'Arn', None):
				continue

			role_evaluation.add(self._evaluate_policy(role.RoleName, policy))

		return role_evaluation

	def _evaluate_policy(self, role_name, policy):
		arn = policy.Arn
		basis = self.approval_report.get_basis_for(arn)

		# prefer the version captured during parsing; fall back to resolving it directly so the
		# gate also works against roles built without the template parser
		resolved_version_id = getattr(policy, 'VersionId', None)
		document = policy.Policy
		read_error = getattr(policy, 'ReadError', None)
		if resolved_version_id is None:
			state = self.resolver.resolve_default_version(arn)
			resolved_version_id = state.version_id
			document = state.document
			read_error = state.read_error

		approved_version_id = basis.approved_version_id if basis is not None else None

		status, detail = self._classify(arn, resolved_version_id, approved_version_id, read_error)

		return PolicyEvaluation(
			role_name=role_name,
			arn=arn,
			resolved_version_id=resolved_version_id,
			approved_version_id=approved_version_id,
			status=status,
			document=self._normalise_document(document),
			detail=detail
		)

	@staticmethod
	def _classify(arn, resolved_version_id, approved_version_id, read_error):
		if read_error is not None:
			return PolicyEvaluation.READ_ERROR, read_error

		if approved_version_id is None:
			return (PolicyEvaluation.MISSING_APPROVAL,
					f'Managed policy {arn} has no approved version in the approval report. Confirm its deployment evidence.')

		if resolved_version_id == approved_version_id:
			return PolicyEvaluation.CONFIRMED, None

		# the role resolves a version of the same ARN that the report did not approve. It may simply
		# still be on the prior (old) version, but either way the migration is not complete and the
		# resolved document has to be reviewed rather than inheriting the new version's approval.
		return (PolicyEvaluation.ON_OLD_VERSION,
				f'Role resolves version {resolved_version_id} of {arn}, but the approved version is '
				f'{approved_version_id}. The old policy must still be reviewed separately.')

	@staticmethod
	def _normalise_document(document):
		if isinstance(document, str):
			try:
				return json.loads(document)
			except json.JSONDecodeError:
				return document
		return document


class ReleaseGateReport:
	"""
	The collection of per-role release judgments.
	"""

	def __init__(self, role_evaluations=None):
		self.role_evaluations = [] if role_evaluations is None else role_evaluations

	@property
	def blocking_roles(self):
		return [evaluation for evaluation in self.role_evaluations if evaluation.requires_confirmation]

	@property
	def is_release_approved(self):
		return all(evaluation.is_confirmed for evaluation in self.role_evaluations)

	def to_json(self):
		return {
			'releaseApproved': self.is_release_approved,
			'roles': [evaluation.custom_to_json() for evaluation in self.role_evaluations]
		}

	def print(self):
		print(json.dumps(self.to_json(), indent=4))
