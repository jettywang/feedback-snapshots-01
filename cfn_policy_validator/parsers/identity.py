"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging

from abc import ABC

from botocore.exceptions import ClientError, BotoCoreError

from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.identity_schemas import groups_schema, managed_policy_schema, \
	roles_schema, inline_policy_schema, users_schema, permission_set_schema, role_policy_schema, group_policy_schema, \
	user_policy_schema, permission_set_assignment_schema
from cfn_policy_validator.parsers.utils.arn_generator import ArnGenerator
from cfn_policy_validator.parsers.output import Role, User, Policy, Group, PermissionSet, \
	INLINE_POLICY_SOURCE, MANAGED_POLICY_TEMPLATE_SOURCE, MANAGED_POLICY_EXTERNAL_SOURCE
from cfn_policy_validator.parsers.utils.topological_sorter import TopologicalSorter


LOGGER = logging.getLogger("cfn-policy-validator")


class IdentityParser:
	"""
	Parses identity policies from IAM CloudFormation resources.  Note that identity policies may have dependencies
	on each other (e.g. policies attached to principals).
	"""

	@classmethod
	def parse(cls, template, account_config, excluded_resource_types={}):
		PermissionSetAssignmentParser.reset()

		parsers = {
			'AWS::IAM::Role': RoleParser(account_config.region),
			'AWS::IAM::Policy': InlinePolicyParser(),
			'AWS::IAM::RolePolicy': RolePolicyParser(),
			'AWS::IAM::GroupPolicy': GroupPolicyParser(),
			'AWS::IAM::UserPolicy': UserPolicyParser(),
			'AWS::IAM::ManagedPolicy': ManagedPolicyParser(account_config),
			'AWS::IAM::User': UserParser(account_config.region),
			'AWS::IAM::Group': GroupParser(account_config.region),
			'AWS::SSO::PermissionSet': PermissionSetParser(account_config),
			'AWS::SSO::Assignment': PermissionSetAssignmentParser()
		}

		# topologically sort which allows us to process dependent resources first
		sorter = TopologicalSorter(template)
		sorted_resources = sorter.sort_resources()

		for resource in sorted_resources:
			resource_type = resource.value['Type']
			if resource_type not in excluded_resource_types:
				parser = parsers.get(resource_type)
				if parser is not None:
					LOGGER.info(f'Parsing resource type {resource_type} with logical name {resource.logical_name}..')
					parser.parse(resource.logical_name, resource.value)

		orphaned_policies = cls.get_orphaned_policies()

		return list(RoleParser.roles.values()), \
			list(UserParser.users.values()), \
			list(GroupParser.groups.values()), \
			list(PermissionSetParser.permission_sets.values()), \
			orphaned_policies

	@classmethod
	def get_permission_set_assignments(cls):
		""" Deployment-time assignments found in the template.  These are intent, not proven access. """
		return list(PermissionSetAssignmentParser.assignments)

	@classmethod
	def get_orphaned_policies(cls):
		"""
		Orphaned policies are policies that are not attached to any principal
		"""
		role_policies = [policy for role in RoleParser.roles.values() for policy in role.Policies]
		user_policies = [policy for user in UserParser.users.values() for policy in user.Policies]
		group_policies = [policy for group in GroupParser.groups.values() for policy in group.Policies]
		permission_set_policies = [policy for permission_set in PermissionSetParser.permission_sets.values()
								   for policy in permission_set.Policies]

		all_attached_policies = list(set(role_policies) | set(user_policies) | set(group_policies) | set(permission_set_policies))
		all_managed_policies = list(ManagedPolicyParser.managed_policies.values())
		all_inline_policies = InlinePolicyParser.inline_policies + \
								RolePolicyParser.role_policies + \
								GroupPolicyParser.group_policies + \
								UserPolicyParser.user_policies

		orphaned_policies = [managed_policy for managed_policy in all_managed_policies if managed_policy not in all_attached_policies]
		orphaned_policies.extend([inline_policy for inline_policy in all_inline_policies if inline_policy not in all_attached_policies])

		return orphaned_policies


class AttachedPolicyParser:
	"""
	Handles parsing managed and inline policies from other resources
	"""
	def __init__(self, region):
		self.client = client.build('iam', region)

	@staticmethod
	def parse_inline_policies(principal, properties):
		inline_policies = properties.get('Policies', [])
		for inline_policy in inline_policies:
			policy_name = inline_policy['PolicyName']
			policy_document = inline_policy['PolicyDocument']

			policy = Policy(policy_name, policy_document, source=INLINE_POLICY_SOURCE)
			principal.add_policy(policy)

	def parse_managed_policies(self, principal, properties, property_name='ManagedPolicyArns',
							   unresolved_reference_handler=None):
		managed_policy_arns = properties.get(property_name, [])
		for arn in managed_policy_arns:
			policy = ManagedPolicyParser.managed_policies.get(arn)
			if policy is not None:
				principal.add_policy(policy)
				if unresolved_reference_handler is not None:
					unresolved_reference_handler(
						arn,
						resolved=True,
						policy=policy,
						reason=None,
						resolved_from_template=True
					)
				continue

			policy_name, default_version_id, policy_path, is_aws_managed_policy = self._lookup_policy(
				arn, unresolved_reference_handler
			)
			if policy_name is None:
				# the reference was recorded as unresolved; keep any already-reviewed inline policy attached
				continue

			try:
				response = self.client.get_policy_version(PolicyArn=arn, VersionId=default_version_id)
			except (ClientError, BotoCoreError):
				if unresolved_reference_handler is not None:
					unresolved_reference_handler(
						arn,
						resolved=False,
						reason='CUSTOMER_MANAGED_POLICY_VERSION_UNAVAILABLE'
					)
					continue
				raise

			policy_document = response['PolicyVersion']['Document']

			# the template attaches the policy by ARN but does not pin a version; the document read from IAM is what we
			# audit, and any later version can differ
			policy = Policy(policy_name, policy_document, policy_path, is_aws_managed_policy,
							source=MANAGED_POLICY_EXTERNAL_SOURCE)
			principal.add_policy(policy)
			if unresolved_reference_handler is not None:
				unresolved_reference_handler(
					arn,
					resolved=True,
					policy=policy,
					reason='CUSTOMER_MANAGED_POLICY_VERSION_NOT_PINNED' if not is_aws_managed_policy else None
				)

	def _lookup_policy(self, arn, unresolved_reference_handler):
		try:
			response = self.client.get_policy(PolicyArn=arn)
		except ClientError as e:
			if e.response['Error']['Code'] == 'NoSuchEntity':
				if unresolved_reference_handler is not None:
					unresolved_reference_handler(
						arn,
						resolved=False,
						reason='CUSTOMER_MANAGED_POLICY_NOT_FOUND_IN_TEMPLATE_OR_ENVIRONMENT'
					)
					return None, None, None, False
				raise ApplicationError(f'Could not find managed policy with {arn} in template or in environment.')
			if unresolved_reference_handler is not None:
				# AccessDenied and similar stop us from reading the document.  That is an evidence gap, not a reason to
				# throw away the policy review that already succeeded for the rest of the permission set.
				unresolved_reference_handler(
					arn,
					resolved=False,
					reason='CUSTOMER_MANAGED_POLICY_LOOKUP_FAILED'
				)
				return None, None, None, False
			raise
		except BotoCoreError:
			if unresolved_reference_handler is not None:
				unresolved_reference_handler(
					arn,
					resolved=False,
					reason='CUSTOMER_MANAGED_POLICY_UNAVAILABLE'
				)
				return None, None, None, False
			raise

		policy_name = response['Policy']['PolicyName']
		default_version_id = response['Policy']['DefaultVersionId']
		policy_path = response['Policy']['Path']

		# it must be a valid ARN if we made it this far
		arn_parts = arn.split(':')
		account_id = arn_parts[4]
		# record whether this is an AWS managed policy because we may treat them slightly different for validation
		is_aws_managed_policy = account_id.lower() == 'aws'

		return policy_name, default_version_id, policy_path, is_aws_managed_policy


class RoleParser:
	""" Parser for AWS::IAM::Role
	"""

	# store roles for the lifetime of the run for static lookup by other parsers
	roles = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		RoleParser.roles = {}

	@classmethod
	def get_role_by(cls, name):
		for role in cls.roles.values():
			if role.RoleName == name:
				return role

		# this means that it the template is referencing a role external to the template,
		# but we still want to validate policies in the template
		return None

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(roles_schema)

		properties = evaluated_resource['Properties']

		path = properties.get('Path', '/')
		trust_policy = properties['AssumeRolePolicyDocument']

		# if RoleName is not a property, use the resource name
		role_name = properties.get('RoleName', resource_name)

		role = Role(role_name, path, trust_policy)

		self.attached_policy_parser.parse_inline_policies(role, properties)
		self.attached_policy_parser.parse_managed_policies(role, properties)

		self.roles[resource_name] = role


class UserParser:
	""" AWS::IAM::User
	"""

	# store users for the lifetime of the run for static lookup by other parsers
	users = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		UserParser.users = {}

	@classmethod
	def get_user_by(cls, name):
		for user in cls.users.values():
			if user.UserName == name:
				return user

		# this means that it the template is referencing a role external to the template,
		# but we still want to validate policies in the template
		return None

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(users_schema)

		properties = evaluated_resource.get('Properties', {})

		path = properties.get('Path', '/')
		user_name = properties.get('UserName', resource_name)

		user = User(user_name, path)

		self.attached_policy_parser.parse_inline_policies(user, properties)
		self.attached_policy_parser.parse_managed_policies(user, properties)

		self.users[resource_name] = user


class GroupParser:
	""" AWS::IAM::Group
	"""

	# store groups for the lifetime of the run for static lookup by other parsers
	groups = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		GroupParser.groups = {}

	@classmethod
	def get_group_by(cls, name):
		for group in cls.groups.values():
			if group.GroupName == name:
				return group

		# this means that the template is referencing a role external to the template,
		# but we still want to validate policies in the template
		return None

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(groups_schema)
		# there are no required properties for a group, so a group without properties is OK
		properties = evaluated_resource.get('Properties', {})

		path = properties.get('Path', '/')
		group_name = properties.get('GroupName', resource_name)

		group = Group(group_name, path)

		self.attached_policy_parser.parse_inline_policies(group, properties)
		self.attached_policy_parser.parse_managed_policies(group, properties)

		self.groups[resource_name] = group


class PermissionSetParser:
	""" Parser for AWS::SSO::PermissionSet
	"""

	permission_sets = {}

	def __init__(self, account_config):
		self.attached_policy_parser = AttachedPolicyParser(account_config.region)
		self.arn_generator = ArnGenerator(account_config)
		PermissionSetParser.permission_sets = {}

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(permission_set_schema)

		properties = evaluated_resource['Properties']

		name = properties['Name']
		instance_arn = properties.get('InstanceArn')
		permission_set_arn = self.arn_generator.try_generate_arn(resource_name, resource, 'PermissionSetArn')

		permission_set = PermissionSet(name, logical_id=resource_name, instance_arn=instance_arn,
									   permission_set_arn=permission_set_arn)

		def handle_managed_policy_reference(reference, resolved, policy=None, reason=None,
											resolved_from_template=False):
			# A policy resolved from the template is audited as written.  A policy read from IAM is audited, but its
			# version is not pinned by the template, so the publisher still owes version evidence for customer-managed
			# policies.
			if policy is not None and policy.Source == MANAGED_POLICY_EXTERNAL_SOURCE and not policy.IsAWSManagedPolicy:
				reason = reason or 'CUSTOMER_MANAGED_POLICY_VERSION_NOT_PINNED'

			requires_publisher_evidence = not resolved or reason is not None
			permission_set.add_managed_policy_reference(
				reference,
				resolved=resolved,
				policy_name=policy.Name if policy is not None else None,
				policy_path=policy.Path if policy is not None else None,
				source=policy.Source if policy is not None else None,
				reason=reason,
				requires_publisher_evidence=requires_publisher_evidence
			)

		self.parse_inline_policy(permission_set, properties)
		self.attached_policy_parser.parse_managed_policies(
			permission_set,
			properties,
			property_name="ManagedPolicies",
			unresolved_reference_handler=handle_managed_policy_reference
		)
		self.parse_customer_managed_policy_references(permission_set, properties)
		self.parse_permissions_boundary(permission_set, properties)

		self.permission_sets[resource_name] = permission_set

	@staticmethod
	def parse_customer_managed_policy_references(permission_set, properties):
		""" Customer-managed policies are referenced by name/path and are not fetched from the environment.

		They must be supplied by the publisher as reviewed evidence.  The reference itself is still recorded so the
		permission set keeps an auditable link to policies the library deliberately did not read.
		"""
		for reference in properties.get('CustomerManagedPolicyReferences', []):
			name = reference['Name']
			path = reference.get('Path', '/')
			permission_set.add_customer_managed_policy_reference(f'{path}{name}')

	@staticmethod
	def parse_permissions_boundary(permission_set, properties):
		boundary = properties.get('PermissionsBoundary')
		if boundary is None:
			return

		reference = boundary.get('ManagedPolicyArn') or boundary.get('CustomerManagedPolicyReference')
		permission_set.set_permissions_boundary(reference)

	@staticmethod
	def parse_inline_policy(permission_set, properties):
		""" PermissionSets can only have a single inline policy so the parsing logic is slightly different
		"""
		inline_policy = properties.get('InlinePolicy')
		if inline_policy is None:
			return

		policy = Policy('InlinePolicy', inline_policy, source=INLINE_POLICY_SOURCE)
		permission_set.add_policy(policy)


class PermissionSetAssignmentParser:
	""" Parser for AWS::SSO::Assignment.

	An assignment is deployment intent, not evidence that the principal can actually use the permission set in the
	target account.  We record it verbatim so the acceptance report can name the exact bindings that still require
	publisher evidence.
	"""

	assignments = []

	def __init__(self):
		PermissionSetAssignmentParser.assignments = []

	@classmethod
	def reset(cls):
		cls.assignments = []

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(permission_set_assignment_schema)
		properties = evaluated_resource['Properties']

		permission_set_arn = properties['PermissionSetArn']
		assignment = {
			'LogicalId': resource_name,
			'InstanceArn': properties['InstanceArn'],
			'PermissionSetArn': permission_set_arn,
			'PrincipalId': properties['PrincipalId'],
			'PrincipalType': properties['PrincipalType'],
			'TargetId': properties['TargetId'],
			'TargetType': properties['TargetType'],
			'RequiresPublisherEvidence': True
		}
		self.assignments.append(assignment)


class PolicyParser(ABC):
	"""
	Base class for common policy (inline and managed) parsing
	"""

	def parse_roles(self, policy, properties):
		roles_to_apply_policy = properties.get('Roles', [])
		for role_name in roles_to_apply_policy:
			self.add_policy_to_role_with(role_name, policy)

	@staticmethod
	def add_policy_to_role_with(role_name, policy):
		referenced_role = RoleParser.get_role_by(role_name)
		if referenced_role is not None:
			referenced_role.add_policy(policy)

	def parse_users(self, policy, properties):
		users_to_apply_policy = properties.get('Users', [])
		for user_name in users_to_apply_policy:
			self.add_policy_to_user_with(user_name, policy)

	@staticmethod
	def add_policy_to_user_with(user_name, policy):
		referenced_user = UserParser.get_user_by(user_name)
		if referenced_user is not None:
			referenced_user.add_policy(policy)

	def parse_groups(self, policy, properties):
		groups_to_apply_policy = properties.get('Groups', [])
		for group_name in groups_to_apply_policy:
			self.add_policy_to_group_with(group_name, policy)

	@staticmethod
	def add_policy_to_group_with(group_name, policy):
		referenced_group = GroupParser.get_group_by(group_name)
		if referenced_group is not None:
			referenced_group.add_policy(policy)


class InlinePolicyParser(PolicyParser):
	""" AWS::IAM::Policy
	"""
	inline_policies = []

	def __init__(self):
		super(InlinePolicyParser, self).__init__()
		InlinePolicyParser.inline_policies = []

	def parse(self, _, resource):
		evaluated_resource = resource.eval(inline_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties['PolicyName']
		policy_document = properties['PolicyDocument']

		policy = Policy(policy_name, policy_document)

		self.parse_roles(policy, properties)
		self.parse_users(policy, properties)
		self.parse_groups(policy, properties)

		self.inline_policies.append(policy)


class RolePolicyParser(PolicyParser):
	""" AWS::IAM::RolePolicy
	"""
	role_policies = []

	def __init__(self):
		super(RolePolicyParser, self).__init__()
		RolePolicyParser.role_policies = []

	def parse(self, _, resource):
		evaluated_resource = resource.eval(role_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties['PolicyName']
		policy_document = properties['PolicyDocument']
		role_name = properties['RoleName']

		policy = Policy(policy_name, policy_document)

		self.add_policy_to_role_with(role_name, policy)
		self.role_policies.append(policy)


class GroupPolicyParser(PolicyParser):
	""" AWS::IAM::GroupPolicy
	"""
	group_policies = []

	def __init__(self):
		super(GroupPolicyParser, self).__init__()
		GroupPolicyParser.group_policies = []

	def parse(self, _, resource):
		evaluated_resource = resource.eval(group_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties['PolicyName']
		policy_document = properties['PolicyDocument']
		group_name = properties['GroupName']

		policy = Policy(policy_name, policy_document)

		self.add_policy_to_group_with(group_name, policy)
		self.group_policies.append(policy)


class UserPolicyParser(PolicyParser):
	""" AWS::IAM::UserPolicy
	"""
	user_policies = []

	def __init__(self):
		super(UserPolicyParser, self).__init__()
		UserPolicyParser.user_policies = []

	def parse(self, _, resource):
		evaluated_resource = resource.eval(user_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties['PolicyName']
		policy_document = properties['PolicyDocument']
		user_name = properties['UserName']

		policy = Policy(policy_name, policy_document)

		self.add_policy_to_user_with(user_name, policy)
		self.user_policies.append(policy)


class ManagedPolicyParser(PolicyParser):
	""" AWS::IAM::ManagedPolicy
	"""

	managed_policies = {}

	def __init__(self, account_config):
		super(ManagedPolicyParser, self).__init__()
		self.arn_generator = ArnGenerator(account_config)
		ManagedPolicyParser.managed_policies = {}

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(managed_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties.get('ManagedPolicyName', resource_name)
		policy_document = properties['PolicyDocument']
		path = properties.get('Path', '/')

		policy = Policy(policy_name, policy_document, path, source=MANAGED_POLICY_TEMPLATE_SOURCE)

		# attempt to see if this managed policy is attached to any roles, users or groups in the template
		self.parse_roles(policy, properties)
		self.parse_users(policy, properties)
		self.parse_groups(policy, properties)

		# generate an ARN to uniquely reference this managed policy since managed policy ARNs can also be referenced
		# from the principal side
		arn = self.arn_generator.try_generate_arn(policy_name, resource, 'Ref')
		self.managed_policies[arn] = policy
