"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Builds a provenance index over the raw template that the conditional analysis uses to attribute a parsed policy back
to the CloudFormation logical resource and to the specific undecidable conditions that can change it.

Everything here is computed from the template structure alone; no AWS calls are made.
"""

from cfn_policy_validator.conditional_analysis.condition_dependencies import find_if_conditions

# resource types whose resource-based policies the validator actually parses
RESOURCE_POLICY_TYPES = {
	'AWS::S3::AccessPoint',
	'AWS::S3::MultiRegionAccessPointPolicy',
	'AWS::S3::Bucket',
	'AWS::S3::BucketPolicy',
	'AWS::S3Tables::TableBucketPolicy',
	'AWS::SQS::QueuePolicy',
	'AWS::SNS::TopicPolicy',
	'AWS::KMS::Key',
	'AWS::Lambda::Permission',
	'AWS::Lambda::LayerVersionPermission',
	'AWS::SecretsManager::ResourcePolicy',
	'AWS::ApiGateway::RestApi',
	'AWS::CodeArtifact::Domain',
	'AWS::CloudTrail::ResourcePolicy',
	'AWS::S3Express::AccessPoint',
	'AWS::Backup::BackupVault',
}

# dedicated policy resources attach a policy to another resource.  When one of these exists it must claim the parsed
# policy before the target resource (which may itself be a policy-bearing type, e.g. an AWS::S3::Bucket with ACLs).
DEDICATED_POLICY_RESOURCE_TYPES = {
	'AWS::S3::BucketPolicy',
	'AWS::S3::MultiRegionAccessPointPolicy',
	'AWS::S3Tables::TableBucketPolicy',
	'AWS::SQS::QueuePolicy',
	'AWS::SNS::TopicPolicy',
	'AWS::SecretsManager::ResourcePolicy',
	'AWS::CloudTrail::ResourcePolicy',
}

# property that conventionally carries the resource's own name for the types we track resolved names for
_NAME_PROPERTY_BY_TYPE = {
	'AWS::S3::Bucket': 'BucketName',
	'AWS::SQS::Queue': 'QueueName',
	'AWS::SNS::Topic': 'TopicName',
	'AWS::KMS::Key': None,
	'AWS::IAM::Role': 'RoleName',
	'AWS::IAM::User': 'UserName',
	'AWS::IAM::Group': 'GroupName',
}


class ProvenanceIndex:
	def __init__(self, template):
		self.template = template
		self.resources = template.get('Resources') or {}

	def build(self):
		"""
		Return two indexes:

		* resource_name_index: logical name -> set of possible resolved names the resource's policy may be reported
		  under (physical name property value, target reference, or the logical name itself as a fallback).
		* condition_index: logical name -> ordered list of undecidable Fn::If condition names reachable under it.
		"""
		resource_name_index = {}
		condition_index = {}

		for logical_name, resource in self.resources.items():
			resource_type = resource.get('Type')
			properties = resource.get('Properties', {}) or {}

			resource_name_index[logical_name] = self._possible_names(logical_name, resource_type, properties)
			condition_index[logical_name] = find_if_conditions(resource)

		return resource_name_index, condition_index

	def _possible_names(self, logical_name, resource_type, properties):
		names = {logical_name}

		name_property = _NAME_PROPERTY_BY_TYPE.get(resource_type)
		if name_property is not None:
			explicit_name = properties.get(name_property)
			if isinstance(explicit_name, str):
				names.add(explicit_name)

		# policy resources reference the resource they apply to; the parser reports the target's name.  Resolve both
		# literal references and Ref/GetAtt links to the target resource's possible names.
		for reference_property in ('Bucket', 'Queues', 'Queue', 'Topics', 'Topic', 'KeyId', 'SecretId', 'RestApiId',
		                           'DomainName', 'BackupVaultName', 'TableBucketARN'):
			target_value = properties.get(reference_property)
			if target_value is None:
				continue

			# some resources (e.g. AWS::SQS::QueuePolicy.Queues) take a list of references
			targets = target_value if isinstance(target_value, list) else [target_value]
			for target in targets:
				if isinstance(target, str):
					names.add(target.split('/')[-1].split(':')[-1])
					continue
				target_logical_name = self._reference_logical_name(target)
				if target_logical_name is not None and target_logical_name in self.resources:
					target_resource = self.resources[target_logical_name]
					target_type = target_resource.get('Type')
					target_properties = target_resource.get('Properties', {}) or {}
					names.update(self._possible_names(target_logical_name, target_type, target_properties))

		return names

	def _reference_logical_name(self, value):
		"""
		Extract the logical resource name from a Ref or Fn::GetAtt intrinsic.  Returns None for anything else.
		"""
		if isinstance(value, dict):
			ref = value.get('Ref')
			if isinstance(ref, str):
				return ref
			get_att = value.get('Fn::GetAtt')
			if isinstance(get_att, list) and get_att:
				return get_att[0]
			if isinstance(get_att, str):
				return get_att.split('.')[0]
		return None
