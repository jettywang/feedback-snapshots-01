"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import io
import json

from unittest.mock import patch

from cfn_policy_validator import _parse_template_output
from cfn_policy_validator.cfn_tools import cfn_loader
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.validation import policy_analysis


POLICY_KEYS = {
    'PolicyDocument',
    'AssumeRolePolicyDocument',
    'Policy',
    'KeyPolicy',
    'ResourcePolicy',
    'AccessPolicy',
    'PermissionsPolicyDocument',
    'InlinePolicy',
}

PARTITION = 'aws'
REGION = 'us-east-2'
ACCOUNT_ID = '111222333444'


class OfflineAwsClients:
    """Resolve parsing's AWS lookups locally and refuse any other calls.

    Parsing can resolve managed policies through IAM and constructs SSM /
    CloudFormation clients eagerly. Returning a client that raises on any real
    call makes it impossible for the release gate to reach AWS unnoticed.
    """

    def __init__(self, analyzer, managed_policy_document=None):
        self.analyzer = analyzer
        self.managed_policy_document = managed_policy_document or {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 'logs:CreateLogGroup',
                'Resource': '*',
            }],
        }
        self.calls = []

    def build(self, service_name, region_name, client_config=None):
        self.calls.append((service_name, region_name))
        if service_name == 'accessanalyzer':
            return self.analyzer
        if service_name == 'iam':
            return self._iam_client()
        return self._unexpected_client(service_name)

    def _iam_client(self):
        clients = self

        class IamClient:
            def get_policy(self, PolicyArn):
                return {
                    'Policy': {
                        'PolicyName': PolicyArn.rsplit('/', 1)[-1],
                        'DefaultVersionId': 'v1',
                        'Path': '/',
                    }
                }

            def get_policy_version(self, PolicyArn, VersionId):
                return {'PolicyVersion': {'Document': clients.managed_policy_document}}

        return IamClient()

    @staticmethod
    def _unexpected_client(service_name):
        class UnexpectedClient:
            def __getattr__(self, attribute):
                def unexpected_call(*args, **kwargs):
                    raise AssertionError(
                        f'Unexpected call to {service_name}.{attribute}; the release gate must be offline.'
                    )

                return unexpected_call

        return UnexpectedClient()


def template_policy_documents(template):
    """Collect (template path, policy document) pairs in template order."""
    documents = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f'{path}.{key}' if path else key
                if key in POLICY_KEYS and isinstance(value, dict):
                    documents.append((child_path, value))
                walk(value, child_path)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f'{path}[{index}]')

    walk(template, '')
    return documents


def evaluate_template_policy_documents(template):
    """Evaluate every policy document and keep its full template path."""
    return [
        {'templatePath': path, 'policy': document.eval({'type': 'object'})}
        for path, document in template_policy_documents(template)
    ]


def load_template(template_path, parameters, account_config):
    with open(template_path) as stream:
        template_body = stream.read()

    return cfn_loader.load(io.StringIO(template_body), account_config, parameters, False)


def run_release_gate(template_path, reference_policy_path, analyzer, parameters=None):
    """Run a template through the real parser and the real policy analysis.

    Only the AWS client boundary is replaced: the semantic analyzer stands in
    for Access Analyzer, and parsing's IAM/SSM/CloudFormation lookups are served
    offline. Parsing, intrinsic evaluation, policy discovery, the analysis
    cache, findings building, and reporting all execute for real.
    """
    parameters = {'Environment': 'prod'} if parameters is None else parameters
    account_config = AccountConfig(PARTITION, REGION, ACCOUNT_ID)

    with open(reference_policy_path) as stream:
        reference_policy = json.load(stream)

    clients = OfflineAwsClients(analyzer)

    # Patch the single AWS client factory for the whole run. Parsing builds SSM,
    # CloudFormation and IAM clients, and policy analysis builds its Access
    # Analyzer client, all through this one function.
    with patch('cfn_policy_validator.client.build', side_effect=clients.build):
        template = load_template(template_path, parameters, account_config)
        evaluated_documents = evaluate_template_policy_documents(template)
        parser_output = _parse_template_output(template, account_config)
        report = policy_analysis.compare(
            parser_output,
            reference_policy,
            'identity',
            None,
            True,
        )

    return {
        'report': report,
        'evaluatedDocuments': evaluated_documents,
        'policyDocumentsByOwner': identity_policy_documents_by_owner(parser_output),
        'analyzer': analyzer,
        'awsClients': clients,
    }


def identity_policy_documents_by_owner(parser_output):
    """Map (resource name, policy name) to the policy document that was analyzed."""
    documents = {}
    for identity_resources in [
        parser_output.PermissionSets,
        parser_output.Users,
        parser_output.Roles,
        parser_output.Groups,
    ]:
        for resource in identity_resources:
            resource_name = _identity_resource_name(resource)
            for policy in resource.Policies:
                documents[(resource_name, policy.Name)] = policy.Policy
    return documents


def _identity_resource_name(resource):
    for attribute in ('Name', 'UserName', 'GroupName', 'RoleName'):
        value = getattr(resource, attribute, None)
        if value is not None:
            return value
    return None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def finding_evidence(report, evaluated_documents, policy_documents_by_owner=None):
    """Resolve every blocking finding to its full template path and statement.

    The finding names the resource and policy; the analyzer reason names the
    statement index/id and the resolved action/resource. The analyzed policy is
    matched against the evaluated template documents so evidence yields a full
    path such as
    ``Resources.WorkerRole.Properties.Policies[0].PolicyDocument.Statement[2]``.
    """
    policy_documents_by_owner = policy_documents_by_owner or {}
    evidence = []
    for finding in report.blocking_findings:
        analyzed_policy = policy_documents_by_owner.get((finding.resourceName, finding.policyName))

        for reason in finding.details.get('reasons', []):
            statement_index = reason['statementIndex']
            statement_id = reason.get('statementId')
            statement_path = None
            statement = None

            for document in evaluated_documents:
                # Prefer the document the analyzer actually saw for this finding.
                if analyzed_policy is not None and document['policy'] != analyzed_policy:
                    continue

                statements = document['policy'].get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                if statement_index is None or statement_index >= len(statements):
                    continue
                candidate = statements[statement_index]
                if statement_id is not None and candidate.get('Sid') != statement_id:
                    continue
                if not any(resource in _as_list(candidate.get('Resource'))
                           for resource in reason.get('resources', [])):
                    continue

                statement_path = f"{document['templatePath']}.Statement[{statement_index}]"
                statement = candidate
                break

            evidence.append({
                'resourceName': finding.resourceName,
                'policyName': finding.policyName,
                'statementPath': statement_path,
                'statement': statement,
                'actions': reason.get('actions', []),
                'resources': reason.get('resources', []),
                'description': reason.get('description'),
            })

    return evidence
