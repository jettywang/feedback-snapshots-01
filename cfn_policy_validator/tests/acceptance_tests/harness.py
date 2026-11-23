"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json

from contextlib import contextmanager
from unittest.mock import patch

from botocore.exceptions import ClientError

from cfn_policy_validator import client


ANALYZER_ARN = 'arn:aws:access-analyzer:us-east-1:111222333444:analyzer/AcceptanceAnalyzer'


class RecordedPolicyAnalysis:
    def __init__(self, operation, policy_type, policy_document):
        if not isinstance(policy_document, str):
            raise AssertionError(
                'The analyzer must receive a policy document string, not a policy name or other identifier'
            )
        try:
            document = json.loads(policy_document)
        except ValueError:
            raise AssertionError(
                f'The analyzer received {policy_document!r}, which is not a JSON policy document.  '
                'A policy name or ARN is not evidence that a policy was analyzed.'
            )
        if not isinstance(document, dict) or 'Statement' not in document:
            raise AssertionError(
                'The analyzer received a JSON value that is not an IAM policy document (missing Statement)'
            )
        self.operation = operation
        self.policy_type = policy_type
        self.policy_document = document
        self.raw_policy_document = policy_document


class RecordingAccessAnalyzer:
    """
    A simulated IAM Access Analyzer policy analysis endpoint.  It records the exact request arguments it receives so a
    test can assert on the policy *document* that was analyzed, not merely on a policy name or resource name.
    """

    def __init__(self, findings_for_document=None):
        self.calls = []
        self.findings_for_document = findings_for_document

    def list_analyzers(self, type):
        return {
            'analyzers': [
                {
                    'arn': ANALYZER_ARN,
                    'name': 'AcceptanceAnalyzer',
                    'type': 'ACCOUNT',
                    'status': 'ACTIVE'
                }
            ]
        }

    def get_paginator(self, operation_name):
        if operation_name != 'validate_policy':
            raise AssertionError(f'Unexpected paginator requested: {operation_name}')

        return _ValidatePolicyPaginator(self)

    def records_for(self, operation=None):
        return [call for call in self.calls if operation is None or call.operation == operation]

    def analyzed_documents(self, operation=None):
        return [call.policy_document for call in self.records_for(operation)]


class _ValidatePolicyPaginator:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def paginate(self, **kwargs):
        record = RecordedPolicyAnalysis(
            operation='ValidatePolicy',
            policy_type=kwargs['policyType'],
            policy_document=kwargs['policyDocument']
        )
        self.analyzer.calls.append(record)

        findings = []
        if self.analyzer.findings_for_document is not None:
            findings = self.analyzer.findings_for_document(record) or []

        return [{'findings': findings}]


class FakeIam:
    """
    Minimal IAM managed policy endpoint.  An ARN maps to either a policy document or an error code.  Calls are recorded
    so a test can tell a lookup that returned a name apart from one that returned a document.
    """

    def __init__(self, managed_policies=None):
        self.managed_policies = managed_policies or {}
        self.calls = []

    def get_policy(self, PolicyArn):
        self.calls.append(('GetPolicy', PolicyArn))
        entry = self._entry(PolicyArn, 'GetPolicy')
        return {
            'Policy': {
                'PolicyName': entry['PolicyName'],
                'DefaultVersionId': entry.get('DefaultVersionId', 'v1'),
                'Path': entry.get('Path', '/')
            }
        }

    def get_policy_version(self, PolicyArn, VersionId):
        self.calls.append(('GetPolicyVersion', PolicyArn, VersionId))
        entry = self._entry(PolicyArn, 'GetPolicyVersion')
        # botocore decodes the IAM Document JSON string before it reaches the caller; mirror the decoded shape
        return {'PolicyVersion': {'Document': entry['Document']}}

    def _entry(self, arn, operation):
        entry = self.managed_policies.get(arn)
        if entry is None:
            raise _client_error('NoSuchEntity', 'GetPolicy')
        if entry.get(operation) is not None:
            raise _client_error(entry[operation], operation)
        if operation == 'GetPolicyVersion' and entry.get('Document') is None:
            raise _client_error('NoSuchEntity', operation)
        return entry


class UnusedAwsService:
    """Any service the parser constructs but the acceptance scenario never calls."""

    def __getattr__(self, item):
        raise AssertionError(f'Unexpected call to unused AWS service member: {item}')


class FakeSts:
    def __init__(self, account_id='111222333444'):
        self.account_id = account_id

    def get_caller_identity(self):
        return {
            'Account': self.account_id,
            'Arn': f'arn:aws:iam::{self.account_id}:user/acceptance'
        }


def _client_error(code, operation):
    return ClientError(
        {
            'Error': {'Code': code, 'Message': f'{code} from simulated endpoint'},
            'ResponseMetadata': {'HTTPStatusCode': 403 if code == 'AccessDenied' else 400}
        },
        operation
    )


class AcceptanceHarness:
    def __init__(self, analyzer=None, iam=None, sts=None):
        self.analyzer = analyzer if analyzer is not None else RecordingAccessAnalyzer()
        self.iam = iam if iam is not None else FakeIam()
        self.sts = sts if sts is not None else FakeSts()

    def build_client(self, service_name, region_name, client_config=None):
        if service_name == 'accessanalyzer':
            return self.analyzer
        if service_name == 'iam':
            return self.iam
        if service_name == 'sts':
            return self.sts
        return UnusedAwsService()

    @contextmanager
    def installed(self):
        with patch.object(client, 'build', side_effect=self.build_client):
            yield self
