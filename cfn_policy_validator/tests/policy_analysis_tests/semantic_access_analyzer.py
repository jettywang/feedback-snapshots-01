"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import re


_ALLOW = 'Allow'


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _canonical(value):
    if isinstance(value, dict):
        return tuple(sorted((key, _canonical(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(sorted(_canonical(item) for item in value))
    return value


def _condition_items(condition):
    if not condition:
        return ()

    items = []
    for operator, entries in condition.items():
        for key, value in entries.items():
            items.append((operator, key, _canonical(value)))
    return tuple(sorted(items))


def _principal_items(principal):
    if not principal:
        return ()
    if principal == '*':
        return (('*', '*'),)

    items = []
    for principal_type, values in principal.items():
        for value in _as_list(values):
            items.append((principal_type, value))
    return tuple(sorted(items))


def _pattern_covers(pattern, value, case_sensitive):
    if not isinstance(pattern, str) or not isinstance(value, str):
        return pattern == value

    regex = '^' + ''.join(
        '.*' if char == '*' else '.' if char == '?' else re.escape(char)
        for char in pattern
    ) + '$'
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.match(regex, value, flags) is not None


class Grant:
    """A single action/resource/condition/principal permission from an Allow statement."""

    def __init__(self, statement_index, statement_id, action, resource, condition, principal):
        self.statement_index = statement_index
        self.statement_id = statement_id
        self.action = action
        self.resource = resource
        self.condition = condition
        self.principal = principal

    def key(self):
        return self.action, self.resource, self.condition, self.principal

    def __eq__(self, other):
        return isinstance(other, Grant) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def covers(self, other):
        if not _pattern_covers(self.action, other.action, case_sensitive=False):
            return False
        if not _pattern_covers(self.resource, other.resource, case_sensitive=True):
            return False

        # A reference statement with a condition only covers a new statement
        # with at least the same conditions. No condition covers everything.
        if not set(self.condition).issubset(set(other.condition)):
            return False

        # Identity policies have no principal. Resource policies do, so keep the
        # principal in the comparison rather than silently widening access.
        if not self.principal:
            return True
        if self.principal == (('*', '*'),):
            return True

        for principal_type, principal_value in other.principal:
            if not any(
                ref_type == principal_type and
                _pattern_covers(ref_value, principal_value, case_sensitive=False)
                for ref_type, ref_value in self.principal
            ):
                return False
        return True


def allow_grants(document):
    """Flatten a policy document into the grants it allows.

    The result is order independent: statement, action and resource order do not
    matter. This is deliberately semantic rather than a serialized comparison.
    """
    if isinstance(document, str):
        document = json.loads(document)

    statements = document.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    grants = []
    for statement_index, statement in enumerate(statements):
        if statement.get('Effect') != _ALLOW:
            # Deny statements restrict access, they never add it.
            continue
        if 'NotAction' in statement or 'NotResource' in statement:
            raise ValueError('NotAction and NotResource are not supported by the release-gate double')

        statement_id = statement.get('Sid')
        condition = _condition_items(statement.get('Condition'))
        principal = _principal_items(statement.get('Principal'))

        for action in _as_list(statement.get('Action')):
            for resource in _as_list(statement.get('Resource')):
                grants.append(Grant(
                    statement_index=statement_index,
                    statement_id=statement_id,
                    action=action,
                    resource=resource,
                    condition=condition,
                    principal=principal,
                ))

    return grants


class SemanticAccessAnalyzer:
    """Offline stand-in for Access Analyzer's CheckNoNewAccess.

    It compares the *meaning* of policies: actions, resources, conditions and
    principals, independent of statement/action/resource ordering. It is used by
    the release-gate acceptance so all scenarios share one analysis double.
    """

    def __init__(self):
        self.calls = []

    def reset(self):
        self.calls = []

    def check_no_new_access(self, policyType, existingPolicyDocument, newPolicyDocument):
        existing_grants = allow_grants(existingPolicyDocument)
        new_grants = allow_grants(newPolicyDocument)

        reasons = []
        for grant in new_grants:
            if any(reference_grant.covers(grant) for reference_grant in existing_grants):
                continue
            reasons.append({
                'statementIndex': grant.statement_index,
                'statementId': grant.statement_id,
                'description': (
                    f'{grant.action} on {grant.resource} is allowed by the new policy '
                    f'but not covered by the reference policy'
                ),
                'actions': [grant.action],
                'resources': [grant.resource],
            })

        call = {
            'policyType': policyType,
            'existingGrants': existing_grants,
            'newGrants': new_grants,
            'result': 'FAIL' if reasons else 'PASS',
        }
        self.calls.append(call)

        response = {
            'result': call['result'],
            'ResponseMetadata': {'HTTPStatusCode': 200},
        }
        if reasons:
            response['message'] = 'The new policy grants permissions that are not present in the reference policy.'
            response['reasons'] = reasons
        return response
