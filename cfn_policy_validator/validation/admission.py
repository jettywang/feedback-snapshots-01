"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import fnmatch
import json
import logging

from cfn_policy_validator.parsers.output import PolicySource, policy_source_category
from cfn_policy_validator.validation.findings import Findings, Finding
from cfn_policy_validator.validation.reporter import Reporter


LOGGER = logging.getLogger("cfn-policy-validator")

SCOPE_EXCEEDED_CODE = 'ADMISSION_SCOPE_EXCEEDED'
EVIDENCE_MISSING_CODE = 'ADMISSION_EVIDENCE_MISSING'

STATUS_COMPLIANT = 'COMPLIANT'
STATUS_NON_COMPLIANT = 'NON_COMPLIANT'
STATUS_INCOMPLETE_EVIDENCE = 'INCOMPLETE_EVIDENCE'

ROLE_IDENTITY_CATEGORY = 'RoleIdentity'
ATTACHED_CATEGORY = 'AttachedPolicies'
RESOURCE_CATEGORY = 'ResourcePolicies'

PRINCIPAL_SCOPE_EXACT = 'Exact'
PRINCIPAL_SCOPE_ACCOUNT = 'Account'
PRINCIPAL_SCOPE_WILDCARD = 'Wildcard'
PRINCIPAL_SCOPE_NOT_PRINCIPAL = 'NotPrincipal'

# Reasons a grant can fall outside the approved baseline.
REASON_ACTION_NOT_APPROVED = 'ACTION_NOT_APPROVED'
REASON_RESOURCE_NOT_APPROVED = 'RESOURCE_NOT_APPROVED'
REASON_CONDITION_MISSING = 'CONDITION_MISSING'
REASON_UNPROVABLE_STATEMENT = 'STATEMENT_FORM_CANNOT_BE_PROVEN'


def check_admission(parser_output, approved_policy, principals=None, ignore_finding=None,
                    findings_are_blocking=True):
    """
    Run the offline admission check over the parsed template.

    `approved_policy` is the only permission set that is admitted.  Every role is evaluated on its own
    so the report can say what it received from its own identity policy, from attached policies, and
    from resource policies that name it.  A managed policy reference that cannot be resolved is
    reported as missing evidence and never as a pass.
    """
    result = evaluate_admission(parser_output, approved_policy, principals)

    finding_types_that_are_blocking = ['SECURITY_WARNING', 'ERROR']
    if not findings_are_blocking:
        finding_types_that_are_blocking = ['NONE']

    reporter = Reporter(ignore_finding, finding_types_that_are_blocking, None)
    report = reporter.build_report_from(result.findings)
    report.additional = result.to_json()
    return report


def evaluate_admission(parser_output, approved_policy, principals=None):
    """Return the analysis result without applying ignore/finding-type reporting rules."""
    return AdmissionAnalyzer(parser_output, approved_policy).analyze(principals)


class AdmissionResult:
    def __init__(self, principals, summary, findings):
        self.principals = principals
        self.summary = summary
        self.findings = findings

    def to_json(self):
        return {
            'AdmissionCheck': self.summary,
            'Principals': self.principals
        }


class AdmissionAnalyzer:
    def __init__(self, parser_output, approved_policy):
        self.parser_output = parser_output
        self.account_id = parser_output.Account
        self.partition = parser_output.Partition
        self.approved_allow_statements = normalize_approved_policy(approved_policy)
        self.unattributed_resource_statements = []

    def analyze(self, principals=None):
        findings = Findings()
        principal_reports = []
        principal_filters = normalize_principal_filter(principals)

        roles = sorted(self.parser_output.Roles, key=lambda r: r.RoleName)
        selected_roles = []
        for role in roles:
            role_arn = build_role_arn(role, self.account_id, self.partition)
            if principal_filters is not None and not _role_matches_filter(role, role_arn, principal_filters):
                continue
            selected_roles.append((role, role_arn))

        for role, role_arn in selected_roles:
            LOGGER.info(f'Running admission check for role {role.RoleName}')
            report = self._analyze_role(role, role_arn)
            principal_reports.append(report)
            self._add_findings_for_principal(findings, report)

        # A statement that names a role in the template is attributed elsewhere, even when that role
        # was filtered out of this run.  Only statements naming a principal outside the template are
        # surfaced as unattributed, so filtering never mislabels an in-template principal.
        template_role_arns = [build_role_arn(role, self.account_id, self.partition) for role in roles]
        self._collect_unattributed_resource_statements(template_role_arns)

        summary = self._build_summary(principal_reports)
        return AdmissionResult(principal_reports, summary, findings)

    # --------------------------------------------------------------- baseline

    # --------------------------------------------------------------- principal

    def _analyze_role(self, role, role_arn):
        identity_grants, identity_denies = self._build_identity_grants(role)
        resource_grants, resource_denies = self._build_resource_grants(role, role_arn)
        denies = identity_denies + resource_denies

        for grant in identity_grants + resource_grants:
            self._apply_scope(grant)

        self._apply_denies(identity_grants, denies)
        self._apply_denies(resource_grants, denies)

        evidence_gaps = [gap.__dict__ for gap in getattr(role, 'UnresolvedPolicies', [])]
        violations = [grant for grant in identity_grants + resource_grants
                      if grant['Effective'] and grant['ScopeViolations']]

        status = status_for(violations, evidence_gaps)
        return {
            'PrincipalName': role.RoleName,
            'PrincipalType': 'role',
            'PrincipalArn': role_arn,
            'Status': status,
            'FullyCompliant': status == STATUS_COMPLIANT,
            'PermissionsBySource': {
                ROLE_IDENTITY_CATEGORY: [g for g in identity_grants if g['Category'] == ROLE_IDENTITY_CATEGORY],
                ATTACHED_CATEGORY: [g for g in identity_grants if g['Category'] == ATTACHED_CATEGORY],
                RESOURCE_CATEGORY: resource_grants
            },
            'EffectiveGrants': [g for g in identity_grants + resource_grants if g['Effective']],
            'EvidenceGaps': evidence_gaps,
            'FindingCodes': finding_codes_for(violations, evidence_gaps)
        }

    # ---------------------------------------------------------- identity side

    def _build_identity_grants(self, role):
        grants = []
        denies = []
        for policy in role.Policies:
            if policy.Policy is None:
                continue
            category = policy_source_category(policy.Source)
            for index, statement in enumerate(_as_statement_list(policy.Policy)):
                grant = build_grant(statement, policy.Source, category, policy.Name, index)
                if grant['Effect'] == 'Deny':
                    denies.append(grant)
                elif grant['Effect'] == 'Allow':
                    grants.append(grant)
        return grants, denies

    # ---------------------------------------------------------- resource side

    def _build_resource_grants(self, role, role_arn):
        grants = []
        denies = []
        for resource in self.parser_output.Resources:
            policy = getattr(resource, 'Policy', None)
            if policy is None or policy.Policy is None:
                continue

            for index, statement in enumerate(_as_statement_list(policy.Policy)):
                match = match_principal(statement, role_arn, self.account_id, self.partition)
                if not match.Matched:
                    continue

                grant = build_grant(statement, PolicySource.RESOURCE_POLICY, RESOURCE_CATEGORY,
                                    policy.Name, index)
                grant['ResourceName'] = resource.ResourceName
                grant['ResourceType'] = resource.ResourceType
                grant['PrincipalMatch'] = match.Scope
                grant['MatchedPrincipal'] = match.Value

                if grant['Effect'] == 'Deny':
                    denies.append(grant)
                elif grant['Effect'] == 'Allow':
                    grants.append(grant)
        return grants, denies

    def _collect_unattributed_resource_statements(self, template_role_arns):
        """
        Record resource-policy allow statements whose named principal is not any role in the template.
        Such statements are not dropped silently, but they also never count toward a role's status.
        """
        for resource in self.parser_output.Resources:
            policy = getattr(resource, 'Policy', None)
            if policy is None or policy.Policy is None:
                continue
            for index, statement in enumerate(_as_statement_list(policy.Policy)):
                if statement.get('Effect', 'Allow') != 'Allow':
                    continue
                principal = statement.get('Principal')
                if principal is None:
                    continue
                if any(match_principal(statement, arn, self.account_id, self.partition).Matched
                       for arn in template_role_arns):
                    continue
                entry = {
                    'ResourceName': resource.ResourceName,
                    'ResourceType': resource.ResourceType,
                    'PolicyName': policy.Name,
                    'StatementIndex': index,
                    'Principal': principal,
                    'Reason': 'PrincipalIsNotAnEvaluatedRole'
                }
                if entry not in self.unattributed_resource_statements:
                    self.unattributed_resource_statements.append(entry)

    # ------------------------------------------------------------- scope eval

    def _apply_scope(self, grant):
        violations = []
        implied_conditions = _implied_conditions(grant, self.account_id)
        for pair in effective_pairs(grant):
            covered, reason, missing = is_pair_approved(
                pair, grant['Conditions'], self.approved_allow_statements, implied_conditions)
            if not covered:
                violations.append({
                    'Action': pair['Action'],
                    'Resource': pair['Resource'],
                    'ActionIsNegated': pair['ActionIsNegated'],
                    'ResourceIsNegated': pair['ResourceIsNegated'],
                    'Reason': reason,
                    'MissingCondition': missing
                })
        grant['ScopeViolations'] = violations
        grant['WithinApprovedScope'] = len(violations) == 0

    # -------------------------------------------------------------- deny eval

    @staticmethod
    def _apply_denies(grants, denies):
        for grant in grants:
            for deny in denies:
                # a conditional deny may or may not apply; do not assume it revokes the grant
                if deny['Conditions']:
                    continue
                if deny_covers(deny, grant):
                    grant['Effective'] = False
                    grant['DeniedBy'] = {
                        'Source': deny['Source'],
                        'Category': deny['Category'],
                        'PolicyName': deny['PolicyName'],
                        'StatementIndex': deny['StatementIndex']
                    }
                    if 'ResourceName' in deny:
                        grant['DeniedBy']['ResourceName'] = deny['ResourceName']
                    break

    # --------------------------------------------------------------- reporting

    def _add_findings_for_principal(self, findings, report):
        for grant in report['EffectiveGrants']:
            if not grant['ScopeViolations']:
                continue

            details = {
                'Principal': report['PrincipalArn'],
                'Source': grant['Source'],
                'Category': grant['Category'],
                'PolicyName': grant['PolicyName'],
                'StatementIndex': grant['StatementIndex'],
                'Actions': grant['Actions'] or grant['NotActions'],
                'Resources': grant['Resources'] or grant['NotResources'],
                'Conditions': grant['Conditions'],
                'ConditionSummary': grant['ConditionSummary'],
                'ScopeViolations': grant['ScopeViolations']
            }
            if 'ResourceName' in grant:
                details['ResourceName'] = grant['ResourceName']
                details['ResourceType'] = grant['ResourceType']
                details['PrincipalMatch'] = grant['PrincipalMatch']

            findings.security_warnings.append(Finding(
                message=_build_scope_exceeded_message(report['PrincipalName'], grant),
                finding_type='SECURITY_WARNING',
                policy_name=grant['PolicyName'],
                resource_name=report['PrincipalName'],
                details=details,
                code=SCOPE_EXCEEDED_CODE
            ))

        for gap in report['EvidenceGaps']:
            details = {
                'Principal': report['PrincipalArn'],
                'Reference': gap.get('Reference'),
                'Name': gap.get('Name'),
                'Source': gap.get('Source'),
                'Reason': gap.get('Reason')
            }
            findings.errors.append(Finding(
                message=f'Role {report["PrincipalName"]} references a policy whose contents could not be '
                        f'retrieved ({gap.get("Reference")}). Its permissions are unknown, so the role '
                        f'cannot be considered compliant.',
                finding_type='ERROR',
                policy_name=gap.get('Name') or 'UnresolvedPolicy',
                resource_name=report['PrincipalName'],
                details=details,
                code=EVIDENCE_MISSING_CODE
            ))

    def _build_summary(self, reports):
        return {
            'ApprovedBaselineStatements': len(self.approved_allow_statements),
            'PrincipalsEvaluated': len(reports),
            'CompliantPrincipals': [r['PrincipalName'] for r in reports if r['Status'] == STATUS_COMPLIANT],
            'NonCompliantPrincipals': [r['PrincipalName'] for r in reports if r['Status'] == STATUS_NON_COMPLIANT],
            'PrincipalsWithMissingEvidence': [r['PrincipalName'] for r in reports
                                              if r['Status'] == STATUS_INCOMPLETE_EVIDENCE],
            'UnattributedResourceStatements': self.unattributed_resource_statements
        }


# ---------------------------------------------------------------- decisions

def status_for(violations, evidence_gaps):
    """Missing evidence is never reported as compliant, and it outranks a scope pass."""
    if violations:
        return STATUS_NON_COMPLIANT
    if evidence_gaps:
        return STATUS_INCOMPLETE_EVIDENCE
    return STATUS_COMPLIANT


def finding_codes_for(violations, evidence_gaps):
    codes = []
    if violations:
        codes.append(SCOPE_EXCEEDED_CODE)
    if evidence_gaps:
        codes.append(EVIDENCE_MISSING_CODE)
    return codes


# ------------------------------------------------------------------ baseline

def normalize_approved_policy(approved_policy):
    if isinstance(approved_policy, str):
        approved_policy = json.loads(approved_policy)

    if not isinstance(approved_policy, dict):
        raise ValueError('Approved policy must be a policy document object.')

    allows = []
    for index, statement in enumerate(_as_statement_list(approved_policy)):
        if statement.get('Effect', 'Allow') != 'Allow':
            continue
        allows.append({
            'StatementIndex': index,
            'Actions': _as_list(statement.get('Action')),
            'NotActions': _as_list(statement.get('NotAction')),
            'Resources': _as_list(statement.get('Resource')),
            'NotResources': _as_list(statement.get('NotResource')),
            'Conditions': statement.get('Condition') or {}
        })
    return allows


def is_pair_approved(pair, grant_conditions, allowed_statements, implied_conditions=None):
    action_seen = False
    resource_seen = False
    missing_conditions = []

    for statement in allowed_statements:
        if not _action_allowed(pair, statement):
            continue
        action_seen = True
        if not _resource_allowed(pair, statement):
            continue
        resource_seen = True

        satisfied, missing = _conditions_satisfied(grant_conditions, statement['Conditions'],
                                                   implied_conditions or {})
        if satisfied:
            return True, None, []
        for key in missing:
            if key not in missing_conditions:
                missing_conditions.append(key)

    # NotAction/NotResource statements cannot be compared against a positive allow list without
    # enumerating the whole action/resource universe, so they are never assumed to be approved.
    if pair['ActionIsNegated'] or pair['ResourceIsNegated']:
        return False, REASON_UNPROVABLE_STATEMENT, missing_conditions

    if not action_seen:
        return False, REASON_ACTION_NOT_APPROVED, missing_conditions
    if not resource_seen:
        return False, REASON_RESOURCE_NOT_APPROVED, missing_conditions
    return False, REASON_CONDITION_MISSING, missing_conditions


def _action_allowed(pair, statement):
    if statement['NotActions'] or pair['ActionIsNegated']:
        return False
    return any(glob_covers(approved_action, pair['Action']) for approved_action in statement['Actions'])


def _resource_allowed(pair, statement):
    if statement['NotResources'] or pair['ResourceIsNegated']:
        return False
    return any(glob_covers(approved_resource, pair['Resource']) for approved_resource in statement['Resources'])


def _conditions_satisfied(grant_conditions, approved_conditions, implied_conditions):
    """
    The approved conditions are the minimum restriction.  A grant must repeat every approved key with
    the same operator and value; extra conditions only narrow the grant further and are accepted.
    Conditions that are structurally guaranteed by the statement itself (see _implied_conditions)
    count as present.
    """
    if not approved_conditions:
        return True, []

    missing = []
    for operator, approved_values in approved_conditions.items():
        if not isinstance(approved_values, dict):
            continue
        grant_values = grant_conditions.get(operator)
        implied_values = implied_conditions.get(operator)
        for key, approved_value in approved_values.items():
            if isinstance(grant_values, dict) and key in grant_values \
                    and grant_values[key] == approved_value:
                continue
            if isinstance(implied_values, dict) and key in implied_values \
                    and implied_values[key] == approved_value:
                continue
            missing.append(key)
    return len(missing) == 0, missing


def _implied_conditions(grant, account_id):
    """
    Conditions an IAM statement guarantees by construction.  A resource policy that names a principal
    exactly already pins that principal to this account, so `aws:PrincipalAccount` needs no separate
    Condition block.  Anything not structurally guaranteed is left for the explicit Condition check.
    """
    implied = {}
    if grant.get('Category') == RESOURCE_CATEGORY and grant.get('PrincipalMatch') == PRINCIPAL_SCOPE_EXACT:
        implied = {'StringEquals': {'aws:PrincipalAccount': account_id}}
    return implied


# ------------------------------------------------------------------- globbing

def glob_covers(approved, candidate):
    """
    True when every value matched by `candidate` is also matched by `approved`.

    Wildcard subset comparisons cannot be decided in general, so the check is conservative: if
    containment cannot be proven the candidate is reported as outside the approved scope.  Each
    `*` in the approved pattern is matched against exactly one segment of the candidate, which is
    sufficient to prove containment without over-claiming when wildcards float in the middle.
    """
    approved = str(approved).lower()
    candidate = str(candidate).lower()

    if approved == '*':
        return True
    if approved == candidate:
        return True

    candidate_has_wildcard = '*' in candidate or '?' in candidate
    if not candidate_has_wildcard:
        return fnmatch.fnmatchcase(candidate, approved)

    # A wildcard candidate can only be contained by a wildcard approved pattern.
    if '*' not in approved:
        return False

    return _wildcard_contains(approved, candidate)


def _wildcard_contains(approved, candidate):
    """
    Greedy segment match: approved `*` may consume one candidate segment only, so a candidate with a
    wildcard where the approved pattern has a literal is not treated as contained.
    """
    approved_parts = approved.split('*')
    if len(approved_parts) == 1:
        return approved == candidate

    # first segment must be a literal prefix
    if not candidate.startswith(approved_parts[0]):
        return False
    position = len(approved_parts[0])

    for index, part in enumerate(approved_parts[1:-1], start=1):
        # a middle `*` spans exactly one candidate segment; find the next literal
        found = candidate.find(part, position)
        if found == -1:
            return False
        position = found + len(part)

    tail = approved_parts[-1]
    if tail and not candidate.endswith(tail):
        return False
    return position <= len(candidate) - len(tail)


def effective_pairs(grant):
    """
    Yield the action/resource pairs a grant applies to.  NotAction/NotResource statements are yielded
    as a single opaque pair so they are judged conservatively rather than expanded to every action.
    """
    if grant['NotActions']:
        actions = grant['NotActions']
        action_is_negated = True
    else:
        actions = grant['Actions'] or ['*']
        action_is_negated = False

    if grant['NotResources']:
        resources = grant['NotResources']
        resource_is_negated = True
    else:
        resources = grant['Resources'] or ['*']
        resource_is_negated = False

    for action in actions:
        for resource in resources:
            yield {
                'Action': action,
                'Resource': resource,
                'ActionIsNegated': action_is_negated,
                'ResourceIsNegated': resource_is_negated
            }


def deny_covers(deny, grant):
    if deny['NotActions'] or deny['NotResources']:
        return False

    for pair in effective_pairs(grant):
        if pair['ActionIsNegated'] or pair['ResourceIsNegated']:
            return False
        action_covered = any(glob_covers(deny_action, pair['Action'])
                             for deny_action in deny['Actions'] or ['*'])
        resource_covered = any(glob_covers(deny_resource, pair['Resource'])
                               for deny_resource in deny['Resources'] or ['*'])
        if not (action_covered and resource_covered):
            return False
    return True


# ------------------------------------------------------------ grant building

def build_grant(statement, source, category, policy_name, statement_index):
    return {
        'Source': source,
        'Category': category,
        'PolicyName': policy_name,
        'StatementIndex': statement_index,
        'Effect': statement.get('Effect', 'Allow'),
        'Actions': _as_list(statement.get('Action')),
        'NotActions': _as_list(statement.get('NotAction')),
        'Resources': _as_list(statement.get('Resource')),
        'NotResources': _as_list(statement.get('NotResource')),
        'Conditions': statement.get('Condition') or {},
        'ConditionSummary': summarize_conditions(statement.get('Condition')),
        'Effective': True,
        'DeniedBy': None,
        'ScopeViolations': [],
        'WithinApprovedScope': True
    }


def _build_scope_exceeded_message(principal_name, grant):
    actions = ', '.join(grant['Actions'] or grant['NotActions']) or '*'
    resources = ', '.join(grant['Resources'] or grant['NotResources']) or '*'
    reasons = ', '.join(sorted({v['Reason'] for v in grant['ScopeViolations']}))
    conditions = ', '.join(grant['ConditionSummary']) if grant['ConditionSummary'] else 'no conditions'
    location = f'resource {grant["ResourceName"]}' if 'ResourceName' in grant else 'identity policy'
    return (f'Role {principal_name} receives {actions} on {resources} from {grant["Source"]} '
            f'"{grant["PolicyName"]}" ({location}) with {conditions}; this exceeds the approved '
            f'scope ({reasons}).')


def summarize_conditions(conditions):
    if not conditions:
        return []
    summary = []
    for operator in sorted(conditions):
        values = conditions[operator]
        if not isinstance(values, dict):
            summary.append(f'{operator} {values}')
            continue
        for key in sorted(values):
            summary.append(f'{operator} {key}={values[key]}')
    return summary


# ------------------------------------------------------------ principal match

class PrincipalMatch:
    def __init__(self, matched, scope=None, value=None):
        self.Matched = matched
        self.Scope = scope
        self.Value = value


def match_principal(statement, role_arn, account_id, partition='aws'):
    if statement.get('NotPrincipal') is not None:
        excluded = _principal_values(statement.get('NotPrincipal'))
        if any(_principal_scope(value, role_arn, account_id, partition) is not None for value in excluded):
            return PrincipalMatch(False)
        return PrincipalMatch(True, PRINCIPAL_SCOPE_NOT_PRINCIPAL, statement.get('NotPrincipal'))

    principal = statement.get('Principal')
    if principal is None:
        return PrincipalMatch(False)

    for value in _principal_values(principal):
        scope = _principal_scope(value, role_arn, account_id, partition)
        if scope is not None:
            return PrincipalMatch(True, scope, value)
    return PrincipalMatch(False)


def _principal_values(principal):
    if principal == '*':
        return ['*']
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        values = []
        for item in principal:
            values.extend(_principal_values(item))
        return values
    if isinstance(principal, dict):
        values = []
        # only the AWS principal type can name an IAM role; Service/Federated/CanonicalUser cannot
        if 'AWS' in principal:
            values.extend(_principal_values(principal['AWS']))
        return values
    return []


def _principal_scope(value, role_arn, account_id, partition):
    if value == '*':
        return PRINCIPAL_SCOPE_WILDCARD
    if not isinstance(value, str):
        return None
    if role_arn is not None and value == role_arn:
        return PRINCIPAL_SCOPE_EXACT
    if value == account_id:
        return PRINCIPAL_SCOPE_ACCOUNT
    if value == f'arn:{partition}:iam::{account_id}:root':
        return PRINCIPAL_SCOPE_ACCOUNT
    parts = value.split(':')
    if len(parts) >= 6 and parts[0] == 'arn' and parts[2] == 'iam' and parts[4] == account_id \
            and value.endswith(':root'):
        return PRINCIPAL_SCOPE_ACCOUNT
    return None


# ------------------------------------------------------------------- helpers

def build_role_arn(role, account_id, partition):
    path = role.RolePath or '/'
    if not path.startswith('/'):
        path = '/' + path
    if path != '/' and not path.endswith('/'):
        path = path + '/'
    prefix = path.lstrip('/')
    return f'arn:{partition}:iam::{account_id}:role/{prefix}{role.RoleName}'


def normalize_principal_filter(principals):
    if principals is None:
        return None
    if isinstance(principals, str):
        principals = [principals]
    values = [value.strip() for value in principals if value and value.strip()]
    return values or None


def _role_matches_filter(role, role_arn, filters):
    normalized = {value.lower() for value in filters}
    return role.RoleName.lower() in normalized or role_arn.lower() in normalized


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_statement_list(policy_document):
    if not isinstance(policy_document, dict):
        return []
    statements = policy_document.get('Statement', [])
    if isinstance(statements, dict):
        return [statements]
    return statements
