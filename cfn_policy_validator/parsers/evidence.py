"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import hashlib
import json


ALL_POLICIES_AUDITED = 'ALL_POLICIES_AUDITED'
PARTIAL_POLICIES_AUDITED = 'PARTIAL_POLICIES_AUDITED'
NO_POLICIES_AUDITED = 'NO_POLICIES_AUDITED'

ANALYSIS_NOT_RUN = 'ANALYSIS_NOT_RUN'
ANALYSIS_NO_FINDINGS = 'ANALYZED_NO_FINDINGS'
ANALYSIS_WITH_FINDINGS = 'ANALYZED_WITH_FINDINGS'
NO_POLICIES_ANALYZED = 'NO_POLICIES_ANALYZED'

# Deployment facts that this library cannot observe from a CloudFormation template.  They are reported alongside the
# parser output so a release gate does not mistake a successful parse (or a clean policy analysis) for proof that the
# target account actually grants the permission.
SOURCE_BOUNDARIES = [
    {
        'Code': 'CLOUDFORMATION_TEMPLATE_POLICIES',
        'Description': 'Only policy documents resolvable from the supplied CloudFormation template were audited. '
                       'A managed policy ARN that resolves to no document is recorded as an evidence gap.'
    },
    {
        'Code': 'IAM_MANAGED_POLICY_LOOKUP',
        'Description': 'AWS-managed policies attached by ARN are read from IAM at analysis time. The template does not '
                       'pin the policy version, so a later version can differ from the one audited.'
    },
    {
        'Code': 'CUSTOMER_MANAGED_POLICY_CONTENT',
        'Description': 'Customer-managed policies referenced by name, path or account-local ARN may not be fetched. '
                       'The publisher must supply the reviewed policy document and the exact version that is deployed.'
    },
    {
        'Code': 'PERMISSIONS_BOUNDARY_EFFECT',
        'Description': 'A permissions boundary is recorded but is not evaluated against the effective permissions '
                       'granted by the attached policies.'
    },
    {
        'Code': 'ACCOUNT_ASSIGNMENTS',
        'Description': 'AWS::SSO::Assignment resources describe intended account/principal/target bindings in the '
                       'template. Assignment propagation, identity store membership, and principal enablement in the '
                       'target account are not observed.'
    },
    {
        'Code': 'IDENTITY_STORE_PRINCIPALS',
        'Description': 'PrincipalId and TargetId are identity store / account identifiers. Group membership, user '
                       'status, and account-level membership are not observed.'
    },
    {
        'Code': 'ORGANIZATION_GUARDRAILS',
        'Description': 'Organization SCPs, resource control policies, and account-level restrictions are not evaluated.'
    },
    {
        'Code': 'EFFECTIVE_ACCOUNT_PERMISSION',
        'Description': 'Policy analysis checks a policy document. A successful parse or a set of non-blocking findings '
                       'does not prove that a principal in the target account can exercise the permission.'
    }
]


def describe_source_boundaries():
    return [dict(boundary) for boundary in SOURCE_BOUNDARIES]


def policy_document_digest(policy_document):
    """
    Stable digest of the exact document handed to the policy analyzer.  Record it alongside findings so the audited
    bytes, not just the display name, are pinned.
    """
    if policy_document is None:
        return None

    canonical = json.dumps(policy_document, sort_keys=True, separators=(',', ':'))
    return 'sha256:' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _audited_policies(permission_set):
    audited = []
    for policy in permission_set.Policies:
        audited.append({
            'PolicyName': policy.Name,
            'Source': policy.Source,
            'Path': policy.Path,
            'IsAWSManagedPolicy': policy.IsAWSManagedPolicy,
            'DocumentAvailable': policy.Policy is not None,
            'DocumentDigest': policy_document_digest(policy.Policy)
        })
    return audited


def _evidence_required(permission_set, assignments):
    evidence = []

    for reference in permission_set.CustomerManagedPolicyReferences:
        evidence.append({
            'Kind': 'CUSTOMER_MANAGED_POLICY_REFERENCE',
            'Reference': reference['Reference'],
            'Reason': reference['Reason'],
            'SourceBoundary': 'CUSTOMER_MANAGED_POLICY_CONTENT'
        })

    for reference in permission_set.ManagedPolicyReferences:
        if reference.get('RequiresPublisherEvidence'):
            if reference['Resolved']:
                kind = 'CUSTOMER_MANAGED_POLICY_VERSION'
                source_boundary = 'CUSTOMER_MANAGED_POLICY_CONTENT'
            else:
                kind = 'UNRESOLVED_MANAGED_POLICY'
                source_boundary = 'CLOUDFORMATION_TEMPLATE_POLICIES'

            evidence.append({
                'Kind': kind,
                'Reference': reference['Reference'],
                'Reason': reference['Reason'],
                'SourceBoundary': source_boundary
            })

    if permission_set.PermissionsBoundary is not None:
        evidence.append({
            'Kind': 'PERMISSIONS_BOUNDARY',
            'Reference': permission_set.PermissionsBoundary['Reference'],
            'Reason': permission_set.PermissionsBoundary['Reason'],
            'SourceBoundary': 'PERMISSIONS_BOUNDARY_EFFECT'
        })

    for assignment in assignments:
        evidence.append({
            'Kind': 'ASSIGNMENT',
            'LogicalId': assignment.get('LogicalId'),
            'PrincipalType': assignment.get('PrincipalType'),
            'PrincipalId': assignment.get('PrincipalId'),
            'TargetType': assignment.get('TargetType'),
            'TargetId': assignment.get('TargetId'),
            'Reason': 'ASSIGNMENT_OUTSIDE_TEMPLATE_EVIDENCE',
            'SourceBoundary': 'ACCOUNT_ASSIGNMENTS'
        })

    return evidence


def _assignments_for(permission_set, assignments):
    if permission_set.PermissionSetArn is None:
        return []

    return [assignment for assignment in assignments
            if assignment.get('PermissionSetArn') == permission_set.PermissionSetArn]


def build_permission_set_evidence(permission_sets, assignments):
    """
    Build a per-permission-set ledger of what documents are available for analysis and which deployment facts still
    require publisher evidence.
    """
    records = []
    matched_assignment_ids = set()
    for permission_set in permission_sets:
        audited_policies = _audited_policies(permission_set)
        matching_assignments = _assignments_for(permission_set, assignments)
        matched_assignment_ids.update(assignment.get('LogicalId') for assignment in matching_assignments)
        evidence_required = _evidence_required(permission_set, matching_assignments)

        if len(audited_policies) == 0:
            coverage = NO_POLICIES_AUDITED
        elif len(evidence_required) > 0:
            coverage = PARTIAL_POLICIES_AUDITED
        else:
            coverage = ALL_POLICIES_AUDITED

        records.append({
            'Name': permission_set.Name,
            'LogicalId': permission_set.LogicalId,
            'InstanceArn': permission_set.InstanceArn,
            'PermissionSetArn': permission_set.PermissionSetArn,
            'Coverage': coverage,
            'AnalysisOutcome': ANALYSIS_NOT_RUN,
            'AuditedPolicies': audited_policies,
            'AnalyzedDocuments': [],
            'EvidenceRequired': evidence_required
        })

    # Assignments to a permission set not described by this template still describe intended access.  Surface them
    # separately so they are not silently dropped.
    unmatched = [assignment for assignment in assignments
                 if assignment.get('LogicalId') not in matched_assignment_ids]

    return records, unmatched


def finalize_permission_set_evidence(evidence_records, analysis_records, findings):
    """
    Reconcile the parse-time ledger with what was actually handed to the policy analyzer and what the analyzer
    returned.  This separates three states that are easy to conflate:

      - no policy document was analyzed
      - policy documents were analyzed and produced no findings
      - policy documents were analyzed and produced findings
    """
    findings_by_resource_and_policy = {}
    for finding in findings.errors + findings.security_warnings + findings.warnings + findings.suggestions:
        key = (finding.resourceName, finding.policyName)
        findings_by_resource_and_policy[key] = findings_by_resource_and_policy.get(key, 0) + 1

    analysis_by_logical_id = {}
    for record in analysis_records:
        analysis_by_logical_id.setdefault(record['LogicalId'], []).append(record)

    finalized = []
    for evidence_record in evidence_records:
        logical_id = evidence_record['LogicalId']
        analyzed = []
        finding_count = 0
        for analysis in analysis_by_logical_id.get(logical_id, []):
            matched = findings_by_resource_and_policy.get(
                (analysis['ReportedResourceName'], analysis['PolicyName']), 0
            )
            finding_count += matched
            analyzed.append({
                'PolicyName': analysis['PolicyName'],
                'ReportedResourceName': analysis['ReportedResourceName'],
                'Source': analysis['Source'],
                'Operation': analysis['Operation'],
                'PolicyType': analysis['PolicyType'],
                'DocumentDigest': analysis['DocumentDigest'],
                'FindingCount': matched
            })

        if len(analyzed) == 0:
            outcome = NO_POLICIES_ANALYZED
        elif finding_count > 0:
            outcome = ANALYSIS_WITH_FINDINGS
        else:
            outcome = ANALYSIS_NO_FINDINGS

        record = dict(evidence_record)
        record['AnalyzedDocuments'] = analyzed
        record['AnalysisOutcome'] = outcome
        finalized.append(record)

    return finalized


def permission_set_display_names(permission_sets):
    """
    Return a mapping from a PermissionSet instance to the name used in findings.  Permission sets from different
    templates (or different logical resources in one template) can share a display name, so collisions are qualified
    with the CloudFormation logical ID.
    """
    counts = {}
    for permission_set in permission_sets:
        counts[permission_set.Name] = counts.get(permission_set.Name, 0) + 1

    names = {}
    for permission_set in permission_sets:
        if counts.get(permission_set.Name, 0) > 1:
            names[id(permission_set)] = f'{permission_set.Name} ({permission_set.LogicalId})'
        else:
            names[id(permission_set)] = permission_set.Name

    return names


def render_acceptance_notes(evidence_records, boundaries):
    """
    Render the acceptance statement as plain text.  It names the source boundaries explicitly so a reviewer does not
    read "parsed" or "no findings" as proof of effective access in the target account.
    """
    lines = ['IAM Identity Center permission set acceptance notes', '']

    lines.append('Permission sets:')
    if not evidence_records:
        lines.append('  (none found in template)')
    for record in evidence_records:
        lines.append(f"  - {record['Name']} (logical id: {record['LogicalId']})")
        lines.append(f"    coverage: {record['Coverage']}")
        lines.append(f"    analysis outcome: {record['AnalysisOutcome']}")
        for policy in record['AuditedPolicies']:
            lines.append(f"    policy document: {policy['PolicyName']} [{policy['Source']}] "
                         f"digest={policy['DocumentDigest']}")
        for evidence in record['EvidenceRequired']:
            detail = evidence.get('Reference') or evidence.get('LogicalId') or ''
            lines.append(f"    evidence required: {evidence['Kind']} {detail} "
                         f"(source boundary: {evidence['SourceBoundary']})")

    lines.extend(['', 'Evidence source boundaries:'])
    for boundary in boundaries:
        lines.append(f"  - {boundary['Code']}: {boundary['Description']}")

    lines.extend([
        '',
        'No policy analysis result in this report proves that an identity in the target account can exercise the '
        'permission. Account bindings, customer-managed policy content and versions, permissions boundaries, '
        'organization guardrails, and identity store membership must be evidenced by the publisher.'
    ])

    return '\n'.join(lines)


def verify_document_backed_analysis(evidence_records, analysis_records):
    """
    Check the invariant that every document a report claims was analyzed is backed by an actual analyzer request with
    a concrete document digest.  Returns a list of human-readable violations; an empty list means the claim is sound.

    This is the guard against a stand-in that treats "we obtained the policy name" as "we validated the policy".
    """
    requests_by_digest = {}
    for record in analysis_records:
        requests_by_digest.setdefault(record['DocumentDigest'], []).append(record)

    violations = []
    for evidence_record in evidence_records:
        for document in evidence_record.get('AnalyzedDocuments', []):
            digest = document.get('DocumentDigest')
            if not digest:
                violations.append(
                    f"{evidence_record['LogicalId']}/{document.get('PolicyName')}: analyzed without a document digest"
                )
                continue
            if digest not in requests_by_digest:
                violations.append(
                    f"{evidence_record['LogicalId']}/{document.get('PolicyName')}: no analyzer request for digest {digest}"
                )
    return violations
