"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import unittest

from cfn_policy_validator import parse, validate
from cfn_policy_validator.parsers.evidence import policy_document_digest
from cfn_policy_validator.tests import account_config
from cfn_policy_validator.tests.acceptance_tests.harness import AcceptanceHarness, RecordingAccessAnalyzer, FakeIam


THESE_TESTS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

READ_ONLY_ACCESS_POLICY = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': ['s3:Get*', 's3:List*'],
            'Resource': '*'
        }
    ]
}

AWS_READ_ONLY_ACCESS_ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
NEEDS_EVIDENCE_ARN = 'arn:aws:iam::111222333444:policy/NeedsEvidence'
PUBLISHER_BOUNDARY_ARN = 'arn:aws:iam::111222333444:policy/PublisherBoundary'


def read_fixture(file_name):
    with open(os.path.join(THESE_TESTS_DIRECTORY, 'fixtures', file_name), 'r') as fixture:
        return fixture.read()


def finding_for_action(action):
    def findings_for_document(record):
        for statement in record.policy_document.get('Statement', []):
            if statement.get('Action') == action or action in (statement.get('Action') or []):
                return [{
                    'issueCode': 'PASS_ROLE_WITH_STAR_IN_RESOURCE',
                    'findingDetails': 'details',
                    'findingType': 'SECURITY_WARNING',
                    'learnMoreLink': 'link',
                    'locations': []
                }]
        return []
    return findings_for_document


def build_iam_endpoint(include_needs_evidence_document=True):
    needs_evidence = {
        'PolicyName': 'NeedsEvidence',
        'DefaultVersionId': 'v1',
        'Path': '/'
    }
    if include_needs_evidence_document:
        needs_evidence['Document'] = {
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Action': 'iam:CreateRole', 'Resource': '*'}]
        }
    else:
        # only the name is obtainable.  The version read fails, so no document can be audited.
        needs_evidence['GetPolicyVersion'] = 'AccessDenied'

    return FakeIam({
        AWS_READ_ONLY_ACCESS_ARN: {
            'PolicyName': 'ReadOnlyAccess',
            'DefaultVersionId': 'v1',
            'Path': '/',
            'Document': READ_ONLY_ACCESS_POLICY
        },
        NEEDS_EVIDENCE_ARN: needs_evidence
    })


class PermissionSetAcceptanceTestCase(unittest.TestCase):
    def validate_stack(self, template_body, analyzer=None, iam=None):
        harness = AcceptanceHarness(
            analyzer=analyzer if analyzer is not None else RecordingAccessAnalyzer(),
            iam=iam if iam is not None else build_iam_endpoint()
        )
        with harness.installed():
            report = validate(
                template_body,
                account_config.region,
                account_config.account_id,
                account_config.partition
            )
        return report, harness

    def parse_stack(self, template_body, iam=None):
        harness = AcceptanceHarness(iam=iam if iam is not None else build_iam_endpoint())
        with harness.installed():
            output = parse(
                template_body,
                account_config.region,
                account_config.account_id,
                account_config.partition
            )
        return output, harness


class WhenAcceptingStackWithInlineAndResolvableAttachedPolicies(PermissionSetAcceptanceTestCase):
    """
    Stack A has one permission set with an inline policy plus a template-defined managed policy and an AWS-managed
    policy, and a second permission set that shares its display name.
    """

    def setUp(self):
        self.template_body = read_fixture('resolvable_managed_policies.yaml')
        self.analyzer = RecordingAccessAnalyzer()
        self.report, self.harness = self.validate_stack(self.template_body, analyzer=self.analyzer)

    def test_every_policy_document_is_submitted_to_the_analyzer(self):
        documents = self.analyzer.analyzed_documents()
        self.assertEqual(4, len(documents), 'Expected inline + template managed + AWS managed + second inline')

        analyzed_digests = {policy_document_digest(document) for document in documents}
        self.assertEqual(analyzed_digests, {policy_document_digest(document) for document in [
            {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': '*'}]},
            {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sqs:SendMessage'], 'Resource': '*'}]},
            READ_ONLY_ACCESS_POLICY,
            {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['iam:ListRoles'], 'Resource': '*'}]}
        ]})

    def test_the_document_handed_to_the_analyzer_matches_the_template_policy_content(self):
        documents = self.analyzer.analyzed_documents()
        sqs_policy = next(document for document in documents
                          if document['Statement'][0].get('Action') == ['sqs:SendMessage'])
        self.assertEqual(
            {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sqs:SendMessage'], 'Resource': '*'}]},
            sqs_policy
        )

    def test_same_display_name_is_resolved_to_distinct_permission_sets(self):
        evidence = self.report['PermissionSetEvidence']
        self.assertEqual(2, len(evidence), 'Two permission sets share the display name but are distinct resources')

        by_logical_id = {record['LogicalId']: record for record in evidence}
        self.assertEqual({'ReadOnlyPermissionSet', 'AdminPermissionSet'}, set(by_logical_id))
        self.assertEqual(2, len({record['PermissionSetArn'] for record in evidence}))
        for record in evidence:
            self.assertEqual('SharedAccess', record['Name'])

    def test_covered_documents_are_recorded_per_permission_set_not_just_by_name(self):
        by_logical_id = {record['LogicalId']: record for record in self.report['PermissionSetEvidence']}

        read_only = by_logical_id['ReadOnlyPermissionSet']
        self.assertEqual(
            {'InlinePolicy', 'AttachedManagedPolicy', 'ReadOnlyAccess'},
            {policy['PolicyName'] for policy in read_only['AuditedPolicies']}
        )
        self.assertEqual(
            {'InlinePolicy', 'AttachedManagedPolicy', 'ReadOnlyAccess'},
            {document['PolicyName'] for document in read_only['AnalyzedDocuments']},
            'All three readable documents were submitted to the analyzer'
        )
        self.assertEqual(
            {'INLINE_POLICY', 'MANAGED_POLICY_TEMPLATE', 'MANAGED_POLICY_EXTERNAL'},
            {policy['Source'] for policy in read_only['AuditedPolicies']}
        )
        self.assertEqual({'InlinePolicy'}, {policy['PolicyName'] for policy in by_logical_id['AdminPermissionSet']['AuditedPolicies']})

    def test_clean_analysis_is_reported_as_no_findings_not_as_absent_coverage(self):
        for record in self.report['PermissionSetEvidence']:
            self.assertEqual('ANALYZED_NO_FINDINGS', record['AnalysisOutcome'])
            self.assertTrue(record['AnalyzedDocuments'], 'A clean result still needs analyzed documents recorded')

        self.assertEqual([], self.report['BlockingFindings'])
        self.assertEqual([], self.report['NonBlockingFindings'])
        self.assertEqual(4, len(self.analyzer.analyzed_documents()),
                         'Four documents were analyzed even though the result is clean')

    def test_account_assignment_is_evidence_the_publisher_still_owes(self):
        read_only = next(record for record in self.report['PermissionSetEvidence']
                         if record['LogicalId'] == 'ReadOnlyPermissionSet')
        self.assertEqual('PARTIAL_POLICIES_AUDITED', read_only['Coverage'])

        assignment_evidence = [evidence for evidence in read_only['EvidenceRequired']
                               if evidence['Kind'] == 'ASSIGNMENT']
        self.assertEqual(1, len(assignment_evidence))
        self.assertEqual('ReadOnlyAssignment', assignment_evidence[0]['LogicalId'])
        self.assertEqual('ACCOUNT_ASSIGNMENTS', assignment_evidence[0]['SourceBoundary'])

    def test_resolvable_stack_has_no_unresolved_managed_policy_evidence(self):
        for record in self.report['PermissionSetEvidence']:
            kinds = {evidence['Kind'] for evidence in record['EvidenceRequired']}
            self.assertNotIn('UNRESOLVED_MANAGED_POLICY', kinds)
            self.assertNotIn('CUSTOMER_MANAGED_POLICY_REFERENCE', kinds)

    def test_analyzed_document_digests_reconcile_with_the_audited_policy_digests(self):
        by_logical_id = {record['LogicalId']: record for record in self.report['PermissionSetEvidence']}

        for logical_id, record in by_logical_id.items():
            audited = {policy['PolicyName']: policy['DocumentDigest'] for policy in record['AuditedPolicies']}
            analyzed = {document['PolicyName']: document['DocumentDigest'] for document in record['AnalyzedDocuments']}
            for policy_name, digest in analyzed.items():
                self.assertEqual(audited[policy_name], digest,
                                 f'Analyzer digest for {logical_id}/{policy_name} must match the recorded policy')


class WhenAcceptingStackWithUnavailableExternalReference(PermissionSetAcceptanceTestCase):
    """
    Stack B has a reviewed inline policy but a customer-managed policy whose document cannot be read, a customer-managed
    policy reference that is never fetched, and a permissions boundary that is not evaluated.
    """

    def setUp(self):
        self.template_body = read_fixture('unavailable_external_reference.yaml')
        self.analyzer = RecordingAccessAnalyzer()
        self.iam = build_iam_endpoint(include_needs_evidence_document=False)
        self.report, self.harness = self.validate_stack(self.template_body, analyzer=self.analyzer, iam=self.iam)
        self.record = self.report['PermissionSetEvidence'][0]

    def test_reviewed_inline_policy_stays_associated_with_the_permission_set(self):
        self.assertEqual(1, len(self.report['PermissionSetEvidence']))
        self.assertEqual('PublisherPending', self.record['Name'])
        self.assertEqual('PublisherPendingPermissionSet', self.record['LogicalId'])

        self.assertEqual(['InlinePolicy'], [policy['PolicyName'] for policy in self.record['AuditedPolicies']])
        self.assertEqual(['InlinePolicy'], [document['PolicyName'] for document in self.record['AnalyzedDocuments']])

        inline_document = self.analyzer.analyzed_documents()[0]
        self.assertEqual(
            {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['s3:ListBucket'], 'Resource': '*'}]},
            inline_document
        )

    def test_partial_coverage_names_each_missing_piece(self):
        self.assertEqual('PARTIAL_POLICIES_AUDITED', self.record['Coverage'])
        self.assertEqual('ANALYZED_NO_FINDINGS', self.record['AnalysisOutcome'])

        kinds = {evidence['Kind']: evidence for evidence in self.record['EvidenceRequired']}
        self.assertEqual(
            {'UNRESOLVED_MANAGED_POLICY', 'CUSTOMER_MANAGED_POLICY_REFERENCE', 'PERMISSIONS_BOUNDARY', 'ASSIGNMENT'},
            set(kinds)
        )
        self.assertEqual(NEEDS_EVIDENCE_ARN, kinds['UNRESOLVED_MANAGED_POLICY']['Reference'])
        self.assertEqual('/team/AnotherCustomerManaged', kinds['CUSTOMER_MANAGED_POLICY_REFERENCE']['Reference'])
        self.assertEqual(PUBLISHER_BOUNDARY_ARN, kinds['PERMISSIONS_BOUNDARY']['Reference'])
        self.assertEqual('PublisherPendingAssignment', kinds['ASSIGNMENT']['LogicalId'])

    def test_unavailable_external_reference_is_not_analyzed_as_content(self):
        analyzed_policy_names = {document['PolicyName'] for document in self.record['AnalyzedDocuments']}
        self.assertNotIn('NeedsEvidence', analyzed_policy_names)
        self.assertNotIn('NeedsEvidence', {policy['PolicyName'] for policy in self.record['AuditedPolicies']})

        # the lookup obtained a name but not a version document
        self.assertIn(('GetPolicy', NEEDS_EVIDENCE_ARN), self.iam.calls)
        self.assertIn(('GetPolicyVersion', NEEDS_EVIDENCE_ARN, 'v1'), self.iam.calls)

    def test_successful_parse_does_not_claim_effective_account_permission(self):
        json_report = self.report
        self.assertEqual([], json_report['BlockingFindings'])

        self.assertIn('EFFECTIVE_ACCOUNT_PERMISSION', {boundary['Code'] for boundary in json_report['EvidenceSourceBoundaries']})
        self.assertIn('does not prove', json_report['AcceptanceNotes'])
        self.assertIn('UNRESOLVED_MANAGED_POLICY', json_report['AcceptanceNotes'])
        self.assertIn('PublisherPendingAssignment', json_report['AcceptanceNotes'])


class WhenAPolicyNameIsAvailableButItsContentIsNot(PermissionSetAcceptanceTestCase):
    """
    A lookup that returns a policy name is not evidence that the policy content was validated.  This guards against a
    test double that mistakes `PolicyName` for the document.
    """

    def setUp(self):
        self.template_body = read_fixture('unavailable_external_reference.yaml')
        self.analyzer = RecordingAccessAnalyzer()
        self.report, _ = self.validate_stack(
            self.template_body,
            analyzer=self.analyzer,
            iam=build_iam_endpoint(include_needs_evidence_document=False)
        )
        self.record = self.report['PermissionSetEvidence'][0]

    def test_name_only_lookup_does_not_create_an_audited_policy(self):
        references = [evidence for evidence in self.record['EvidenceRequired']
                      if evidence['Kind'] == 'UNRESOLVED_MANAGED_POLICY']
        self.assertEqual(1, len(references))
        self.assertEqual(NEEDS_EVIDENCE_ARN, references[0]['Reference'])

        documents = self.analyzer.analyzed_documents()
        self.assertEqual(1, len(documents))
        self.assertEqual(['s3:ListBucket'], documents[0]['Statement'][0]['Action'])

    def test_a_policy_name_does_not_grow_the_audited_policy_list(self):
        # only the inline policy had a readable document, so it is the only audited policy.  The name returned by the
        # IAM lookup must not be recorded as a policy that was reviewed.
        self.assertEqual(['InlinePolicy'], [policy['PolicyName'] for policy in self.record['AuditedPolicies']])
        self.assertEqual(['INLINE_POLICY'], [policy['Source'] for policy in self.record['AuditedPolicies']])

    def test_name_only_reference_cannot_be_claimed_as_analyzed_document(self):
        from cfn_policy_validator.parsers.evidence import verify_document_backed_analysis

        # a stand-in that records an analysis by policy name only (no document digest) must be rejected
        forged = [{
            'Name': 'PublisherPending',
            'LogicalId': 'PublisherPendingPermissionSet',
            'AnalyzedDocuments': [{
                'PolicyName': 'NeedsEvidence',
                'DocumentDigest': None
            }]
        }]
        violations = verify_document_backed_analysis(forged, [])
        self.assertEqual(1, len(violations))
        self.assertIn('without a document digest', violations[0])

    def test_report_rejects_a_name_only_analysis_record(self):
        from cfn_policy_validator.parsers.evidence import verify_document_backed_analysis

        forged = [{
            'Name': 'PublisherPending',
            'LogicalId': 'PublisherPendingPermissionSet',
            'AnalyzedDocuments': [{
                'PolicyName': 'InlinePolicy',
                'DocumentDigest': 'sha256:not-a-real-request'
            }]
        }]
        violations = verify_document_backed_analysis(forged, [])
        self.assertEqual(1, len(violations))
        self.assertIn('no analyzer request for digest', violations[0])

    def test_analyzer_endpoint_rejects_a_policy_name_in_place_of_a_document(self):
        from cfn_policy_validator.tests.acceptance_tests.harness import RecordedPolicyAnalysis

        with self.assertRaises(AssertionError):
            RecordedPolicyAnalysis(operation='ValidatePolicy', policy_type='IDENTITY_POLICY',
                                   policy_document='NeedsEvidence')


class WhenAPermissionSetHasNoPolicies(PermissionSetAcceptanceTestCase):
    def test_reports_no_policies_audited_rather_than_clean(self):
        template_body = json.dumps({
            'Resources': {
                'EmptyPermissionSet': {
                    'Type': 'AWS::SSO::PermissionSet',
                    'Properties': {
                        'Name': 'Empty',
                        'InstanceArn': 'arn:aws:sso:::instance/ssoins-111222333444'
                    }
                }
            }
        })

        report, harness = self.validate_stack(template_body)

        self.assertEqual(1, len(report['PermissionSetEvidence']))
        record = report['PermissionSetEvidence'][0]
        self.assertEqual('NO_POLICIES_AUDITED', record['Coverage'])
        self.assertEqual('NO_POLICIES_ANALYZED', record['AnalysisOutcome'])
        self.assertEqual([], harness.analyzer.analyzed_documents())


class WhenFindingsAreReportedForSameNamedPermissionSets(PermissionSetAcceptanceTestCase):
    def test_findings_name_the_specific_permission_set(self):
        analyzer = RecordingAccessAnalyzer(findings_for_document=finding_for_action('iam:ListRoles'))
        report, _ = self.validate_stack(read_fixture('resolvable_managed_policies.yaml'), analyzer=analyzer)

        blocking = report['BlockingFindings']
        self.assertEqual(1, len(blocking))
        self.assertEqual('SharedAccess (AdminPermissionSet)', blocking[0]['resourceName'])
        self.assertEqual('InlinePolicy', blocking[0]['policyName'])

        evidence = {record['LogicalId']: record for record in report['PermissionSetEvidence']}
        self.assertEqual('ANALYZED_WITH_FINDINGS', evidence['AdminPermissionSet']['AnalysisOutcome'])
        self.assertEqual(1, evidence['AdminPermissionSet']['AnalyzedDocuments'][0]['FindingCount'])
        self.assertEqual('ANALYZED_NO_FINDINGS', evidence['ReadOnlyPermissionSet']['AnalysisOutcome'])

    def test_a_finding_for_one_same_named_set_does_not_mark_the_other_as_flagged(self):
        # only the ReadOnlyPermissionSet inline policy (s3:GetObject) is flagged; the AdminPermissionSet policy is not
        analyzer = RecordingAccessAnalyzer(findings_for_document=finding_for_action('s3:GetObject'))
        report, _ = self.validate_stack(read_fixture('resolvable_managed_policies.yaml'), analyzer=analyzer)

        blocking = report['BlockingFindings']
        self.assertEqual(1, len(blocking))
        self.assertEqual('SharedAccess (ReadOnlyPermissionSet)', blocking[0]['resourceName'])

        evidence = {record['LogicalId']: record for record in report['PermissionSetEvidence']}
        self.assertEqual('ANALYZED_WITH_FINDINGS', evidence['ReadOnlyPermissionSet']['AnalysisOutcome'])
        inline_documents = [document for document in evidence['ReadOnlyPermissionSet']['AnalyzedDocuments']
                            if document['PolicyName'] == 'InlinePolicy']
        self.assertEqual(1, len(inline_documents))
        self.assertEqual(1, inline_documents[0]['FindingCount'])
        self.assertEqual('ANALYZED_NO_FINDINGS', evidence['AdminPermissionSet']['AnalysisOutcome'])


class WhenCoverageAndFindingsDiffer(PermissionSetAcceptanceTestCase):
    """
    Coverage (what was audited) and analysis outcome (what the analyzer returned) are independent.  A permission set
    with a missing external reference can still have zero findings; that is not full coverage, and a fully covered set
    can still have findings.
    """

    def test_unavailable_reference_with_clean_findings_is_partial_not_all_audited(self):
        report, _ = self.validate_stack(
            read_fixture('unavailable_external_reference.yaml'),
            analyzer=RecordingAccessAnalyzer(),
            iam=build_iam_endpoint(include_needs_evidence_document=False)
        )
        record = report['PermissionSetEvidence'][0]
        self.assertEqual('PARTIAL_POLICIES_AUDITED', record['Coverage'])
        self.assertEqual('ANALYZED_NO_FINDINGS', record['AnalysisOutcome'])
        self.assertEqual([], report['BlockingFindings'])

    def test_fully_covered_set_with_findings_is_all_audited_and_with_findings(self):
        analyzer = RecordingAccessAnalyzer(findings_for_document=finding_for_action('sqs:SendMessage'))
        report, _ = self.validate_stack(read_fixture('resolvable_managed_policies.yaml'), analyzer=analyzer)

        evidence = {record['LogicalId']: record for record in report['PermissionSetEvidence']}
        self.assertEqual('PARTIAL_POLICIES_AUDITED', evidence['ReadOnlyPermissionSet']['Coverage'],
                         'The assignment still requires evidence')
        self.assertEqual('ANALYZED_WITH_FINDINGS', evidence['ReadOnlyPermissionSet']['AnalysisOutcome'])
        self.assertEqual(1, len(report['BlockingFindings']))
        self.assertEqual('SharedAccess (ReadOnlyPermissionSet)', report['BlockingFindings'][0]['resourceName'])
        self.assertEqual('AttachedManagedPolicy', report['BlockingFindings'][0]['policyName'])


class WhenACustomerManagedPolicyDocumentIsReadable(PermissionSetAcceptanceTestCase):
    def test_version_pinning_is_still_an_evidence_gap(self):
        # The document is readable, so it can be analyzed, but the template does not pin the version that will be
        # attached at deploy time.  Coverage is therefore partial even though every document was analyzed.
        report, harness = self.validate_stack(
            read_fixture('unavailable_external_reference.yaml'),
            analyzer=RecordingAccessAnalyzer(),
            iam=build_iam_endpoint(include_needs_evidence_document=True)
        )
        record = report['PermissionSetEvidence'][0]

        self.assertIn('NeedsEvidence', {document['PolicyName'] for document in record['AnalyzedDocuments']})
        evidence = {entry['Kind']: entry for entry in record['EvidenceRequired']}
        self.assertEqual('CUSTOMER_MANAGED_POLICY_VERSION', evidence['CUSTOMER_MANAGED_POLICY_VERSION']['Kind'])
        self.assertEqual('CUSTOMER_MANAGED_POLICY_CONTENT',
                         evidence['CUSTOMER_MANAGED_POLICY_VERSION']['SourceBoundary'])
        self.assertEqual('PARTIAL_POLICIES_AUDITED', record['Coverage'])


class WhenParsingWithoutAnAnalyzer(PermissionSetAcceptanceTestCase):
    def test_parse_output_marks_analysis_as_not_run_and_lists_source_boundaries(self):
        output, harness = self.parse_stack(read_fixture('resolvable_managed_policies.yaml'))

        self.assertEqual([], harness.analyzer.analyzed_documents())
        self.assertEqual(2, len(output['PermissionSetEvidence']))
        for record in output['PermissionSetEvidence']:
            self.assertEqual('ANALYSIS_NOT_RUN', record['AnalysisOutcome'])

        boundaries = {boundary['Code'] for boundary in output['EvidenceSourceBoundaries']}
        self.assertTrue({'ACCOUNT_ASSIGNMENTS', 'CUSTOMER_MANAGED_POLICY_CONTENT', 'EFFECTIVE_ACCOUNT_PERMISSION'} <= boundaries)


class WhenRunningTheCliParseCommand(PermissionSetAcceptanceTestCase):
    def test_cli_parse_emits_the_same_evidence_ledger(self):
        import json as json_module
        from cfn_policy_validator import main
        from cfn_policy_validator.tests.utils import captured_output

        template_path = os.path.join(THESE_TESTS_DIRECTORY, 'fixtures', 'unavailable_external_reference.yaml')
        harness = AcceptanceHarness(iam=build_iam_endpoint(include_needs_evidence_document=False))

        with harness.installed(), captured_output() as (out, err):
            with self.assertRaises(SystemExit) as context_manager:
                main.main(['parse', '--template-path', template_path, '--region', account_config.region])

        self.assertEqual(0, context_manager.exception.code, err.getvalue())
        output = json_module.loads(out.getvalue())

        self.assertEqual('ANALYSIS_NOT_RUN', output['PermissionSetEvidence'][0]['AnalysisOutcome'])
        self.assertEqual('PARTIAL_POLICIES_AUDITED', output['PermissionSetEvidence'][0]['Coverage'])
        self.assertEqual(1, len(output['PermissionSetAssignments']))
        self.assertEqual([], harness.analyzer.analyzed_documents())
