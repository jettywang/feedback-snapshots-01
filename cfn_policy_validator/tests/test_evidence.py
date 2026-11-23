import json
import os
import shutil
import unittest

from cfn_policy_validator import evidence
from cfn_policy_validator.application_error import ApplicationError


NETWORK_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  EnvName:
    Type: String
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'network-${EnvName}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: 'sts:AssumeRole'
      Policies:
        - PolicyName: network-policy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: 's3:GetObject'
                Resource: !Sub
                  - '${BucketArn}/network/*'
                  - BucketArn:
                      Fn::ImportValue: SharedBucketArn
"""

APP_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  EnvName:
    Type: String
  DbPassword:
    Type: String
    NoEcho: true
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'app-${EnvName}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: 'sts:AssumeRole'
      Policies:
        - PolicyName: app-policy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: 's3:GetObject'
                Resource: !Sub
                  - '${BucketArn}/app/*'
                  - BucketArn:
                      Fn::ImportValue: SharedBucketArn
              - Effect: Allow
                Action: 'secretsmanager:GetSecretValue'
                Resource: !Sub 'arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:${DbPassword}'
"""

SECRET_VALUE = 'correct-horse-battery-staple'


def _record(export_value='arn:aws:s3:::shared-team-bucket'):
	return {
		'account': '123456789012',
		'partition': 'aws',
		'region': 'us-east-1',
		'parameters': {
			'EnvName': 'prod',
			'DbPassword': SECRET_VALUE
		},
		'exports': {
			'SharedBucketArn': export_value
		}
	}


class EvidenceTestCase(unittest.TestCase):
	def setUp(self):
		self.test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp_evidence_tests')
		os.makedirs(self.test_dir, exist_ok=True)
		self._files = []
		self.network_path = self._write('network.yaml', NETWORK_TEMPLATE)
		self.app_path = self._write('app.yaml', APP_TEMPLATE)
		self.pack_path = os.path.join(self.test_dir, 'pack.json')
		self.stacks = {'NetworkStack': self.network_path, 'AppStack': self.app_path}

	def tearDown(self):
		shutil.rmtree(self.test_dir, ignore_errors=True)

	def _write(self, name, contents):
		path = os.path.join(self.test_dir, name)
		with open(path, 'w') as stream:
			stream.write(contents)
		self._files.append(path)
		return path

	def _write_record(self, name, record):
		return self._write(name, json.dumps(record))

	def _generate(self):
		return evidence.generate_evidence(self.stacks, _record(), self.pack_path)


class TestGenerateEvidence(EvidenceTestCase):
	def test_records_template_hashes_and_per_stack_provenance(self):
		pack = self._generate()
		self.assertEqual(2, len(pack['templates']))
		claim_ids = {claim['id'] for claim in pack['claims']}
		# both stacks define a role that resolves to AppRole's policies; claims keep per-stack provenance
		self.assertIn('NetworkStack:IdentityPolicy:network-prod:network-policy', claim_ids)
		self.assertIn('AppStack:IdentityPolicy:app-prod:app-policy', claim_ids)
		for claim in pack['claims']:
			self.assertEqual(claim['stack'], claim['id'].split(':')[0])

	def test_sensitive_parameter_values_are_withheld_from_pack(self):
		self._generate()
		with open(self.pack_path) as stream:
			raw_pack = stream.read()
		self.assertNotIn(SECRET_VALUE, raw_pack)

		pack = json.loads(raw_pack)
		secret_entry = [v for v in pack['values'] if v['key'] == 'parameter:AppStack:DbPassword']
		self.assertEqual(1, len(secret_entry))
		self.assertTrue(secret_entry[0]['redacted'])
		self.assertNotIn('value', secret_entry[0])

		unprovable_keys = {entry['key'] for entry in pack['unprovable']}
		self.assertIn('parameter:AppStack:DbPassword', unprovable_keys)

	def test_claims_affected_by_withheld_values_are_marked_not_provable(self):
		pack = self._generate()
		claims_by_id = {claim['id']: claim for claim in pack['claims']}
		app_policy = claims_by_id['AppStack:IdentityPolicy:app-prod:app-policy']
		self.assertFalse(app_policy['provableOffline'])
		self.assertIn('parameter:AppStack:DbPassword', app_policy['affectedBy'])
		self.assertIn('export:SharedBucketArn', app_policy['affectedBy'])
		# the trust policy does not depend on the secret and remains provable
		trust_policy = claims_by_id['AppStack:TrustPolicy:app-prod:AssumeRolePolicyDocument']
		self.assertTrue(trust_policy['provableOffline'])

	def test_templates_are_not_modified(self):
		with open(self.app_path) as stream:
			before = stream.read()
		self._generate()
		with open(self.app_path) as stream:
			after = stream.read()
		self.assertEqual(before, after)


class TestReplayEvidence(EvidenceTestCase):
	def test_replay_reconciles_recorded_review(self):
		self._generate()
		report, reconciled = evidence.replay_evidence(self.pack_path)
		self.assertTrue(reconciled)
		self.assertEqual([], report['failures'])
		self.assertEqual(3, report['claimsCompared'])
		self.assertEqual(['AppStack:IdentityPolicy:app-prod:app-policy'],
		                 report['claimsNotProvableOffline'])

	def test_replay_is_independent_of_read_order(self):
		self._generate()
		recorded_report, recorded_reconciled = evidence.replay_evidence(self.pack_path, read_order='recorded')
		reversed_report, reversed_reconciled = evidence.replay_evidence(self.pack_path, read_order='reverse')
		self.assertTrue(recorded_reconciled)
		self.assertTrue(reversed_reconciled)
		self.assertEqual(recorded_report['claimsCompared'], reversed_report['claimsCompared'])
		self.assertEqual([], reversed_report['failures'])

	def test_replay_reports_claims_affected_by_changed_export(self):
		self._generate()
		changed_record_path = self._write_record('changed.json', _record('arn:aws:s3:::shared-team-bucket-v2'))
		report, reconciled = evidence.replay_evidence(self.pack_path, deployment_record_path=changed_record_path)
		self.assertFalse(reconciled)
		self.assertEqual(1, len(report['changedValues']))
		change = report['changedValues'][0]
		self.assertEqual('export:SharedBucketArn', change['key'])
		self.assertEqual('arn:aws:s3:::shared-team-bucket', change['reviewedValue'])
		self.assertEqual('arn:aws:s3:::shared-team-bucket-v2', change['replayValue'])
		self.assertEqual([
			'AppStack:IdentityPolicy:app-prod:app-policy',
			'NetworkStack:IdentityPolicy:network-prod:network-policy'
		], change['affectedClaims'])

	def test_replay_with_unchanged_record_reconciles(self):
		self._generate()
		same_record_path = self._write_record('same.json', _record())
		report, reconciled = evidence.replay_evidence(self.pack_path, deployment_record_path=same_record_path)
		self.assertTrue(reconciled)
		self.assertEqual([], report['changedValues'])

	def test_replay_detects_modified_template(self):
		self._generate()
		with open(self.app_path, 'a') as stream:
			stream.write('\n# changed after review\n')
		report, reconciled = evidence.replay_evidence(self.pack_path)
		self.assertFalse(reconciled)
		failure_types = {failure['type'] for failure in report['failures']}
		self.assertIn('TemplateModified', failure_types)

	def test_replay_rejects_tampered_pack(self):
		self._generate()
		with open(self.pack_path) as stream:
			pack = json.load(stream)
		pack['claims'][0]['document'] = {}
		with open(self.pack_path, 'w') as stream:
			json.dump(pack, stream)
		with self.assertRaises(ApplicationError):
			evidence.replay_evidence(self.pack_path)


if __name__ == '__main__':
	unittest.main()
