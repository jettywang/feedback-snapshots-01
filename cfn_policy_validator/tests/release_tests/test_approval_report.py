"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import tempfile
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.release.approval_report import ApprovalReport

from cfn_policy_validator.tests.release_tests.fixtures import POLICY_ARN, NEW_VERSION, build_approval_report


class WhenLoadingAnApprovalReportFromFile(unittest.TestCase):
	def test_loads_pinned_versions(self):
		with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
			json.dump(build_approval_report(), handle)
			path = handle.name

		try:
			report = ApprovalReport.load(path)
		finally:
			os.remove(path)

		self.assertEqual(1, len(report))
		self.assertEqual(NEW_VERSION, report.get_basis_for(POLICY_ARN).approved_version_id)

	def test_missing_file_raises_application_error(self):
		missing = os.path.join(tempfile.gettempdir(), 'does-not-exist-approval-report.json')
		if os.path.exists(missing):
			os.remove(missing)

		with self.assertRaises(ApplicationError):
			ApprovalReport.load(missing)

	def test_invalid_json_raises_application_error(self):
		with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
			handle.write('{not valid json')
			path = handle.name

		try:
			with self.assertRaises(ApplicationError):
				ApprovalReport.load(path)
		finally:
			os.remove(path)


if __name__ == '__main__':
	unittest.main()
