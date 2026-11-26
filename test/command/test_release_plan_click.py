import json
import os
import unittest
from pathlib import Path

import orjson
from click.testing import CliRunner

from policy_sentry.command.release_plan import release_plan

SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenySecretExport",
            "Effect": "Deny",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
        },
        {
            "Sid": "S3ReadWrite",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::example-org-audit-logs",
                "arn:aws:s3:::example-org-audit-logs/*",
                "arn:aws:s3:::example-org-data",
                "arn:aws:s3:::example-org-data/*",
            ],
        },
    ],
}


class ReleasePlanClickTestCase(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.tmpdir = os.environ["TMPDIR"]

    def test_stdin_input_produces_feasible_plan(self):
        result = self.runner.invoke(
            release_plan,
            ["--max-bytes", "450"],
            input=orjson.dumps(SAMPLE_POLICY),
        )
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["feasible"])
        self.assertGreaterEqual(payload["manifest"]["batch_count"], 2)
        first_batch = payload["documents"][0]
        self.assertEqual(first_batch["Statement"][0]["Effect"], "Deny")

    def test_output_dir_writes_batch_artifacts_and_manifest(self):
        input_path = Path(self.tmpdir) / "release-input.json"
        output_dir = Path(self.tmpdir) / "release-out"
        input_path.write_bytes(orjson.dumps(SAMPLE_POLICY))
        result = self.runner.invoke(
            release_plan,
            ["-i", str(input_path), "--max-bytes", "450", "-o", str(output_dir)],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        manifest = orjson.loads((output_dir / "release-manifest.json").read_bytes())
        self.assertTrue(manifest["feasible"])
        written = sorted(path.name for path in output_dir.glob("batch-*.json"))
        self.assertEqual(len(written), manifest["batch_count"])
        for name in written:
            document = orjson.loads((output_dir / name).read_bytes())
            self.assertEqual(document["Version"], "2012-10-17")

    def test_infeasible_policy_exits_two_with_blockers(self):
        impossible = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::" + "x" * 9000]}
            ],
        }
        result = self.runner.invoke(release_plan, input=orjson.dumps(impossible))
        self.assertEqual(result.exit_code, 2)
        payload = json.loads(result.output)
        self.assertFalse(payload["feasible"])
        self.assertTrue(payload["blockers"])

    def test_yaml_output_format(self):
        result = self.runner.invoke(
            release_plan,
            ["--fmt", "yaml", "--max-bytes", "450"],
            input=orjson.dumps(SAMPLE_POLICY),
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("feasible: true", result.output)

    def test_missing_statement_exits_cleanly(self):
        result = self.runner.invoke(release_plan, input=orjson.dumps({"Version": "2012-10-17"}))
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Statement", result.output)


if __name__ == "__main__":
    unittest.main()
