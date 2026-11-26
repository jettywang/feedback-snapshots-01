import json
import os
import unittest

from click.testing import CliRunner

from policy_sentry.command.create_template import create_template
from policy_sentry.command.handover import handover

EXAMPLE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.path.pardir,
        os.path.pardir,
        "examples",
        "yml",
        "handover",
        "two-project-handover.yml",
    )
)


class HandoverClickTestCase(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def _invoke(self, *args):
        result = self.runner.invoke(handover, list(args))
        self.assertEqual(result.exit_code, 0, result.output)
        return result

    def test_single_timestamp_returns_one_report(self):
        result = self._invoke("--input-file", EXAMPLE, "--at", "2026-12-01T12:00:00Z")
        report = json.loads(result.output)
        self.assertEqual(report["handover"]["status"], "active")
        self.assertEqual(report["handover"]["active_projects"], ["project-alpha"])

    def test_repeated_timestamps_compare_phases(self):
        result = self._invoke(
            "--input-file",
            EXAMPLE,
            "--at",
            "2026-11-30T00:00:00Z",
            "--at",
            "2026-12-01T12:00:00Z",
            "--at",
            "2026-12-03T00:00:00Z",
        )
        reports = json.loads(result.output)
        self.assertEqual([report["handover"]["status"] for report in reports], ["scheduled", "active", "expired"])

    def test_show_temporary_is_empty_after_expiry(self):
        result = self._invoke("--input-file", EXAMPLE, "--at", "2026-12-03T00:00:00Z", "--show", "temporary")
        self.assertEqual(json.loads(result.output)["Statement"], [])

    def test_show_effective_during_window(self):
        result = self._invoke("--input-file", EXAMPLE, "--at", "2026-12-01T12:00:00Z", "--show", "effective")
        policy = json.loads(result.output)
        self.assertTrue(any("s3:PutObject" in statement["Action"] for statement in policy["Statement"]))

    def test_yaml_output(self):
        result = self._invoke("--input-file", EXAMPLE, "--at", "2026-12-01T12:00:00Z", "--fmt", "yaml")
        self.assertIn("status: active", result.output)

    def test_missing_handover_block_is_a_click_error(self):
        with self.runner.isolated_filesystem():
            with open("plain.yml", "w", encoding="utf-8") as file:
                file.write("mode: crud\nread:\n- 'arn:aws:s3:::bucket/*'\n")
            result = self.runner.invoke(handover, ["--input-file", "plain.yml", "--at", "2026-12-01T12:00:00Z"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("no `handover` block", result.output)


class CreateHandoverTemplateClickTestCase(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_create_handover_template(self):
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                create_template, ["--output-file", "handover.yml", "--template-type", "handover"]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            with open("handover.yml", encoding="utf-8") as file:
                content = file.read()
        self.assertIn("handover:", content)
        self.assertIn("approval:", content)
        self.assertIn("projects:", content)

    def test_create_crud_template_has_no_handover(self):
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(create_template, ["--output-file", "crud.yml", "--template-type", "crud"])
            self.assertEqual(result.exit_code, 0, result.output)
            with open("crud.yml", encoding="utf-8") as file:
                content = file.read()
        self.assertNotIn("handover:", content)
