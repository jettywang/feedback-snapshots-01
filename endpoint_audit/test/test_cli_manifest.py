"""Tests for manifest loading, source coordinates and the CLI entry point."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from endpoint_audit.cli import main
from endpoint_audit.manifest import (
    load_json_manifest,
    load_text_manifest,
)


TEXT_MANIFEST = """\
# a comment
edge   tcp:8080
loop   tcp:8081:interface=127.0.0.1
broken tcp:not-a-port
"""

JSON_MANIFEST = json.dumps([
    {"service": "edge", "endpoint": "tcp:8080", "line": 2},
    {"service": "loop", "endpoint": "tcp:9000:interface=127.0.0.1", "line": 3},
])


class ManifestTests(unittest.TestCase):
    def test_text_manifest_keeps_line_coordinates(self):
        declarations = load_text_manifest(TEXT_MANIFEST, "services.manifest")
        self.assertEqual([d.service for d in declarations],
                         ["edge", "loop", "broken"])
        self.assertEqual(declarations[1].coordinate.line, 3)
        self.assertEqual(declarations[2].coordinate.service, "broken")

    def test_text_manifest_rejects_bad_shape_and_duplicates(self):
        with self.assertRaises(ValueError):
            load_text_manifest("only-one-token\n", "x")
        with self.assertRaises(ValueError):
            load_text_manifest("a tcp:1\na tcp:2\n", "x")

    def test_json_manifest_keeps_coordinates(self):
        declarations = load_json_manifest(JSON_MANIFEST, "services.json")
        self.assertEqual(declarations[0].coordinate.line, 2)
        self.assertEqual(declarations[1].endpoint,
                         "tcp:9000:interface=127.0.0.1")


class CliTests(unittest.TestCase):
    def _write(self, content: str, suffix: str = ".manifest") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        self.addCleanup(os.remove, path)
        return path

    def test_exit_codes_and_json_payload(self):
        overlap_path = self._write(
            "a tcp:80\nb haproxy:ssl:80:privateKey=k.pem:certKey=c.pem\n"
        )
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([overlap_path, "--json"])
        self.assertEqual(code, 2)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["summary"]["overlap"], 1)
        pair = payload["pairs"][0]
        self.assertEqual(pair["verdict"], "overlap")
        # Coordinates must lead back to the source lines.
        self.assertEqual(pair["left"]["line"], 1)
        self.assertEqual(pair["right"]["line"], 2)

    def test_clean_manifest_exits_zero(self):
        clean_path = self._write(
            "a tcp:80:interface=127.0.0.1\nb tcp:81:interface=127.0.0.1\n"
        )
        with redirect_stdout(io.StringIO()):
            code = main([clean_path])
        self.assertEqual(code, 0)

    def test_parse_issue_exit_code_is_one(self):
        broken_path = self._write("a tcp:not-a-port\n")
        with redirect_stdout(io.StringIO()):
            code = main([broken_path])
        self.assertEqual(code, 1)

    def test_missing_manifest_is_reported_not_raised(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main([os.path.join(tempfile.gettempdir(), "no-such-file")])
        self.assertEqual(code, 1)
        self.assertIn("manifest error", err.getvalue())

    def test_extension_argument_enables_disclosure(self):
        path = self._write(
            "m metricsd:9100:interface=127.0.0.1\n"
            "t tcp:9100:interface=127.0.0.1\n"
        )
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([path, "--json",
                         "--extension", "examples.runtime_plugin"])
        self.assertEqual(code, 2)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["summary"]["overlap"], 1)

    def test_json_manifest_runs_through_the_cli(self):
        path = self._write(
            json.dumps([
                {"service": "a", "endpoint": "tcp:80", "line": 1},
                {"service": "b", "endpoint": "tcp:81", "line": 2},
            ]),
            suffix=".json",
        )
        with redirect_stdout(io.StringIO()) as out:
            code = main([path])
        self.assertEqual(code, 0)
        self.assertIn("CONFIRMED SEPARATE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
