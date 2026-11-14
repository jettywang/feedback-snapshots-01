# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for explicit inspection input binding before execution."""

import hashlib
import json
import os
import sys
import unittest
import unittest.mock
from pathlib import Path

import securesystemslib.exceptions

import in_toto.inspection_binding
from in_toto.exceptions import InspectionInputError
from in_toto.in_toto_verify import main as in_toto_verify_main
from in_toto.models.layout import Inspection, InspectionInput, Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import in_toto_verify, run_all_inspections
from tests import common
from tests.common import PEMS, SignerStore, TmpDirMixin

FAKE_EXECUTOR = """import os
import sys

COUNTER = os.environ["FAKE_EXECUTOR_COUNTER"]
with open(COUNTER, encoding="utf8") as fp:
    count = int(fp.read())

with open(COUNTER, "w", encoding="utf8") as fp:
    fp.write(str(count + 1))

with open("executed.txt", "a", encoding="utf8") as fp:
    fp.write("executed\\n")

sys.exit(0)
"""


class TmpDirTestCase(TmpDirMixin, unittest.TestCase):
    """Test case that creates and changes into a temporary directory."""

    def setUp(self):
        self.set_up_test_dir()

    def tearDown(self):
        self.tear_down_test_dir()

    def write(self, path, data):
        """Write data to path, creating parent directories."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf8")
        return path


class TestInspectionInputModel(unittest.TestCase):
    """Test InspectionInput parsing and validation."""

    def test_compact_forms(self):
        """Compact and dict forms resolve to explicit binding fields."""
        compact = InspectionInput(name="package:dist/foo.tar.gz")
        self.assertEqual(compact.from_step, "package")
        self.assertEqual(compact.from_type, "products")
        self.assertEqual(compact.name, "dist/foo.tar.gz")
        self.assertEqual(compact.link_path, "dist/foo.tar.gz")
        self.assertEqual(compact.record_method, "file")

        materials = InspectionInput(name="compile:src/foo.c@materials")
        self.assertEqual(materials.from_step, "compile")
        self.assertEqual(materials.from_type, "materials")
        self.assertEqual(materials.name, "src/foo.c")

        explicit = InspectionInput(
            name="src/foo.c",
            from_step="compile",
            from_type="materials",
            link_path="foo.c",
        )
        self.assertEqual(explicit.link_path, "foo.c")

    def test_invalid_paths(self):
        """Absolute, traversing, unnormalized and backslash paths are rejected."""
        for name in [
            "/etc/passwd",
            "package:/etc/passwd",
            "../foo",
            "package:../foo",
            "package:./foo",
            "package:foo/../bar",
            "package:foo//bar",
            "package:foo/",
            "package:foo\\bar",
        ]:
            with self.assertRaises(
                securesystemslib.exceptions.FormatError, msg=name
            ):
                InspectionInput(name=name)

    def test_invalid_record_method(self):
        """Non-file recording methods are rejected."""
        for record_method in ["directory", "ostree", "dir"]:
            with self.assertRaises(securesystemslib.exceptions.FormatError):
                InspectionInput(name="package:foo", record_method=record_method)

    def test_add_input_from_string(self):
        """Inspection helper appends and validates a compact declaration."""
        inspection = Inspection(name="untar")
        inspection.add_input_from_string("package:foo.tar.gz")
        self.assertEqual(inspection.inputs[0].from_step, "package")
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            inspection.add_input_from_string("/absolute/path")

    def test_invalid_source_type(self):
        """Only materials and products are accepted."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            InspectionInput(name="package:foo@byproducts")

    def test_missing_source_step(self):
        """A name without source step cannot be bound."""
        for name in ["foo", "foo@products"]:
            with self.assertRaises(securesystemslib.exceptions.FormatError):
                InspectionInput(name=name)

    def test_duplicate_inputs(self):
        """Duplicate inspection view names are rejected."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            Inspection(
                name="check",
                inputs=["package:foo", "package:foo@products"],
            )

    def test_layout_roundtrip(self):
        """Inputs survive read/serialization as part of the layout."""
        layout = Layout.read(
            {
                "_type": "layout",
                "steps": [],
                "inspect": [
                    {
                        "name": "check",
                        "run": ["true"],
                        "inputs": ["package:foo.tar.gz"],
                    }
                ],
            }
        )
        self.assertEqual(layout.inspect[0].inputs[0].from_step, "package")
        data = json.loads(repr(layout))
        self.assertEqual(
            data["inspect"][0]["inputs"][0]["from_step"], "package"
        )

    def test_empty_inputs_are_omitted_from_signable(self):
        """Layouts without inputs keep the historical canonical representation."""
        inspection = Inspection(name="check", run=["true"])
        metablock = Metablock(signed=Layout(inspect=[inspection]))
        serialized = metablock.to_dict()["signed"]["inspect"][0]
        self.assertNotIn("inputs", serialized)


class TestBindInspectionInputs(TmpDirTestCase):
    """Test the binding preflight against authenticated Links."""

    def setUp(self):
        super().setUp()
        self.foo = self.write("foo.tar.gz", "original")
        self.link = Link(
            name="package",
            products={"foo.tar.gz": {"sha256": self._sha256(b"original")}},
        )
        self.inspection = Inspection(
            name="untar",
            inputs=["package:foo.tar.gz"],
        )

    @staticmethod
    def _sha256(data):
        return hashlib.sha256(data).hexdigest()

    def test_matching_input_binds(self):
        """A file matching the authenticated Link binds successfully."""
        report = in_toto.inspection_binding.bind_inspection_inputs(
            self.inspection,
            {"package": self.link},
            link_keyids={"package": "a" * 64},
        )
        self.assertEqual(report.status, "bound")
        self.assertEqual(report.inputs[0]["status"], "matched")
        self.assertEqual(
            report.inputs[0]["declared_digests"],
            {"sha256": self._sha256(b"original")},
        )

    def test_missing_file_rejected(self):
        """A missing declared file is rejected before execution."""
        os.remove(self.foo)
        with self.assertRaises(InspectionInputError) as ctx:
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {"package": self.link}
            )
        self.assertEqual(ctx.exception.report.status, "rejected")
        self.assertIn("missing", str(ctx.exception))

    def test_same_name_different_content_rejected(self):
        """A same-name replacement with different content is rejected."""
        self.write("foo.tar.gz", "replacement")
        with self.assertRaises(InspectionInputError) as ctx:
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {"package": self.link}
            )
        self.assertEqual(ctx.exception.report.status, "rejected")
        self.assertIn("Digest mismatch", str(ctx.exception))

    def test_unnormalized_name_rejected(self):
        """Names are not normalized into matching Link artifacts."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            Inspection(name="untar", inputs=["package:./foo.tar.gz"])
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            InspectionInput,
            name="package:foo.tar.gz/../foo.tar.gz",
        )

    def test_link_missing_artifact_rejected(self):
        """An artifact absent from the authenticated Link is rejected."""
        self.inspection = Inspection(name="untar", inputs=["package:other"])
        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {"package": self.link}
            )

    def test_no_authenticated_link_rejected(self):
        """Without a verified Link, no binding can be made."""
        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {}
            )

    def test_link_alias_maps_inspection_name_to_link_path(self):
        """Explicit link_path binds a differently named inspect file."""
        self.write("build/foo.tar.gz", "original")
        self.link.products["dist/foo.tar.gz"] = {
            "sha256": self._sha256(b"original")
        }
        inspection = Inspection(
            name="untar",
            inputs=[
                {
                    "name": "build/foo.tar.gz",
                    "from_step": "package",
                    "from_type": "products",
                    "link_path": "dist/foo.tar.gz",
                }
            ],
        )
        report = in_toto.inspection_binding.bind_inspection_inputs(
            inspection, {"package": self.link}
        )
        self.assertEqual(report.status, "bound")
        self.assertEqual(report.inputs[0]["link_path"], "dist/foo.tar.gz")

    def test_directory_recording_rejected(self):
        """A directory-recorded Link artifact is not accepted as a file input."""
        self.inspection = Inspection(
            name="untar", inputs=["package:dir:foo.tar.gz"]
        )
        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {"package": self.link}
            )

    def test_non_file_digest_algorithm_rejected(self):
        """A Link artifact must carry supported digest evidence."""
        self.link.products["foo.tar.gz"] = {"sha256": "not-hex-but-wrong"}
        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {"package": self.link}
            )

    def test_multiple_hash_algorithms_match(self):
        """All algorithms reported by the Link are compared on the same bytes."""
        self.link.products["foo.tar.gz"] = {
            "sha256": self._sha256(b"original"),
            "sha512": hashlib.sha512(b"original").hexdigest(),
        }
        report = in_toto.inspection_binding.bind_inspection_inputs(
            self.inspection, {"package": self.link}
        )
        self.assertEqual(report.status, "bound")
        self.assertEqual(
            report.inputs[0]["observed_digests"],
            self.link.products["foo.tar.gz"],
        )

    def test_stale_file_symlink_rejected(self):
        """Symlinks are not accepted as declared regular-file inputs."""
        os.remove(self.foo)
        os.symlink("elsewhere", "foo.tar.gz")
        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.bind_inspection_inputs(
                self.inspection, {"package": self.link}
            )

    def test_no_declarations_report_is_explicit(self):
        """An empty input list does not silently trust the directory."""
        report = in_toto.inspection_binding.bind_inspection_inputs(
            Inspection(name="check"), {}
        )
        self.assertEqual(report.status, "no-inputs-declared")
        self.assertTrue(report.errors)
        self.assertIn(
            "must not be treated as authenticated inputs", report.errors[0]
        )

    def test_report_contains_link_identity_and_limits(self):
        """Report records Link identity, file evidence, and limits."""
        report = in_toto.inspection_binding.bind_inspection_inputs(
            self.inspection,
            {"package": self.link},
            link_keyids={"package": ["b" * 64]},
        )
        data = report.to_dict()
        record = data["inputs"][0]
        self.assertEqual(record["link"]["step"], "package")
        self.assertEqual(record["link"]["keyids"], ["b" * 64])
        self.assertEqual(
            record["file"]["resolved_path"], os.path.abspath("foo.tar.gz")
        )
        self.assertEqual(record["observed_digests"], record["declared_digests"])
        self.assertIn("policy", data)
        self.assertIn("not_guaranteed", data["policy"])
        self.assertIn("concurrency", data["policy"])
        self.assertIn("caller_requirements", data["policy"])


class TestMechanismBoundaries(TmpDirTestCase):
    """Tests documenting what the binding does not attempt to guarantee."""

    def test_binding_does_not_restrict_inspection_file_access(self):
        """Preflight success does not sandbox the inspection process."""
        Path("declared.txt").write_text("declared", encoding="utf8")
        Path("undeclared.txt").write_text("undeclared", encoding="utf8")
        Path("fake_executor.py").write_text(
            "import os\n"
            "with open('undeclared.txt', encoding='utf8') as fp:\n"
            "    assert fp.read() == 'undeclared'\n",
            encoding="utf8",
        )
        link = Link(
            name="build",
            products={
                "declared.txt": {
                    "sha256": hashlib.sha256(b"declared").hexdigest()
                }
            },
        )
        layout = Layout(
            inspect=[
                Inspection(
                    name="check",
                    run=[sys.executable, "fake_executor.py"],
                    inputs=["build:declared.txt"],
                )
            ]
        )
        links = run_all_inspections(layout, False, step_links={"build": link})
        self.assertEqual(links["check"].byproducts["return-value"], 0)

    def test_inspection_link_materials_are_only_declared_inputs(self):
        """Undeclared working-directory files are not recorded as materials."""
        Path("declared.txt").write_text("declared", encoding="utf8")
        Path("undeclared.txt").write_text("undeclared", encoding="utf8")
        Path("fake_executor.py").write_text("", encoding="utf8")
        link = Link(
            name="build",
            products={
                "declared.txt": {
                    "sha256": hashlib.sha256(b"declared").hexdigest()
                }
            },
        )
        layout = Layout(
            inspect=[
                Inspection(
                    name="check",
                    run=[sys.executable, "fake_executor.py"],
                    inputs=["build:declared.txt"],
                )
            ]
        )
        links = run_all_inspections(layout, False, step_links={"build": link})
        self.assertEqual(list(links["check"].materials), ["declared.txt"])
        self.assertNotIn("undeclared.txt", links["check"].materials)
        self.assertEqual(
            links["check"].materials["declared.txt"],
            link.products["declared.txt"],
        )


class TestFakeExecutorBinding(TmpDirTestCase):
    """Acceptance: the fake executor starts once for valid data and zero times
    when a same-name file has different content."""

    def _make_layout(self):
        layout = Layout(
            inspect=[
                Inspection(
                    name="untar",
                    run=[sys.executable, "fake_executor.py"],
                    inputs=["package:foo.tar.gz"],
                )
            ]
        )
        return Metablock(signed=layout)

    def _make_link(self, content):
        return Link(
            name="package",
            products={
                "foo.tar.gz": {"sha256": hashlib.sha256(content).hexdigest()}
            },
        )

    def _run(self, layout, link):
        os.environ["FAKE_EXECUTOR_COUNTER"] = os.path.abspath("counter.txt")
        try:
            run_all_inspections(
                layout.signed,
                False,
                step_links={"package": link},
                link_keyids={"package": "a" * 64},
            )
        finally:
            del os.environ["FAKE_EXECUTOR_COUNTER"]

    def test_valid_product_executes_once(self):
        """Valid, authenticated product starts the executor exactly once."""
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")
        self.write("foo.tar.gz", "authentic product")

        self._run(self._make_layout(), self._make_link(b"authentic product"))
        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "1")

    def test_same_name_replaced_content_executes_zero_times(self):
        """A same-name replacement never starts the executor."""
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")
        self.write("foo.tar.gz", "replacement content")

        with self.assertRaises(InspectionInputError):
            self._run(
                self._make_layout(), self._make_link(b"authentic product")
            )

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "0")
        self.assertFalse(Path("executed.txt").exists())

    def test_late_replacement_after_preflight_executes_zero_times(self):
        """The executor is not started if the file changes before process start."""
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")
        self.write("foo.tar.gz", "authentic product")

        link = self._make_link(b"authentic product")
        inspection = Inspection(name="untar", inputs=["package:foo.tar.gz"])

        original_bind = in_toto.inspection_binding.bind_inspection_inputs

        def bind_then_replace(*args, **kwargs):
            report = original_bind(*args, **kwargs)
            Path("foo.tar.gz").write_text("replaced", encoding="utf8")
            return report

        os.environ["FAKE_EXECUTOR_COUNTER"] = os.path.abspath("counter.txt")
        try:
            with (
                unittest.mock.patch.object(
                    in_toto.inspection_binding,
                    "bind_inspection_inputs",
                    side_effect=bind_then_replace,
                ),
                self.assertRaises(InspectionInputError),
            ):
                run_all_inspections(
                    Layout(inspect=[inspection]),
                    False,
                    step_links={"package": link},
                )
        finally:
            del os.environ["FAKE_EXECUTOR_COUNTER"]

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "0")

    def test_missing_file_executes_zero_times(self):
        """A missing declared input never starts the executor."""
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")

        with self.assertRaises(InspectionInputError):
            self._run(
                self._make_layout(), self._make_link(b"authentic product")
            )

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "0")
        self.assertFalse(Path("executed.txt").exists())

    def test_recheck_before_execution_rejects_late_replacement(self):
        """A replacement between preflight and exec is caught by the recheck."""
        self.write("foo.tar.gz", "authentic product")
        link = self._make_link(b"authentic product")
        inspection = Inspection(name="untar", inputs=["package:foo.tar.gz"])

        report = in_toto.inspection_binding.bind_inspection_inputs(
            inspection, {"package": link}, link_keyids={"package": "a" * 64}
        )
        self.assertEqual(report.status, "bound")

        # Simulate a concurrent writer replacing the file after preflight.
        self.write("foo.tar.gz", "replaced after preflight")

        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.recheck_declared_digests(report)
        self.assertEqual(report.status, "rejected")

    def test_recheck_rejects_same_content_new_inode(self):
        """A same-content replacement is still a different file identity."""
        self.write("foo.tar.gz", "authentic product")
        link = self._make_link(b"authentic product")
        inspection = Inspection(name="untar", inputs=["package:foo.tar.gz"])

        report = in_toto.inspection_binding.bind_inspection_inputs(
            inspection, {"package": link}, link_keyids={"package": "a" * 64}
        )

        # Replace with identical bytes via rename, changing the inode.
        self.write("tmp-replacement", "authentic product")
        os.replace("tmp-replacement", "foo.tar.gz")

        with self.assertRaises(InspectionInputError):
            in_toto.inspection_binding.recheck_declared_digests(report)
        self.assertIn("replaced", report.errors[-1])
        self.assertEqual(
            report.inputs[0]["recheck"]["digests"],
            report.inputs[0]["declared_digests"],
        )

    def test_full_verify_uses_authenticated_step_link(self):
        """in_toto_verify binds inspection inputs to signed step Links."""
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")
        self.write("foo.tar.gz", "authentic product")
        link = self._make_link(b"authentic product")

        signer = SignerStore.rsa
        keyid = signer.public_key.keyid
        link_metadata = Metablock(signed=link)
        link_metadata.create_signature(signer)
        link_metadata.dump(f"package.{keyid[:8]}.link")

        layout = Layout(
            keys={keyid: SignerStore.rsa_pub},
            steps=[
                Step(
                    name="package",
                    pubkeys=[keyid],
                    expected_materials=[],
                    expected_products=[],
                )
            ],
            inspect=[
                Inspection(
                    name="untar",
                    run=[sys.executable, "fake_executor.py"],
                    inputs=["package:foo.tar.gz"],
                )
            ],
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(signer)

        reports = []
        os.environ["FAKE_EXECUTOR_COUNTER"] = os.path.abspath("counter.txt")
        try:
            in_toto_verify(
                layout_metadata,
                {keyid: SignerStore.rsa_pub},
                persist_inspection_links=False,
                binding_report_callback=reports.append,
            )
        finally:
            del os.environ["FAKE_EXECUTOR_COUNTER"]

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "1")
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].inspection_name, "untar")
        self.assertEqual(reports[0].status, "bound")
        self.assertEqual(reports[0].inputs[0]["link"]["keyids"], [keyid])


class TestVerifyCliInspectionInputs(common.CliTestCase, TmpDirTestCase):
    """Test the in-toto-verify CLI report and strict-input options."""

    cli_main_func = staticmethod(in_toto_verify_main)

    def _prepare(self):
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")
        self.write("foo.tar.gz", "authentic product")

        signer = SignerStore.rsa
        keyid = signer.public_key.keyid
        link = Link(
            name="package",
            products={
                "foo.tar.gz": {
                    "sha256": hashlib.sha256(b"authentic product").hexdigest()
                }
            },
        )
        link_metadata = Metablock(signed=link)
        link_metadata.create_signature(signer)
        link_metadata.dump(f"package.{keyid[:8]}.link")

        layout = Layout(
            keys={keyid: SignerStore.rsa_pub},
            steps=[
                Step(
                    name="package",
                    pubkeys=[keyid],
                    expected_materials=[],
                    expected_products=[],
                )
            ],
            inspect=[
                Inspection(
                    name="untar",
                    run=[sys.executable, "fake_executor.py"],
                    inputs=["package:foo.tar.gz"],
                )
            ],
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(signer)
        layout_metadata.dump("root.layout")

        key_path = Path(self.test_dir) / "rsa_public.pem"
        key_path.write_bytes((PEMS / "rsa_public.pem").read_bytes())
        return keyid, str(key_path)

    def test_cli_writes_report_and_runs_once(self):
        """CLI writes the evidence report and starts the executor once."""
        keyid, key_path = self._prepare()
        os.environ["FAKE_EXECUTOR_COUNTER"] = os.path.abspath("counter.txt")
        try:
            args = [
                "--layout",
                "root.layout",
                "--verification-keys",
                key_path,
                "--require-inspection-inputs",
                "--inspection-input-report",
                "binding-report.json",
            ]
            self.assert_cli_sys_exit(args, 0)
        finally:
            del os.environ["FAKE_EXECUTOR_COUNTER"]

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "1")
        report = json.loads(
            Path("binding-report.json").read_text(encoding="utf8")
        )
        self.assertEqual(report["inspections"][0]["status"], "bound")
        self.assertEqual(
            report["inspections"][0]["inputs"][0]["link"]["keyids"], [keyid]
        )
        self.assertIn("concurrency", report["policy"])

    def test_cli_report_written_on_binding_failure(self):
        """A rejected inspection still yields an evidence report."""
        keyid, key_path = self._prepare()
        self.write("foo.tar.gz", "replacement content")
        os.environ["FAKE_EXECUTOR_COUNTER"] = os.path.abspath("counter.txt")
        try:
            self.assert_cli_sys_exit(
                [
                    "--layout",
                    "root.layout",
                    "--verification-keys",
                    key_path,
                    "--inspection-input-report",
                    "binding-report.json",
                ],
                1,
            )
        finally:
            del os.environ["FAKE_EXECUTOR_COUNTER"]

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "0")
        report = json.loads(
            Path("binding-report.json").read_text(encoding="utf8")
        )
        self.assertEqual(report["inspections"][0]["status"], "rejected")

    def test_cli_strict_flag_rejects_undeclared_inspection(self):
        """Strict mode refuses to start an inspection with no declarations."""
        self.write("fake_executor.py", FAKE_EXECUTOR)
        self.write("counter.txt", "0")
        signer = SignerStore.rsa
        keyid = signer.public_key.keyid
        layout = Layout(
            keys={keyid: SignerStore.rsa_pub},
            steps=[],
            inspect=[
                Inspection(
                    name="untar", run=[sys.executable, "fake_executor.py"]
                )
            ],
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(signer)
        layout_metadata.dump("root.layout")
        key_path = Path(self.test_dir) / "rsa_public.pem"
        key_path.write_bytes((PEMS / "rsa_public.pem").read_bytes())

        os.environ["FAKE_EXECUTOR_COUNTER"] = os.path.abspath("counter.txt")
        try:
            self.assert_cli_sys_exit(
                [
                    "--layout",
                    "root.layout",
                    "--verification-keys",
                    str(key_path),
                    "--require-inspection-inputs",
                    "--inspection-input-report",
                    "binding-report.json",
                ],
                1,
            )
        finally:
            del os.environ["FAKE_EXECUTOR_COUNTER"]

        self.assertEqual(Path("counter.txt").read_text(encoding="utf8"), "0")
        report = json.loads(
            Path("binding-report.json").read_text(encoding="utf8")
        )
        self.assertEqual(report["inspections"][0]["status"], "rejected")
        self.assertIn(
            "declares no inputs", report["inspections"][0]["errors"][0]
        )


if __name__ == "__main__":
    unittest.main()
