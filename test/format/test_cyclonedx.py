import json
import xml.etree.ElementTree as ET

import pretend  # type: ignore
import pytest

from pip_audit._format import CycloneDxFormat


@pytest.mark.parametrize(
    "inner", [CycloneDxFormat.InnerFormat.Xml, CycloneDxFormat.InnerFormat.Json]
)
def test_cyclonedx_manifest(inner):
    fmt = CycloneDxFormat(inner_format=inner)
    assert fmt.is_manifest


def test_cyclonedx_inner_json(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    # We don't test CycloneDX's formatting/layout decisions, only that
    # the formatter emits correct JSON when initialized in JSON mode.
    assert json.loads(formatter.format(vuln_data, [])) is not None


def test_cyclonedx_inner_xml(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Xml)

    # We don't test CycloneDX's formatting/layout decisions, only that
    # the formatter emits correct XML when initialized in XML mode.
    assert ET.fromstring(formatter.format(vuln_data, [])) is not None


def test_cyclonedx_skipped_dep(vuln_data_skipped_dep):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    # Just test that a skipped dependency doesn't cause the formatter to blow up
    assert json.loads(formatter.format(vuln_data_skipped_dep, [])) is not None


def test_cyclonedx_fix(monkeypatch, vuln_data, fix_data):
    import pip_audit._format.cyclonedx as cyclonedx

    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(cyclonedx, "logger", logger)

    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    assert json.loads(formatter.format(vuln_data, fix_data)) is not None

    # The CycloneDX format doesn't support fixes so we expect to log a warning
    assert len(logger.warning.calls) == 1


def test_cyclonedx_vulnerabilities_linked_to_components(vuln_data):
    """
    Backstop test to ensure vulnerabilities are correctly linked to their components.

    This test verifies that the CycloneDX output properly links vulnerabilities
    to components via the 'affects' field. If the cyclonedx-python-lib library
    changes its API in a future version, this test will fail and provide advance
    warning of breaking changes.
    """
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    output = formatter.format(vuln_data, [])
    data = json.loads(output)

    # Build a mapping of component names to their bom-refs
    component_bomrefs = {comp["name"]: comp["bom-ref"] for comp in data.get("components", [])}

    # Verify we have components and vulnerabilities in the output
    assert len(component_bomrefs) > 0, "Should have components in CycloneDX output"
    assert (
        len(data.get("vulnerabilities", [])) > 0
    ), "Should have vulnerabilities in CycloneDX output"

    # Track which components have vulnerabilities linked to them
    components_with_vulns = set()

    # Check each vulnerability has proper 'affects' linking
    for vuln in data["vulnerabilities"]:
        affects = vuln.get("affects", [])

        # Each vulnerability should have at least one affected component
        assert len(affects) > 0, f"Vulnerability {vuln.get('id')} should have 'affects' field"

        for affected in affects:
            # Each affected entry should have a 'ref' field
            assert "ref" in affected, f"Vulnerability {vuln.get('id')} affects entry missing 'ref'"

            vuln_ref = affected["ref"]

            # The ref should not be empty
            assert vuln_ref, f"Vulnerability {vuln.get('id')} has empty 'ref' in affects"

            # The ref should match one of the component bom-refs
            assert (
                vuln_ref in component_bomrefs.values()
            ), f"Vulnerability {vuln.get('id')} references unknown bom-ref: {vuln_ref}"

            # Track that this component has a vulnerability linked to it
            for comp_name, comp_ref in component_bomrefs.items():
                if comp_ref == vuln_ref:
                    components_with_vulns.add(comp_name)

    # Verify that components with vulnerabilities in vuln_data have them linked in output
    # (This ensures the linking is actually working, not just present but wrong)
    for dep, vulns in vuln_data.items():
        if vulns:  # If this dependency has vulnerabilities
            assert (
                dep.name in components_with_vulns
            ), f"Component {dep.name} has vulnerabilities but they're not properly linked"


def _subject():
    from pip_audit._subject import AuditSubject, SubjectInput

    return AuditSubject(
        source="requirements",
        inputs=(SubjectInput(path="requirements.txt", sha256="f" * 64),),
        dependencies_sha256="a" * 64,
    )


def test_cyclonedx_summary_properties(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(vuln_data, []))

    properties = {p["name"]: p["value"] for p in data["metadata"]["properties"]}
    assert properties["pip_audit:summary:dependencies"] == "2"
    assert properties["pip_audit:summary:skipped"] == "0"
    assert properties["pip_audit:summary:vulnerabilities"] == "3"
    assert properties["pip_audit:summary:fixes"] == "0"
    assert "pip_audit:subject:source" not in properties


def test_cyclonedx_subject_properties(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(vuln_data, [], subject=_subject()))

    properties = {p["name"]: p["value"] for p in data["metadata"]["properties"]}
    assert properties["pip_audit:subject:source"] == "requirements"
    assert properties["pip_audit:subject:dependencies_sha256"] == "a" * 64
    assert properties["pip_audit:subject:inputs:0:path"] == "requirements.txt"
    assert properties["pip_audit:subject:inputs:0:sha256"] == "f" * 64


def test_cyclonedx_subject_deterministic_serial_number(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    first = json.loads(formatter.format(vuln_data, [], subject=_subject()))
    reordered = dict(reversed(list(vuln_data.items())))
    second = json.loads(formatter.format(reordered, [], subject=_subject()))

    # The same dependency set, collected in any order, yields the same
    # serial number, components, and subject properties.
    assert first["serialNumber"] == second["serialNumber"]
    assert first["components"] == second["components"]
    assert first["metadata"]["properties"] == second["metadata"]["properties"]


def test_cyclonedx_subject_xml(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Xml)
    root = ET.fromstring(formatter.format(vuln_data, [], subject=_subject()))

    ns = "{http://cyclonedx.org/schema/bom/1.4}"
    values = {p.get("name"): p.text for p in root.iter(f"{ns}property")}
    assert values["pip_audit:subject:source"] == "requirements"
    assert values["pip_audit:summary:vulnerabilities"] == "3"
