import json

import pytest

import pip_audit._format as format
from pip_audit._subject import AuditSubject, SubjectInput


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_json_manifest(output_desc, output_aliases):
    fmt = format.JsonFormat(output_desc, output_aliases)

    assert fmt.is_manifest


def test_json(vuln_data):
    json_format = format.JsonFormat(True, True)
    expected_json = {
        "summary": {
            "dependencies": 2,
            "skipped": 0,
            "vulnerabilities": 3,
            "fixes": 0,
        },
        "dependencies": [
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                        "description": "The third vulnerability",
                    }
                ],
            },
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                        "description": "The second vulnerability",
                    },
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, []) == json.dumps(expected_json)


def test_json_no_desc(vuln_data):
    json_format = format.JsonFormat(False, True)
    expected_json = {
        "summary": {
            "dependencies": 2,
            "skipped": 0,
            "vulnerabilities": 3,
            "fixes": 0,
        },
        "dependencies": [
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                    }
                ],
            },
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                    },
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, []) == json.dumps(expected_json)


def test_json_no_desc_no_aliases(vuln_data):
    json_format = format.JsonFormat(False, False)
    expected_json = {
        "summary": {
            "dependencies": 2,
            "skipped": 0,
            "vulnerabilities": 3,
            "fixes": 0,
        },
        "dependencies": [
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                    }
                ],
            },
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                    },
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, []) == json.dumps(expected_json)


def test_json_skipped_dep(vuln_data_skipped_dep):
    json_format = format.JsonFormat(False, True)
    expected_json = {
        "summary": {
            "dependencies": 1,
            "skipped": 1,
            "vulnerabilities": 1,
            "fixes": 0,
        },
        "dependencies": [
            {
                "name": "bar",
                "skip_reason": "skip-reason",
            },
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                    },
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data_skipped_dep, []) == json.dumps(expected_json)


def test_json_fix(vuln_data, fix_data):
    json_format = format.JsonFormat(True, True)
    expected_json = {
        "summary": {
            "dependencies": 2,
            "skipped": 0,
            "vulnerabilities": 3,
            "fixes": 2,
        },
        "dependencies": [
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                        "description": "The third vulnerability",
                    }
                ],
            },
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                        "description": "The second vulnerability",
                    },
                ],
            },
        ],
        "fixes": [
            {
                "name": "bar",
                "old_version": "0.1",
                "new_version": "0.3",
            },
            {
                "name": "foo",
                "old_version": "1.0",
                "new_version": "1.8",
            },
        ],
    }
    assert json_format.format(vuln_data, fix_data) == json.dumps(expected_json)


def test_json_skipped_fix(vuln_data, skipped_fix_data):
    json_format = format.JsonFormat(True, True)
    expected_json = {
        "summary": {
            "dependencies": 2,
            "skipped": 0,
            "vulnerabilities": 3,
            "fixes": 2,
        },
        "dependencies": [
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                        "description": "The third vulnerability",
                    }
                ],
            },
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                        "description": "The second vulnerability",
                    },
                ],
            },
        ],
        "fixes": [
            {"name": "bar", "version": "0.1", "skip_reason": "skip-reason"},
            {
                "name": "foo",
                "old_version": "1.0",
                "new_version": "1.8",
            },
        ],
    }
    assert json_format.format(vuln_data, skipped_fix_data) == json.dumps(expected_json)


def test_json_subject(vuln_data):
    json_format = format.JsonFormat(True, True)
    subject = AuditSubject(
        source="requirements",
        inputs=(SubjectInput(path="requirements.txt", sha256="f" * 64),),
        dependencies_sha256="a" * 64,
    )

    output = json.loads(json_format.format(vuln_data, [], subject=subject))

    assert output["subject"] == {
        "source": "requirements",
        "inputs": [{"path": "requirements.txt", "sha256": "f" * 64}],
        "dependencies_sha256": "a" * 64,
    }


def test_json_no_subject_by_default(vuln_data):
    json_format = format.JsonFormat(True, True)

    output = json.loads(json_format.format(vuln_data, []))

    assert "subject" not in output


def test_json_collection_order_independent(vuln_data):
    json_format = format.JsonFormat(True, True)
    reordered = dict(reversed(list(vuln_data.items())))

    assert json_format.format(vuln_data, []) == json_format.format(reordered, [])
