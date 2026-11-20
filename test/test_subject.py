import hashlib
import os
from pathlib import Path

import pretend  # type: ignore
from packaging.version import Version

import pip_audit._service as service
from pip_audit._subject import AuditSubject, SubjectInput


def test_subject_input_from_file_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("foo==1.0\n")

    input_ = SubjectInput.from_file(Path("requirements.txt"))

    assert input_.path == "requirements.txt"
    assert not os.path.isabs(input_.path)
    assert input_.sha256 == hashlib.sha256(b"foo==1.0\n").hexdigest()


def test_subject_input_from_file_outside_cwd_is_not_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path / "subdir" if (tmp_path / "subdir").mkdir() or True else tmp_path)
    (tmp_path / "requirements.txt").write_text("foo==1.0\n")

    input_ = SubjectInput.from_file(tmp_path / "requirements.txt")

    assert not os.path.isabs(input_.path)
    assert input_.path == os.path.join("..", "requirements.txt")


def _source(kind, files):
    return pretend.stub(source_kind=kind, subject_files=lambda: files)


def test_audit_subject_from_audit(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    req = tmp_path / "requirements.txt"
    req.write_text("foo==1.0\n")

    result = {
        service.ResolvedDependency(name="foo", version=Version("1.0")): [],
        service.ResolvedDependency(name="bar", version=Version("0.1")): [],
        service.SkippedDependency(name="baz", skip_reason="nope"): [],
    }

    subject = AuditSubject.from_audit(_source("requirements", [req]), result)

    assert subject.source == "requirements"
    assert len(subject.inputs) == 1
    assert subject.inputs[0].path == "requirements.txt"
    assert subject.inputs[0].sha256 == hashlib.sha256(b"foo==1.0\n").hexdigest()
    assert subject.dependencies_sha256 == hashlib.sha256(b"bar==0.1\nfoo==1.0").hexdigest()


def test_audit_subject_order_independent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    foo = service.ResolvedDependency(name="foo", version=Version("1.0"))
    bar = service.ResolvedDependency(name="bar", version=Version("0.1"))

    first = AuditSubject.from_audit(_source("environment", []), {foo: [], bar: []})
    second = AuditSubject.from_audit(_source("environment", []), {bar: [], foo: []})

    assert first == second
    assert first.inputs == ()


def test_audit_subject_detects_changed_dependencies():
    foo = service.ResolvedDependency(name="foo", version=Version("1.0"))

    first = AuditSubject.from_audit(_source("environment", []), {foo: []})
    changed = AuditSubject.from_audit(
        _source("environment", []),
        {service.ResolvedDependency(name="foo", version=Version("2.0")): []},
    )

    assert first.dependencies_sha256 != changed.dependencies_sha256


def test_audit_subject_detects_changed_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    req = tmp_path / "requirements.txt"
    req.write_text("foo==1.0\n")
    foo = service.ResolvedDependency(name="foo", version=Version("1.0"))

    first = AuditSubject.from_audit(_source("requirements", [req]), {foo: []})

    req.write_text("foo==1.0\n# comment\n")
    second = AuditSubject.from_audit(_source("requirements", [req]), {foo: []})

    assert first.inputs[0].sha256 != second.inputs[0].sha256


def test_audit_subject_detects_changed_source():
    foo = service.ResolvedDependency(name="foo", version=Version("1.0"))

    environment = AuditSubject.from_audit(_source("environment", []), {foo: []})
    requirements = AuditSubject.from_audit(_source("requirements", []), {foo: []})

    assert environment.source != requirements.source
