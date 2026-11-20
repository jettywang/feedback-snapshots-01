from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from packaging.version import Version

from pip_audit._dependency_source import requirement
from pip_audit._index_policy import IndexPolicy, IndexPolicyError
from pip_audit._service import ResolvedDependency
from pip_audit._virtual_env import VirtualEnv

INTERNAL_INDEX = "https://mirror.internal.example.com/simple/"
PROJECT_INDEX = "https://packages.project.example.com/simple/"


class FakeSubprocess:
    """
    A fake `pip_audit._virtual_env.run` that records the arguments and
    visible configuration of every subprocess invocation, and answers the
    `pip install --report` command with a canned resolution result.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args, *, log_stdout=False, state=None):
        self.calls.append([str(a) for a in args])
        if "--report" in args:
            report_path = Path(args[args.index("--report") + 1])
            report_path.write_text(
                json.dumps({"install": [{"metadata": {"name": "flask", "version": "2.0.1"}}]})
            )
        return ""

    @property
    def install_cmd(self) -> list[str]:
        # The last invocation is the `pip install ... --report ...` command
        # that performs the actual resolution.
        return self.calls[-1]


@pytest.fixture
def fake_subprocess(monkeypatch):
    fake = FakeSubprocess()
    monkeypatch.setattr("pip_audit._virtual_env.run", fake)
    # Skip real virtualenv creation; drive `post_setup` directly so the
    # (fake) subprocess invocations still happen exactly as in production.
    monkeypatch.setattr(
        VirtualEnv,
        "create",
        lambda self, env_dir: self.post_setup(SimpleNamespace(env_exe="python")),
    )
    return fake


def _make_source(req_file, contents, **kwargs):
    path = req_file()
    path.write_text(contents)
    return requirement.RequirementSource([path], **kwargs)


def test_policy_clean_file_resolves_against_internal_mirror(req_file, fake_subprocess):
    policy = IndexPolicy(internal_index_url=INTERNAL_INDEX)
    source = _make_source(req_file, "flask==2.0.1\n", index_policy=policy)

    specs = list(source.collect())

    # The legitimate path proceeds through resolution and yields results.
    assert ResolvedDependency("flask", Version("2.0.1")) in specs
    # The temporary resolution environment is pinned to the internal mirror.
    assert "--index-url" in fake_subprocess.install_cmd
    idx = fake_subprocess.install_cmd.index("--index-url")
    assert fake_subprocess.install_cmd[idx + 1] == INTERNAL_INDEX


def test_policy_blocks_project_declared_sources(req_file, fake_subprocess):
    policy = IndexPolicy(internal_index_url=INTERNAL_INDEX)
    source = _make_source(
        req_file,
        f"--index-url {PROJECT_INDEX}\n"
        "--extra-index-url https://evil.example.com/simple/\n"
        "flask==2.0.1\n",
        index_policy=policy,
    )

    with pytest.raises(IndexPolicyError) as excinfo:
        list(source.collect())

    # Conflicts are reported before resolution, with file and line numbers.
    message = str(excinfo.value)
    assert "--index-url" in message and PROJECT_INDEX in message
    assert "--extra-index-url" in message and "evil.example.com" in message
    # The resolver is never invoked for a blocked file.
    assert fake_subprocess.calls == []


def test_policy_blocks_no_index_declaration(req_file, fake_subprocess):
    policy = IndexPolicy(internal_index_url=INTERNAL_INDEX)
    source = _make_source(req_file, "--no-index\nflask==2.0.1\n", index_policy=policy)

    with pytest.raises(IndexPolicyError):
        list(source.collect())
    assert fake_subprocess.calls == []


def test_policy_authorized_exception_resolves(req_file, fake_subprocess):
    policy = IndexPolicy(
        internal_index_url=INTERNAL_INDEX,
        authorized_index_urls=frozenset({PROJECT_INDEX}),
    )
    source = _make_source(
        req_file,
        f"--extra-index-url {PROJECT_INDEX}\nflask==2.0.1\n",
        index_policy=policy,
    )

    specs = list(source.collect())

    assert ResolvedDependency("flask", Version("2.0.1")) in specs
    assert fake_subprocess.calls != []


def test_policy_accepts_declaration_of_internal_mirror(req_file, fake_subprocess):
    policy = IndexPolicy(internal_index_url=INTERNAL_INDEX)
    source = _make_source(
        req_file,
        f"--index-url {INTERNAL_INDEX}\nflask==2.0.1\n",
        index_policy=policy,
    )

    specs = list(source.collect())

    assert ResolvedDependency("flask", Version("2.0.1")) in specs


def test_check_requirements_files_reports_accepted_declarations(req_file):
    path = req_file()
    path.write_text(f"--extra-index-url {PROJECT_INDEX}\nflask==2.0.1\n")
    policy = IndexPolicy(
        internal_index_url=INTERNAL_INDEX,
        authorized_index_urls=frozenset({PROJECT_INDEX}),
    )

    accepted = policy.check_requirements_files([path])

    assert len(accepted) == 1
    assert accepted[0].filename == path
    assert accepted[0].option == "--extra-index-url"
    assert accepted[0].value == PROJECT_INDEX
