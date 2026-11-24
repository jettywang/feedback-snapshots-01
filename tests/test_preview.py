"""Tests for dynaconf.preview: controlled merge preview."""

from __future__ import annotations

import os

import pytest

from dynaconf import Dynaconf
from dynaconf import post_hook
from dynaconf.loaders.base import SourceMetadata
from dynaconf.preview import PreviewReport
from dynaconf.utils.parse_conf import Lazy

pytestmark = pytest.mark.usefixtures("no_deprecations")


class RecordingLoader:
    """A loader that records every call it receives."""

    def __init__(self, **values):
        self.values = values
        self.calls = []

    def load(self, obj, env=None, silent=True, key=None):
        self.calls.append(
            {"obj": obj, "env": env, "silent": silent, "key": key}
        )
        obj.update(
            self.values,
            loader_identifier=SourceMetadata(
                loader="recording",
                identifier="recording_loader",
                env=str(env or obj.current_env).lower(),
            ),
        )


@pytest.fixture(autouse=True)
def clean_dynaconf_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("DYNACONF_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def two_files(create_file):
    file_a = create_file(
        "settings_a.toml",
        """
        [default]
        name = "panel"
        shared = "from_a"
        greeting = "@format Hello {this[NAME]}"

        [development]
        port = 8000
        """,
    )
    file_b = create_file(
        "settings_b.toml",
        """
        [default]
        shared = "from_b"

        [development]
        debug = true
        """,
    )
    return str(file_a), str(file_b)


def make_settings(hook_calls):
    @post_hook
    def app_hook(settings):
        hook_calls.append("post")

    settings = Dynaconf(
        environments=True,
        env="development",
        post_hooks=[app_hook],
    )
    settings.current_env  # force initial load, the app's own hook fires
    assert hook_calls == ["post"]
    hook_calls.clear()
    app_hook._called = False  # allow the hook to fire on the next real load
    return settings


def test_preview_does_not_mutate_or_trigger_callbacks(two_files):
    file_a, file_b = two_files
    recorder = RecordingLoader(extra="from_loader")
    hook_calls = []
    settings = make_settings(hook_calls)

    report = settings.preview_merge(
        files=[file_a, file_b],
        loaders=[recorder],
    )

    assert isinstance(report, PreviewReport)

    # merged state visible in the preview, file_b wins over file_a
    assert report.data["NAME"] == "panel"
    assert report.data["SHARED"] == "from_b"
    assert report.data["PORT"] == 8000
    assert report.data["DEBUG"] is True
    assert report.data["EXTRA"] == "from_loader"

    # lazy value kept unevaluated and marked pending
    assert "GREETING" in report.pending
    assert isinstance(report.data["GREETING"], Lazy)

    # merge order preserved: file_a -> file_b -> recording loader
    order = [getattr(meta, "identifier", meta) for meta in report.merge_order]
    assert order.index(file_a) < order.index(file_b)
    assert order.index("recording_loader") > order.index(file_b)

    # the loader was replayed against the throwaway clone only
    assert len(recorder.calls) == 1
    assert recorder.calls[0]["obj"] is report.settings

    # running config untouched and app load hooks not triggered
    assert hook_calls == []
    assert "SHARED" not in settings.as_dict()
    assert "EXTRA" not in settings.as_dict()


def test_preview_uses_only_caller_selected_sources(two_files):
    file_a, file_b = two_files
    settings = Dynaconf(environments=True, env="development")

    report = settings.preview_merge(files=[file_a])

    assert report.data["SHARED"] == "from_a"
    assert "GREETING" in report.pending
    assert "DEBUG" not in report.data  # file_b was not selected
    assert "EXTRA" not in report.data  # no loader was selected


def test_apply_then_fresh_matches_preview(two_files, monkeypatch):
    file_a, file_b = two_files
    recorder = RecordingLoader(extra="from_loader")
    hook_calls = []
    settings = make_settings(hook_calls)

    report = settings.preview_merge(
        files=[file_a, file_b],
        loaders=[recorder],
    )
    assert hook_calls == []

    # apply the very same sources for real
    settings.load_file(path=[file_a, file_b])
    recorder.load(settings, settings.current_env, silent=True, key=None)

    # callbacks fired on apply: loader now hit the live settings
    # and the app post hook ran
    assert len(recorder.calls) == 2
    assert recorder.calls[-1]["obj"] is settings
    assert hook_calls == ["post"]

    # visible state now matches the preview, pending value resolved
    assert settings.NAME == report.data["NAME"]
    assert settings.SHARED == report.data["SHARED"]
    assert settings.PORT == report.data["PORT"]
    assert settings.DEBUG == report.data["DEBUG"]
    assert settings.EXTRA == report.data["EXTRA"]
    assert settings.GREETING == "Hello panel"

    # dynamic reads keep working after preview and apply
    monkeypatch.setenv("DYNACONF_SHARED", "from_env")
    assert settings.SHARED == "from_b"  # stored value
    assert settings.get_fresh("SHARED") == "from_env"  # reloaded from source
