"""Causal regression tests for swapping in a custom loader.

These tests pin down the safety contract that must hold while a custom
loader is being replaced:

* lazy retrieval means the loader is not read until a setting is first
  accessed (startup) or explicitly re-read (``get_fresh`` / ``fresh``);
* the loader is told which environment and which configuration generation
  it is serving on every read, through an instrumented transformer;
* a candidate configuration that fails validation must never become the
  live runtime state, even though :meth:`Settings.update` writes values to
  the store *before* running the validators.

A guarded loader (snapshot/rollback around the validated write) is used as
the reference implementation, and a naive loader that reuses the rejected
candidate is asserted to be detected by the same runtime-state checks.
"""

from __future__ import annotations

import copy
import sys
import textwrap
from contextlib import suppress

import pytest

from dynaconf import Dynaconf
from dynaconf import ValidationError
from dynaconf import Validator
from dynaconf.utils.inspect import get_history

LOADER_PACKAGE = "security_swap_loader_pkg"
FAULTY_LOADER_PACKAGE = "security_swap_faulty_pkg"

# Two immutable configuration generations served by the controlled backend.
GENERATION_1 = {
    "TOKEN": "v1-token",
    "MODE": "dev",
    "SECURITY_FLAG": "safe",
}
GENERATION_2 = {
    "TOKEN": "v2-token",
    "MODE": "prod",
    "SECURITY_FLAG": "safe",
}

# The reference loader keeps an instrumented backend, applies candidates
# through a snapshot/rollback guard and only commits when validation passes.
REFERENCE_LOADER = textwrap.dedent(
    """
    import copy
    from contextlib import suppress

    from dynaconf.base import SourceMetadata
    from dynaconf.validator import ValidationError

    IDENTIFIER = "security_swap"

    class InstrumentedBackend:
        def __init__(self):
            # generation -> raw config dict
            self.generations = {1: None, 2: None}
            self.active_generation = 1
            # every read is recorded as (env, key, generation)
            self.reads = []

        def read(self, env, key=None):
            generation = self.active_generation
            self.reads.append((env, key, generation))
            data = dict(self.generations[generation])
            if key is not None:
                return {key: data.get(key)}
            return data

    backend = InstrumentedBackend()

    def _store_snapshot(obj):
        return copy.deepcopy(dict(obj.store))

    def _restore_store(obj, snapshot):
        for name in list(obj.store.keys()):
            if name not in snapshot:
                with suppress(KeyError):
                    del obj.store[name]
        for name, value in snapshot.items():
            obj.store[name] = value

    def _history_snapshot(obj):
        return copy.deepcopy(dict(obj.loaded_by_loaders))

    def _restore_history(obj, snapshot):
        obj.loaded_by_loaders.clear()
        obj.loaded_by_loaders.update(snapshot)

    def load(obj, env=None, silent=True, key=None, filename=None,
             validate=False):
        env = env or obj.current_env
        data = backend.read(env, key)
        metadata = SourceMetadata(IDENTIFIER, "memory", str(env).lower())
        store_snapshot = _store_snapshot(obj)
        history_snapshot = _history_snapshot(obj)
        try:
            if key is not None:
                if data.get(key) is not None:
                    obj.set(
                        key,
                        data[key],
                        loader_identifier=metadata,
                        validate=validate,
                    )
            else:
                obj.update(
                    data,
                    loader_identifier=metadata,
                    validate=validate,
                )
        except ValidationError:
            # rejected candidates must never leak into the runtime store
            # or the inspect history
            _restore_store(obj, store_snapshot)
            _restore_history(obj, history_snapshot)
            raise
    """
)

# The faulty loader writes the candidate straight into the live store and
# only validates afterwards, so a rejected candidate survives the error.
FAULTY_LOADER = textwrap.dedent(
    """
    from dynaconf.base import SourceMetadata
    from dynaconf.validator import ValidationError

    IDENTIFIER = "security_swap"

    class InstrumentedBackend:
        def __init__(self):
            self.generations = {1: None, 2: None}
            self.active_generation = 1
            self.reads = []

        def read(self, env, key=None):
            generation = self.active_generation
            self.reads.append((env, key, generation))
            data = dict(self.generations[generation])
            if key is not None:
                return {key: data.get(key)}
            return data

    backend = InstrumentedBackend()

    def load(obj, env=None, silent=True, key=None, filename=None,
             validate=False):
        env = env or obj.current_env
        data = backend.read(env, key)
        metadata = SourceMetadata(IDENTIFIER, "memory", str(env).lower())
        if key is not None:
            if data.get(key) is not None:
                obj.set(key, data[key], loader_identifier=metadata)
        else:
            # candidate is committed before validation runs
            obj.update(data, loader_identifier=metadata)
        if validate:
            obj.validators.validate()
    """
)


def _write_loader_package(
    tmp_path, source: str, package: str = LOADER_PACKAGE
) -> None:
    package_dir = tmp_path / package
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("")
    (package_dir / "custom_loader.py").write_text(source)


def _raw_store_value(settings, key: str):
    """Read a value straight from the store, bypassing lazy/fresh machinery."""
    store = settings.store
    try:
        return store.get(key, bypass_eval=True)
    except TypeError:
        return store.get(key)


@pytest.fixture
def loader_package(tmp_path, monkeypatch):
    """Install the guarded reference loader and expose its backend."""
    module_name = f"{LOADER_PACKAGE}.custom_loader"
    _write_loader_package(tmp_path, REFERENCE_LOADER)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    module = __import__(module_name, fromlist=["custom_loader"])
    # deep copies keep the shared module-level backend isolated per test
    module.backend.generations[1] = copy.deepcopy(GENERATION_1)
    module.backend.generations[2] = copy.deepcopy(GENERATION_2)
    module.backend.active_generation = 1
    module.backend.reads.clear()
    yield module
    # drop the cached module so a later faulty-loader import is not shadowed
    sys.modules.pop(module_name, None)
    sys.modules.pop(LOADER_PACKAGE, None)


@pytest.fixture
def settings_factory(tmp_path, loader_package):
    """Factory producing settings wired to the instrumented custom loader."""
    (tmp_path / "settings.toml").write_text("# placeholder settings file\n")

    def _factory(**overrides):
        options = dict(
            environments=True,
            ENV_FOR_DYNACONF="DEVELOPMENT",
            settings_files=["settings.toml"],
            ROOT_PATH_FOR_DYNACONF=str(tmp_path),
            LOADERS_FOR_DYNACONF=[
                f"{LOADER_PACKAGE}.custom_loader",
                "dynaconf.loaders.env_loader",
            ],
        )
        options.update(overrides)
        return Dynaconf(**options)

    return _factory


def test_startup_is_lazy_and_reads_active_env_and_generation(
    settings_factory, loader_package
):
    """Startup entry: no backend read happens until the first access."""
    settings = settings_factory()

    # LazySettings configures on first access, so construction must not
    # touch the custom backend.
    assert settings.configured is False
    assert loader_package.backend.reads == []

    # the first lazy access triggers one full read of the active env
    assert settings.TOKEN == "v1-token"
    reads = loader_package.backend.reads
    assert len(reads) == 1
    env, key, generation = reads[0]
    assert env == "DEVELOPMENT"
    assert key is None  # full-load on first access, not a per-key read
    assert generation == 1
    assert settings.current_env == "DEVELOPMENT"

    # cached subsequent access does not re-read the backend
    assert settings.TOKEN == "v1-token"
    assert len(loader_package.backend.reads) == 1


def test_get_fresh_rereads_current_generation_per_key(
    settings_factory, loader_package
):
    """On-demand entry: get_fresh re-reads only the requested key."""
    settings = settings_factory()
    assert settings.TOKEN == "v1-token"  # prime the runtime

    loader_package.backend.reads.clear()
    assert settings.get_fresh("TOKEN") == "v1-token"

    reads = loader_package.backend.reads
    assert len(reads) == 1
    env, key, generation = reads[0]
    assert env == "DEVELOPMENT"
    assert key == "TOKEN"
    assert generation == 1

    # moving the backend forward is observable through the next fresh read
    loader_package.backend.active_generation = 2
    assert settings.get_fresh("TOKEN") == "v2-token"
    assert loader_package.backend.reads[-1] == ("DEVELOPMENT", "TOKEN", 2)


def test_fresh_context_observes_new_generation_then_keeps_runtime(
    settings_factory, loader_package
):
    """The fresh() context re-reads and the committed value persists."""
    settings = settings_factory()
    assert settings.MODE == "dev"

    loader_package.backend.active_generation = 2
    with settings.fresh():
        assert settings.MODE == "prod"

    # after the context exits the freshly committed value is the runtime value
    assert settings.MODE == "prod"
    fresh_reads = [
        read for read in loader_package.backend.reads if read[2] == 2
    ]
    assert fresh_reads  # the second generation was actually read
    assert all(read[0] == "DEVELOPMENT" for read in fresh_reads)


def test_default_value_survives_when_backend_has_no_key(
    settings_factory, loader_package
):
    """Existing default-value behavior is preserved by both entries."""
    settings = settings_factory()
    assert settings.get("MISSING_KEY", "fallback") == "fallback"

    loader_package.backend.reads.clear()
    assert (
        settings.get("MISSING_KEY", "fresh-fallback", fresh=True)
        == "fresh-fallback"
    )
    # the backend was consulted for the missing key but returned no value
    assert loader_package.backend.reads[-1][1] == "MISSING_KEY"


def test_rejected_candidate_does_not_become_runtime_state(
    settings_factory, loader_package
):
    """First validation fails, second succeeds; runtime never sees failure.

    The guarded loader rolls the store back when validation rejects a
    candidate, then accepts the next valid candidate.
    """
    settings = settings_factory(
        validators=[Validator("SECURITY_FLAG", eq="safe")],
    )

    # establish the known-good runtime state through the custom loader
    assert settings.TOKEN == "v1-token"
    assert settings.SECURITY_FLAG == "safe"

    # poison the second generation so the first validation fails
    loader_package.backend.generations[2]["SECURITY_FLAG"] = "compromised"
    loader_package.backend.active_generation = 2

    with pytest.raises(ValidationError) as excinfo:
        loader_package.load(settings, env="DEVELOPMENT", validate=True)

    # the report names the offending setting and the rejected value
    assert "SECURITY_FLAG" in str(excinfo.value)
    assert len(excinfo.value.details) == 1
    failed_validator, message = excinfo.value.details[0]
    assert failed_validator.names == ("SECURITY_FLAG",)
    assert "compromised" in message

    # runtime state must remain the previous good generation
    assert _raw_store_value(settings, "TOKEN") == "v1-token"
    assert _raw_store_value(settings, "SECURITY_FLAG") == "safe"
    assert settings.TOKEN == "v1-token"
    assert settings.SECURITY_FLAG == "safe"

    # a repaired candidate passes validation and becomes the new runtime
    loader_package.backend.generations[2]["SECURITY_FLAG"] = "safe"
    loader_package.load(settings, env="DEVELOPMENT", validate=True)

    assert _raw_store_value(settings, "TOKEN") == "v2-token"
    assert settings.TOKEN == "v2-token"
    assert settings.SECURITY_FLAG == "safe"


def test_guarded_loader_rolls_back_on_validated_write(
    settings_factory, loader_package
):
    """The reference loader itself rolls back when its write is validated."""
    settings = settings_factory(
        validators=[Validator("SECURITY_FLAG", eq="safe")],
    )
    # prime runtime through the actual custom loader entry point
    assert settings.TOKEN == "v1-token"
    assert settings.SECURITY_FLAG == "safe"

    loader_package.backend.generations[2]["SECURITY_FLAG"] = "compromised"
    loader_package.backend.active_generation = 2

    with pytest.raises(ValidationError):
        loader_package.load(
            settings,
            env="DEVELOPMENT",
            validate=True,
        )

    assert _raw_store_value(settings, "TOKEN") == "v1-token"
    assert _raw_store_value(settings, "SECURITY_FLAG") == "safe"


def test_naive_loader_reusing_candidate_is_detected(tmp_path, monkeypatch):
    """A loader that keeps a rejected candidate fails the runtime assertion.

    This is a mutation-style guard: the same checks that pass for the
    reference loader must identify a loader which commits before validating.
    """
    _write_loader_package(
        tmp_path, FAULTY_LOADER, package=FAULTY_LOADER_PACKAGE
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    module_name = f"{FAULTY_LOADER_PACKAGE}.custom_loader"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    faulty = __import__(module_name, fromlist=["custom_loader"])
    faulty.backend.generations[1] = dict(GENERATION_1)
    faulty.backend.generations[2] = dict(GENERATION_2)
    faulty.backend.generations[2]["SECURITY_FLAG"] = "compromised"
    faulty.backend.active_generation = 1

    (tmp_path / "settings.toml").write_text("# placeholder settings file\n")
    settings = Dynaconf(
        environments=True,
        ENV_FOR_DYNACONF="DEVELOPMENT",
        settings_files=["settings.toml"],
        ROOT_PATH_FOR_DYNACONF=str(tmp_path),
        validators=[Validator("SECURITY_FLAG", eq="safe")],
        LOADERS_FOR_DYNACONF=[
            f"{FAULTY_LOADER_PACKAGE}.custom_loader",
            "dynaconf.loaders.env_loader",
        ],
    )
    # prime the good runtime while generation 1 is still active
    assert settings.TOKEN == "v1-token"
    assert settings.SECURITY_FLAG == "safe"

    # the faulty loader now serves a rejected candidate ...
    faulty.backend.active_generation = 2
    with pytest.raises(ValidationError) as excinfo:
        faulty.load(settings, env="DEVELOPMENT", validate=True)
    assert "SECURITY_FLAG" in str(excinfo.value)

    # ... but it has already committed the rejected candidate to the store,
    # so the runtime-state safety assertion must flag the leak
    assert _raw_store_value(settings, "TOKEN") == "v2-token"
    with pytest.raises(AssertionError):
        assert _raw_store_value(settings, "TOKEN") == "v1-token"


def test_inspect_history_tracks_only_committed_loads(
    settings_factory, loader_package
):
    """Inspect reporting reflects committed runtime values, not failed ones."""
    settings = settings_factory(
        validators=[Validator("SECURITY_FLAG", eq="safe")],
    )
    # prime the runtime through the guarded custom loader
    assert settings.TOKEN == "v1-token"

    loader_package.backend.generations[2]["SECURITY_FLAG"] = "compromised"
    loader_package.backend.active_generation = 2
    with suppress(ValidationError):
        loader_package.load(settings, env="DEVELOPMENT", validate=True)

    history = get_history(settings, "TOKEN")
    assert history, "history must still expose the committed good value"
    latest = history[0]
    assert latest["loader"] == "security_swap"
    assert latest["env"] == "development"
    assert latest["value"] == "v1-token"
