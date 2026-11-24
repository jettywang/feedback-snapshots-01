from __future__ import annotations

import threading

import pytest

from dynaconf import Dynaconf
from dynaconf import TransactionCancelled
from dynaconf import TransactionManager
from dynaconf import ValidationError
from dynaconf import Validator


def _settings(**kwargs):
    kwargs.setdefault("environments", False)
    return Dynaconf(**kwargs)


def test_commit_publishes_whole_record():
    settings = _settings(ITEM_ONE="v1", ITEM_TWO="v1")
    manager = TransactionManager(settings)

    with manager.transaction() as tx:
        tx.set("ITEM_ONE", "v2")
        tx.set("ITEM_TWO", "v2")

    assert settings.ITEM_ONE == "v2"
    assert settings.ITEM_TWO == "v2"
    assert manager.generation == 1


def test_staged_writes_are_invisible_until_commit():
    settings = _settings(ITEM_ONE="v1", ITEM_TWO="v1")
    manager = TransactionManager(settings)

    tx = manager.begin()
    tx.set("ITEM_ONE", "v2")
    # The live object keeps serving the previously approved configuration.
    assert settings.ITEM_ONE == "v1"
    assert settings.ITEM_TWO == "v1"
    tx.commit(validate=False)

    assert settings.ITEM_ONE == "v2"


def test_failed_validation_keeps_previous_configuration():
    settings = _settings(
        A=1,
        B=2,
        validators=[Validator("B", gte=0)],
    )
    manager = TransactionManager(settings)

    tx = manager.begin()
    tx.set("A", 100)  # would be visible if writes were not atomic
    tx.set("B", -1)   # rejected by the validator
    with pytest.raises(ValidationError):
        tx.commit(validate="all")

    assert settings.A == 1
    assert settings.B == 2
    # Even a fresh reload must not surface the rejected partial record.
    assert settings.get_fresh("A") == 1
    assert settings.get_fresh("B") == 2


def test_failed_candidate_is_archived_for_diagnostics():
    settings = _settings(A=1, validators=[Validator("A", gte=0)])
    manager = TransactionManager(settings)

    tx = manager.begin()
    tx.set("A", -5)
    with pytest.raises(ValidationError):
        tx.commit()

    record = manager.candidate(1)
    assert record["status"] == "failed"
    assert record["changes"] == {"A": -5}
    assert "ValidationError" in record["error"]
    assert manager.history(status="failed") == [record]


def test_cancel_discards_candidate_and_rejects_further_writes():
    settings = _settings(A=1)
    manager = TransactionManager(settings)

    tx = manager.begin()
    tx.set("A", 99)
    tx.cancel("operator abort")

    assert settings.A == 1
    assert manager.candidate(1)["status"] == "cancelled"
    with pytest.raises(TransactionCancelled):
        tx.set("A", 1)


def test_context_manager_commits_on_success_and_cancels_on_error():
    settings = _settings(A=1)
    manager = TransactionManager(settings)

    with manager.transaction() as tx:
        tx.set("A", 7)
    assert settings.A == 7

    with pytest.raises(RuntimeError):
        with manager.transaction() as tx:
            tx.set("A", 8)
            raise RuntimeError("boom")
    assert settings.A == 7
    assert manager.history(status="cancelled")


def test_fresh_read_reflects_committed_generation():
    settings = _settings(COLOR="blue")
    manager = TransactionManager(settings)

    with manager.transaction() as tx:
        tx.set("COLOR", "green")

    assert settings.COLOR == "green"
    assert settings.get_fresh("COLOR") == "green"
    assert settings.get("COLOR") == "green"


def test_lazy_value_reads_same_generation_data():
    settings = _settings(
        TARGET="old",
        BASE="@format this is {this.TARGET}",
    )
    manager = TransactionManager(settings)
    assert settings.BASE == "this is old"

    with manager.transaction() as tx:
        tx.set("TARGET", "new")

    assert settings.BASE == "this is new"
    assert settings.get_fresh("BASE") == "this is new"


def test_rollback_restores_previous_generation():
    settings = _settings(A=1, B=2)
    manager = TransactionManager(settings)

    with manager.transaction() as tx:
        tx.update({"A": 10, "B": 20})
    assert (settings.A, settings.B) == (10, 20)

    generation = manager.rollback()
    assert (settings.A, settings.B) == (1, 2)
    assert generation == 2
    assert manager.candidate(2)["changes"] == {"rollback": True}


def test_dotted_and_merge_writes_apply_atomically():
    settings = _settings(DB={"host": "h1", "port": 1})
    manager = TransactionManager(settings)

    with manager.transaction() as tx:
        tx.set("DB.port", 2)
        tx.set("DB.user", "admin")

    assert dict(settings.DB) == {"host": "h1", "port": 2, "user": "admin"}
    assert settings.get_fresh("DB")["port"] == 2


def test_memory_loader_is_registered_once():
    settings = _settings(A=1)
    TransactionManager(settings)
    manager_two = TransactionManager(settings)
    path = "dynaconf.loaders.memory_loader"
    assert list(settings.LOADERS_FOR_DYNACONF).count(path) == 1
    assert manager_two is not None


def test_consistent_read_pins_one_generation():
    settings = _settings(ITEM_ONE="v1", ITEM_TWO="v1")
    manager = TransactionManager(settings)

    with manager.consistent_read() as view:
        assert view.generation == 0
        assert view("ITEM_ONE") == "v1"
        # A commit inside the block does not change the pinned view.
        with manager.transaction() as tx:
            tx.set("ITEM_ONE", "v2")
            tx.set("ITEM_TWO", "v2")
        assert view("ITEM_ONE") == "v1"
        assert view("ITEM_TWO") == "v1"

    # A new read sees the newly published generation.
    with manager.consistent_read() as view:
        assert view.generation == 1
        assert (view("ITEM_ONE"), view("ITEM_TWO")) == ("v2", "v2")


def test_read_generation_returns_coherent_snapshot():
    settings = _settings(A=1, B=2)
    manager = TransactionManager(settings)
    with manager.transaction() as tx:
        tx.update({"A": 10, "B": 20})

    generation, data = manager.read_generation()
    assert generation == 1
    assert data["A"] == 10
    assert data["B"] == 20


def test_concurrent_commits_do_not_lose_updates():
    settings = _settings()
    manager = TransactionManager(settings)

    def writer(worker):
        for index in range(20):
            with manager.transaction() as tx:
                tx.set(f"KEY_{worker}_{index}", f"w{worker}-{index}")

    threads = [
        threading.Thread(target=writer, args=(worker,)) for worker in range(5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    expected = {
        f"KEY_{worker}_{index}".upper()
        for worker in range(5)
        for index in range(20)
    }
    assert {k for k in settings.store if k.startswith("KEY_")} == expected
    assert len(manager.history(status="committed")) == 100


def test_concurrent_readers_never_see_a_partial_record():
    settings = _settings(
        ITEM_ONE="v1",
        ITEM_TWO="v1",
        validators=[
            Validator(
                "ITEM_TWO",
                must_exist=True,
                condition=lambda value: value != "bad",
            )
        ],
    )
    manager = TransactionManager(settings)

    observations = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            with manager.consistent_read() as view:
                observations.append(
                    (view("ITEM_ONE"), view("ITEM_TWO"))
                )

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for thread in threads:
        thread.start()

    # First item staged, then a deliberately invalid second item.
    tx = manager.begin()
    tx.set("ITEM_ONE", "v2")
    tx.set("ITEM_TWO", "bad")
    with pytest.raises(ValidationError):
        tx.commit(validate="all")

    # A valid full record becomes visible atomically.
    with manager.transaction() as ok:
        ok.set("ITEM_ONE", "v3")
        ok.set("ITEM_TWO", "v3")

    stop.set()
    for thread in threads:
        thread.join()

    valid_pairs = {("v1", "v1"), ("v3", "v3")}
    assert all(pair in valid_pairs for pair in observations)
    assert (settings.ITEM_ONE, settings.ITEM_TWO) == ("v3", "v3")
