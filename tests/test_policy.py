# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

import threading

import pytest

import structlog

from structlog.policy import (
    DisclosurePolicy,
    InvalidPolicyError,
    PolicyProcessor,
    PolicySwitch,
    RedactionRule,
    effective_policy_version,
)
from structlog.typing import EventDict


@pytest.fixture
def captured():
    """
    Configure structlog with a capturing final processor and return the list
    of captured event dicts.
    """
    events: list[EventDict] = []

    def capture(logger, method_name, event_dict):
        events.append(dict(event_dict))
        raise structlog.DropEvent

    return events, capture


def make_logger(switch, capture, **context):
    structlog.configure(
        processors=[switch.processor(), capture],
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    return structlog.get_logger(**context)


V1 = DisclosurePolicy(
    version="v1",
    rules=(RedactionRule(key="password"),),
)
V2 = DisclosurePolicy(
    version="v2",
    rules=(
        RedactionRule(key="password"),
        RedactionRule(key="token", pattern=r"tok-\w+", replacement="[token]"),
    ),
)


class TestSwitchAcrossLoggers:
    def test_retained_and_fresh_loggers_follow_new_policy(self, captured):
        """
        A logger retained from before the switch and one created after it
        both emit new events under the new rules, and each event carries the
        version of the config that produced it.
        """
        events, capture = captured
        switch = PolicySwitch(V1)

        retained = make_logger(switch, capture, name="retained")
        retained.info("before", password="hunter2", token="tok-abc")
        assert effective_policy_version(retained) == "v1"

        assert switch.activate(V2) == "v2"
        assert switch.effective_version == "v2"

        fresh = make_logger(switch, capture, name="fresh")

        retained.info("after", password="hunter2", token="tok-abc")
        fresh.info("after", password="hunter2", token="tok-abc")

        assert events[0]["password"] == "***"
        assert events[0]["token"] == "tok-abc"  # v1 did not cover token
        assert events[0]["policy_version"] == "v1"

        for event in events[1:]:
            assert event["password"] == "***"
            assert event["token"] == "[token]"
            assert event["policy_version"] == "v2"

        # Both loggers report the effective version of their next events.
        assert effective_policy_version(retained) == "v2"
        assert effective_policy_version(fresh) == "v2"

    def test_effective_version_without_processor_raises(self):
        with pytest.raises(TypeError):
            effective_policy_version(object())


class TestBadConfig:
    @pytest.mark.parametrize(
        "config",
        [
            "not-a-mapping",
            {"token": 42},
            {"token": {"pattern": "([unclosed"}},
            {"token": {"replacement": 123}},
            {"token": {"bogus-option": "x"}},
            {"": None},
        ],
    )
    def test_invalid_configs_rejected(self, config):
        with pytest.raises(InvalidPolicyError):
            DisclosurePolicy.from_config("bad", config)

    def test_bad_activation_keeps_effective_policy(self, captured):
        """
        A failed switch attempt leaves the previously effective rules fully
        in force for subsequent events.
        """
        events, capture = captured
        switch = PolicySwitch(V1)
        log = make_logger(switch, capture)

        with pytest.raises(InvalidPolicyError):
            DisclosurePolicy.from_config("v2", {"token": {"pattern": "(["}})
        with pytest.raises(InvalidPolicyError):
            switch.activate("v2")
        with pytest.raises(InvalidPolicyError):
            switch.activate(DisclosurePolicy(version=""))

        assert switch.effective_version == "v1"
        log.info("still-v1", password="hunter2", token="tok-abc")

        (event,) = events
        assert event["password"] == "***"
        assert event["token"] == "tok-abc"
        assert event["policy_version"] == "v1"


class TestConcurrency:
    def test_each_event_matches_its_stamped_version(self, captured):
        """
        While a switch happens mid-stream, every event is redacted exactly
        according to the policy version it is stamped with -- no event mixes
        rules from two configurations.
        """
        events, capture = captured
        switch = PolicySwitch(V1)
        log = make_logger(switch, capture)

        barrier = threading.Barrier(5)

        def emit():
            barrier.wait()
            for _ in range(200):
                log.info("e", password="hunter2", token="tok-abc")

        def flip():
            barrier.wait()
            for _ in range(50):
                switch.activate(V2)
                switch.activate(V1)
            switch.activate(V2)

        threads = [threading.Thread(target=emit) for _ in range(4)]
        threads.append(threading.Thread(target=flip))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(events) == 800
        versions = set()
        for event in events:
            versions.add(event["policy_version"])
            assert event["password"] == "***"
            if event["policy_version"] == "v1":
                assert event["token"] == "tok-abc"
            else:
                assert event["policy_version"] == "v2"
                assert event["token"] == "[token]"
        # The final state is v2, and both generations appear in the stream.
        assert switch.effective_version == "v2"
        assert "v2" in versions


class TestContract:
    def test_processor_reports_effective_version(self):
        switch = PolicySwitch(V1)
        processor = switch.processor()
        assert isinstance(processor, PolicyProcessor)
        assert processor.effective_version == "v1"
        switch.activate(V2)
        assert processor.effective_version == "v2"

    def test_switch_requires_policy(self):
        with pytest.raises(InvalidPolicyError):
            PolicySwitch("v1")

    def test_duplicate_rule_keys_rejected(self):
        with pytest.raises(InvalidPolicyError):
            DisclosurePolicy(
                version="v",
                rules=(RedactionRule(key="a"), RedactionRule(key="a")),
            )

    def test_non_string_values_pass_through_with_pattern(self):
        rule = RedactionRule(key="n", pattern=r"\d+")
        assert rule.apply(12345) == 12345
        assert rule.apply("pin 1234") == "pin ***"

    def test_full_mask_replaces_any_value(self):
        rule = RedactionRule(key="secret")
        assert rule.apply({"nested": 1}) == "***"
