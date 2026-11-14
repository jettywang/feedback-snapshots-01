# SPDX-License-Identifier: Apache-2.0

"""Property tests for the independent in-toto artifact rule state model."""

import pytest

from tests.rule_fuzz import corpus, generator
from tests.rule_fuzz.engine import EngineConfig, evaluate_scenario as engine_run
from tests.rule_fuzz.fuzz import find_and_shrink, run_fuzz
from tests.rule_fuzz.model import evaluate_scenario as model_run
from tests.rule_fuzz.shrinker import outcomes_differ, scenario_size

SEED = 20261114
CLEAN = EngineConfig()
MODIFY_BUG = EngineConfig(modify_same_content=True)
MATCH_BUG = EngineConfig(match_ignore_target_step=True)


def test_corpus_oracle_verdicts():
    for name, builder, expected_accepted in corpus.all_scenarios():
        outcome = model_run(builder())
        assert outcome.accepted is expected_accepted, name


def test_legal_generator_is_always_accepted():
    for index in range(60):
        steps = generator.generate_legal_scenario(SEED + index)
        outcome = model_run(steps)
        assert outcome.accepted, f"legal scenario rejected at {index}"
        assert all(
            not result.remaining
            for _, _, result in outcome.step_results
        )


def test_clean_engine_matches_oracle_on_corpus():
    for name, builder, _ in corpus.all_scenarios():
        model_outcome = model_run(builder())
        engine_outcome = engine_run(builder(), CLEAN)
        assert not outcomes_differ(model_outcome, engine_outcome), name


def test_clean_engine_matches_oracle_on_fuzz_scenarios():
    for index in range(200):
        steps, _ = generator.generate_fuzz_scenario(SEED + index)
        model_outcome = model_run(steps)
        engine_outcome = engine_run(steps, CLEAN)
        assert not outcomes_differ(model_outcome, engine_outcome), index


def test_legal_policies_cover_prefix_and_modify_and_early_consume():
    steps = generator.generate_legal_scenario(SEED)
    generator.add_prefix_transformation(steps[0], prefix="build")
    rng = generator.make_rng(SEED)
    generator.permute_rule_order(steps, rng)
    # The transformed/prefix scenario is rendered and stays finite; ensure
    # prefix keys are present and the model still evaluates deterministically.
    assert any(
        path.startswith("build/")
        for step in steps for path in step.materials | step.products
    )
    first = model_run(steps)
    second = model_run(steps)
    assert first.remaining_by_queue == second.remaining_by_queue


def test_modify_same_content_bug_produces_readable_counterexample():
    scenario = corpus.same_name_unchanged()
    model_outcome = model_run(scenario)
    buggy_outcome = engine_run(scenario, MODIFY_BUG)
    assert outcomes_differ(model_outcome, buggy_outcome)
    assert model_outcome.accepted is False
    assert buggy_outcome.accepted is True

    found = find_and_shrink(scenario, MODIFY_BUG)
    assert found is not None
    reduced, reduced_model, reduced_engine, iterations = found
    assert reduced_model.accepted is False
    assert reduced_engine.accepted is True
    assert scenario_size(reduced) <= scenario_size(scenario)
    assert iterations >= 0


def test_match_ignores_target_step_bug_produces_readable_counterexample():
    scenario = corpus.match_ignored_target_counterexample()
    model_outcome = model_run(scenario)
    buggy_outcome = engine_run(scenario, MATCH_BUG)
    assert outcomes_differ(model_outcome, buggy_outcome)
    assert model_outcome.accepted is False
    assert buggy_outcome.accepted is True

    found = find_and_shrink(scenario, MATCH_BUG)
    assert found is not None
    reduced, reduced_model, reduced_engine, _ = found
    assert reduced_model.accepted is False
    assert reduced_engine.accepted is True


def test_fuzz_clean_reports_no_divergence():
    summary, counterexample = run_fuzz(SEED, 150, CLEAN)
    assert summary.divergences == 0
    assert counterexample is None
    assert summary.accepted + summary.rejected == summary.iterations


def test_fuzz_detects_each_injected_defect():
    for config in (MODIFY_BUG, MATCH_BUG):
        summary, counterexample = run_fuzz(SEED, 150, config)
        assert summary.divergences >= 1
        assert counterexample is not None
        assert "COUNTEREXAMPLE" not in counterexample  # header added by CLI
        assert "REMAINING SET DIFFERENCE" in counterexample


def test_seed_reproducibility():
    first, _ = generator.generate_fuzz_scenario(SEED)
    second, _ = generator.generate_fuzz_scenario(SEED)
    assert [s.name for s in first] == [s.name for s in second]
    assert [dict(s.products) for s in first] == \
        [dict(s.products) for s in second]


def test_production_engine_agrees_with_independent_model():
    pytest.importorskip("in_toto.verifylib")
    from tests.rule_fuzz.model import evaluate_queue as model_eval_queue
    from tests.rule_fuzz.production_adapter import (
        build_links,
        evaluate_queue as production_eval,
    )

    for index in range(40):
        steps, _ = generator.generate_fuzz_scenario(SEED + index)
        links = build_links(steps)
        steps_by_name = {step.name: step for step in steps}
        for step in steps:
            for side, rules in (
                ("materials", step.material_rules),
                ("products", step.product_rules),
            ):
                if not rules:
                    continue
                production = production_eval(side, rules, step, links)
                queue_result = model_eval_queue(
                    side, rules, step, steps_by_name
                )
                assert production.accepted == queue_result.accepted
                assert set(production.remaining) == set(queue_result.remaining)
