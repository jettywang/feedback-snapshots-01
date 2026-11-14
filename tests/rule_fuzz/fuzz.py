# SPDX-License-Identifier: Apache-2.0

"""Property fuzzing driver for the artifact rule state model.

The driver compares the independent set-based oracle in
:mod:`tests.rule_fuzz.model` against the queue-based engine under test in
:mod:`tests.rule_fuzz.engine`. A fixed seed makes every run reproducible.

For every generated scenario the property checked is:

* the accept/reject verdicts must agree, and
* every per-queue remaining set must be identical.

On the first disagreement the scenario is automatically shrunk to a small,
readable counterexample. Two engine defect injections demonstrate the
shrinker end to end.
"""

import argparse
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

from tests.rule_fuzz import corpus, generator
from tests.rule_fuzz.engine import EngineConfig, evaluate_scenario as run_engine
from tests.rule_fuzz.model import Outcome, Step, evaluate_scenario as run_model
from tests.rule_fuzz.report import render_counterexample
from tests.rule_fuzz.shrinker import outcomes_differ, shrink


@dataclass
class FuzzSummary:
    iterations: int
    accepted: int
    rejected: int
    legal_checked: int
    divergences: int


def compare(steps: List[Step], config: EngineConfig
            ) -> Tuple[Outcome, Outcome, bool]:
    model_outcome = run_model(steps)
    engine_outcome = run_engine(steps, config)
    return model_outcome, engine_outcome, \
        outcomes_differ(model_outcome, engine_outcome)


def _predicate(config: EngineConfig):
    def is_failure(candidate: List[Step]) -> bool:
        model_outcome, engine_outcome, _ = compare(candidate, config)
        # The injected defects over-consume artifacts, so the security-relevant
        # divergence is: oracle rejects while the engine wrongly accepts.
        return (not model_outcome.accepted) and engine_outcome.accepted
    return is_failure


def find_and_shrink(steps: List[Step], config: EngineConfig
                    ) -> Optional[Tuple[List[Step], Outcome, Outcome, int]]:
    predicate = _predicate(config)
    if not predicate(steps):
        return None
    reduced, iterations = shrink(steps, predicate)
    reduced_model, reduced_engine, _ = compare(reduced, config)
    return reduced, reduced_model, reduced_engine, iterations


def run_fuzz(seed: int, iterations: int, config: EngineConfig,
             verbose: bool = False) -> Tuple[FuzzSummary, Optional[str]]:
    accepted = rejected = divergences = 0
    counterexample_text: Optional[str] = None

    # Handcrafted corpus first, then seeded random scenarios.
    scenarios: List[List[Step]] = [builder() for _, builder, _ in
                                   corpus.all_scenarios()]
    for index in range(iterations):
        steps, _ = generator.generate_fuzz_scenario(seed + index)
        scenarios.append(steps)

    legal_checked = 0
    for index in range(max(8, iterations // 4)):
        legal = generator.generate_legal_scenario(seed + 10_000 + index)
        model_outcome = run_model(legal)
        legal_checked += 1
        if not model_outcome.accepted:
            raise AssertionError(
                "legal generator produced a rejected scenario; oracle broken"
            )
        engine_outcome = run_engine(legal, config)
        # A legal policy must never be rejected, even by an engine with an
        # over-consumption defect (those only consume extra artifacts). Any
        # rejection here would be a false-positive bug in the engine.
        if not engine_outcome.accepted:
            raise AssertionError(
                "engine rejected a policy the independent model accepts"
            )

    for steps in scenarios:
        model_outcome, engine_outcome, differ = compare(steps, config)
        if model_outcome.accepted:
            accepted += 1
        else:
            rejected += 1
        if differ:
            divergences += 1
            found = find_and_shrink(steps, config)
            if found is None:
                # Divergence was not an accept/reject escape; report without
                # directional shrinking.
                counterexample_text = render_counterexample(
                    steps, model_outcome, engine_outcome, None
                )
                break
            reduced, m_out, e_out, shrunk = found
            counterexample_text = render_counterexample(
                reduced, m_out, e_out, shrunk
            )
            break
        if verbose:
            print(render_counterexample(
                steps, model_outcome, engine_outcome, None
            ).split("REMAINING")[0])

    summary = FuzzSummary(
        iterations=len(scenarios),
        accepted=accepted,
        rejected=rejected,
        legal_checked=legal_checked,
        divergences=divergences,
    )
    return summary, counterexample_text


def _build_config(mode: str) -> EngineConfig:
    if mode == "clean":
        return EngineConfig()
    if mode == "modify-same":
        return EngineConfig(modify_same_content=True)
    if mode == "match-step":
        return EngineConfig(match_ignore_target_step=True)
    if mode == "both":
        return EngineConfig(
            modify_same_content=True, match_ignore_target_step=True
        )
    raise ValueError(f"unknown mode {mode!r}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fuzz the in-toto artifact rule state model."
    )
    parser.add_argument("--seed", type=int, default=20261114,
                        help="fixed RNG seed for reproducibility")
    parser.add_argument("--iterations", type=int, default=300,
                        help="number of random scenarios to generate")
    parser.add_argument(
        "--mode",
        choices=["clean", "modify-same", "match-step", "both"],
        default="clean",
        help="engine defect injection to demonstrate",
    )
    parser.add_argument("--verbose", action="store_true",
                        help="print every scenario verdict")
    args = parser.parse_args(argv)

    config = _build_config(args.mode)
    summary, counterexample = run_fuzz(
        args.seed, args.iterations, config, args.verbose
    )

    print(
        f"mode={args.mode} seed={args.seed} "
        f"scenarios={summary.iterations} "
        f"accepted={summary.accepted} rejected={summary.rejected} "
        f"legal_policies={summary.legal_checked} "
        f"divergences={summary.divergences}"
    )
    if counterexample:
        print("\n=== COUNTEREXAMPLE (shrunk) ===")
        print(counterexample)
        return 1
    print("no divergence: engine matches the independent model")
    return 0


if __name__ == "__main__":
    sys.exit(main())
