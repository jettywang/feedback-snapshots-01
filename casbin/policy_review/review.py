# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Trial-deletion analysis against an immutable policy snapshot."""

import hashlib
from typing import Dict, List, Optional, Sequence, Tuple

from casbin import Enforcer
from casbin.persist.adapters.string_adapter import StringAdapter

from .data import (
    ArchivedRequest,
    CandidateRule,
    DecisionChange,
    Probe,
    ReviewReport,
    RuleReview,
    VERDICT_BLOCKED,
    VERDICT_NOT_VERIFIABLE,
    VERDICT_REMOVABLE,
)
from .role_chains import find_role_chains

_DOMAIN_TOKENS = {"dom", "domain"}
_DENY_VALUES = {"deny"}


class PolicySnapshot:
    """Read-only view of a model plus its archived policy text.

    The snapshot keeps the raw policy lines as rollback evidence and never
    writes back to the policy file.  Trial enforcers are built from in-memory
    copies, so the baseline enforcer is untouched.
    """

    def __init__(self, model_path: str, policy_path: str):
        self.model_path = model_path
        self.policy_path = policy_path
        with open(policy_path, encoding="utf-8") as handle:
            self.policy_text = handle.read()
        self.policy_sha256 = hashlib.sha256(self.policy_text.encode("utf-8")).hexdigest()
        self.enforcer = Enforcer(model_path, StringAdapter(self.policy_text))
        self.request_tokens = list(self.enforcer.model.model["r"]["r"].tokens)
        self._effect_tokens = self._policy_effect_tokens()

    def _policy_effect_tokens(self) -> Dict[str, List[str]]:
        tokens = {}
        for ptype, ast in self.enforcer.model.model.get("p", {}).items():
            tokens[ptype] = list(ast.tokens)
        return tokens

    def baseline_enforce(self, rvals: Sequence[str]) -> Tuple[bool, Tuple[str, ...]]:
        allow, explain = self.enforcer.enforce_ex(*rvals)
        return bool(allow), tuple(explain)

    def build_trial_enforcer(self, candidate: CandidateRule) -> Enforcer:
        """Return a fresh enforcer with every copy of the candidate rule removed."""

        kept_lines = []
        target = list(candidate.rule)
        for raw_line in self.policy_text.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                kept_lines.append(raw_line)
                continue
            tokens = [part.strip() for part in stripped.split(",")]
            if tokens and tokens[0] == candidate.ptype and tokens[1:] == target:
                continue
            kept_lines.append(raw_line)

        return Enforcer(self.model_path, StringAdapter("\n".join(kept_lines)))

    def count_matching_rules(self, candidate: CandidateRule) -> int:
        target = list(candidate.rule)
        count = 0
        for rule in self.enforcer.get_named_policy(candidate.ptype):
            if rule == target:
                count += 1
        return count

    def is_deny_rule(self, candidate: CandidateRule) -> bool:
        tokens = self._effect_tokens.get(candidate.ptype, [])
        for index, token in enumerate(tokens):
            short = token.split("_", 1)[-1].lower()
            if short == "eft" and index < len(candidate.rule):
                return candidate.rule[index].lower() in _DENY_VALUES
        return False

    def role_manager_for(self, ptype: str = "g"):
        return self.enforcer.get_named_role_manager(ptype)


def _rule_matches_explain(explain: Tuple[str, ...], rule: Tuple[str, ...]) -> bool:
    return bool(explain) and list(explain) == list(rule)


def _synthesise_probes(
    snapshot: PolicySnapshot,
    candidate: CandidateRule,
    observed_keys: set,
    chains: Dict[str, List[List[str]]],
    is_deny_rule: bool,
) -> List[Probe]:
    """Build concrete, evaluable requests inside the candidate's coverage.

    Probes are kept even when a deny rule overrides the final decision: the
    candidate allow rule still matches the request, so the masked access is
    part of the rule's coverage that the archive fails to observe.
    """

    rule = list(candidate.rule)
    p_tokens = snapshot._effect_tokens.get(candidate.ptype, [])
    r_tokens = snapshot.request_tokens

    # Map each request position to the candidate rule field at the same index,
    # supporting both "sub, dom, obj, act" style models and extra tokens such
    # as an optional scope parameter.
    field_by_request_index: Dict[int, str] = {}
    for index, request_token in enumerate(r_tokens):
        short = request_token.split("_", 1)[-1].lower()
        for policy_index, policy_token in enumerate(p_tokens):
            if policy_token.split("_", 1)[-1].lower() == short:
                field_by_request_index[index] = rule[policy_index]
                break

    rule_domain: Optional[str] = None
    for index, token in enumerate(p_tokens):
        if token.split("_", 1)[-1].lower() in _DOMAIN_TOKENS and index < len(rule):
            value = rule[index]
            rule_domain = value if value else None
            break
    role_manager = snapshot.role_manager_for("g")

    # Probe every concrete root subject that reaches the rule's subject token
    # through a role chain, then the rule subject itself (covers direct uses
    # and rules nobody inherits).
    # A real principal only exists when at least one grant chain has more than
    # the target's self-chain; an isolated target role is dead coverage.
    real_subjects = {
        subject
        for subject, paths in chains.items()
        if any(len(path) > 1 for path in paths)
    }
    # Probe real root subjects first.  When none exist, probe the rule's own
    # subject exactly once so the dead coverage remains verifiable.
    subjects = sorted(real_subjects) if real_subjects else ([rule[0]] if rule else [])
    probes: List[Probe] = []
    seen = set()
    for subject in subjects:
        rvals = list(rule[: len(r_tokens)]) if len(rule) >= len(r_tokens) else rule + [""] * (len(r_tokens) - len(rule))
        for index, _token_name in enumerate(r_tokens):
            if index in field_by_request_index:
                rvals[index] = field_by_request_index[index]
        rvals[0] = subject
        key = tuple(rvals)
        if key in seen:
            continue

        # The candidate covers this probe only when the subject really reaches
        # the rule's subject token through the (domain-aware) role graph.
        if rule_domain is None:
            reaches = role_manager.has_link(subject, rule[0])
        else:
            reaches = role_manager.has_link(subject, rule[0], rule_domain)
        if not reaches:
            continue

        allow, explain = snapshot.baseline_enforce(rvals)
        matcher_covers = _rule_matches_explain(explain, candidate.rule)
        shadowed_by_deny = not is_deny_rule and not allow
        if not matcher_covers and not shadowed_by_deny:
            # The candidate neither decides nor matches this request: it lies
            # outside the rule's effective coverage.
            continue
        # With no real principal reaching the rule, its own subject is an
        # isolated role placeholder: the single self-probe is verifiably dead.
        orphan_self_probe = not real_subjects and subject == rule[0]
        # An allow rule masked by a deny rule stays unobservable even when an
        # archived request has the same rvals, so such probes must not be
        # filtered out as "already covered".
        if key in observed_keys and not shadowed_by_deny and not orphan_self_probe:
            continue
        seen.add(key)
        subject_chains = chains.get(subject, [[subject]])
        probes.append(
            Probe(
                rvals=tuple(rvals),
                subject=subject,
                role_chain=tuple(subject_chains[0]),
                baseline_allow=allow,
                explain_rule=explain,
                orphan=orphan_self_probe,
            )
        )
    return probes


def review_candidate(snapshot: PolicySnapshot, candidate: CandidateRule, requests: List[ArchivedRequest]) -> RuleReview:
    """Explain who is affected by deleting one candidate rule."""

    review = RuleReview(
        candidate=candidate,
        rule_present=snapshot.enforcer.has_named_policy(candidate.ptype, list(candidate.rule)),
        matching_rule_count=snapshot.count_matching_rules(candidate),
        is_deny_rule=snapshot.is_deny_rule(candidate),
    )

    if not review.rule_present:
        review.verdict = VERDICT_NOT_VERIFIABLE
        review.reasons.append("candidate rule is not present in the policy snapshot; nothing would be deleted")
        return review

    # 1. Baseline must reproduce every archived decision, otherwise the
    #    snapshot itself is untrustworthy and no deletion claim is verifiable.
    baseline_by_id: Dict[str, Tuple[bool, Tuple[str, ...]]] = {}
    for archived in requests:
        allow, explain = snapshot.baseline_enforce(archived.rvals)
        baseline_by_id[archived.request_id] = (allow, explain)
        if allow != archived.expected_allow:
            review.baseline_mismatches.append(archived)

    # 2. Role chains, respecting domain inheritance when the model has domains.
    rule_domain: Optional[str] = None
    p_tokens = snapshot._effect_tokens.get(candidate.ptype, [])
    for index, token in enumerate(p_tokens):
        if token.split("_", 1)[-1].lower() in _DOMAIN_TOKENS and index < len(candidate.rule):
            value = candidate.rule[index]
            rule_domain = value if value else None
            break
    role_manager = snapshot.role_manager_for("g")
    try:
        chains = find_role_chains(role_manager, candidate.rule[0], rule_domain)
    except Exception:  # pragma: no cover - defensive: custom role managers
        chains = {}
    review.role_chains = {subject: paths for subject, paths in sorted(chains.items())}
    review.coverage_subjects = sorted(review.role_chains.keys())

    # 3. Trial deletion and per-request decision comparison.
    trial = snapshot.build_trial_enforcer(candidate)
    observed_keys = set()
    for archived in requests:
        baseline_allow, baseline_explain = baseline_by_id[archived.request_id]
        observed_keys.add(tuple(archived.rvals))
        trial_allow, trial_explain = trial.enforce_ex(*archived.rvals)
        trial_allow = bool(trial_allow)
        trial_explain = tuple(trial_explain)

        decides_request = _rule_matches_explain(baseline_explain, candidate.rule)
        if decides_request:
            review.observed_requests.append(archived.request_id)

        if trial_allow != baseline_allow:
            if review.is_deny_rule:
                effect = "deny_override_lost"
            elif baseline_allow:
                effect = "allow_lost"
            else:
                effect = "decision_flipped"
            review.decision_changes.append(
                DecisionChange(
                    request_id=archived.request_id,
                    rvals=archived.rvals,
                    expected_allow=archived.expected_allow,
                    trial_allow=trial_allow,
                    baseline_explain=baseline_explain,
                    trial_explain=trial_explain,
                    effect=effect,
                    optional_tokens=archived.optional_tokens,
                )
            )

    # 4. Unknown scope: effective coverage with no archived request twin.
    # Deny rules act on literal subjects and never grant access, so allow-style
    # coverage probes do not apply to them.
    if review.is_deny_rule:
        all_probes = []
    else:
        all_probes = _synthesise_probes(
            snapshot, candidate, observed_keys, chains, review.is_deny_rule
        )
    # Orphan probes back a verifiable "dead rule" claim; only probes reachable
    # by a real principal count as unknown coverage.
    review.unobserved_probes = [probe for probe in all_probes if not probe.orphan]
    review.orphan_probes = [probe for probe in all_probes if probe.orphan]

    # 5. Conservative verdict: only "removable" when every claim is backed by
    #    archived evidence; any flip blocks, any blind spot blocks signing off.
    if review.baseline_mismatches:
        review.verdict = VERDICT_NOT_VERIFIABLE
        review.reasons.append(
            "baseline snapshot fails to reproduce "
            f"{len(review.baseline_mismatches)} archived decision(s); evidence is unreliable"
        )
    if review.decision_changes:
        review.verdict = VERDICT_BLOCKED
        if review.is_deny_rule:
            review.reasons.append(
                f"deleting this deny rule flips {len(review.decision_changes)} archived request(s) "
                "from deny to allow; deny overrides must stay in place"
            )
        else:
            review.reasons.append(
                f"deleting this rule changes the decision of {len(review.decision_changes)} archived request(s)"
            )
    elif review.unobserved_probes:
        review.verdict = VERDICT_NOT_VERIFIABLE
        review.reasons.append(
            f"{len(review.unobserved_probes)} concrete request(s) inside the rule's effective coverage "
            "have no archived twin; impact outside the archive is unknown"
        )
    elif not review.baseline_mismatches:
        review.verdict = VERDICT_REMOVABLE
        if review.orphan_probes:
            review.reasons.append(
                f"{len(review.orphan_probes)} probe(s) only match the rule's own subject, which no role grant "
                "reaches: the coverage is verifiably dead within this snapshot"
            )
        review.reasons.append(
            "every archived decision stays unchanged and the rule has no effective coverage "
            "beyond the archived evidence; deletion is verifiable from this snapshot"
        )

    return review


def review_candidates(
    model_path: str,
    policy_path: str,
    requests: List[ArchivedRequest],
    candidates: List[CandidateRule],
) -> ReviewReport:
    """Run the full review and assemble a serialisable report."""

    snapshot = PolicySnapshot(model_path, policy_path)
    reviews = [review_candidate(snapshot, candidate, requests) for candidate in candidates]
    return ReviewReport(
        model_path=model_path,
        policy_path=policy_path,
        policy_sha256=snapshot.policy_sha256,
        request_tokens=snapshot.request_tokens,
        archived_count=len(requests),
        reviews=reviews,
    )
