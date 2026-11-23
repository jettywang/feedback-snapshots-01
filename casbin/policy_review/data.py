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

"""Plain data containers shared by the policy review workflow."""

import json
from dataclasses import asdict, dataclass, field
from typing import List, Optional

# Recommendation verdicts, ordered from most to least actionable.
VERDICT_REMOVABLE = "removable"
VERDICT_NOT_VERIFIABLE = "not_verifiable"
VERDICT_BLOCKED = "blocked"

_ALLOW_WORDS = {"allow", "allowed", "permit", "true", "1", "yes"}
_DENY_WORDS = {"deny", "denied", "forbid", "false", "0", "no"}


def _coerce_expected(value) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _ALLOW_WORDS:
        return True
    if text in _DENY_WORDS:
        return False
    raise ValueError(f"unrecognised expected decision {value!r}")


@dataclass(frozen=True)
class ArchivedRequest:
    """One archived API request with the decision recorded at the time."""

    request_id: str
    rvals: tuple
    expected_allow: bool
    optional_tokens: tuple = ()

    @property
    def expected_label(self) -> str:
        return "allow" if self.expected_allow else "deny"

    @classmethod
    def from_dict(cls, raw: dict, request_tokens: List[str]) -> "ArchivedRequest":
        if "request_id" not in raw:
            raise ValueError("archived request is missing 'request_id'")
        request_id = str(raw["request_id"])

        values = raw.get("rvals")
        optional = []
        if values is None:
            if "request" in raw and isinstance(raw["request"], (list, tuple)):
                values = raw["request"]
            else:
                values = [raw.get(token, "") for token in request_tokens]
        if not isinstance(values, (list, tuple)):
            raise ValueError(f"request {request_id}: 'rvals' must be a list")
        values = list(values)

        if len(values) > len(request_tokens):
            raise ValueError(
                f"request {request_id}: {len(values)} values for "
                f"{len(request_tokens)} request tokens {request_tokens}"
            )

        optional_tokens = tuple(request_tokens[len(values):])
        # Optional request parameters are normalised to "" so they still take
        # part in matcher evaluation instead of being silently dropped.
        values += [""] * (len(request_tokens) - len(values))
        return cls(
            request_id=request_id,
            rvals=tuple("" if value is None else str(value) for value in values),
            expected_allow=_coerce_expected(raw["expected"] if "expected" in raw else raw.get("decision")),
            optional_tokens=optional_tokens,
        )


@dataclass(frozen=True)
class CandidateRule:
    """A policy rule proposed for deletion, identified by its CSV fields."""

    rule_id: str
    ptype: str
    rule: tuple

    @classmethod
    def from_dict(cls, raw: dict) -> "CandidateRule":
        if "rule_id" not in raw:
            raise ValueError("candidate rule is missing 'rule_id'")
        rule_id = str(raw["rule_id"])
        ptype = str(raw.get("ptype", "p"))
        if "rule" not in raw or not isinstance(raw["rule"], (list, tuple)):
            raise ValueError(f"candidate {rule_id}: 'rule' must be a list")
        rule = tuple(str(field_value) for field_value in raw["rule"])
        return cls(rule_id=rule_id, ptype=ptype, rule=rule)

    @property
    def csv_line(self) -> str:
        return ", ".join((self.ptype,) + self.rule)


@dataclass(frozen=True)
class DecisionChange:
    """An archived request whose decision would change after the trial deletion."""

    request_id: str
    rvals: tuple
    expected_allow: bool
    trial_allow: bool
    baseline_explain: tuple
    trial_explain: tuple
    effect: str
    optional_tokens: tuple = ()

    @property
    def change_label(self) -> str:
        if self.expected_allow and not self.trial_allow:
            return "allow -> deny (access lost)"
        if not self.expected_allow and self.trial_allow:
            return "deny -> allow (deny override lost)"
        return self.effect


@dataclass(frozen=True)
class Probe:
    """A concrete request inside the candidate's coverage with no archived twin."""

    rvals: tuple
    subject: str
    role_chain: tuple
    baseline_allow: bool
    explain_rule: tuple
    optional_tokens: tuple = ()
    orphan: bool = False


@dataclass
class RuleReview:
    """Full, evidence-backed explanation for one trial deletion."""

    candidate: CandidateRule
    rule_present: bool
    matching_rule_count: int
    is_deny_rule: bool
    baseline_mismatches: List[ArchivedRequest] = field(default_factory=list)
    decision_changes: List[DecisionChange] = field(default_factory=list)
    role_chains: dict = field(default_factory=dict)
    observed_requests: List[str] = field(default_factory=list)
    unobserved_probes: List[Probe] = field(default_factory=list)
    orphan_probes: List[Probe] = field(default_factory=list)
    coverage_subjects: List[str] = field(default_factory=list)
    verdict: str = VERDICT_NOT_VERIFIABLE
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["candidate"] = asdict(self.candidate)
        data["baseline_mismatches"] = [asdict(item) for item in self.baseline_mismatches]
        data["decision_changes"] = [asdict(item) for item in self.decision_changes]
        data["unobserved_probes"] = [asdict(item) for item in self.unobserved_probes]
        data["orphan_probes"] = [asdict(item) for item in self.orphan_probes]
        return data


@dataclass
class ReviewReport:
    """Aggregated result for a whole review run."""

    model_path: str
    policy_path: str
    policy_sha256: str
    request_tokens: List[str]
    archived_count: int
    reviews: List[RuleReview]

    def to_dict(self) -> dict:
        return {
            "model_path": self.model_path,
            "policy_path": self.policy_path,
            "policy_sha256": self.policy_sha256,
            "request_tokens": self.request_tokens,
            "archived_count": self.archived_count,
            "reviews": [review.to_dict() for review in self.reviews],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def load_review_input(path: str, request_tokens: List[str]):
    """Load archived requests and candidate rules from one JSON document.

    Expected shape: {"requests": [...], "candidates": [...]}.
    """

    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    requests = [
        ArchivedRequest.from_dict(raw, request_tokens)
        for raw in document.get("requests", [])
    ]
    candidates = [CandidateRule.from_dict(raw) for raw in document.get("candidates", [])]
    if not requests:
        raise ValueError("review input contains no archived requests")
    if not candidates:
        raise ValueError("review input contains no candidate rules")
    return requests, candidates
