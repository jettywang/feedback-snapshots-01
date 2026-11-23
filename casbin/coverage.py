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

"""Coverage evidence for partially loaded (filtered) policies.

When only a slice of the policy is loaded to save memory, a boolean
enforce result alone cannot tell the caller whether the answer is final.
The types here let an enforcer report how much of the relevant scope
(policy rules, role links, priority ordering) backs each decision.
"""

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    """Outcome of a coverage-aware authorization decision."""

    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class CoverageSnapshot:
    """Adapter-reported view of which parts of the policy are loaded.

    Adapters that serve the policy in batches (e.g. per domain or per page)
    may implement ``coverage()`` returning this snapshot so the enforcer can
    reason about the known scope.
    """

    complete: bool = True
    policy_domains: frozenset = frozenset()
    role_domains: frozenset = frozenset()
    missing: tuple = ()


@dataclass(frozen=True)
class CoverageEvidence:
    """Describes the known scope backing a single decision."""

    complete: bool
    request_domains: tuple
    policy_known: bool
    role_links_known: bool
    priority_known: bool
    loaded_batches: tuple = ()
    missing: tuple = ()


@dataclass(frozen=True)
class CoverageDecision:
    """Authorization decision plus the coverage evidence behind it."""

    decision: Decision
    allowed: bool
    explain: tuple = ()
    evidence: CoverageEvidence = None
