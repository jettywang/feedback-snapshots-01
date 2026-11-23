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

"""Conservative policy-convergence review helpers.

The package never mutates a stored policy.  It loads a policy snapshot and a
set of archived API requests, then explains, for every candidate rule, who
would be affected if that rule were deleted:

* archived requests whose decision changes (observed effects),
* the role chains that connect real subjects to the candidate rule,
* the part of the rule's coverage that no archived request exercises
  (unknown scope), so a deletion can only be recommended when every claim is
  verifiable from the supplied evidence.
"""

from .data import (
    ArchivedRequest,
    CandidateRule,
    DecisionChange,
    Probe,
    ReviewReport,
    RuleReview,
)
from .review import PolicySnapshot, review_candidate, review_candidates

__all__ = [
    "ArchivedRequest",
    "CandidateRule",
    "DecisionChange",
    "PolicySnapshot",
    "Probe",
    "ReviewReport",
    "RuleReview",
    "review_candidate",
    "review_candidates",
]
