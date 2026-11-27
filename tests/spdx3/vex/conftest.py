# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import List, Optional

import pytest

from spdx_tools.spdx3.model import RelationshipType
from spdx_tools.spdx3.model.hash import Hash, HashAlgorithm
from spdx_tools.spdx3.model.security import (
    VexAffectedVulnAssessmentRelationship,
    VexFixedVulnAssessmentRelationship,
    VexNotAffectedVulnAssessmentRelationship,
    VexUnderInvestigationVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.software import Package
from spdx_tools.spdx3.payload import Payload

NAMESPACE = "https://internal-archive.example/spdx"
VULN_ID = f"{NAMESPACE}#SPDXRef-Vulnerability-CVE-2026-0001"

VEX_CLASSES = {
    "fixed": VexFixedVulnAssessmentRelationship,
    "affected": VexAffectedVulnAssessmentRelationship,
    "not_affected": VexNotAffectedVulnAssessmentRelationship,
    "under_investigation": VexUnderInvestigationVulnAssessmentRelationship,
}


def package_id(local_id: str) -> str:
    return f"{NAMESPACE}#{local_id}"


def make_package(
    local_id: str,
    name: str,
    version: Optional[str],
    with_hash: bool = True,
    purl: Optional[str] = None,
) -> Package:
    verified_using = [Hash(HashAlgorithm.SHA256, f"hash-of-{local_id}")] if with_hash else []
    return Package(
        spdx_id=package_id(local_id),
        name=name,
        package_version=version,
        package_url=purl,
        verified_using=verified_using,
    )


def make_vex(
    local_id: str,
    kind: str,
    assessed_local_id: str,
    published: datetime,
    modified: Optional[datetime] = None,
    withdrawn: Optional[datetime] = None,
    supplied_by: Optional[str] = f"{NAMESPACE}#SPDXRef-Agent-security-team",
    with_hash: bool = True,
    status_notes: Optional[str] = None,
) -> object:
    assessed_id = package_id(assessed_local_id)
    verified_using = [Hash(HashAlgorithm.SHA256, f"patch-evidence-{local_id}")] if with_hash else []
    return VEX_CLASSES[kind](
        spdx_id=package_id(local_id),
        from_element=VULN_ID,
        relationship_type=RelationshipType.HAS_ASSESSMENT_FOR,
        to=[assessed_id],
        assessed_element=assessed_id,
        published_time=published,
        modified_time=modified,
        withdrawn_time=withdrawn,
        supplied_by=supplied_by,
        vex_version="2.0.0",
        status_notes=status_notes,
        verified_using=verified_using,
    )


@pytest.fixture
def payload_with_branches() -> Payload:
    payload = Payload()
    payload.add_element(make_package("SPDXRef-Package-legacy", "legacy-logger", "1.2.0"))
    payload.add_element(make_package("SPDXRef-Package-upgraded", "legacy-logger", "1.3.0"))
    payload.add_element(make_package("SPDXRef-Package-no-version", "mystery-lib", None))
    payload.add_element(make_package("SPDXRef-Package-no-evidence", "thin-lib", "3.4.0", with_hash=False))
    payload.add_element(make_package("SPDXRef-Package-unrelated", "unrelated-lib", "9.0.0"))
    return payload


@pytest.fixture
def migrated_ids() -> List[str]:
    return [package_id("SPDXRef-Package-legacy"), package_id("SPDXRef-Package-no-version")]
