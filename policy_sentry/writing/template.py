"""Templates for the policy_sentry YML files.
These can be used for generating policies
"""

from __future__ import annotations

import copy
from typing import Any

ACTIONS_TEMPLATE = """mode: actions
name: ''
# Effect: Allow or Deny. Defaults to Allow.
# effect: Deny
actions:
- ''
"""

CRUD_TEMPLATE = """mode: crud
name: ''
# Effect: Allow or Deny. Defaults to Allow.
# effect: Deny
# Specify resource ARNs
read:
- ''
write:
- ''
list:
- ''
tagging:
- ''
permissions-management:
- ''
# Actions that do not support resource constraints
wildcard-only:
  single-actions: # standalone actions
  - ''
  # Service-wide - like 's3' or 'ec2'
  service-read:
  - ''
  service-write:
  - ''
  service-list:
  - ''
  service-tagging:
  - ''
  service-permissions-management:
  - ''
# Skip resource constraint requirements by listing actions here.
skip-resource-constraints:
- ''
# Exclude actions from the output by specifying them here. Accepts wildcards, like kms:Delete*
exclude-actions:
- ''
# If this policy needs to include an AssumeRole action
sts:
  assume-role:
    - ''
  assume-role-with-saml:
    - ''
  assume-role-with-web-identity:
    - ''
"""

# Optional role handover section. It is appended to the CRUD template only on request so that
# templates without a handover keep their existing shape.
CRUD_HANDOVER_TEMPLATE = """# Optional role handover: a colleague temporarily operates ONE approved project.
# The block above is the role's formal/standing permission. The approvals below are temporary.
# Temporary access only applies while BOTH the approving project name and the time window match
# a `policy_sentry handover --at <timestamp>` evaluation. Removing the temporary approval must never remove
# the formal permission declared above.
handover:
  # The single project approved for the handover. Required when projects are declared.
  approval:
    project: 'project-alpha'
    # ISO-8601 timestamps. The window is [start, end): start is inclusive, end is exclusive.
    start: '2026-12-01T00:00:00Z'
    end: '2026-12-02T00:00:00Z'
  # Projects the temporary operator may act on during the approved window.
  projects:
  - name: 'project-alpha'
    description: 'Temporary operator on the approved project only'
    access:
      read:
      - 'arn:aws:s3:::project-alpha/artifacts/*'
      write:
      - 'arn:aws:s3:::project-alpha/artifacts/*'
"""

CRUD_HANDOVER_TEMPLATE_DICT = {
    "approval": {
        "project": "project-alpha",
        "start": "2026-12-01T00:00:00Z",
        "end": "2026-12-02T00:00:00Z",
    },
    "projects": [
        {
            "name": "project-alpha",
            "description": "Temporary operator on the approved project only",
            "access": {
                "read": ["arn:aws:s3:::project-alpha/artifacts/*"],
                "write": ["arn:aws:s3:::project-alpha/artifacts/*"],
            },
        }
    ],
}

CRUD_TEMPLATE_DICT = {
    "mode": "crud",
    "name": "",
    "read": [],
    "write": [],
    "list": [],
    "tagging": [],
    "permissions-management": [],
    "wildcard-only": {
        "single-actions": [],
        "service-read": [],
        "service-write": [],
        "service-list": [],
        "service-tagging": [],
        "service-permissions-management": [],
    },
    "skip-resource-constraints": [],
    "exclude-actions": [],
    "sts": {
        "assume-role": [],
        "assume-role-with-saml": [],
        "assume-role-with-web-identity": [],
    },
}

ACTIONS_TEMPLATE_DICT = {"mode": "actions", "name": "", "actions": []}


def create_crud_template(with_handover: bool = False) -> str:
    """Generate the CRUD YML Template"""
    if with_handover:
        return CRUD_TEMPLATE + CRUD_HANDOVER_TEMPLATE
    return CRUD_TEMPLATE


def create_actions_template() -> str:
    """Generate the Actions YML template"""
    return ACTIONS_TEMPLATE


def get_crud_template_dict(with_handover: bool = False) -> dict[str, Any]:
    """Generate the CRUD template in dict format"""
    if with_handover:
        template = copy.deepcopy(CRUD_TEMPLATE_DICT)
        template["handover"] = copy.deepcopy(CRUD_HANDOVER_TEMPLATE_DICT)
        return template
    return CRUD_TEMPLATE_DICT


def get_actions_template_dict() -> dict[str, Any]:
    """Get the Actions template in dict format."""
    return ACTIONS_TEMPLATE_DICT
