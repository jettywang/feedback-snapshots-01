from typing import Dict, List, Optional

from pydantic import model_validator

from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.mozilla_tls_profile.tls_config_checker import (
    TlsConfigurationCheckResult,
    TlsConfigurationCheckStatusEnum,
    TlsConfigurationCriterionCheckResult,
)
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum


class TlsConfigurationCriterionCheckResultAsJson(BaseModelWithOrmModeAndForbid):
    criterion_name: str
    status: TlsConfigurationCheckStatusEnum
    issue_description: Optional[str]
    # The scan commands the criterion depends on, keyed by scan command name, with the NOT_SCHEDULED ("not run"),
    # ERROR and COMPLETED distinction preserved
    dependencies: Dict[ScanCommand, ScanCommandAttemptStatusEnum]

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data):
        if not isinstance(data, TlsConfigurationCriterionCheckResult):
            return data

        return dict(
            criterion_name=data.criterion_name,
            status=data.status,
            issue_description=data.issue_description,
            dependencies=data.dependencies,
        )


class TlsConfigurationCheckResultAsJson(BaseModelWithOrmModeAndForbid):
    overall_status: TlsConfigurationCheckStatusEnum
    is_compliant: bool
    issues: Dict[str, str]
    criteria: List[TlsConfigurationCriterionCheckResultAsJson]

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data):
        if not isinstance(data, TlsConfigurationCheckResult):
            return data

        return dict(
            overall_status=data.overall_status,
            is_compliant=data.is_compliant,
            issues=data.issues,
            criteria=[
                TlsConfigurationCriterionCheckResultAsJson.model_validate(criterion) for criterion in data.criteria
            ],
        )
