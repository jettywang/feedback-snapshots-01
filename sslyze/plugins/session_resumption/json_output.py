from typing import List, Optional

from sslyze import (
    SessionResumptionSupportExtraArgument,
    SessionResumptionSupportScanResult,
    TlsResumptionSupportEnum,
    ResumptionAttemptEvidence,
    ResumptionAttemptOutcomeEnum,
    ResumptionMechanismEnum,
)
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid, StrFromEnumValueName
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson


class SessionResumptionSupportExtraArgumentAsJson(BaseModelWithOrmModeAndForbid):
    number_of_resumptions_to_attempt: int


assert SessionResumptionSupportExtraArgument.__doc__
SessionResumptionSupportExtraArgumentAsJson.__doc__ = SessionResumptionSupportExtraArgument.__doc__


class ResumptionAttemptEvidenceAsJson(BaseModelWithOrmModeAndForbid):
    mechanism: ResumptionMechanismEnum
    server_hostname: str
    server_port: int
    server_ip_address: Optional[str]
    tls_server_name_indication: str
    tls_version_used: StrFromEnumValueName
    outcome: ResumptionAttemptOutcomeEnum
    initial_session_fingerprint: Optional[str] = None
    resumed_session_fingerprint: Optional[str] = None
    error_message: Optional[str] = None


assert ResumptionAttemptEvidence.__doc__
ResumptionAttemptEvidenceAsJson.__doc__ = ResumptionAttemptEvidence.__doc__


class SessionResumptionSupportScanResultAsJson(BaseModelWithOrmModeAndForbid):
    session_id_resumption_result: TlsResumptionSupportEnum
    session_id_attempted_resumptions_count: int
    session_id_successful_resumptions_count: int

    tls_ticket_resumption_result: TlsResumptionSupportEnum
    tls_ticket_attempted_resumptions_count: int
    tls_ticket_successful_resumptions_count: int

    session_id_attempts: List[ResumptionAttemptEvidenceAsJson] = []
    tls_ticket_attempts: List[ResumptionAttemptEvidenceAsJson] = []


assert SessionResumptionSupportScanResult.__doc__
SessionResumptionSupportScanResultAsJson.__doc__ = SessionResumptionSupportScanResult.__doc__


class SessionResumptionSupportScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[SessionResumptionSupportScanResultAsJson]
