from typing import Tuple

import nassl

from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.session_resumption._resumption_with_id import (
    retrieve_tls_session,
    _ScanJobResultEnum,
    _build_attempt_evidence,
    _fingerprint_session_material,
    ResumptionAttemptEvidence,
    ResumptionAttemptOutcomeEnum,
    ResumptionMechanismEnum,
)
from sslyze.server_connectivity import ServerConnectivityInfo


def resume_with_tls_ticket(
    server_info: ServerConnectivityInfo,
) -> Tuple[_ScanJobResultEnum, ResumptionAttemptEvidence]:
    """Perform one session resumption using TLS Session Tickets and return auditable evidence about the attempt."""
    # Connect to the server and keep the TLS session
    try:
        session1 = retrieve_tls_session(server_info, should_enable_tls_ticket=True)
    except ConnectionToServerFailed as e:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.TLS_TICKET,
            ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED,
            error_message=str(e),
        )

    try:
        # Recover the TLS ticket
        session1_tls_ticket = _extract_tls_session_ticket(session1)
    except IndexError:
        # Ticket was not assigned
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, _build_attempt_evidence(
            server_info, ResumptionMechanismEnum.TLS_TICKET, ResumptionAttemptOutcomeEnum.NO_SESSION_ASSIGNED
        )

    session1_tls_ticket_fingerprint = _fingerprint_session_material(session1_tls_ticket)

    # Try to resume that session using the TLS ticket
    try:
        session2 = retrieve_tls_session(server_info, session_to_resume=session1, should_enable_tls_ticket=True)
    except ConnectionToServerFailed as e:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.TLS_TICKET,
            ResumptionAttemptOutcomeEnum.RESUMPTION_HANDSHAKE_FAILED,
            initial_session_fingerprint=session1_tls_ticket_fingerprint,
            error_message=str(e),
        )

    try:
        # Recover the TLS ticket
        session2_tls_ticket = _extract_tls_session_ticket(session2)
    except IndexError:
        # Ticket was not assigned
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.TLS_TICKET,
            ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE,
            initial_session_fingerprint=session1_tls_ticket_fingerprint,
        )

    # Finally, compare the two TLS Tickets
    if session1_tls_ticket != session2_tls_ticket:
        # The Ticket we supplied got ignored
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.TLS_TICKET,
            ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE,
            initial_session_fingerprint=session1_tls_ticket_fingerprint,
            resumed_session_fingerprint=_fingerprint_session_material(session2_tls_ticket),
        )

    return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, _build_attempt_evidence(
        server_info,
        ResumptionMechanismEnum.TLS_TICKET,
        ResumptionAttemptOutcomeEnum.RESUMED,
        initial_session_fingerprint=session1_tls_ticket_fingerprint,
        resumed_session_fingerprint=_fingerprint_session_material(session2_tls_ticket),
    )


def _extract_tls_session_ticket(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the TLS session ticket from a SSL session object or raises IndexError if the ticket was not set."""
    session_string = ((ssl_session.as_text()).split("TLS session ticket:"))[1]
    session_tls_ticket = (session_string.split("Compression:"))[0]
    return session_tls_ticket
