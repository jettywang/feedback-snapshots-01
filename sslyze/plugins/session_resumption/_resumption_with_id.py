import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

import nassl

from sslyze.errors import ConnectionToServerFailed, ServerRejectedTlsHandshake
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


class TlsResumptionSupportEnum(str, Enum):
    """The result of attempting to resume TLS sessions with the server.

    Attributes:
        FULLY_SUPPORTED: All the session resumption attempts were successful.
        PARTIALLY_SUPPORTED: Only some of the session resumption attempts were successful.
        NOT_SUPPORTED: None of the session resumption attempts were successful.
        SERVER_IS_TLS_1_3_ONLY: The server only supports TLS 1.3, which does not support Session ID nor TLS Tickets
            resumption.
    """

    FULLY_SUPPORTED = "FULLY_SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    SERVER_IS_TLS_1_3_ONLY = "SERVER_IS_TLS_1_3_ONLY"


class _ScanJobResultEnum(Enum):
    TLS_TICKET_RESUMPTION = 1
    SESSION_ID_RESUMPTION = 2


class ServerOnlySupportsTls13(Exception):
    """If the server only supports TLS 1.3 or higher, it does not support session resumption with IDs or tickets."""

    pass


class ResumptionMechanismEnum(str, Enum):
    """Which TLS 1.2 session resumption mechanism a single resumption attempt exercised."""

    SESSION_ID = "SESSION_ID"
    TLS_TICKET = "TLS_TICKET"


class ResumptionAttemptOutcomeEnum(str, Enum):
    """The auditable outcome of a single session resumption attempt.

    Attributes:
        RESUMED: The server accepted the initial session and resumed it.
        FULL_REHANDSHAKE: The server ignored the initial session and performed a full handshake instead.
        NO_SESSION_ASSIGNED: The server did not assign a session ID or TLS ticket on the initial connection, so
            there was no session to resume.
        INITIAL_HANDSHAKE_FAILED: The initial connection (to obtain the session) failed; the attempt could not be
            completed.
        RESUMPTION_HANDSHAKE_FAILED: The follow-up connection (to resume the session) failed; the attempt could not
            be completed.
    """

    RESUMED = "RESUMED"
    FULL_REHANDSHAKE = "FULL_REHANDSHAKE"
    NO_SESSION_ASSIGNED = "NO_SESSION_ASSIGNED"
    INITIAL_HANDSHAKE_FAILED = "INITIAL_HANDSHAKE_FAILED"
    RESUMPTION_HANDSHAKE_FAILED = "RESUMPTION_HANDSHAKE_FAILED"


@dataclass(frozen=True)
class ResumptionAttemptEvidence:
    """Auditable evidence for one single session resumption attempt.

    Each attempt is fully described by its own evidence record: which target the initial session was obtained from
    (hostname, port, IP address), which SNI and TLS version were configured for the attempt's connections, and what
    the outcome was. Because every attempt carries its own evidence, scan jobs can complete in any order without
    one server's session ever being attributed to another server's result.

    The evidence never contains session secrets: instead of the raw session ID or TLS ticket (which could be
    replayed to resume the session), only one-way SHA-256 fingerprints are stored. This allows auditors to confirm
    that the initial and resumed sessions match, without exposing reusable material.

    Attributes:
        mechanism: Whether the attempt exercised session ID or TLS ticket resumption.
        server_hostname: The hostname of the server the initial session was obtained from.
        server_port: The port of the server the initial session was obtained from.
        server_ip_address: The IP address of the server the initial session was obtained from, if known.
        tls_server_name_indication: The SNI hostname sent in the attempt's ClientHello messages.
        tls_version_used: The TLS version configured for the attempt's connections.
        outcome: The outcome of the attempt.
        initial_session_fingerprint: The SHA-256 fingerprint of the session ID or TLS ticket obtained on the
            initial connection; None if the server did not assign one.
        resumed_session_fingerprint: The SHA-256 fingerprint of the session ID or TLS ticket received on the
            follow-up connection; None if the follow-up connection did not happen or none was assigned.
        error_message: The connectivity error if the attempt could not be completed; None otherwise.
    """

    mechanism: ResumptionMechanismEnum
    server_hostname: str
    server_port: int
    server_ip_address: Optional[str]
    tls_server_name_indication: str
    tls_version_used: TlsVersionEnum
    outcome: ResumptionAttemptOutcomeEnum
    initial_session_fingerprint: Optional[str] = None
    resumed_session_fingerprint: Optional[str] = None
    error_message: Optional[str] = None


def _fingerprint_session_material(session_material: str) -> str:
    """Return a one-way fingerprint of session material, so that evidence never contains reusable secrets."""
    return hashlib.sha256(session_material.encode("utf-8")).hexdigest()


def _tls_version_for_resumption(server_info: ServerConnectivityInfo) -> Tuple[TlsVersionEnum, bool]:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no session resumption (with IDs or
    # tickets) with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        return TlsVersionEnum.TLS_1_2, True
    return server_info.tls_probing_result.highest_tls_version_supported, False


def _build_attempt_evidence(
    server_info: ServerConnectivityInfo,
    mechanism: ResumptionMechanismEnum,
    outcome: ResumptionAttemptOutcomeEnum,
    initial_session_fingerprint: Optional[str] = None,
    resumed_session_fingerprint: Optional[str] = None,
    error_message: Optional[str] = None,
) -> ResumptionAttemptEvidence:
    tls_version_used, _ = _tls_version_for_resumption(server_info)
    return ResumptionAttemptEvidence(
        mechanism=mechanism,
        server_hostname=server_info.server_location.hostname,
        server_port=server_info.server_location.port,
        server_ip_address=server_info.server_location.ip_address,
        tls_server_name_indication=server_info.network_configuration.tls_server_name_indication,
        tls_version_used=tls_version_used,
        outcome=outcome,
        initial_session_fingerprint=initial_session_fingerprint,
        resumed_session_fingerprint=resumed_session_fingerprint,
        error_message=error_message,
    )


def retrieve_tls_session(
    server_info: ServerConnectivityInfo,
    session_to_resume: Optional[nassl._nassl.SSL_SESSION] = None,
    should_enable_tls_ticket: bool = False,
) -> nassl._nassl.SSL_SESSION:
    """Connect to the server and returns the session object that was assigned for that connection.

    If ssl_session is given, tries to resume that session.
    """
    tls_version_to_use, downgraded_from_tls_1_3 = _tls_version_for_resumption(server_info)

    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=tls_version_to_use)
    if not should_enable_tls_ticket:
        # Need to disable TLS tickets to test session IDs, according to rfc5077:
        # If a ticket is presented by the client, the server MUST NOT attempt
        # to use the Session ID in the ClientHello for stateful session resumption
        ssl_connection.ssl_client.disable_stateless_session_resumption()  # Turning off TLS tickets.

    if session_to_resume:
        ssl_connection.ssl_client.set_session(session_to_resume)

    try:
        # Perform the TLS handshake
        ssl_connection.connect()
        new_session = ssl_connection.ssl_client.get_session()  # Get session data

    except ServerRejectedTlsHandshake:
        if downgraded_from_tls_1_3:
            raise ServerOnlySupportsTls13()
        else:
            raise

    finally:
        ssl_connection.close()

    return new_session


def _extract_session_id(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the SSL session ID from a SSL session object or raises IndexError if the session ID was not set."""
    session_string = ((ssl_session.as_text()).split("Session-ID:"))[1]
    session_id = (session_string.split("Session-ID-ctx:"))[0].strip()
    return session_id


def resume_with_session_id(server_info: ServerConnectivityInfo) -> Tuple[_ScanJobResultEnum, ResumptionAttemptEvidence]:
    """Perform one session resumption using Session IDs and return auditable evidence about the attempt."""
    # Create a new TLS session with the server
    try:
        session1 = retrieve_tls_session(server_info)
    except ConnectionToServerFailed as e:
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.SESSION_ID,
            ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED,
            error_message=str(e),
        )

    try:
        # Recover the session ID
        session1_id = _extract_session_id(session1)
    except IndexError:
        # Session ID not assigned
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
            server_info, ResumptionMechanismEnum.SESSION_ID, ResumptionAttemptOutcomeEnum.NO_SESSION_ASSIGNED
        )

    if session1_id == "":
        # Session ID empty
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
            server_info, ResumptionMechanismEnum.SESSION_ID, ResumptionAttemptOutcomeEnum.NO_SESSION_ASSIGNED
        )

    session1_id_fingerprint = _fingerprint_session_material(session1_id)

    # Try to resume that TLS session
    try:
        session2 = retrieve_tls_session(server_info, session_to_resume=session1)
    except ConnectionToServerFailed as e:
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.SESSION_ID,
            ResumptionAttemptOutcomeEnum.RESUMPTION_HANDSHAKE_FAILED,
            initial_session_fingerprint=session1_id_fingerprint,
            error_message=str(e),
        )

    try:
        # Recover the session ID
        session2_id = _extract_session_id(session2)
    except IndexError:
        # Session ID not assigned
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.SESSION_ID,
            ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE,
            initial_session_fingerprint=session1_id_fingerprint,
        )

    # Finally, compare the two Session IDs
    if session1_id != session2_id:
        # Session ID assigned but not accepted
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
            server_info,
            ResumptionMechanismEnum.SESSION_ID,
            ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE,
            initial_session_fingerprint=session1_id_fingerprint,
            resumed_session_fingerprint=_fingerprint_session_material(session2_id),
        )

    return _ScanJobResultEnum.SESSION_ID_RESUMPTION, _build_attempt_evidence(
        server_info,
        ResumptionMechanismEnum.SESSION_ID,
        ResumptionAttemptOutcomeEnum.RESUMED,
        initial_session_fingerprint=session1_id_fingerprint,
        resumed_session_fingerprint=_fingerprint_session_material(session2_id),
    )
