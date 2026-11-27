"""
Stand-in step-up verifiers for the test suite.

A real deployment would point ``STEP_UP_VERIFIER`` at a callable that checks a
second factor (TOTP, push notification, hardware key, ...). These fakes only
record their invocations so tests can assert that the backend trusts the
server-registered source and nothing else.
"""


class RecordingVerifier:
    """
    Records every verification request and returns a configurable result.
    """

    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.calls: list[dict] = []

    def __call__(self, user, evidence: str, request=None) -> bool:
        self.calls.append(
            {"user": user, "evidence": evidence, "request": request}
        )
        return self.result

    def reset(self) -> None:
        self.calls = []


# Module-level singletons so the import-string configured verifier keeps its
# recorded state across the serializer boundary.
recording_verifier = RecordingVerifier(result=True)
rejecting_verifier = RecordingVerifier(result=False)


def verify_step_up(user, evidence: str, request=None) -> bool:
    return recording_verifier(user, evidence, request)


def reject_step_up(user, evidence: str, request=None) -> bool:
    return rejecting_verifier(user, evidence, request)
