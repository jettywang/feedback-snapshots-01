"""Example: an update service that gates on format and failure stage.

This is intentionally explicit instead of a single boolean: a service needs
different responses for unsupported input, an accepted unsigned artifact, a
damaged signature, and a cryptographic failure.
"""

from __future__ import annotations

import enum

from signify.authenticode import AuthenticodeFile
from signify.file_types import FailureStage


class Decision(enum.Enum):
    ACCEPT = "accept"
    MANUAL_REVIEW = "manual_review"
    REJECT = "reject"


def triage(path: str) -> Decision:
    with open(path, "rb") as file_obj:
        detection = AuthenticodeFile.detect(file_obj)

        # 1. No supported container: this is a policy choice, not damage.
        if detection.stage == FailureStage.UNSUPPORTED_FORMAT:
            return Decision.REJECT

        # 2. Recognized container that could not be opened at all.
        if detection.stage == FailureStage.MALFORMED_SIGNATURE:
            return Decision.MANUAL_REVIEW

        signed_file = detection.signed_file
        assert signed_file is not None
        status, _error = signed_file.explain_verify()

        # 3. Validly parsed but no signature at all.
        if status.name == "NOT_SIGNED":
            return Decision.ACCEPT  # e.g. hash-pinned or catalog-signed later

        # 4. Structural damage discovered while reading embedded signatures.
        if status.name == "PARSE_ERROR":
            return Decision.MANUAL_REVIEW

        # 5. A signature exists and does not validate (digest, chain, time).
        return Decision.ACCEPT if status.name == "OK" else Decision.REJECT
