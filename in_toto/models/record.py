# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  record.py

<Purpose>
  Provides an explicit handle for metadata recordings that are started with
  ``runlib.in_toto_record_start`` and finished later with
  ``runlib.in_toto_record_stop``.

  A handle binds the step name, the signing identity of the start proof, the
  exact bytes of the unfinished metadata, and the working directory in which
  the record was started. It is serializable, so a build backend can persist it
  between separate start and stop jobs.

"""

import json
import re
import secrets

import attr

import in_toto.exceptions

_RECORD_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_START_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def make_record_token():
    """Return a random token suitable for a record handle."""
    return secrets.token_hex(16)


def check_record_token(token):
    """Validate and return a record token.

    Tokens are part of session-specific unfinished and completed link file
    names, so they must not contain path separators or other unsafe characters.
    """
    if not isinstance(token, str) or not _RECORD_TOKEN_RE.fullmatch(token):
        raise in_toto.exceptions.RecordHandleFormatError(
            "Record token must be 8-128 characters of 'A-Za-z0-9_-'."
        )

    return token


@attr.s(frozen=True, slots=True)
class RecordHandle:
    """A serializable binding for one started record.

    Attributes:
      step_name: The step name the record was started for.
      keyid: The full keyid of the signing identity that created the start
          proof.
      token: A session token used in session-specific file names.
      start_digest: The SHA-256 digest of the exact unfinished metadata file
          written by ``in_toto_record_start``.
      start_materials_digest: The SHA-256 digest of the canonical JSON
          representation of the recorded materials.
      unfinished_path: The absolute path of the unfinished metadata file.
      completed_path: The absolute path of the completed link metadata.
      workdir: The absolute working directory at start time.
      artifact_base_path: The absolute directory against which artifacts are
          recorded by default when finishing the record.
      use_dsse: Whether the start proof uses a DSSE envelope.
    """

    step_name = attr.ib()
    keyid = attr.ib()
    token = attr.ib()
    start_digest = attr.ib()
    start_materials_digest = attr.ib()
    unfinished_path = attr.ib()
    completed_path = attr.ib()
    workdir = attr.ib()
    artifact_base_path = attr.ib()
    use_dsse = attr.ib(default=False)

    def __attrs_post_init__(self):
        for name in (
            "step_name",
            "keyid",
            "token",
            "start_digest",
            "start_materials_digest",
            "unfinished_path",
            "completed_path",
            "workdir",
            "artifact_base_path",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise in_toto.exceptions.RecordHandleFormatError(
                    f"Record handle field '{name}' must be a non-empty string."
                )
            if "\x00" in value:
                raise in_toto.exceptions.RecordHandleFormatError(
                    f"Record handle field '{name}' contains a NUL byte."
                )

        check_record_token(self.token)

        for name in ("start_digest", "start_materials_digest"):
            if not _START_DIGEST_RE.fullmatch(getattr(self, name)):
                raise in_toto.exceptions.RecordHandleFormatError(
                    f"Record handle field '{name}' must be a lowercase"
                    " SHA-256 hex digest."
                )

        if not isinstance(self.use_dsse, bool):
            raise in_toto.exceptions.RecordHandleFormatError(
                "Record handle field 'use_dsse' must be a boolean."
            )

    _FIELDS = (
        "step_name",
        "keyid",
        "token",
        "start_digest",
        "start_materials_digest",
        "unfinished_path",
        "completed_path",
        "workdir",
        "artifact_base_path",
        "use_dsse",
    )

    def to_dict(self):
        """Return a JSON-serializable dictionary representation of the handle."""
        return {field: getattr(self, field) for field in self._FIELDS}

    @classmethod
    def from_dict(cls, data):
        """Create a handle from its dictionary representation.

        Raises:
          RecordHandleFormatError: The passed data is not a complete,
              well-formed record handle.
        """
        if not isinstance(data, dict):
            raise in_toto.exceptions.RecordHandleFormatError(
                "Record handle must be a RecordHandle, dict, or JSON object."
            )

        missing = set(cls._FIELDS) - set(data)
        unknown = set(data) - set(cls._FIELDS)
        if missing or unknown:
            raise in_toto.exceptions.RecordHandleFormatError(
                "Record handle has missing or unknown fields:"
                f" missing={sorted(missing)}, unknown={sorted(unknown)}."
            )

        try:
            return cls(**{field: data[field] for field in cls._FIELDS})
        except in_toto.exceptions.RecordHandleFormatError:
            raise
        except (TypeError, ValueError) as exc:
            raise in_toto.exceptions.RecordHandleFormatError(
                f"Malformed record handle: {exc}"
            ) from exc

    def to_json(self):
        """Return the JSON string representation of the handle."""
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, value):
        """Create a handle from a JSON string representation."""
        try:
            data = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise in_toto.exceptions.RecordHandleFormatError(
                f"Record handle is not valid JSON: {exc}"
            ) from exc

        return cls.from_dict(data)

    def __str__(self):
        return self.to_json()
