# SPDX-License-Identifier: MIT

from __future__ import annotations

import platform
import sys

from dataclasses import dataclass, field
from enum import Enum

from .exceptions import InvalidHashError, UnsupportedParametersError
from .low_level import Type


NoneType = type(None)


def _check_types(**kw: tuple[object, type | tuple[type, ...]]) -> str | None:
    """
    Check each ``name: (value, types)`` in *kw*.

    Returns a human-readable string of all violations or `None``.
    """
    errors = []
    for name, (value, types) in kw.items():
        if not isinstance(value, types):
            if isinstance(types, tuple):
                type_names = ", or ".join(t.__name__ for t in types)
            else:
                type_names = types.__name__
            errors.append(
                f"'{name}' must be a {type_names} (got {type(value).__name__})"
            )

    if errors != []:
        return ", ".join(errors) + "."

    return None


def _is_wasm() -> bool:
    return sys.platform == "emscripten" or platform.machine() in [
        "wasm32",
        "wasm64",
    ]


def _decoded_str_len(length: int) -> int:
    """
    Compute how long an encoded string of length *l* becomes.
    """
    rem = length % 4

    if rem == 3:
        last_group_len = 2
    elif rem == 2:
        last_group_len = 1
    else:
        last_group_len = 0

    return length // 4 * 3 + last_group_len


@dataclass
class Parameters:
    """
    Argon2 hash parameters.

    See :doc:`parameters` on how to pick them.

    Attributes:
        type: Hash type.

        version: Argon2 version.

        salt_len: Length of the salt in bytes.

        hash_len: Length of the hash in bytes.

        time_cost: Time cost in iterations.

        memory_cost: Memory cost in kibibytes.

        parallelism: Number of parallel threads.

    .. versionadded:: 18.2.0
    """

    type: Type
    version: int
    salt_len: int
    hash_len: int
    time_cost: int
    memory_cost: int
    parallelism: int

    __slots__ = (
        "hash_len",
        "memory_cost",
        "parallelism",
        "salt_len",
        "time_cost",
        "type",
        "version",
    )


class HashFormat(str, Enum):
    """
    Encoding generation of an Argon2 hash string.

    Attributes:
        LEGACY_1_2:
            Argon2 v1.2 hash without an explicit ``v=`` field (five
            ``$``-separated parts).  The version has to be inferred as 18.

        MODERN:
            Hash carrying an explicit ``v=`` field (six ``$``-separated
            parts).

    .. versionadded:: 25.2.0
    """

    LEGACY_1_2 = "argon2-1.2"
    MODERN = "argon2-1.3"


# Version that pre-1.3 ("v1.2") Argon2 hashes are understood to use.
LEGACY_1_2_VERSION = 18


@dataclass(frozen=True)
class HashInspection:
    """
    Evidence obtained by parsing an encoded Argon2 hash string.

    A successful inspection means that the hash's *text* could be explained.
    It does not say anything about whether a password matches it; that is a
    separate, cryptographic step.

    Attributes:
        hash_format: Encoding generation of the hash.

        parameters:
            Parameters parsed from the text.  For legacy hashes, values that
            were not carried by the text are filled in per historical
            convention and additionally listed in *inferred_parameters*.

        inferred_parameters:
            Mapping of parameter names to the values the library assumed
            because the hash did not state them explicitly.  An empty mapping
            means every value was read directly from the hash text.

    .. versionadded:: 25.2.0
    """

    hash_format: HashFormat
    parameters: Parameters
    inferred_parameters: dict[str, int] = field(default_factory=dict)


_NAME_TO_TYPE = {"argon2id": Type.ID, "argon2i": Type.I, "argon2d": Type.D}
_REQUIRED_KEYS = sorted(("v", "m", "t", "p"))


def inspect_hash(hash: str) -> HashInspection:
    """
    Parse an encoded Argon2 *hash* and report how the result was derived.

    Unlike :func:`extract_parameters`, this keeps track of which values were
    stated in the hash text and which the library inferred.

    Args:
        hash: An encoded Argon2 hash string.

    Returns:
        The parsing evidence for *hash*.

    Raises:
        argon2.exceptions.InvalidHashError:
            If the text does not follow the Argon2 encoded-hash grammar or
            carries parameters that cannot be interpreted.

    .. versionadded:: 25.2.0
    """
    parts = hash.split("$")

    # Backwards compatibility for Argon v1.2 hashes, which omit the version
    # field entirely.
    if len(parts) == 5:
        hash_format = HashFormat.LEGACY_1_2
        parts.insert(2, f"v={LEGACY_1_2_VERSION}")
        inferred_parameters: dict[str, int] = {"version": LEGACY_1_2_VERSION}
    else:
        hash_format = HashFormat.MODERN
        inferred_parameters = {}

    if len(parts) != 6 or parts[0]:
        raise InvalidHashError

    try:
        type = _NAME_TO_TYPE[parts[1]]

        kvs = {
            k: int(v)
            for k, v in (
                s.split("=") for s in [parts[2], *parts[3].split(",")]
            )
        }
    except Exception:  # noqa: BLE001
        raise InvalidHashError from None

    if sorted(kvs.keys()) != _REQUIRED_KEYS:
        raise InvalidHashError

    parameters = Parameters(
        type=type,
        salt_len=_decoded_str_len(len(parts[4])),
        hash_len=_decoded_str_len(len(parts[5])),
        version=kvs["v"],
        time_cost=kvs["t"],
        memory_cost=kvs["m"],
        parallelism=kvs["p"],
    )

    return HashInspection(
        hash_format=hash_format,
        parameters=parameters,
        inferred_parameters=inferred_parameters,
    )


def extract_parameters(hash: str) -> Parameters:
    """
    Extract parameters from an encoded *hash*.

    Args:
        hash: An encoded Argon2 hash string.

    Returns:
        The parameters used to create the hash.

    .. versionadded:: 18.2.0
    """
    return inspect_hash(hash).parameters


def validate_params_for_platform(params: Parameters) -> None:
    """
    Validate *params* against current platform.

    Args:
        params: Parameters to be validated

    Returns:
       None
    """
    if _is_wasm() and params.parallelism != 1:
        msg = "In WebAssembly environments `parallelism` must be 1."
        raise UnsupportedParametersError(msg)
