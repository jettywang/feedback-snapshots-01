# SPDX-License-Identifier: MIT

"""
Argon2 for Python
"""

from . import exceptions, low_level, profiles
from ._legacy import hash_password, hash_password_raw, verify_password
from ._password_hasher import (
    DEFAULT_HASH_LENGTH,
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_RANDOM_SALT_LENGTH,
    DEFAULT_TIME_COST,
    PasswordHasher,
)
from ._utils import (
    HashFormat,
    HashInspection,
    Parameters,
    extract_parameters,
    inspect_hash,
)
from ._verification import (
    DEFAULT_VERIFICATION_POLICY,
    VerificationOutcome,
    VerificationPolicy,
    VerificationReport,
)
from .low_level import Type


__title__ = "argon2-cffi"

__author__ = "Hynek Schlawack"
__copyright__ = "Copyright (c) 2015 " + __author__
__license__ = "MIT"


__all__ = [
    "DEFAULT_HASH_LENGTH",
    "DEFAULT_MEMORY_COST",
    "DEFAULT_PARALLELISM",
    "DEFAULT_RANDOM_SALT_LENGTH",
    "DEFAULT_TIME_COST",
    "DEFAULT_VERIFICATION_POLICY",
    "HashFormat",
    "HashInspection",
    "Parameters",
    "PasswordHasher",
    "Type",
    "VerificationOutcome",
    "VerificationPolicy",
    "VerificationReport",
    "exceptions",
    "extract_parameters",
    "hash_password",
    "hash_password_raw",
    "inspect_hash",
    "low_level",
    "profiles",
    "verify_password",
]


def __getattr__(name: str) -> str:
    dunder_to_metadata = {
        "__version__": "version",
        "__description__": "summary",
        "__uri__": "",
        "__url__": "",
        "__email__": "",
    }
    if name not in dunder_to_metadata:
        msg = f"module {__name__} has no attribute {name}"
        raise AttributeError(msg)

    import warnings

    from importlib.metadata import metadata

    warnings.warn(
        f"Accessing argon2.{name} is deprecated and will be "
        "removed in a future release. Use importlib.metadata directly "
        "to query for argon2-cffi's packaging metadata.",
        DeprecationWarning,
        stacklevel=2,
    )

    meta = metadata("argon2-cffi")

    if name in ("__uri__", "__url__"):
        return meta["Project-URL"].split(" ", 1)[-1]

    if name == "__email__":
        return meta["Author-email"].split("<", 1)[1].rstrip(">")

    return meta[dunder_to_metadata[name]]
