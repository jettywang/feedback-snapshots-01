"""Used for loading the IAM data"""

from __future__ import annotations

import contextlib
import functools
import gc
import hashlib
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import orjson

from policy_sentry.shared.constants import (
    DATASTORE_FILE_PATH,
    POLICY_SENTRY_SCHEMA_VERSION_NAME,
)

logger = logging.getLogger()
# On initialization, load the IAM data
iam_definition_path = DATASTORE_FILE_PATH
logger.debug(f"Leveraging the IAM definition at {iam_definition_path}")


def load_iam_definition(path: str | Path | None = None) -> dict[str, Any]:
    """Load an IAM definition from disk. Defaults to the configured datastore."""
    data_path = Path(path) if path is not None else iam_definition_path
    gc_enabled = gc.isenabled()
    if gc_enabled:
        # https://github.com/msgpack/msgpack-python?tab=readme-ov-file#performance-tips
        gc.disable()

    data: dict[str, Any] = orjson.loads(data_path.read_bytes())

    if gc_enabled:
        gc.enable()

    return data


def _clear_query_caches() -> None:
    """Drop the memoized lookups that read from the active IAM definition."""
    # Imported lazily so that switching catalogs does not require importing the
    # whole query layer when it is not otherwise in use.
    from policy_sentry.querying import actions, all as all_queries, arns, conditions

    for module in (actions, all_queries, arns, conditions):
        for name in dir(module):
            if name.startswith("__"):
                continue
            candidate = getattr(module, name)
            cache_clear = getattr(candidate, "cache_clear", None)
            if callable(cache_clear):
                cache_clear()


def _rebind_definition_aliases(data: dict[str, Any]) -> dict[str, Any]:
    """
    Point modules that did ``from ... import iam_definition`` at ``data``.

    Those imports copy the reference, so reassigning the global in this module
    alone would leave the query layer reading the previous catalog.
    """
    import sys

    previous: dict[str, Any] = {}
    for module in list(sys.modules.values()):
        if module is None or module is sys.modules[__name__]:
            continue
        if getattr(module, "iam_definition", None) is None:
            continue
        if "policy_sentry" not in getattr(module, "__name__", ""):
            continue
        previous[module.__name__] = module.iam_definition
        module.iam_definition = data
    return previous


@contextlib.contextmanager
def use_iam_definition(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """
    Temporarily make ``data`` the active IAM definition.

    This is what lets a single process render the same template against two
    catalog versions without reloading the interpreter.
    """
    global iam_definition
    previous = iam_definition
    aliases = _rebind_definition_aliases(data)
    iam_definition = data
    _clear_query_caches()
    try:
        yield data
    finally:
        iam_definition = previous
        for name, value in aliases.items():
            module = __import__(name, fromlist=["*"])
            module.iam_definition = value
        _clear_query_caches()


def get_iam_definition_fingerprint(data: dict[str, Any] | None = None) -> str:
    """
    A stable content fingerprint for a catalog, so that an audit record can
    name the exact catalog version it was generated against.

    The bundled database is pretty-printed and the packaged one is minified, so
    hashing the raw bytes would report a different version for the same data.
    Hashing a canonical serialization keeps the fingerprint comparable.
    """
    definition = iam_definition if data is None else data
    canonical = orjson.dumps(definition, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(canonical).hexdigest()


iam_definition = load_iam_definition()


@functools.lru_cache(maxsize=1)
def get_iam_definition_schema_version() -> str:
    """
    Returns the schema version of the IAM datastore
    """

    return cast(
        "str",
        iam_definition[POLICY_SENTRY_SCHEMA_VERSION_NAME],
    )


@functools.lru_cache(maxsize=1024)
def get_service_prefix_data(service_prefix: str) -> dict[str, Any]:
    """
    Given an AWS service prefix, return a large dictionary of IAM privilege data for processing and analysis.

    Arguments:
        service_prefix: An AWS service prefix, like s3 or ssm
    Returns:
        List: A list of metadata about that service
    """
    try:
        return cast("dict[str, Any]", iam_definition[service_prefix])
    except:  # ruff: ignore[bare-except]
        if service_prefix == "catalog":
            # the resource types "Portfolio" and "Product" have the service name "catalog" in their ARN
            # https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsservicecatalog.html#awsservicecatalog-resources-for-iam-policies
            return cast("dict[str, Any]", iam_definition["servicecatalog"])

        logger.info(f"Service prefix not {service_prefix} found.")
        return {}
