"""Load service endpoint manifests while preserving source coordinates.

Two formats are accepted.

Text manifest (C{#} starts a full-line comment)::

    web    tcp:80
    api    tcp:8080:interface=127.0.0.1

JSON manifest::

    [
      {"service": "web", "endpoint": "tcp:80"}
    ]

Every declaration is tagged with a L{SourceCoordinate} so any reported
overlap or parse error can be traced back to the exact line of the file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .model import SourceCoordinate


@dataclass(frozen=True)
class Declaration:
    service: str
    endpoint: str
    coordinate: SourceCoordinate


def load_text_manifest(content: str, source: str) -> list[Declaration]:
    declarations: list[Declaration] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(
                f"{source}:{line_number}: expected '<service> <endpoint>', "
                f"got {raw_line!r}"
            )
        service, endpoint = parts
        if service in seen:
            raise ValueError(
                f"{source}:{line_number}: duplicate service name {service!r}"
            )
        seen.add(service)
        declarations.append(
            Declaration(
                service=service,
                endpoint=endpoint,
                coordinate=SourceCoordinate(
                    source=source, line=line_number, service=service
                ),
            )
        )
    return declarations


def load_json_manifest(content: str, source: str) -> list[Declaration]:
    document = json.loads(content)
    if not isinstance(document, list):
        raise ValueError(f"{source}: JSON manifest must be a list of services")
    declarations: list[Declaration] = []
    seen: set[str] = set()
    for index, item in enumerate(document):
        if not isinstance(item, dict):
            raise ValueError(f"{source}: entry {index} is not an object")
        service = item.get("service")
        endpoint = item.get("endpoint")
        line = item.get("line")
        if not isinstance(service, str) or not isinstance(endpoint, str):
            raise ValueError(
                f"{source}: entry {index} needs string 'service' and 'endpoint'"
            )
        if service in seen:
            raise ValueError(f"{source}: duplicate service name {service!r}")
        seen.add(service)
        declarations.append(
            Declaration(
                service=service,
                endpoint=endpoint,
                coordinate=SourceCoordinate(
                    source=source,
                    line=line if isinstance(line, int) else None,
                    service=service,
                ),
            )
        )
    return declarations


def load_manifest(path: str) -> list[Declaration]:
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    if path.endswith(".json"):
        return load_json_manifest(content, path)
    return load_text_manifest(content, path)
