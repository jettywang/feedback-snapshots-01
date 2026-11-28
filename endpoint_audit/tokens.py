"""Endpoint description tokenisation, matching Twisted's strports rules.

The behaviour mirrors C{twisted.internet.endpoints._tokenize} and C{_parse}
so the audit understands exactly the same strings as C{serverFromString},
without constructing any endpoint object (and therefore without reading key
material or touching sockets).

Notably:

* C{:} separates parameters and C{=} introduces a keyword value;
* a backslash escapes the next byte literally (so C{\\:} is a literal colon);
* after C{=}, a colon still starts the next parameter (an IPv6 literal used
  as a keyword value therefore has to be escaped, exactly as Twisted does).
"""

from __future__ import annotations

_OP = "op"
_STRING = "string"


def tokenize(description: str) -> list[tuple[str, str]]:
    """Split an endpoint description into string and operator tokens."""

    tokens: list[tuple[str, str]] = []
    current = ""
    ops = (":", "=")
    next_ops = {":": (":", "="), "=": (":",)}
    characters = iter(description)
    for char in characters:
        if char in ops:
            tokens.append((_STRING, current))
            tokens.append((_OP, char))
            current = ""
            ops = next_ops[char]
        elif char == "\\":
            try:
                current += next(characters)
            except StopIteration:
                raise ValueError("trailing backslash in endpoint description")
        else:
            current += char
    tokens.append((_STRING, current))
    return tokens


def parse_arguments(description: str) -> tuple[list[str], dict[str, str]]:
    """Return positional arguments and keyword arguments of a description."""

    args: list[str] = []
    kwargs: dict[str, str] = {}
    chunk: tuple[str, ...] = ()

    def flush() -> None:
        nonlocal chunk
        if not chunk:
            return
        if len(chunk) == 1:
            args.append(chunk[0])
        else:
            kwargs[chunk[0]] = chunk[1]
        chunk = ()

    for token_type, value in tokenize(description):
        if token_type == _STRING:
            chunk += (value,)
        elif value == ":":
            flush()
    flush()
    return args, kwargs
