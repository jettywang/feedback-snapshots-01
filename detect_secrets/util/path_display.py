"""
Path display policy for outbound artifacts (uploads, audit reports and logs).

Findings only need to communicate *where* a secret lives relative to a known
project checkout -- the customer's machine-specific absolute paths must never
leave the host. A :class:`PathDisplayPolicy` registers one or more checkout
roots (each with a stable, non-sensitive alias) and maps every local path to a
display path of the form ``<alias>/<project-relative-path>``.

Because aliases are chosen by the caller rather than derived from the checkout
location, a checkout can be moved to a different directory (or another machine)
and re-registered with the same alias: the display path stays identical and the
finding can still be traced back to the correct file.

Files that live outside every registered root are marked as out of scope and
only their basename is disclosed, so no directory layout leaks.
"""
import logging
import os
import re
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union


# Prefix used for files that do not belong to any registered checkout root.
OUT_OF_SCOPE_ALIAS = 'out-of-scope'

# Matches POSIX absolute paths (e.g. /Users/alice/secret.txt) and Windows
# absolute paths (e.g. C:\\Users\\alice\\secret.txt or C:/Users/alice/...).
_ABSOLUTE_PATH_PATTERN = re.compile(
    r'(?:(?<=^)|(?<=\s|[:=(,"\']))'
    r'(?:/[^\s:*?"<>|]*)'
    r'|(?:[A-Za-z]:[\\/][^\s:*?"<>|]*)',
)


@dataclass(frozen=True)
class DisplayPath:
    """A path safe to include in outbound artifacts."""

    raw: str
    alias: str
    relative_path: Optional[str]
    in_scope: bool

    def __str__(self) -> str:
        if self.relative_path:
            return f'{self.alias}/{self.relative_path}'
        return self.alias

    @property
    def display_path(self) -> str:
        return str(self)


class PathDisplayPolicy:
    """
    Maps machine-local paths to stable, project-relative display paths.

    :param scope: iterable of ``(root, alias)`` pairs (or bare root paths, in
        which case the root's directory name is used as the alias). Aliases are
        made unique automatically, so two checkouts sharing a directory name
        (e.g. two ``workspace`` checkouts) yield distinct display paths.
    """

    def __init__(self, scope: Iterable[Union[str, Tuple[str, str]]] = ()) -> None:
        self._roots: List[str] = []
        self._aliases: Dict[str, str] = {}
        self._used_aliases: Set[str] = set()
        # Log messages may use un-normalized paths (e.g. macOS logs ``/tmp``
        # while the registered root realpaths to ``/private/tmp``). Keep every
        # spelling we were given so the log sanitizer can match both.
        self._root_spellings: Dict[str, Set[str]] = {}

        for entry in scope:
            if isinstance(entry, (tuple, list)):
                root, alias = entry
            else:
                root, alias = entry, os.path.basename(os.path.normpath(entry))
            self.register(root, alias)

    @property
    def roots(self) -> List[str]:
        return list(self._roots)

    def register(self, root: str, alias: Optional[str] = None) -> str:
        """
        Registers a checkout root and returns its assigned alias.

        Re-registering the same root (e.g. after the checkout moved) keeps the
        requested alias, which keeps previously emitted display paths valid.
        """
        normalized_root = os.path.realpath(root)
        if not alias:
            alias = os.path.basename(normalized_root)
        alias = _sanitize_alias(alias)

        existing_alias = self._aliases.get(normalized_root)
        if existing_alias is not None:
            self._root_spellings[normalized_root].add(os.path.abspath(root))
            return existing_alias

        unique_alias = alias
        suffix = 2
        while unique_alias in self._used_aliases:
            unique_alias = f'{alias}-{suffix}'
            suffix += 1

        self._used_aliases.add(unique_alias)
        self._aliases[normalized_root] = unique_alias
        self._root_spellings[normalized_root] = {
            normalized_root,
            os.path.abspath(root),
        }
        self._roots.append(normalized_root)
        # Nested roots are uncommon, but matching the deepest root first makes
        # the mapping deterministic when they do occur.
        self._roots.sort(key=len, reverse=True)
        return unique_alias

    def root_spellings(self, root: str) -> Set[str]:
        """All textual forms (realpath and as-registered) of a checkout root."""
        return set(self._root_spellings.get(root, {root}))

    def locate(self, path: str) -> Optional[Tuple[str, str]]:
        """
        :returns: the matching ``(root, alias)`` pair, or ``None`` if the path
            does not live inside a registered root.
        """
        try:
            normalized_path = os.path.realpath(path)
        except (OSError, ValueError):
            return None

        for root in self._roots:
            relative_path = _path_within_root(root, normalized_path)
            if relative_path is not None:
                return root, self._aliases[root]
        return None

    def is_in_scope(self, path: str) -> bool:
        return self.locate(path) is not None

    def display_for(self, path: str) -> DisplayPath:
        """Converts a machine-local path to a safe display path."""
        located = self.locate(path)
        if not located:
            return DisplayPath(
                raw=path,
                alias=OUT_OF_SCOPE_ALIAS,
                relative_path=os.path.basename(os.path.normpath(path)) or None,
                in_scope=False,
            )

        _, alias = located
        root, _ = located
        relative_path = _path_within_root(root, os.path.realpath(path))
        return DisplayPath(
            raw=path,
            alias=alias,
            relative_path=relative_path,
            in_scope=True,
        )

    def display_string(self, path: str) -> str:
        return self.display_for(path).display_path

    def resolve(self, display_path: str) -> Optional[str]:
        """
        Resolves a display path back to a machine-local path.

        This is the local-only inverse of :meth:`display_for`: it allows an
        operator reviewing an outbound artifact to reopen the original file.
        Returns ``None`` when the alias is unknown or the target no longer
        exists within the registered root.
        """
        alias, separator, relative_path = display_path.partition('/')
        if not separator:
            return None

        root = self._root_for_alias(alias)
        if root is None:
            return None

        candidate = os.path.realpath(os.path.join(root, relative_path))
        if _path_within_root(root, candidate) is None:
            return None
        return candidate

    def remap_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rewrites the ``results`` mapping of a baseline/report so that neither
        its keys nor the nested ``filename`` fields carry machine-local paths.
        Secret contents (hashes, types, line numbers) are untouched.
        """
        remapped: Dict[str, Any] = {}
        for filename, findings in results.items():
            display_path = self.display_string(filename)
            safe_findings = [
                self._sanitize_finding(finding, filename, display_path)
                for finding in findings
            ]
            remapped[display_path] = safe_findings
        return remapped

    def _sanitize_finding(
        self,
        finding: Any,
        original_filename: str,
        display_path: str,
    ) -> Any:
        if not isinstance(finding, dict):
            return finding

        sanitized = dict(finding)
        nested_filename = sanitized.get('filename')
        if isinstance(nested_filename, str):
            sanitized['filename'] = (
                display_path
                if nested_filename == original_filename
                else self.display_string(nested_filename)
            )
        return sanitized

    def install_log_sanitizer(
        self,
        logger: logging.Logger,
    ) -> 'LogPathSanitizer':
        """
        Attaches a :class:`LogPathSanitizer` to ``logger`` so that log records
        emitted through it cannot disclose absolute paths.
        """
        sanitizer = LogPathSanitizer(self)
        logger.addFilter(sanitizer)
        return sanitizer

    def _root_for_alias(self, alias: str) -> Optional[str]:
        for root, root_alias in self._aliases.items():
            if root_alias == alias:
                return root
        return None


def build_policy_from_specs(specs: Iterable[str]) -> PathDisplayPolicy:
    """
    Builds a policy from CLI-style ``root=alias`` specifications.

    A bare ``root`` (no ``=``) falls back to the root's directory name as the
    alias. Empty entries are ignored, so an opt-in flag without a value still
    produces an empty policy rather than raising.
    """
    policy = PathDisplayPolicy()
    for spec in specs:
        if not spec:
            continue
        if '=' in spec:
            root, alias = spec.split('=', 1)
            policy.register(root, alias)
        else:
            policy.register(spec)
    return policy


class LogPathSanitizer(logging.Filter):
    """
    Logging filter that strips machine-local paths from log messages.

    Registered roots are replaced by their alias (keeping the project-relative
    suffix); any remaining absolute path (in-scope or not) is reduced to its
    basename, so outbound logs never carry host directory information.
    """

    def __init__(self, policy: PathDisplayPolicy) -> None:
        super().__init__()
        self.policy = policy

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.sanitize(record.msg)
        if record.args:
            record.args = tuple(
                self.sanitize(arg) if isinstance(arg, str) else arg
                for arg in record.args
            ) if isinstance(record.args, tuple) else {
                key: self.sanitize(value) if isinstance(value, str) else value
                for key, value in record.args.items()
            }
        return True

    def sanitize(self, message: str) -> str:
        placeholders: Dict[str, str] = {}
        for index, root in enumerate(self.policy.roots):
            # Park every in-scope path behind a sentinel that contains no path
            # separator, so the absolute-path sweep below cannot touch it.
            placeholder = f'\x00scope{index}\x00'
            placeholders[placeholder] = self.policy._aliases[root]
            # Logged paths may not be realpath-normalized (e.g. macOS ``/tmp``
            # is a symlink to ``/private/tmp``), so cover every registered form.
            for candidate in self.policy.root_spellings(root):
                message = message.replace(candidate + os.sep, placeholder)
                message = message.replace(candidate, placeholder)

        message = _ABSOLUTE_PATH_PATTERN.sub(self._strip_absolute_path, message)

        for placeholder, alias in placeholders.items():
            # The sentinel already stands in for ``root + os.sep``, so prefix
            # the alias and re-add the display path separator.
            message = message.replace(placeholder, alias + '/')
        return message

    @staticmethod
    def _strip_absolute_path(match: re.Match) -> str:
        return os.path.basename(match.group().rstrip('/\\')) or match.group()


def _sanitize_alias(alias: str) -> str:
    cleaned = re.sub(r'[^A-Za-z0-9._-]', '-', alias).strip('-._')
    return cleaned or 'checkout'


def _path_within_root(root: str, path: str) -> Optional[str]:
    """
    Returns the project-relative path when ``path`` is inside ``root``.

    Both arguments must already be normalized via :func:`os.path.realpath`.
    Returns ``None`` for paths outside the root, which also blocks ``..``
    traversal from escaping the checkout boundary.
    """
    if path == root:
        return ''

    root_with_separator = root + os.sep
    if not path.startswith(root_with_separator):
        return None

    relative_path = path[len(root_with_separator):]
    if os.path.isabs(relative_path) or '..' in relative_path.split(os.sep):
        return None
    return relative_path
