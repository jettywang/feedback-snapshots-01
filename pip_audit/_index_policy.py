"""
Company index policy enforcement for requirements-file based resolution.

The security team mandates that the audit service resolves dependencies
against a fixed internal mirror. Requirements files, however, may declare
their own package sources (`--index-url`, `--extra-index-url`,
`--find-links`, `--no-index`), which would silently redirect the temporary
resolution environment away from the mandated mirror.

This module defines an `IndexPolicy` that makes explicit which declarations
may influence the temporary resolution environment, and reports conflicts
*before* any resolution takes place. When a conflict is found, an
`IndexPolicyError` is raised and the resolver is never invoked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from pip_requirements_parser import RequirementsFile

from pip_audit._dependency_source.interface import DependencySourceError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IndexDeclaration:
    """
    A single index-affecting declaration found in a requirements file.
    """

    filename: Path
    line_number: int
    option: str
    value: str


class IndexPolicyError(DependencySourceError):
    """
    Raised when a requirements file declares package sources that the
    company `IndexPolicy` does not allow to influence the temporary
    resolution environment.
    """

    pass


@dataclass(frozen=True)
class IndexPolicy:
    """
    The company policy governing which package-source declarations may
    affect the temporary resolution environment.

    `internal_index_url` is the fixed internal mirror that resolution must
    use. Declarations pointing at this URL are always accepted.

    `authorized_index_urls` are explicit, security-approved exceptions:
    project-declared `--index-url`, `--extra-index-url`, or `--find-links`
    values matching one of these URLs are permitted (and reported).

    `allow_no_index` controls whether `--no-index` declarations (which
    bypass the internal mirror entirely) are permitted.
    """

    internal_index_url: str
    authorized_index_urls: frozenset[str] = field(default_factory=frozenset)
    allow_no_index: bool = False

    def _is_permitted(self, url: str) -> bool:
        return url == self.internal_index_url or url in self.authorized_index_urls

    def check_requirements_files(self, filenames: list[Path]) -> list[IndexDeclaration]:
        """
        Inspect each requirements file for index-affecting declarations and
        enforce the policy *before* any resolution happens.

        Returns the list of accepted declarations (for audit reporting).
        Raises `IndexPolicyError` listing every conflicting declaration;
        when raised, the caller must not invoke the resolver.
        """
        accepted: list[IndexDeclaration] = []
        conflicts: list[IndexDeclaration] = []

        for filename in filenames:
            rf = RequirementsFile.from_file(filename)
            for option_line in rf.options:
                options = option_line.options
                line_number = option_line.requirement_line.line_number

                declarations: list[tuple[str, str]] = []
                if "index_url" in options:
                    declarations.append(("--index-url", options["index_url"]))
                declarations.extend(
                    ("--extra-index-url", url) for url in options.get("extra_index_urls", [])
                )
                declarations.extend(("--find-links", url) for url in options.get("find_links", []))

                for option, url in declarations:
                    declaration = IndexDeclaration(filename, line_number, option, url)
                    if self._is_permitted(url):
                        accepted.append(declaration)
                        if url != self.internal_index_url:
                            logger.warning(
                                f"requirements file {filename} line {line_number}: "
                                f"authorized index exception in use: {option} {url}"
                            )
                    else:
                        conflicts.append(declaration)

                if options.get("no_index"):
                    declaration = IndexDeclaration(filename, line_number, "--no-index", "")
                    if self.allow_no_index:
                        accepted.append(declaration)
                        logger.warning(
                            f"requirements file {filename} line {line_number}: "
                            "authorized --no-index declaration in use"
                        )
                    else:
                        conflicts.append(declaration)

        if conflicts:
            details = "; ".join(
                f"{c.filename} line {c.line_number}: {c.option} {c.value}".rstrip()
                for c in conflicts
            )
            raise IndexPolicyError(
                "requirements files declare package sources that conflict with the "
                f"company index policy (internal mirror: {self.internal_index_url}): "
                f"{details}; resolution has been blocked"
            )

        return accepted
