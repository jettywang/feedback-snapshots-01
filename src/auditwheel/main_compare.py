from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from packaging.utils import InvalidWheelFilename

from auditwheel import options

if TYPE_CHECKING:
    import argparse

    from auditwheel.candidates import SymbolRequirement

logger = logging.getLogger(__name__)


def configure_parser(sub_parsers: Any) -> None:  # noqa: ANN401
    help_ = "Compare offline patch candidates against a wheel's real symbol requirements."
    p = sub_parsers.add_parser("compare", help=help_, description=help_)
    p.add_argument("WHEEL_FILE", type=Path, help="Path to wheel file.")
    p.add_argument(
        "--candidates",
        dest="CANDIDATES",
        type=Path,
        required=True,
        metavar="MANIFEST",
        help=(
            "Offline JSON manifest listing replacement library candidates "
            "and their patch evidence."
        ),
    )
    p.add_argument(
        "--json",
        dest="JSON",
        action="store_true",
        default=False,
        help="Output results in JSON format",
    )
    options.disable_isa_check(p)
    options.ldpaths(p)
    p.set_defaults(func=execute)


def _binding_constraints(winfo: Any) -> tuple[Any, ...]:  # noqa: ANN401
    """Non-replaced constraints that still bound the wheel's tags.

    ``auditwheel.wheel_abi`` reports "no constraint" as ``policies.highest``
    and a hard incompatibility (UCS2/PyFPE) as ``policies.linux``; only real
    constraints are returned here.
    """
    policies = winfo.policies
    constraints = []
    if winfo.ucs_policy is policies.linux:
        constraints.append(policies.linux)
    if winfo.pyfpe_policy is policies.linux:
        constraints.append(policies.linux)
    if winfo.machine_policy is policies.linux:
        constraints.append(policies.linux)
    elif winfo.machine_policy != policies.highest:
        constraints.append(winfo.machine_policy)
    if winfo.blacklist_policy is policies.linux:
        constraints.append(policies.linux)
    elif winfo.blacklist_policy != policies.highest:
        constraints.append(winfo.blacklist_policy)
    return tuple(constraints)


def _describe_requirement(requirement: SymbolRequirement) -> str:
    return f"{requirement.symbol}@{requirement.version} (from {requirement.soname})"


def execute(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from auditwheel import json
    from auditwheel.candidates import (
        CandidateError,
        compare_candidates,
        load_manifest,
        required_sonames,
    )
    from auditwheel.error import NonPlatformWheelError, WheelToolsError
    from auditwheel.wheel_abi import analyze_wheel_abi
    from auditwheel.wheeltools import get_wheel_architecture, get_wheel_libc

    wheel_file: Path = args.WHEEL_FILE
    fn = wheel_file.name

    if not wheel_file.is_file():
        parser.error(f"cannot access {wheel_file}. No such file")

    try:
        manifest = load_manifest(args.CANDIDATES)
    except CandidateError as e:
        parser.error(str(e))

    try:
        arch = get_wheel_architecture(fn)
    except InvalidWheelFilename as e:
        parser.error(str(e))
    except (WheelToolsError, NonPlatformWheelError) as e:
        if args.JSON:
            print(json.dumps({"version": 1, "wheel": fn, "error": e.message}))
        else:
            parser.error(str(e))
        return 1

    try:
        libc = get_wheel_libc(fn)
    except WheelToolsError:
        logger.debug("The libc could not be deduced from the wheel filename")
        libc = None

    try:
        winfo = analyze_wheel_abi(
            libc,
            arch,
            wheel_file,
            frozenset(),
            disable_isa_ext_check=args.DISABLE_ISA_EXT_CHECK,
            allow_graft=False,
            args_ldpaths=args.LDPATHS,
        )
    except NonPlatformWheelError as e:
        logger.info("%s", e.message)
        if args.JSON:
            print(json.dumps({"version": 1, "wheel": fn, "error": e.message}))
        else:
            parser.error(str(e))
        return 1

    external_libs = {lib for ref in winfo.external_refs.values() for lib in ref.libs}
    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        constraint_policies=_binding_constraints(winfo),
        required_sonames=required_sonames(manifest, external_libs, winfo.imported_symbols),
    )

    if args.JSON:
        output = report.as_dict()
        output["wheel"] = fn
        print(json.dumps(output))
        return 0

    from auditwheel.main_show import printp

    printp(f'Candidate comparison for "{fn}".')
    printp(f'Wheel policy without replacement candidates: "{winfo.overall_policy.name}".')
    if report.baseline_covered:
        printp(
            f'The wheel can still be published for "{winfo.overall_policy.name}" '
            "or any newer tag listed as kept.",
        )
    else:
        printp(
            "No candidate can cover the wheel's current support range "
            f'("{winfo.overall_policy.name}" and newer); this is a regression.',
        )
    if report.retained:
        printp(
            "Publication tags that can be kept with a candidate: "
            + ", ".join(f'"{verdict.policy}"' for verdict in report.retained),
        )
    else:
        printp("No candidate keeps any publication tag for this wheel.")
    if report.reclaimed:
        printp(
            "Older publication tags reclaimed by an independently evidenced candidate: "
            + ", ".join(f'"{verdict.policy}"' for verdict in report.reclaimed),
        )
    if report.baseline_regressions:
        printp(
            "Publication tags that would have to be dropped: "
            + ", ".join(f'"{verdict.policy}"' for verdict in report.baseline_regressions),
        )
    if report.unreachable:
        printp(
            "Tags below the wheel's remaining requirements (not a candidate regression): "
            + ", ".join(f'"{verdict.policy}"' for verdict in report.unreachable),
        )

    for library in report.libraries:
        if not library.required:
            continue
        printp(f'Library "{library.soname}" requires:')
        for requirement in library.required:
            printp(f"- {_describe_requirement(requirement)}")
        for comparison in library.comparisons:
            candidate = comparison.candidate
            status = "satisfies" if comparison.satisfies_symbols else "does NOT satisfy"
            printp(f"Candidate {candidate.label()} ({candidate.path}) {status} these symbols.")
            for requirement in comparison.missing_symbols:
                printp(f"- missing symbol {_describe_requirement(requirement)}")
            for conflict in comparison.version_conflicts:
                provided = ", ".join(conflict.provided_versions) or "none"
                printp(
                    f"- symbol {conflict.symbol} requires {conflict.required_version} "
                    f"but candidate only provides {provided}",
                )

    # Group identical drop reasons so a long policy list stays readable.
    grouped: dict[tuple[str, tuple[str, ...], tuple[str, ...]], list[str]] = {}
    for verdict in report.baseline_regressions:
        key = (
            verdict.reason,
            tuple(sorted({_describe_requirement(r) for r in verdict.missing_symbols})),
            tuple(verdict.blocked_by),
        )
        grouped.setdefault(key, []).append(verdict.policy)
    for (reason, symbol_lines, blocked_by), policies in grouped.items():
        printp(f"Dropped ({reason}): " + ", ".join(f'"{p}"' for p in policies))
        for symbol_line in symbol_lines:
            printp(f"- real symbol {symbol_line} is not provided by any candidate")
        if blocked_by:
            printp("Blocked by: " + ", ".join(blocked_by))
    return 0
