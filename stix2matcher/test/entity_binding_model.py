"""
A finite object model for entity-binding regression tests.

The matcher must not combine properties of different root SCOs into a single
hit of one comparison expression.  It must still allow different referents of
the *same* root SCO to satisfy different parts of a complex path.  The two
rules are easy to confuse, so this module defines a small, explicit universe
of objects and scenarios and spells out which bindings are legal.

Vocabulary
----------
* object key: a logical file object in ``OBJECTS``.  In STIX 2.0 it is used
  directly as the observed-data ``objects`` key; in STIX 2.1 it becomes the
  SCO id ``file--<key>``.
* scenario: one observed-data SDO (STIX 2.0) or one bundle containing a single
  observed-data SDO plus its SCOs (STIX 2.1).  Scenario names double as the
  observed-data id suffix, i.e. ``observed-data--<scenario>``.
* binding: a tuple with one entry per observation expression in the pattern.
  Each entry is the observed-data id the expression bound to, or ``None`` for
  the unused side of a pattern-level OR.
* provenance: the observed-data ids in a binding.  Checking these (rather
  than merely asserting a non-empty result) is what shows *which* entity
  produced a hit.

The model deliberately contains both "half" and "whole" objects:

* ``malware-name-only`` and ``report-size-only`` live in one observed-data and
  each satisfies exactly one half of ``name = 'malware.exe' AND size > 1000``.
* ``malware-both-properties`` satisfies the whole expression.
* ``ref-two-roots`` splits the two halves over two different roots, while
  ``ref-cross-branches`` satisfies them through two different referents of one
  root (which is legal).
"""
from collections import namedtuple

from stix2matcher.matcher import MatchListener, Pattern, match

STIX_20 = "2.0"
STIX_21 = "2.1"


def _file(**props):
    obj = {"type": "file"}
    obj.update(props)
    return obj


# Logical objects.  Keys must be unique: they identify SCOs in STIX 2.1 and
# objects in STIX 2.0, and therefore pin down which entity produced a hit.
OBJECTS = {
    # Two files in one observed-data: each one satisfies exactly one half.
    "malware-name-only": _file(name="malware.exe", size=10),
    "report-size-only": _file(name="report.pdf", size=5000),
    # One file that satisfies both halves.
    "malware-both-properties": _file(name="malware.exe", size=5000),

    # Independent observations for the observation-level AND.
    "name-file": _file(name="malware.exe", size=10),
    "size-file": _file(name="report.pdf", size=5000),

    # The reference halves are split over two roots: "dropper" points at a
    # small "bad" file, while an unrelated root "bystander" points at a big
    # "good" file.  No single root satisfies "dropper AND big referent".
    "ref-halves-dropper": _file(name="dropper", parent_ref="ref-halves-bad"),
    "ref-halves-bystander": _file(name="bystander", parent_ref="ref-halves-good"),
    "ref-halves-bad": _file(name="bad", size=1),
    "ref-halves-good": _file(name="good", size=5000),
    # One root whose own referent satisfies the other half.
    "ref-whole-dropper": _file(name="dropper", parent_ref="ref-whole-good"),
    "ref-whole-good": _file(name="good", size=5000),

    # A legal cross-referent comparison: one root points at two referents and
    # each referent satisfies a different half of the expression.
    "cross-container": _file(name="container", parent_refs=["cross-alpha", "cross-beta"]),
    "cross-alpha": _file(name="alpha", size=1),
    "cross-beta": _file(name="beta", size=5000),

    # The same alpha/beta halves, but attached to two *different* roots.
    "split-alpha-root": _file(name="alpha-root", parent_refs=["split-alpha"]),
    "split-beta-root": _file(name="beta-root", parent_refs=["split-beta"]),
    "split-alpha": _file(name="alpha", size=1),
    "split-beta": _file(name="beta", size=5000),

    # A deep reference chain within one root.
    "chain-root": _file(name="chain-root", parent_ref="chain-mid"),
    "chain-mid": _file(name="chain-mid", parent_ref="chain-leaf"),
    "chain-leaf": _file(name="chain-leaf", size=5000),

    # The same shape split over two roots: one chain ends small, the other big.
    "chain-split-root": _file(name="chain-split-root", parent_ref="chain-split-mid"),
    "chain-split-mid": _file(name="chain-split-mid", parent_ref="chain-split-leaf"),
    "chain-split-leaf": _file(name="chain-split-leaf", size=1),
    "chain-split-other": _file(name="chain-split-other", parent_ref="chain-split-other-mid"),
    "chain-split-other-mid": _file(name="chain-split-other-mid", parent_ref="chain-split-other-leaf"),
    "chain-split-other-leaf": _file(name="chain-split-other-leaf", size=5000),
}


# Each scenario is one observed-data.  All objects listed for a scenario are
# reachable roots of that observed-data, so a hit's observed-data id together
# with the scenario definition identifies the root(s) that could produce it.
SCENARIOS = {
    "two-files-one-observation": ("malware-name-only", "report-size-only"),
    "one-file-both-properties": ("malware-both-properties",),
    "name-file": ("name-file",),
    "size-file": ("size-file",),
    "ref-two-roots": (
        "ref-halves-dropper",
        "ref-halves-bystander",
        "ref-halves-bad",
        "ref-halves-good",
    ),
    "ref-one-root": ("ref-whole-dropper", "ref-whole-good"),
    "ref-cross-branches": ("cross-container", "cross-alpha", "cross-beta"),
    "ref-split-roots": ("split-alpha-root", "split-beta-root", "split-alpha", "split-beta"),
    "ref-chain": ("chain-root", "chain-mid", "chain-leaf"),
    "ref-chain-split-roots": (
        "chain-split-root",
        "chain-split-mid",
        "chain-split-leaf",
        "chain-split-other",
        "chain-split-other-mid",
        "chain-split-other-leaf",
    ),
}


def observed_data_id(scenario):
    """The observed-data id generated for a scenario."""
    return "observed-data--" + scenario


def bundle_id(scenario):
    """The bundle id generated for a STIX 2.1 scenario."""
    return "bundle--" + scenario


def _resolve_references(key):
    """Copy an object, rewriting logical reference keys to STIX 2.1 SCO ids."""
    obj = dict(OBJECTS[key])
    for prop, value in list(obj.items()):
        if prop.endswith("_refs"):
            obj[prop] = ["file--" + ref for ref in value]
        elif prop.endswith("_ref"):
            obj[prop] = "file--" + value
    return obj


def _build_20(scenarios):
    observations = []
    for scenario in scenarios:
        observations.append({
            "id": observed_data_id(scenario),
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {key: dict(OBJECTS[key]) for key in SCENARIOS[scenario]},
        })
    return observations


def _build_21(scenarios):
    bundles = []
    for scenario in scenarios:
        objects = []
        for key in SCENARIOS[scenario]:
            obj = _resolve_references(key)
            obj["id"] = "file--" + key
            obj["spec_version"] = "2.1"
            objects.append(obj)

        observed_data = {
            "id": observed_data_id(scenario),
            "type": "observed-data",
            "spec_version": "2.1",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "object_refs": ["file--" + key for key in SCENARIOS[scenario]],
        }
        bundles.append({
            "type": "bundle",
            "id": bundle_id(scenario),
            "objects": [observed_data] + objects,
        })
    return bundles


def build_observations(version, scenarios):
    """Build the input SDOs for the given version and scenario names."""
    unknown = [name for name in scenarios if name not in SCENARIOS]
    if unknown:
        raise KeyError("unknown scenario(s): {}".format(", ".join(unknown)))

    if version == STIX_20:
        return _build_20(scenarios)
    if version == STIX_21:
        return _build_21(scenarios)
    raise ValueError("unsupported STIX version: {}".format(version))


def _observed_data_id_of_sdo(sdo):
    """Return the observed-data id contained in a matched SDO or bundle."""
    if sdo.get("type") == "observed-data":
        return sdo["id"]

    observed_data_objects = [
        obj for obj in sdo.get("objects", [])
        if obj.get("type") == "observed-data"
    ]
    if len(observed_data_objects) != 1:
        raise AssertionError(
            "expected a matched bundle with exactly one observed-data, got {!r}".format(sdo)
        )
    return observed_data_objects[0]["id"]


def binding_provenance(version, pattern_text, scenarios):
    """
    Return every binding found for a pattern as a frozenset of tuples.

    Each tuple entry is the observed-data id that the corresponding
    observation expression bound to, or ``None`` for an unbound OR branch.
    """
    listener = MatchListener(
        build_observations(version, scenarios),
        stix_version=version,
    )
    Pattern(pattern_text, stix_version=version).walk(listener)

    bindings = set()
    for binding in listener.matched():
        provenance = []
        for instance_id in binding:
            if instance_id is None:
                provenance.append(None)
                continue

            matched_sdos = listener.get_sdos_from_binding((instance_id,))
            if len(matched_sdos) != 1:
                raise AssertionError(
                    "expected one matched SDO for instance {!r}, got {!r}".format(
                        instance_id, matched_sdos
                    )
                )
            provenance.append(_observed_data_id_of_sdo(matched_sdos[0]))

        bindings.add(tuple(provenance))

    return frozenset(bindings)


def public_hit_observed_data(version, pattern_text, scenarios):
    """
    Return the observed-data ids reported by the public ``match()`` API.

    ``match()`` only exposes the first binding, so this is used as a
    supplementary check that the public hit source is one of the legal
    bindings, never a stitched one.
    """
    matched_sdos = match(
        pattern_text,
        build_observations(version, scenarios),
        stix_version=version,
    )
    return frozenset(_observed_data_id_of_sdo(sdo) for sdo in matched_sdos)


BindingCase = namedtuple("BindingCase", "id pattern scenarios bindings why")


def _binding(*values):
    """Build an expected binding from observed-data ids and None fillers."""
    return tuple(values)


ALLOWED_BINDINGS = (
    BindingCase(
        id="comparison-and-one-file-both-properties",
        pattern="[file:name = 'malware.exe' AND file:size > 1000]",
        scenarios=("one-file-both-properties",),
        bindings=frozenset({
            _binding(observed_data_id("one-file-both-properties")),
        }),
        why="one file object satisfies both halves of the comparison expression",
    ),
    BindingCase(
        id="comparison-and-picks-whole-over-halves",
        pattern="[file:name = 'malware.exe' AND file:size > 1000]",
        scenarios=("two-files-one-observation", "one-file-both-properties"),
        bindings=frozenset({
            _binding(observed_data_id("one-file-both-properties")),
        }),
        why="the half/half observed-data must not be stitched; only the whole one may hit",
    ),
    BindingCase(
        id="comparison-and-other-half-same-root",
        pattern="[file:name = 'report.pdf' AND file:size > 1000]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset({
            _binding(observed_data_id("two-files-one-observation")),
        }),
        why="report.pdf and size 5000 belong to the same root file object",
    ),
    BindingCase(
        id="observation-and-two-observations",
        pattern="[file:name = 'malware.exe'] AND [file:size > 1000]",
        scenarios=("name-file", "size-file"),
        bindings=frozenset({
            _binding(
                observed_data_id("name-file"),
                observed_data_id("size-file"),
            ),
        }),
        why="each observation expression binds its own observed-data",
    ),
    BindingCase(
        id="observation-and-distinct-observations-either-order",
        pattern="[file:name = 'malware.exe'] AND [file:size > 1000]",
        scenarios=("two-files-one-observation", "one-file-both-properties"),
        bindings=frozenset({
            _binding(
                observed_data_id("two-files-one-observation"),
                observed_data_id("one-file-both-properties"),
            ),
            _binding(
                observed_data_id("one-file-both-properties"),
                observed_data_id("two-files-one-observation"),
            ),
        }),
        why="both observed-data satisfy both sides, but the two bindings must be distinct",
    ),
    BindingCase(
        id="comparison-or-name-branch-may-select-other-half",
        pattern="[(file:name = 'malware.exe' OR file:name = 'report.pdf') AND file:size > 1000]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset({
            _binding(observed_data_id("two-files-one-observation")),
        }),
        why="the OR may pick report.pdf, which is also the root that has the big size",
    ),
    BindingCase(
        id="comparison-or-and-precedence-keeps-root",
        pattern="[file:name = 'malware.exe' OR file:name = 'report.pdf' AND file:size > 1000]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset({
            _binding(observed_data_id("two-files-one-observation")),
        }),
        why="AND binds tighter; report.pdf+size is a legal rooted match inside the OR",
    ),
    BindingCase(
        id="observation-or-keeps-sides-separate",
        pattern="[file:name = 'malware.exe'] OR [file:size > 1000]",
        scenarios=("name-file", "size-file"),
        bindings=frozenset({
            _binding(observed_data_id("name-file"), None),
            _binding(None, observed_data_id("size-file")),
        }),
        why="observation-level OR binds only one side and pads the other with None",
    ),
    BindingCase(
        id="reference-comparison-and-one-root",
        pattern="[file:name = 'dropper' AND file:parent_ref.size > 1000]",
        scenarios=("ref-one-root",),
        bindings=frozenset({
            _binding(observed_data_id("ref-one-root")),
        }),
        why="dropper's own referent is big, so both halves share one root",
    ),
    BindingCase(
        id="reference-comparison-and-picks-whole-root",
        pattern="[file:name = 'dropper' AND file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots", "ref-one-root"),
        bindings=frozenset({
            _binding(observed_data_id("ref-one-root")),
        }),
        why="the split reference graph must not be stitched from the bystander root",
    ),
    BindingCase(
        id="reference-or-selects-root-with-big-referent",
        pattern="[(file:name = 'dropper' OR file:name = 'bystander') AND file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots",),
        bindings=frozenset({
            _binding(observed_data_id("ref-two-roots")),
        }),
        why="the OR may select bystander, whose own referent is big",
    ),
    BindingCase(
        id="reference-or-right-branch-on-same-root",
        pattern="[file:name = 'dropper' AND (file:parent_ref.size > 1000 OR file:name = 'bystander')]",
        scenarios=("ref-one-root",),
        bindings=frozenset({
            _binding(observed_data_id("ref-one-root")),
        }),
        why="the OR's size branch belongs to the dropper root itself",
    ),
    BindingCase(
        id="reference-cross-referents-same-root",
        pattern="[file:parent_refs[*].name = 'alpha' AND file:parent_refs[*].size > 1000]",
        scenarios=("ref-cross-branches",),
        bindings=frozenset({
            _binding(observed_data_id("ref-cross-branches")),
        }),
        why="complex paths stay legal: different referents of one root may satisfy different halves",
    ),
    BindingCase(
        id="reference-cross-referents-with-root-name",
        pattern="[file:name = 'container' AND file:parent_refs[*].name = 'alpha' AND file:parent_refs[*].size > 1000]",
        scenarios=("ref-cross-branches",),
        bindings=frozenset({
            _binding(observed_data_id("ref-cross-branches")),
        }),
        why="all tests are rooted at the same container object",
    ),
    BindingCase(
        id="reference-cross-referents-or-branch",
        pattern="[(file:name = 'container' OR file:name = 'unrelated') AND file:parent_refs[*].name = 'alpha' AND file:parent_refs[*].size > 1000]",
        scenarios=("ref-cross-branches",),
        bindings=frozenset({
            _binding(observed_data_id("ref-cross-branches")),
        }),
        why="an OR branch plus a complex path must still preserve the root identity",
    ),
    BindingCase(
        id="reference-split-roots-legal-root",
        pattern="[file:parent_refs[*].name = 'beta' AND file:parent_refs[*].size > 1000]",
        scenarios=("ref-split-roots",),
        bindings=frozenset({
            _binding(observed_data_id("ref-split-roots")),
        }),
        why="beta-root and beta belong to the same root, so this remains a legal match",
    ),
    BindingCase(
        id="reference-deep-chain",
        pattern="[file:name = 'chain-root' AND file:parent_ref.parent_ref.size > 1000]",
        scenarios=("ref-chain",),
        bindings=frozenset({
            _binding(observed_data_id("ref-chain")),
        }),
        why="deep reference paths are legal when they stay on one root",
    ),
    BindingCase(
        id="reference-deep-chain-other-root",
        pattern="[file:name = 'chain-split-other' AND file:parent_ref.parent_ref.size > 1000]",
        scenarios=("ref-chain-split-roots",),
        bindings=frozenset({
            _binding(observed_data_id("ref-chain-split-roots")),
        }),
        why="the well-formed part of a scenario still matches; only cross-root stitching is banned",
    ),
    BindingCase(
        id="observation-and-reference-two-observations",
        pattern="[file:name = 'dropper'] AND [file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots", "ref-one-root"),
        bindings=frozenset({
            _binding(
                observed_data_id("ref-two-roots"),
                observed_data_id("ref-one-root"),
            ),
            _binding(
                observed_data_id("ref-one-root"),
                observed_data_id("ref-two-roots"),
            ),
        }),
        why="observation-level AND may use both observations, each satisfying one expression",
    ),
)


REJECTED_BINDINGS = (
    BindingCase(
        id="comparison-and-does-not-stitch-two-files",
        pattern="[file:name = 'malware.exe' AND file:size > 1000]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset(),
        why="name and size are satisfied by two different root files",
    ),
    BindingCase(
        id="comparison-and-does-not-stitch-two-observations",
        pattern="[file:name = 'malware.exe' AND file:size > 1000]",
        scenarios=("name-file", "size-file"),
        bindings=frozenset(),
        why="a comparison expression is scoped to a single observation expression",
    ),
    BindingCase(
        id="comparison-and-distinct-names-need-one-root",
        pattern="[file:name = 'malware.exe' AND file:name = 'report.pdf']",
        scenarios=("two-files-one-observation",),
        bindings=frozenset(),
        why="two different names cannot both be true of one root file",
    ),
    BindingCase(
        id="comparison-and-contradictory-sizes",
        pattern="[file:size < 100 AND file:size > 1000]",
        scenarios=("one-file-both-properties",),
        bindings=frozenset(),
        why="one size value cannot satisfy both bounds",
    ),
    BindingCase(
        id="comparison-or-cannot-lend-name-branch",
        pattern="[(file:name = 'malware.exe' OR file:name = 'unrelated') AND file:size > 1000]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset(),
        why="the name branch selects file 0 while the size test is true only of file 1",
    ),
    BindingCase(
        id="comparison-or-cannot-lend-size-branch",
        pattern="[file:name = 'malware.exe' AND (file:size > 1000 OR file:name = 'unrelated')]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset(),
        why="the size branch selects file 1 while the name test is true only of file 0",
    ),
    BindingCase(
        id="observation-and-cannot-reuse-one-observation",
        pattern="[file:name = 'malware.exe'] AND [file:size > 1000]",
        scenarios=("two-files-one-observation",),
        bindings=frozenset(),
        why="one observation expression may not bind the same observation twice",
    ),
    BindingCase(
        id="observation-and-single-object-cannot-bind-twice",
        pattern="[file:name = 'malware.exe'] AND [file:size > 1000]",
        scenarios=("one-file-both-properties",),
        bindings=frozenset(),
        why="number_observed is 1, so one observed-data provides only one observation",
    ),
    BindingCase(
        id="observation-and-reference-cannot-reuse-one-observation",
        pattern="[file:name = 'dropper'] AND [file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots",),
        bindings=frozenset(),
        why="both expressions are true of the same single observation",
    ),
    BindingCase(
        id="reference-splits-name-and-size-across-roots",
        pattern="[file:name = 'dropper' AND file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots",),
        bindings=frozenset(),
        why="dropper's referent is small; bystander's big referent belongs to another root",
    ),
    BindingCase(
        id="reference-splits-name-and-other-half-across-roots",
        pattern="[file:name = 'dropper' AND file:parent_ref.name = 'bad' AND file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots",),
        bindings=frozenset(),
        why="the same referent must satisfy both referent tests",
    ),
    BindingCase(
        id="reference-or-cannot-lend-bystander-size",
        pattern="[(file:name = 'dropper' OR file:name = 'unrelated') AND file:parent_ref.size > 1000]",
        scenarios=("ref-two-roots",),
        bindings=frozenset(),
        why="no OR branch selects the bystander root whose referent is big",
    ),
    BindingCase(
        id="reference-or-rhs-cannot-lend-bystander-size",
        pattern="[file:name = 'dropper' AND (file:parent_ref.size > 1000 OR file:name = 'unrelated')]",
        scenarios=("ref-two-roots",),
        bindings=frozenset(),
        why="the big referent belongs to the bystander root, not to dropper",
    ),
    BindingCase(
        id="reference-cross-roots-cannot-stitch",
        pattern="[file:parent_refs[*].name = 'alpha' AND file:parent_refs[*].size > 1000]",
        scenarios=("ref-split-roots",),
        bindings=frozenset(),
        why="alpha and beta are referents of two different roots",
    ),
    BindingCase(
        id="reference-cross-roots-cannot-lend-size",
        pattern="[file:name = 'alpha-root' AND file:parent_refs[*].size > 1000]",
        scenarios=("ref-split-roots",),
        bindings=frozenset(),
        why="alpha-root's own referent is small; beta's big referent is rooted elsewhere",
    ),
    BindingCase(
        id="reference-deep-chain-cannot-stitch",
        pattern="[file:name = 'chain-split-root' AND file:parent_ref.parent_ref.size > 1000]",
        scenarios=("ref-chain-split-roots",),
        bindings=frozenset(),
        why="the deep big leaf belongs to the other root's chain",
    ),
    BindingCase(
        id="reference-deep-chain-cannot-lend-leaf-name",
        pattern="[file:name = 'chain-split-root' AND file:parent_ref.parent_ref.name = 'chain-split-other-leaf']",
        scenarios=("ref-chain-split-roots",),
        bindings=frozenset(),
        why="the leaf name belongs to the other root's chain",
    ),
)
