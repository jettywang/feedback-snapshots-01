from __future__ import print_function

import argparse
import base64
import binascii
import datetime
import io
import itertools
import json
import operator
import pprint
import re
import socket
import struct
import sys
import unicodedata

import antlr4
import antlr4.error.ErrorListener
import antlr4.error.Errors
import dateutil.relativedelta
import dateutil.tz
from deepmerge import always_merger
import six
from stix2patterns.grammars.STIXPatternListener import STIXPatternListener
from stix2patterns.grammars.STIXPatternParser import STIXPatternParser
from stix2patterns.v20.pattern import Pattern as Stix2Pattern20
from stix2patterns.v21.pattern import Pattern as Stix2Pattern21

from stix2matcher import DEFAULT_VERSION, VARSION_2_1
from stix2matcher.enums import TYPES_V21

# Example observed-data SDO.  This represents N observations, where N is
# the value of the "number_observed" property (in this case, 5).
#
# {
#   "type": "observed-data",
#   "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
#   "created": "2016-04-06T19:58:16.000Z",
#   "modified": "2016-04-06T19:58:16.000Z",
#   "first_observed": "2005-01-21T11:17:41Z",
#   "last_observed": "2005-01-21T11:22:41Z",
#   "number_observed": 5,
#   "objects": {
#     "0": {
#       "type": "file",
#       "hashes": {
#         "sha-256": "bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52"
#       }
#     },
#     "1": {
#       "type": "file",
#       "hashes": {
#         "md5": "22A0FB8F3879FB569F8A3FF65850A82E"
#       }
#     },
#     "2": {
#       "type": "file",
#       "hashes": {
#         "md5": "8D98A25E9D0662B1F4CA3BF22D6F53E9"
#       }
#     },
#     "3": {
#       "type": "file",
#       "hashes": {
#         "sha-256": "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb00"
#       },
#       "mime_type": "application/zip",
#       "extensions": {
#         "archive-ext": {
#           "contains_refs": [
#             "0",
#             "1",
#             "2"
#           ],
#           "version": "5.0"
#         }
#       }
#     }
#   }
# }


# Coercers from strings (what all token values are) to python types.
# Set and regex literals are not handled here; they're a different beast...
_TOKEN_TYPE_COERCERS = {
    STIXPatternParser.IntPosLiteral: int,
    STIXPatternParser.IntNegLiteral: int,
    STIXPatternParser.StringLiteral: lambda s: s[1:-1].replace(u"\\'", u"'").replace(u"\\\\", u"\\"),
    STIXPatternParser.BoolLiteral: lambda s: s.lower() == u"true",
    STIXPatternParser.FloatPosLiteral: float,
    STIXPatternParser.FloatNegLiteral: float,
    STIXPatternParser.BinaryLiteral: lambda s: base64.standard_b64decode(s[2:-1]),
    STIXPatternParser.HexLiteral: lambda s: binascii.a2b_hex(s[2:-1]),
    STIXPatternParser.TimestampLiteral: lambda t: _str_to_datetime(t[2:-1]),
}


# Map python types to 2-arg equality functions.  The functions must return
# True if equal, False otherwise.
#
# This table may be treated symmetrically via _get_table_symmetric() below.
# (I only added half the entries since I plan to use that.)  And of course,
# that means all the functions in the table must be insensitive to the order
# of types of their arguments.
#
# Where I use python operators, python's mixed-type comparison rules are
# in effect, e.g. conversion of operands to a common type.


def _bin_str_equals(val1, val2):
    # Figure out which arg is the binary one, and which is the string...
    if isinstance(val1, six.text_type):
        str_val = val1
        bin_val = val2
    else:
        str_val = val2
        bin_val = val1

    # Comparison is only allowed if all the string codepoints are < 256.
    cmp_allowed = all(ord(c) < 256 for c in str_val)

    if not cmp_allowed:
        # Per spec, this results in not-equal.
        return False

    str_as_bin = bytearray(ord(c) for c in str_val)
    return str_as_bin == bin_val


_COMPARE_EQ_FUNCS = {
    int: {
        int: operator.eq,
        float: operator.eq
    },
    float: {
        float: operator.eq
    },
    six.binary_type: {
        six.binary_type: operator.eq,
        six.text_type: _bin_str_equals
    },
    six.text_type: {
        six.text_type: operator.eq
    },
    bool: {
        bool: operator.eq
    },
    datetime.datetime: {
        datetime.datetime: operator.eq
    }
}


# Similar for <, >, etc comparisons.  These functions should return <0 if
# first arg is less than second; 0 if equal, >0 if first arg is greater.
#
# This table may be treated symmetrically via _get_table_symmetric() below.
# (I only added half the entries since I plan to use that.)  And of course,
# that means all the functions in the table must be insensitive to the order
# of types of their arguments.
#
# Where I use python operators, python's mixed-type comparison rules are
# in effect, e.g. conversion of operands to a common type.
#
# cmp() was removed in Python 3. See
# https://docs.python.org/3.0/whatsnew/3.0.html#ordering-comparisons
def _cmp(a, b):
    return (a > b) - (a < b)


def _bin_str_compare(val1, val2):
    """
    Does string/binary comparison as described in the spec.  Raises an
    exception if the string is unsuitable for comparison.  The spec says
    the result must be "false", but order comparators can't return true or
    false.  Their purpose is to compute an ordering: less, equal, or greater.
    So I have to use an exception.

    One of the args must be of unicode type, the other must be a binary type
    (bytes/str, bytearray, etc).
    """

    # Figure out which arg is the binary one, and which is the string...
    if isinstance(val1, six.text_type):
        str_val = val1
        str_was_first = True
    else:
        str_val = val2
        str_was_first = False

    # Comparison is only allowed if all the string codepoints are < 256.
    cmp_allowed = all(ord(c) < 256 for c in str_val)

    if not cmp_allowed:
        raise ValueError(u"Can't compare to binary: " + str_val)

    str_as_bin = bytearray(ord(c) for c in str_val)

    if str_was_first:
        return _cmp(str_as_bin, val2)
    else:
        return _cmp(val1, str_as_bin)


_COMPARE_ORDER_FUNCS = {
    int: {
        int: _cmp,
        float: _cmp
    },
    float: {
        float: _cmp
    },
    six.binary_type: {
        six.binary_type: _cmp,
        six.text_type: _bin_str_compare
    },
    six.text_type: {
        six.text_type: _cmp
    },
    datetime.datetime: {
        datetime.datetime: _cmp
    }
}


class MatcherException(Exception):
    """Base class for matcher exceptions."""
    pass


class MatcherInternalError(MatcherException):
    """For errors that probably represent bugs or incomplete matcher
    implementation."""
    pass


class UnsupportedOperatorError(MatcherInternalError):
    """This means I just haven't yet added support for a particular operator.
    (A genuinely invalid operator ought to be caught during parsing right??)
    I found I was throwing internal errors for this in several places, so I
    just gave the error its own class to make it easier.
    """
    def __init__(self, op_str):
        super(UnsupportedOperatorError, self).__init__(
            u"Unsupported operator: '{}'".format(op_str)
        )


class MatcherErrorListener(antlr4.error.ErrorListener.ErrorListener):
    """
    Simple error listener which just remembers the last error message received.
    """
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.error_message = u"{}:{}: {}".format(line, column, msg)


# Canonical semantic stages at which a candidate can be eliminated.  These
# values are stable, machine-readable identifiers used in diagnostic reports.
DIAG_PATH_MISSING = u"path_missing"
DIAG_REFERENCE_UNREACHABLE = u"reference_unreachable"
DIAG_TYPE_MISMATCH = u"type_mismatch"
DIAG_COMPARISON_FAILED = u"comparison_failed"
DIAG_TEMPORAL_FAILED = u"temporal_combination_failed"

DIAGNOSTIC_STAGES = (
    DIAG_PATH_MISSING,
    DIAG_REFERENCE_UNREACHABLE,
    DIAG_TYPE_MISMATCH,
    DIAG_COMPARISON_FAILED,
    DIAG_TEMPORAL_FAILED,
)


def _diagnostic_value(value, depth=0, expand=False):
    """
    Convert a value into a compact JSON-safe representation for diagnostics.

    Diagnostic reports deliberately avoid embedding whole objects or bundles.
    Observation-side values are represented by their type and size instead of
    their contents, so a report can identify the relevant candidate without
    dumping unrelated observation data.  Values the matcher itself constructs
    for details (for example timestamp bounds or reference IDs) may be expanded
    with expand=True.

    :param value: Any Python value.
    :param depth: Current recursion depth.
    :param expand: If True, containers are expanded (bounded); otherwise they
        are summarized.
    :return: A JSON-safe representation.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, six.text_type):
        if len(value) > 512:
            return value[:509] + u"..."
        return value

    if isinstance(value, datetime.datetime):
        return value.isoformat()

    if isinstance(value, datetime.date):
        return value.isoformat()

    if isinstance(value, (bytes, bytearray)):
        try:
            encoded = base64.standard_b64encode(bytes(value)).decode(u"ascii")
        except Exception:
            encoded = u""
        return {u"type": u"binary", u"base64": encoded}

    if isinstance(value, (set, frozenset)):
        safe_values = [
            _diagnostic_value(v, depth + 1, expand) for v in value
        ]
        safe_values.sort(key=lambda v: repr(v))
        return {u"type": type(value).__name__, u"values": safe_values[:20],
                u"size": len(value)}

    if isinstance(value, (list, tuple)):
        if expand and depth < 3:
            return [_diagnostic_value(v, depth + 1, expand)
                    for v in value[:20]]
        return {u"type": type(value).__name__, u"size": len(value)}

    if isinstance(value, dict):
        if expand and depth < 3:
            result = {}
            for idx, key in enumerate(value):
                if idx >= 20:
                    break
                result[six.text_type(key)] = _diagnostic_value(
                    value[key], depth + 1, expand)
            return result
        return {u"type": u"dict", u"size": len(value)}

    try:
        return {u"type": type(value).__name__,
                u"repr": repr(value)[:200]}
    except Exception:
        return {u"type": type(value).__name__}


def _type_name(value):
    """Return a stable, readable type name for diagnostics."""
    if value is None:
        return u"null"
    if isinstance(value, bool):
        return u"boolean"
    if isinstance(value, datetime.datetime):
        return u"timestamp"
    return type(value).__name__


def _rule_location(ctx, pattern_str=None):
    """
    Build a compact description of the pattern location represented by a
    parse-tree node.

    Line numbers are 1-based and columns are 0-based, matching ANTLR's token
    positions.  Character offsets refer to the original pattern string.

    :param ctx: An ANTLR parse-tree context, or None.
    :param pattern_str: The original pattern string, if available.
    :return: A dict with location information, or None.
    """
    if ctx is None:
        return None

    start = getattr(ctx, u"start", None)
    stop = getattr(ctx, u"stop", None)
    if start is None:
        return None

    start_offset = getattr(start, u"start", None)
    stop_offset = getattr(stop, u"stop", None) if stop is not None else None

    text = ctx.getText()
    if pattern_str is not None and \
            isinstance(start_offset, int) and isinstance(stop_offset, int) and \
            0 <= start_offset <= stop_offset < len(pattern_str):
        text = pattern_str[start_offset:stop_offset + 1]

    if len(text) > 300:
        text = text[:297] + u"..."

    return {
        u"line": getattr(start, u"line", None),
        u"column": getattr(start, u"column", None),
        u"end_line": getattr(stop, u"line", None) if stop is not None else None,
        u"end_column": getattr(stop, u"column", None) if stop is not None else None,
        u"start": start_offset,
        u"stop": stop_offset,
        u"text": text,
    }


class DiagnosticReport(dict):
    """
    A structured diagnostic report.

    This is a regular dict, so it can be serialized with json.dumps() or
    consumed with normal mapping access.  Convenience attribute access is
    also supported (e.g. report.matched).

    The match determination is always in the "matched" key; the is_match
    property provides the same value.  Note that bool(report) deliberately
    follows normal dict semantics (non-empty mapping), because JSON encoders
    rely on the truthiness of dict subclasses; use report.is_match or
    report["matched"] to test the determination.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    @property
    def is_match(self):
        """The match determination, as a boolean."""
        return bool(self.get(u"matched", False))


class MatchDiagnostics(object):
    """
    Collects the reasons candidates were eliminated while matching.

    The collector is intentionally passive: it never changes matching
    decisions, never consumes binding generators on its own, and never
    swallows matcher or parser exceptions.  It simply records identities and
    rule locations for candidates which were actually rejected.
    """

    # Keep reports bounded even for pathological patterns; the report says
    # when this happens rather than silently dropping everything.
    MAX_ELIMINATIONS = 1000
    MAX_BRANCHES = 200

    def __init__(self, pattern=None, stix_version=DEFAULT_VERSION,
                 observations=None):
        self.__pattern = pattern
        self.__stix_version = stix_version
        self.__observations = observations or []
        self.__eliminations = []
        self.__branches = []
        self.__seen = set()
        self.__branch_seen = set()
        self.truncated = False

    def set_observations(self, observations):
        self.__observations = observations

    @property
    def eliminations(self):
        return self.__eliminations

    @property
    def branches(self):
        return self.__branches

    def observation_identity(self, obs_idx):
        """Return a minimal identity for an observation index."""
        if obs_idx is None:
            return None

        identity = {u"index": obs_idx}
        try:
            sdo = self.__observations[obs_idx]
        except (IndexError, TypeError):
            return identity

        if self.__stix_version == VARSION_2_1:
            for obj in sdo.get(u"objects", []):
                if isinstance(obj, dict) and \
                        obj.get(u"type") == u"observed-data":
                    if u"id" in obj:
                        identity[u"id"] = obj[u"id"]
                    break
        else:
            if u"id" in sdo:
                identity[u"id"] = sdo[u"id"]

        return identity

    def object_identity(self, obs_idx, object_id):
        """Return a minimal identity for a Cyber Observable object."""
        if object_id is None:
            return None

        identity = {u"id": object_id}
        try:
            sdo = self.__observations[obs_idx]
        except (IndexError, TypeError):
            return identity

        if self.__stix_version == VARSION_2_1:
            for obj in sdo.get(u"objects", []):
                if isinstance(obj, dict) and obj.get(u"id") == object_id:
                    if u"type" in obj:
                        identity[u"type"] = obj[u"type"]
                    break
        else:
            objects = sdo.get(u"objects", {})
            obj = objects.get(object_id)
            if obj is None:
                obj = objects.get(six.text_type(object_id))
            if isinstance(obj, dict) and u"type" in obj:
                identity[u"type"] = obj[u"type"]

        return identity

    def record(self, stage, reason, ctx=None, obs_idx=None, obs_idxs=None,
               object_id=None, path=None, detail=None, expected=None,
               actual=None, rule=None):
        """
        Record one candidate elimination.

        :param stage: One of DIAGNOSTIC_STAGES.
        :param reason: A granular, machine-readable reason.
        :param ctx: Parse-tree node for the rule location.
        :param obs_idx: Observation index, if the candidate is observation
            scoped.
        :param obs_idxs: Observation indices, for combination failures.
        :param object_id: Root Cyber Observable object identity.
        :param path: The object path text, if relevant.
        :param detail: Additional JSON-safe details.
        :param expected: Pattern-side value, if relevant.
        :param actual: Observation-side value, if relevant.
        :param rule: Explicit rule location; overrides ctx.
        """
        if len(self.__eliminations) >= self.MAX_ELIMINATIONS:
            self.truncated = True
            return

        if rule is None:
            rule = _rule_location(ctx, self.__pattern)

        record = {u"stage": stage, u"reason": reason}

        if rule is not None:
            record[u"rule"] = rule

        observation = self.observation_identity(obs_idx)
        if observation is not None:
            record[u"observation"] = observation

        if obs_idxs is not None:
            unique_idxs = []
            for idx in obs_idxs:
                if idx is not None and idx not in unique_idxs:
                    unique_idxs.append(idx)
            record[u"observations"] = [
                self.observation_identity(idx) for idx in unique_idxs
            ]

        obj = self.object_identity(obs_idx, object_id)
        if obj is not None:
            record[u"object"] = obj

        if path is not None:
            record[u"path"] = path

        if detail is not None:
            record[u"detail"] = _diagnostic_value(detail, expand=True)

        if expected is not None:
            record[u"expected"] = _diagnostic_value(expected, expand=True)

        if actual is not None:
            record[u"actual"] = _diagnostic_value(actual)

        try:
            key = json.dumps(record, sort_keys=True, default=repr)
        except Exception:
            key = repr(record)

        if key in self.__seen:
            return
        self.__seen.add(key)
        self.__eliminations.append(record)

    def record_branch(self, operator, ctx, left, right, result=None):
        """
        Record the availability of the two operands of a boolean or temporal
        operator.  This makes successful OR branches visible in reports
        without changing how one-sided OR bindings are generated.
        """
        if len(self.__branches) >= self.MAX_BRANCHES:
            self.truncated = True
            return

        record = {
            u"operator": operator,
            u"left": bool(left),
            u"right": bool(right),
        }
        if result is not None:
            record[u"result"] = bool(result)

        rule = _rule_location(ctx, self.__pattern)
        if rule is not None:
            record[u"rule"] = rule

        try:
            key = json.dumps(record, sort_keys=True, default=repr)
        except Exception:
            key = repr(record)

        if key in self.__branch_seen:
            return
        self.__branch_seen.add(key)
        self.__branches.append(record)

    def build_report(self, matched, matches, binding=None, observation_count=None):
        """
        Produce the public DiagnosticReport.

        :param matched: The match determination, identical to normal mode.
        :param matches: Matching SDOs (only matched observations are included,
            never the complete input bundle).
        :param binding: The first binding (observation indices), if any.
        :param observation_count: Number of input observations.
        :return: DiagnosticReport
        """
        stage_counts = {}
        for elimination in self.__eliminations:
            stage = elimination[u"stage"]
            stage_counts[stage] = stage_counts.get(stage, 0) + 1

        stages = [
            stage for stage in DIAGNOSTIC_STAGES if stage in stage_counts
        ]
        primary_stage = stages[0] if len(stages) == 1 else None

        matching_observations = []
        if binding:
            seen_idxs = set()
            for idx in binding:
                if idx is None or idx in seen_idxs:
                    continue
                seen_idxs.add(idx)
                identity = self.observation_identity(idx)
                if identity is not None:
                    matching_observations.append(identity)

        # "partial" means at least one side of a conjunction was satisfied
        # even though the whole rule did not match.  It must never be true
        # for a match, and must never turn a failed comparison into a
        # claimed success.
        partial = False
        if not matched:
            partial = any(
                branch.get(u"operator") in (u"AND", u"comparison AND") and
                (branch.get(u"left") is True or
                 branch.get(u"right") is True)
                for branch in self.__branches
            )

        report = DiagnosticReport({
            u"matched": bool(matched),
            u"pattern": self.__pattern,
            u"stix_version": self.__stix_version,
            u"observation_count": observation_count,
            u"binding": list(binding) if binding else [],
            u"matches": list(matches),
            u"matching_observations": matching_observations,
            u"partial": partial,
            u"primary_stage": None if matched else primary_stage,
            u"stages": [] if matched else stages,
            u"stage_counts": stage_counts,
            u"eliminations": self.__eliminations,
            u"branches": self.__branches,
            u"truncated": self.truncated,
        })

        return report


def _get_table_symmetric(table, val1, val2):
    """
    Gets an operator from a table according to the given types.  This
    gives the illusion of a symmetric matrix, e.g. if tbl[a][b] doesn't exist,
    tbl[b][a] is automatically tried.  That means you only have to fill out
    half of the given table.  (The "table" is a nested dict.)
    """
    tmp = table.get(val1)
    if tmp is None:
        # table[val1] is missing; try table[val2]
        tmp = table.get(val2)
        if tmp is None:
            return None
        return tmp.get(val1)
    else:
        # table[val1] is there.  But if table[val1][val2] is missing,
        # we still gotta try it the other way.
        tmp = tmp.get(val2)
        if tmp is not None:
            return tmp

        # gotta try table[val2][val1] now.
        tmp = table.get(val2)
        if tmp is None:
            return None
        return tmp.get(val1)


def _process_prop_suffix(prop_name, value):
    """
    Some JSON properties have suffixes indicating the type of the value.  This
    will translate the json value into a Python type with the proper semantics,
    so that subsequent property tests will work properly.

    :param prop_name: The JSON property name
    :param value: The JSON property value
    :return: If key is a specially suffixed property name, an instance of an
        appropriate python type.  Otherwise, value itself is returned.
    """

    if prop_name.endswith(u"_hex"):
        # binary type, expressed as hex
        value = binascii.a2b_hex(value)
    elif prop_name.endswith(u"_bin"):
        # binary type, expressed as base64
        value = base64.standard_b64decode(value)

    return value


def _step_into_objs(objs, step):
    """
    'objs' is a list of Cyber Observable object (sub)structures.  'step'
    describes a step into the structure, relative to the top level: if an int,
    we assume the top level is a list, and the int is a list index.  If a
    string, assume the top level is a dict, and the string is a key.  If a
    structure is such that the step can't be taken (e.g. the dict doesn't have
    the particular key), filter the value from the list.

    This will also automatically convert values of specially suffixed
    properties into the proper type.  See _process_prop_suffix().

    :return: A new list containing the "stepped-into" structures, minus
       any structures which couldn't be stepped into.
    """

    stepped_cyber_obs_objs = []
    if isinstance(step, int):
        for obj in objs:
            if isinstance(obj, list) and 0 <= step < len(obj):
                stepped_cyber_obs_objs.append(obj[step])
            # can't index non-lists
    elif isinstance(step, six.text_type):
        for obj in objs:
            if isinstance(obj, dict) and step in obj:
                processed_value = _process_prop_suffix(step, obj[step])
                stepped_cyber_obs_objs.append(processed_value)
            # can't do key lookup in non-dicts

    else:
        raise MatcherInternalError(
            u"Unsupported step type: {}".format(type(step)))

    return stepped_cyber_obs_objs


def _step_failure_reason(objs, step):
    """
    Explain why a step produced no values for the given Cyber Observable
    (sub)structures.  Used only for diagnostics.
    """
    if isinstance(step, int):
        if not objs:
            return u"empty_value_list"
        if any(not isinstance(obj, list) for obj in objs):
            return u"index_on_non_list"
        return u"index_out_of_range"

    if not objs:
        return u"empty_value_list"
    if any(not isinstance(obj, dict) for obj in objs):
        return u"key_on_non_object"
    return u"missing_key"


def _step_filter_observations(observations, step, diagnostics=None, ctx=None,
                              path=None):
    """
    A helper for the listener.  Given a particular structure in 'observations'
    (see exitObjectType(), exitFirstPathComponent()), representing a set of
    observations and partial path stepping state, do a pass over all the
    observations, attempting to take the given step on all of their Cyber
    Observable objects (or partial Cyber Observable object structures).

    :return: a filtered observation map: it includes those for which at
      least one contained Cyber Observable object was successfully stepped.  If none
      of an observation's Cyber Observable objects could be successfully stepped,
      the observation is dropped.
    """

    filtered_obs_map = {}
    for obs_idx, cyber_obs_obj_map in six.iteritems(observations):
        filtered_cyber_obs_obj_map = {}
        failures = [] if diagnostics is not None else None
        for cyber_obs_obj_id, cyber_obs_objs in six.iteritems(cyber_obs_obj_map):
            filtered_cyber_obs_obj_list = _step_into_objs(cyber_obs_objs, step)

            if len(filtered_cyber_obs_obj_list) > 0:
                filtered_cyber_obs_obj_map[cyber_obs_obj_id] = \
                    filtered_cyber_obs_obj_list
            elif diagnostics is not None:
                failures.append({
                    u"reason": _step_failure_reason(cyber_obs_objs, step),
                    u"object_id": cyber_obs_obj_id,
                })

        if len(filtered_cyber_obs_obj_map) > 0:
            filtered_obs_map[obs_idx] = filtered_cyber_obs_obj_map
        elif failures:
            for failure in failures:
                diagnostics.record(
                    DIAG_PATH_MISSING, failure[u"reason"],
                    ctx=ctx, obs_idx=obs_idx,
                    object_id=failure[u"object_id"], path=path,
                    detail={u"step": step},
                )

    return filtered_obs_map


def _step_filter_observations_index_star(observations, diagnostics=None,
                                          ctx=None, path=None):
    """
    Does an index "star" step, i.e. "[*]".  This will pull out all elements of
    the list as if they were parts of separate Cyber Observable objects, which
    has the desired effect for matching: if any list elements match the
    remainder of the pattern, they are selected for the subsequent property
    test.  As usual, non-lists at this point are dropped, and observations for
    whom all Cyber Observable object (sub)structure was dropped, are also
    dropped.

    See also _step_filter_observations().
    """

    filtered_obs_map = {}
    collecting = diagnostics is not None
    for obs_idx, cyber_obs_obj_map in six.iteritems(observations):
        filtered_cyber_obs_obj_map = {}
        failures = [] if collecting else None
        for cyber_obs_obj_id, cyber_obs_objs in six.iteritems(cyber_obs_obj_map):
            stepped_cyber_obs_objs = []
            for cyber_obs_obj in cyber_obs_objs:
                if not isinstance(cyber_obs_obj, list):
                    continue

                stepped_cyber_obs_objs.extend(cyber_obs_obj)

            if len(stepped_cyber_obs_objs) > 0:
                filtered_cyber_obs_obj_map[cyber_obs_obj_id] = stepped_cyber_obs_objs
            elif collecting:
                if any(not isinstance(obj, list) for obj in cyber_obs_objs):
                    reason = u"index_on_non_list"
                else:
                    reason = u"empty_list"
                failures.append({
                    u"reason": reason,
                    u"object_id": cyber_obs_obj_id,
                })

        if filtered_cyber_obs_obj_map:
            filtered_obs_map[obs_idx] = filtered_cyber_obs_obj_map
        elif failures:
            for failure in failures:
                diagnostics.record(
                    DIAG_PATH_MISSING, failure[u"reason"], ctx=ctx,
                    obs_idx=obs_idx, object_id=failure[u"object_id"],
                    path=path, detail={u"step": u"[*]"},
                )

    return filtered_obs_map


def _get_first_terminal_descendant(ctx):
    """
    Gets the first terminal descendant of the given parse tree node.
    I use this with nodes for literals to get the actual literal terminal
    node, from which I can get the literal value itself.
    """
    if isinstance(ctx, antlr4.TerminalNode):
        return ctx

    # else, it's a RuleContext
    term = None
    for child in ctx.getChildren():
        term = _get_first_terminal_descendant(child)
        if term is not None:
            break

    return term


def _literal_terminal_to_python_val(literal_terminal):
    """
    Use the table of "coercer" functions to convert a terminal node from the
    parse tree to a Python value.
    """
    token_type = literal_terminal.getSymbol().type
    token_text = literal_terminal.getText()

    if token_type in _TOKEN_TYPE_COERCERS:
        coercer = _TOKEN_TYPE_COERCERS[token_type]
        try:
            python_value = coercer(token_text)
        except Exception as e:
            six.raise_from(MatcherException(u"Invalid {}: {}".format(
                STIXPatternParser.symbolicNames[token_type], token_text
            )), e)
    else:
        raise MatcherInternalError(u"Unsupported literal type: {}".format(
            STIXPatternParser.symbolicNames[token_type]))

    return python_value


def _like_to_regex(like):
    """Convert a "like" pattern to a regex."""

    with io.StringIO() as sbuf:
        # "like" always must match the whole string, so surround with anchors
        sbuf.write(u"^")
        for c in like:
            if c == u"%":
                sbuf.write(u".*")
            elif c == u"_":
                sbuf.write(u".")
            else:
                if not c.isalnum():
                    sbuf.write(u'\\')
                sbuf.write(c)
        sbuf.write(u"$")
        s = sbuf.getvalue()

    # print(like, "=>", s)
    return s


def _str_to_datetime(timestamp_str, ignore_case=False):
    """
    Convert a timestamp string from a pattern to a datetime.datetime object.
    If conversion fails, raises a ValueError.
    """

    # strptime() appears to work case-insensitively.  I think we require
    # case-sensitivity for timestamp literals inside patterns and JSON
    # (for the "T" and "Z" chars).  So check case first.
    if not ignore_case and any(c.islower() for c in timestamp_str):
        raise ValueError(u"Invalid timestamp format "
                         u"(require upper case): {}".format(timestamp_str))

    # Can't create a pattern with an optional part... so use two patterns
    if u"." in timestamp_str:
        fmt = u"%Y-%m-%dT%H:%M:%S.%fZ"
        # maximum supported precision by Datetime is microsecond
        timestamp_parts = timestamp_str.split(u".")
        if len(timestamp_parts[1]) > 7 and timestamp_parts[1].endswith(u"Z"):
            timestamp_parts[1] = timestamp_parts[1][:6] + timestamp_parts[1][-1:]
            timestamp_str = u".".join(timestamp_parts)
    else:
        fmt = u"%Y-%m-%dT%H:%M:%SZ"

    dt = datetime.datetime.strptime(timestamp_str, fmt)
    dt = dt.replace(tzinfo=dateutil.tz.tzutc())

    return dt


def _ip_addr_to_int(ip_str):
    """
    Converts a dotted-quad IP address string to an int.  The int is equal
    to binary representation of the four bytes in the address concatenated
    together, in the order they appear in the address.  E.g.

        1.2.3.4

    converts to

        00000001 00000010 00000011 00000100
      = 0x01020304
      = 16909060 (decimal)
    """
    try:
        ip_bytes = socket.inet_aton(ip_str)
    except socket.error:
        raise MatcherException(u"Invalid IPv4 address: {}".format(ip_str))

    int_val, = struct.unpack(">I", ip_bytes)  # unsigned big-endian

    return int_val


def _cidr_subnet_to_ints(subnet_cidr):
    """
    Converts a CIDR style subnet string to a 2-tuple of ints.  The
    first element is the IP address portion as an int, and the second
    is the prefix size.
    """

    slash_idx = subnet_cidr.find(u"/")
    if slash_idx == -1:
        raise MatcherException(u"Invalid CIDR subnet: {}".format(subnet_cidr))

    ip_str = subnet_cidr[:slash_idx]
    prefix_str = subnet_cidr[slash_idx+1:]

    ip_int = _ip_addr_to_int(ip_str)
    if not prefix_str.isdigit():
        raise MatcherException(u"Invalid CIDR subnet: {}".format(subnet_cidr))
    prefix_size = int(prefix_str)

    if prefix_size < 1 or prefix_size > 32:
        raise MatcherException(u"Invalid CIDR subnet: {}".format(subnet_cidr))

    return ip_int, prefix_size


def _ip_or_cidr_in_subnet(ip_or_cidr_str, subnet_cidr):
    """
    Determine if the IP or CIDR subnet given in the first arg, is contained
    within the CIDR subnet given in the second arg.

    :param ip_or_cidr_str: An IP address as a string in dotted-quad notation,
        or a subnet as a string in CIDR notation
    :param subnet_cidr: A subnet as a string in CIDR notation
    """

    # First arg is the containee, second is the container.  Does the
    # container contain the containee?

    # Handle either plain IP or CIDR notation for the containee.
    slash_idx = ip_or_cidr_str.find(u"/")
    if slash_idx == -1:
        containee_ip_int = _ip_addr_to_int(ip_or_cidr_str)
        containee_prefix_size = 32
    else:
        containee_ip_int, containee_prefix_size = _cidr_subnet_to_ints(
            ip_or_cidr_str)

    container_ip_int, container_prefix_size = _cidr_subnet_to_ints(subnet_cidr)

    if container_prefix_size > containee_prefix_size:
        return False

    # Use container mask for both IPs
    container_mask = ((1 << container_prefix_size) - 1) << \
                     (32 - container_prefix_size)
    masked_containee_ip = containee_ip_int & container_mask
    masked_container_ip = container_ip_int & container_mask

    return masked_containee_ip == masked_container_ip


def _disjoint(first_seq, *rest_seq):
    """
    Checks whether the values in first sequence are disjoint from the
    values in the sequences in rest_seq.

    All 'None' values in the sequences are ignored.

    :return: True if first_seq is disjoint from the rest, False otherwise.
    """

    if len(rest_seq) == 0:
        return True

    # is there a faster way to do this?
    fs = set(x for x in first_seq if x is not None)
    return all(
        fs.isdisjoint(x for x in seq if x is not None)
        for seq in rest_seq
    )


# Constants used as return values of the _overlap() function.
_OVERLAP_NONE = 0
_OVERLAP = 1
_OVERLAP_TOUCH_INNER = 2
_OVERLAP_TOUCH_OUTER = 3
_OVERLAP_TOUCH_POINT = 4


def _overlap(min1, max1, min2, max2):
    """
    Test for overlap between interval [min1, max1] and [min2, max2].  For the
    purposes of this function, both intervals are treated as closed.  The
    result is one of four mutually exclusive values:

    - _OVERLAP_NONE: no overlap
    - _OVERLAP: the intervals overlap, such that they are not just touching
        at endpoints
    - _OVERLAP_TOUCH_INNER: the intervals overlap at exactly one point, and
        that point is max1==min2 (the "inner" two parameters of this function),
        and at least one is of non-zero length
    - _OVERLAP_TOUCH_OUTER: the intervals overlap at exactly one point, and
        that point is min1==max2 (the "outer" two parameters of this function),
        and at least one is of non-zero length
    - _OVERLAP_TOUCH_POINT: the intervals overlap at exactly one point, and
        both are zero-length (i.e. all parameters are equal).  This is a kind
        of corner case, to disambiguate it from inner/outer touches.

    The "touch" results allow callers to distinguish between ordinary overlaps
    and "touching" overlaps, and if it was touching, how the intervals touched
    each other.  This essentially allows callers to behave as if one or both
    if the intervals were not closed.  It pushes a little bit of the burden
    onto callers, when they don't want to treat both intervals as closed.  But
    caller code is still pretty simple; I think it simplifies the code overall.

    So overall, this function doesn't behave symmetrically.  You must carefully
    consider the order of intervals passed to the function, and what result(s)
    you're looking for.

    min1 must be <= max1, and analogously for min2 and max2.  There are
    assertions to emphasize this assumption.  The parameters can be of any type
    which is comparable for <= and equality.

    :param min1: the lower bound of the first interval
    :param max1: the upper bound of the first interval
    :param min2: the lower bound of the second interval
    :param max2: the upper bound of the second interval
    :return: The overlap result
    """
    assert min1 <= max1
    assert min2 <= max2

    if min1 == max1 == min2 == max2:
        return _OVERLAP_TOUCH_POINT
    elif max1 == min2:
        return _OVERLAP_TOUCH_INNER
    elif max2 == min1:
        return _OVERLAP_TOUCH_OUTER
    elif min2 <= max1 and min1 <= max2:
        return _OVERLAP

    return _OVERLAP_NONE


def _timestamp_intervals_within(timestamp_intervals, duration):
    """
    Checks whether it's possible to choose a timestamp from each of the given
    intervals such that all are within the given duration.  Viewed another way,
    this function checks whether an interval of the given duration exists,
    which overlaps all intervals in timestamp_intervals (including just
    "touching" on either end).

    :param timestamp_intervals: A sequence of 2-tuples of timestamps
        (datetime.datetime), each being a first_observed and last_observed
        timestamp for an observation.
    :param duration: A duration (dateutil.relativedelta.relativedelta).
    :return: True if a set of timestamps exists which satisfies the duration
        constraint; False otherwise.
    """

    # We need to find an interval of length 'duration' which overlaps all
    # timestamp_intervals (if one exists).  It is the premise of this
    # implementation that if any such intervals exist, one of them must be an
    # interval which touches at the earliest last_observed time and extends to
    # the "right" (in the direction of increasing time).  Therefore if that
    # interval is not a solution, then there are no solutions, and the given
    # intervals don't satisfy the constraint.
    #
    # The intuition is that the interval with the earliest last_observed time
    # is the furthest left as far as overlaps are concerned.  We construct a
    # test interval of the required duration which minimally overlaps this
    # furthest left interval, and maximizes its reach to the right to overlap
    # as many others as possible.  If we were to move the test interval right,
    # we lose overlap with our furthest-left interval, so none of those test
    # intervals can be a solution.  If we were able to move it left to reach a
    # previously unoverlapped interval and obtain a solution, then we didn't
    # find the earliest last_observed time, which is a contradiction w.r.t. the
    # aforementioned construction of the test interval, so that's not possible
    # either.  So it is impossible to improve the overlap by moving the test
    # interval either left or right; overlaps are maximized at our chosen test
    # interval location.  Therefore our test interval must be a solution, if
    # one exists.

    earliest_last_observed = min(interval[1] for interval in timestamp_intervals)
    test_interval = (earliest_last_observed, earliest_last_observed + duration)

    result = True
    for interval in timestamp_intervals:
        if not _overlap(interval[0], interval[1], *test_interval):
            result = False
            break

    return result


def _dereference_cyber_obs_objs(cyber_obs_objs, cyber_obs_obj_references, ref_prop_name, stix_version=DEFAULT_VERSION):
    """
    Dereferences a sequence of Cyber Observable object references.  Returns a list of
    the referenced objects.  If a reference does not resolve, it is not
    treated as an error, it is ignored.

    :param cyber_obs_objs: The context for reference resolution.  This is a mapping
        from Cyber Observable object ID to Cyber Observable object, i.e. the "objects" property of
        an observed-data SDO.
    :param cyber_obs_obj_references: An iterable of Cyber Observable object references.  These
        must all be strings, otherwise an exception is raised.
    :param ref_prop_name: For better error messages, the reference property
        being processed.
    :return: A list of the referenced Cyber Observable objects.  This could be fewer than
        the number of references, if some references didn't resolve.
    """
    dereferenced_cyber_obs_objs = []
    for referenced_obj_id in cyber_obs_obj_references:
        if not isinstance(referenced_obj_id, six.text_type):
            raise MatcherException(
                u"{} value of reference property '{}' was not "
                u"a string!  Got {}".format(
                    # Say "A value" if the property is a reference list,
                    # otherwise "The value".
                    u"A" if ref_prop_name.endswith(u"_refs") else u"The",
                    ref_prop_name, referenced_obj_id
                ))
        if stix_version == VARSION_2_1:
            ref_obj = [d for d in cyber_obs_objs if d['id'] == referenced_obj_id]
            if ref_obj:
                dereferenced_cyber_obs_objs.extend(ref_obj)
        else:
            if referenced_obj_id in cyber_obs_objs:
                dereferenced_cyber_obs_objs.append(cyber_obs_objs[referenced_obj_id])

    return dereferenced_cyber_obs_objs


def _obs_map_prop_test(obs_map, predicate, diagnostics=None, ctx=None,
                       path=None, classify=None):
    """
    Property tests always perform the same structural transformation of
    observation data on the stack.  There are several callbacks within the
    matcher listener to do various types of tests, and I found I was having to
    update the same basic code in many places.  So I have factored it out to
    this function.  As the pattern design evolves and my program changes, the
    data structures and required transformations evolve too.  This gives me a
    single place to update one of these transformations, instead of having to
    do it repeatedly in N different places.  It also gives a nice centralized
    place to document it.

    Required structure for obs_map is the result of object path selection;
    see MatchListener.exitObjectPath() for details.

    The structure of the result of a property test is:

    {
      obs_idx: {cyber_obs_obj_id1, cyber_obs_obj_id2, ...},
      obs_idx: {cyber_obs_obj_id1, cyber_obs_obj_id2, ...},
      etc...
    }

    I.e. for each observation, a set of Cyber Observable object IDs is associated, which
    are the "root" objects which caused the match.  The Cyber Observable object ID info
    is necessary to eliminate observation expression matches not rooted at the
    same Cyber Observable object.

    :param obs_map: Observation data, as selected by an object path.
    :param predicate: This encompasses the actual test to perform.  It must
        be a function of one parameter, which returns True or False.
    :param diagnostics: Optional MatchDiagnostics collector.  When given,
        predicate failures are recorded.  This does not affect results.
    :param ctx: Parse-tree node used for diagnostic rule locations.
    :param path: Object path text, for diagnostics.
    :param classify: Optional callable taking a value and returning either
        None (ordinary comparison failure) or a dict with a stage and details
        describing a more specific failure (e.g. type mismatch).
    :return: The transformed and filtered data, according to predicate.
    """
    passed_obs = {}
    collecting = diagnostics is not None
    for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
        passed_cyber_obs_obj_roots = set()
        failures = [] if collecting else None
        for cyber_obs_obj_id, values in six.iteritems(cyber_obs_obj_map):
            for value in values:
                if predicate(value):
                    passed_cyber_obs_obj_roots.add(cyber_obs_obj_id)
                    break
                elif collecting:
                    classification = classify(value) if classify else None
                    if classification:
                        stage = classification.get(u"stage",
                                                   DIAG_COMPARISON_FAILED)
                        reason = classification.get(
                            u"reason", DIAG_COMPARISON_FAILED)
                        detail = classification.get(u"detail")
                        expected = classification.get(u"expected")
                    else:
                        stage = DIAG_COMPARISON_FAILED
                        reason = u"value_did_not_satisfy_test"
                        detail = None
                        expected = None
                    failures.append({
                        u"stage": stage,
                        u"reason": reason,
                        u"object_id": cyber_obs_obj_id,
                        u"value": value,
                        u"detail": detail,
                        u"expected": expected,
                    })

        if passed_cyber_obs_obj_roots:
            passed_obs[obs_idx] = passed_cyber_obs_obj_roots
        elif failures:
            for failure in failures:
                diagnostics.record(
                    failure[u"stage"], failure[u"reason"], ctx=ctx,
                    obs_idx=obs_idx, object_id=failure[u"object_id"],
                    path=path, expected=failure[u"expected"],
                    actual=failure[u"value"], detail=failure[u"detail"],
                )

    return passed_obs


class NotEnoughValues(ValueError):
    pass


def _filtered_combinations(value_generator, combo_size):
    """
    Finds disjoint combinations of values of the given size from the given sequence.

    This function builds up the combinations incrementally.

    :param values: The sequence of values
    :param combo_size: The desired combination size (must be >= 1)
    :return: The combinations, as a generator of tuples.
    """

    if combo_size < 1:
        raise ValueError(u"combo_size must be >= 1")
    elif combo_size == 1:
        # Each value is its own combo
        for value in value_generator:
            yield (value,)
        return

    # combo_size > 1
    # generate up to combo_size - 1 values
    generated_values = [x for _, x in zip(range(combo_size - 1), value_generator)]

    for next_value in value_generator:
        filtered_values = [
            candidate
            for candidate in generated_values
            if _disjoint(candidate, next_value)
        ]
        sub_combos = _filtered_combinations_from_list(
            filtered_values,
            combo_size - 1,
        )
        try:
            for sub_combo in sub_combos:
                yield sub_combo + (next_value,)
        except NotEnoughValues:
            pass

        generated_values.append(next_value)


def _tuple_size(value):
    """
    return number of non-None elements
    """
    return sum(idx is not None for idx in value)


def _ceildiv(a, b):
    return -(-a // b)


def _bound_largest_combination(value_list):
    """
    Returns an upper bound on the largest disjoint combination

    Given a valid combination of disjoint tuples, replacing a tuple
    with a sub-tuple (smaller and included) leads to a valid combination
    of the same size. Thus we can bound size of largest possible combination
    by considering small tuples first.

    :param value_list: List of tuples of obs (internal) ids
    """
    if value_list == []:
        return 0

    # First get max tuple size
    max_size = max(_tuple_size(value) for value in value_list)

    # init array of sets of obs_idx
    obs_idx = [set() for _ in range(max_size + 1)]
    for value in value_list:
        obs_idx[_tuple_size(value)] |= {idx for idx in value if idx is not None}

    # build largest combination
    # considering that all possible tuples are availables
    consumed_idx = set()
    combination_size = 0
    for i in range(1, max_size):
        available_idx = obs_idx[i] - consumed_idx
        # each tuple consumes i idx
        # (rounded up since we remove all idx from bigger tuples)
        combination_size += _ceildiv(len(available_idx), i)
        # update mark all idx as consumed
        consumed_idx |= available_idx
    # last size does not need rounding up
    available_idx = obs_idx[max_size] - consumed_idx
    combination_size += len(available_idx) // max_size
    return combination_size


def _filtered_combinations_from_list(value_list, combo_size):
    """
    _filtered_combinations that works on lists

    :param value_list: The sequence of values
    :param combo_size: The desired combination size (must be >= 1)
    :return: The combinations, as a generator of tuples.
    """

    if combo_size < 1:
        raise ValueError(u"combo_size must be >= 1")
    elif combo_size == 1:
        # Each value is its own combo
        for value in value_list:
            yield (value,)
        return

    bound = _bound_largest_combination(value_list)
    if bound < combo_size:
        # there is no way we can build a combination large enough
        # `combo_size - bound` tuples are missing
        raise NotEnoughValues(combo_size - bound)

    for i in range(len(value_list) + 1 - combo_size):
        filtered_values = [
            candidate
            for candidate in value_list[i + 1:]
            if _disjoint(value_list[i], candidate)
        ]

        sub_combos = _filtered_combinations_from_list(
            filtered_values,
            combo_size - 1,
        )

        yielded_combos = False
        try:
            for sub_combo in sub_combos:
                yield (value_list[i],) + sub_combo
                yielded_combos = True
        except NotEnoughValues as e:
            if yielded_combos:
                continue
            # retrieve number of missing values to build a combo of size `combo_size - 1`
            # from `filtered_values` (value_list[i + 1:] disjoint value_list[i])
            missing_values = e.args[0]
            # Bound number of additional values we can expect if we do not remove
            # those that intersect with value_list[i]
            # - it is smaller than the number of values we removed
            # - and smaller than `_tuple_size(value_list[i])` because they all intersect
            #   value_list[i] and can not intersect each other to be in the same combo
            max_add_values = min(
                len(value_list[i + 1:]) - len(filtered_values),
                _tuple_size(value_list[i]),
            )
            # +1 because we now want combo of size `combo_size` (not `combo_size - 1`)
            expected_missing_values = missing_values + 1 - max_add_values
            if expected_missing_values > 0:
                # no need to inspect `value_list[i + 1:]` and others
                # there is no way we can build a combo large enough
                if i == 0:
                    raise NotEnoughValues(expected_missing_values)
                else:
                    return


def _compute_expected_binding_size(ctx):
    """
    Computes the expected size of bindings to the given subset of the pattern.
    This is used purely to improve understandability of the generated bindings.
    It essentially allows me to add "filler" to generated bindings so they have
    the expected size.
    :param ctx: A node of the pattern parse tree representing a subset of the
        pattern.
    :return: A binding size (a number)
    """
    if isinstance(ctx, STIXPatternParser.ComparisonExpressionContext):
        return 1
    elif isinstance(ctx, STIXPatternParser.ObservationExpressionRepeatedContext):
        # Guess I ought to correctly handle the repeat-qualified observation
        # expressions too huh?
        child_count = _compute_expected_binding_size(
            ctx.observationExpression())
        rep_count = _literal_terminal_to_python_val(
            ctx.repeatedQualifier().IntPosLiteral())

        if rep_count < 1:
            raise MatcherException(u"Invalid repetition count: {}".format(
                rep_count))

        return child_count * rep_count

    else:
        # Not all node types have getChildren(), but afaict they all have
        # getChildCount() and getChild().
        return sum(_compute_expected_binding_size(ctx.getChild(i))
                   for i in range(ctx.getChildCount()))


def _unicode_escape(src):
    """
    Escapes unicode characters in src, using the \\uXXXX syntax.  The
    unicode_escape codec escapes newlines too, so it's unusable for me.
    I have to write my own.  This will affect all codepoints > 127.
    """
    with io.StringIO() as dst:
        for c in src:
            ordc = ord(c)
            dst.write(
                c if ordc < 128
                else u"\\u{:04x}".format(ordc)
            )
        return dst.getvalue()


class MatchListener(STIXPatternListener):
    """
    A parser listener which performs pattern matching.  It works like an
    RPN calculator, pushing and popping intermediate results to/from an
    internal stack as the parse tree is traversed.  I tried to document
    for each callback method, what it consumes from the stack, and kind of
    values it produces.

    Matching a pattern is equivalent to finding a set of "bindings": an
    observation "bound" to each observation expression such that the
    constraints embodied in the pattern are satisfied.  The final value
    on top of the stack after the pattern matching process is complete contains
    these bindings.  If any bindings were found, the pattern matched, otherwise
    it didn't match.  (Assuming there were no errors during the matching
    process, of course.)

    There are different ways of doing this; one obvious way is a depth-first
    search, where you try different bindings, and backtrack to earlier
    decision points as you hit dead-ends.  I had originally been aiming to
    perform a complete pattern matching operation in a single post-order
    traversal of the parse tree, which means no backtracking.  So this matcher
    is implemented in a different way.  It essentially tracks all possible
    bindings at once, pruning away those which don't work as it goes.  This
    will likely use more memory, and the bookkeeping is a bit more complex,
    but it only needs one pass through the tree.  And at the end, you get
    many bindings, rather than just the first one found, as might
    be the case with a backtracking algorithm.

    Actually, through the use of generators to represent sets of bindings an
    implicit form of backtracking limits the memory usage.

    I made the conscious decision to skip some bindings in one particular case,
    to improve scalability (see exitObservationExpressionOr()) without
    affecting correctness.
    """

    def __init__(self, observed_data_sdos, verbose=False, stix_version=DEFAULT_VERSION,
                 diagnostics=None):
        """
        Initialize this match listener.

        :param observed_data_sdos: A list of STIX observed-data SDOs.
        :param verbose: If True, dump detailed information about triggered
            callbacks and stack activity to stdout.  This can provide useful
            information about what the matcher is doing.
        :param diagnostics: Optional MatchDiagnostics collector.  When given,
            it records why candidates were eliminated.  It never affects
            matching results.
        """
        self.__observations = []
        self.__time_intervals = []  # 2-tuples of first,last timestamps
        self.__number_observed = []

        if stix_version == VARSION_2_1:
            observed_data_sdos = self.__split_multi_observed_data(observed_data_sdos)

        for sdo in observed_data_sdos:
            number_observed = 0
            if stix_version == VARSION_2_1:
                for obj in sdo["objects"]:
                    if obj['type'] == "observed-data":
                        if all(key in obj for key in ('number_observed', 'first_observed', 'last_observed')):
                            number_observed = obj["number_observed"]
                            first_observed = obj["first_observed"]
                            last_observed = obj["last_observed"]
                            break
                        else:
                            raise MatcherException(
                                "STIX v2.1 observed-data object must have all the following keys: "
                                "number_observed, first_observed, last_observed.")
            else:
                if all(key in sdo for key in ('number_observed', 'first_observed', 'last_observed')):
                    number_observed = sdo["number_observed"]
                    first_observed = sdo["first_observed"]
                    last_observed = sdo["last_observed"]
                else:
                    raise MatcherException(
                        "STIX v2.0 SDO must have all the following keys: "
                        "number_observed, first_observed, last_observed.")

            if number_observed < 1:
                raise MatcherException(
                    "SDO with invalid number_observed "
                    "(must be >= 1): {}".format(number_observed))

            self.__observations.append(sdo)
            self.__time_intervals.append((_str_to_datetime(first_observed),
                                          _str_to_datetime(last_observed)))
            self.__number_observed.append(number_observed)

        self.__verbose = verbose
        self.__stix_version = stix_version
        # Holds intermediate results
        self.__compute_stack = []
        self.__diagnostics = diagnostics
        if self.__diagnostics is not None:
            self.__diagnostics.set_observations(self.__observations)

    def __split_multi_observed_data(self, observed_data_bundles):
        new_bundles = []
        merged_bundle = {}
        for bundle in observed_data_bundles:
            merged_bundle = always_merger.merge(merged_bundle, bundle)

        observed_data_bundles = [merged_bundle]
        observed_data_list = []
        sco_data_map = {}
        if 'objects' not in merged_bundle:
            raise MatcherException(
                "STIX v2.1 bundle object must have 'objects' key")

        for sco in merged_bundle['objects']:
            if sco['type'] == "observed-data":
                observed_data_list.append(sco)
            else:
                sco_data_map[sco['id']] = sco

        new_observed_data_scos = []
        for observed_data in observed_data_list:
            new_observed_data_scos = [observed_data]
            if 'object_refs' not in observed_data:
                raise MatcherException(
                    "STIX v2.1 observed-data object must have 'object_refs' key")
            observed_scos = self.__extract_referenced_scos_for_observed_data(observed_data['object_refs'], sco_data_map)
            new_observed_data_scos.extend(observed_scos)
            # make a shallow copy
            new_bundle = merged_bundle.copy()
            new_bundle['objects'] = new_observed_data_scos
            new_bundles.append(new_bundle)

        return new_bundles

    def __extract_referenced_scos_for_observed_data(self, object_refs, sco_data_map):
        scos = []

        for ref in object_refs:
            if ref in sco_data_map:
                scos.append(sco_data_map[ref])

        return scos

    def __path_text(self, ctx):
        """Get the object path text for a property test node, for diagnostics."""
        path = ctx.objectPath()
        return path.getText() if path is not None else None

    def __push(self, val, label=None):
        """Utility for pushing a value onto the compute stack.
        In verbose mode, show what's being pushed.  'label' lets you prefix
        the message with something... e.g. I imagine using a parser rule name.
        """
        self.__compute_stack.append(val)

        if self.__verbose:
            if label:
                print(u"{}: ".format(_unicode_escape(label)), end=u"")

            # Python2's pformat() returns str (the binary type), therefore
            # it must escape unicode chars.  Python3's pformat() returns str
            # (the text type), and does not escape unicode chars.  The
            # unicode_escape codec escapes newlines, which ruins the pretty
            # formatting, so it's not usable at all.
            if six.PY2:
                str_val = pprint.pformat(val).decode("ascii")
            else:
                str_val = _unicode_escape(pprint.pformat(val))
            print(u"push", str_val)

    def __pop(self, label=None):
        """Utility for popping a value off the compute stack.
        In verbose mode, show what's being popped.  'label' lets you prefix
        the message with something... e.g. I imagine using a parser rule name.
        """
        val = self.__compute_stack.pop()

        if self.__verbose:
            if label:
                print(u"{}: ".format(_unicode_escape(label)), end=u"")

            # Python2's pformat() returns str (the binary type), therefore
            # it must escape unicode chars.  Python3's pformat() returns str
            # (the text type), and does not escape unicode chars.  The
            # unicode_escape codec escapes newlines, which ruins the pretty
            # formatting, so it's not usable at all.
            if six.PY2:
                str_val = pprint.pformat(val).decode("ascii")
            else:
                str_val = _unicode_escape(pprint.pformat(val))
            print(u"pop", str_val)

        return val

    def matched(self):
        """
        After a successful parse tree traveral, this will tell you whether the
        pattern matched its input.  You should only call this if the parse
        succeeded and traversal completed without errors.  All of the found
        bindings are returned.

        The returned bindings will be a generator of tuples of ints.  These ints
        correspond to SDOs.  `None` can also occur in any tuple.
        This corresponds to a portion of the pattern to which no observation
        was bound (because a binding was not necessary).  To get the actual
        SDOs from a binding, see get_sdos_from_binding().  If the pattern
        didn't match, an empty generator is returned.

        :return: The found bindings, if any.
        """
        # At the end of the parse, the top stack element will be a generator of
        # all the found bindings (as tuples).  If there is at least one, the
        # pattern matched.  If the tree traversal failed, the top stack element
        # could be anything... so don't call this function in that situation!
        if self.__compute_stack:
            for binding in self.__compute_stack[0]:
                # convert back from complex instance_id to obs_index
                yield tuple(map(self.get_obs_index_filtered, binding))
        return

    @property
    def observations(self):
        """
        The observations this listener was initialized with.

        For STIX 2.1 this is the list of split observed-data SDOs, matching the
        indices used in bindings.
        """
        return self.__observations

    def get_sdos_from_binding(self, binding):
        """
        Resolves a binding to a list of SDOs.

        :param binding: A binding, as returned from matched(); it should be an
            iterable of ints.
        :return: A list of SDOs.
        """
        sdos = []
        for obs_idx in sorted(val for val in binding if val is not None):
            if not sdos or sdos[-1] is not self.__observations[obs_idx]:
                sdos.append(self.__observations[obs_idx])

        return sdos

    @staticmethod
    def get_obs_index(instance_id):
        """
        Calculates the observable index from instance index.
        :param instance_id: an instance id representation, created by
        create_instance_index(obs_idx, inst_idx)
        :return: int: the original observation index
        """
        if instance_id is None:
            return None
        return instance_id[0]

    @staticmethod
    def get_obs_index_filtered(instance_id):
        """
        Same as `get_obs_index(instance_index)`, but returns `None`
        if instance_index is not 0. Useful with a filter predicate
        to make sure every observable is included only once.
        :param instance_id: an instance id representation, created by
        create_instance_index(obs_idx, inst_idx)
        :return: int: the original observation index for the first
        instance of each observable and `None` for the rest.
        """
        if instance_id is None:
            return None
        return instance_id[0] if instance_id[1] == 0 else None

    @staticmethod
    def create_instance_id(obs_idx: int, inst_idx: int):
        """
        Creates instance index from an observable index and instance id.
        This complex index is used after the initial filtering of the
        observables to represent the "real" appearance if the objects
        for REPEATS, FOLLOWEDBY and other high level operators.
        :param obs_idx: index of the observed_data object
        :param inst_idx: id of the instance, based on the `number_occured`
        field.
        :returns a Tuple, representing the complex instance id
        """
        return obs_idx, inst_idx

    def exitObservationExpressions(self, ctx):
        """
        Implements the FOLLOWEDBY operator.  If there are two child nodes:

        Consumes two generators of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined generator of binding tuples.  This essentially produces a
          filtered cartesian cross-product of the LHS and RHS tuples.  Results
          include those with no duplicate observation IDs, and such that it is
          possible to choose legal timestamps (i.e. within the interval defined
          by the observation's first_observed and last_observed timestamps) for
          all observations such that the timestamps on the RHS binding are >=
          than the timestamps on the LHS binding.
        """
        num_operands = len(ctx.observationExpressions())

        if num_operands not in (0, 2):
            # Just in case...
            msg = u"Unexpected number of observationExpressions children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 0:
            # If only the one observationExpressionOr child, we don't need to do
            # anything to the top of the stack.
            return

        # num_operands == 2
        debug_label = u"exitObservationExpressions"

        rhs_bindings = self.__pop(debug_label)
        lhs_bindings = self.__pop(debug_label)

        # we need to return the filtered cartesian product of rhs_bindings
        # and lhs_bindings but they are generators:
        # we need to store the generated elements
        def joined_bindings():
            _rhs_cache = []
            _lhs_cache = []
            _next_rhs_binding = next(rhs_bindings, None)
            _next_lhs_binding = next(lhs_bindings, None)
            if _next_rhs_binding is None or _next_lhs_binding is None:
                # cache and one generator are empty.  The branch record shows
                # which side was empty; the reason that side had no
                # candidates was already recorded deeper in the tree, so it
                # would be misleading to blame the temporal operator here.
                if self.__diagnostics is not None:
                    self.__diagnostics.record_branch(
                        u"FOLLOWEDBY", ctx,
                        _next_lhs_binding is not None,
                        _next_rhs_binding is not None,
                        result=False,
                    )
                return
            while _next_rhs_binding is not None or _next_lhs_binding is not None:
                # while there are new bindings to explore
                if _next_rhs_binding is not None:
                    # if there is a new rhs binding yield valid combinations
                    for combination in self.__followed_by_right_join(
                            _lhs_cache, _next_rhs_binding, ctx):
                        yield combination
                    # update cache
                    _rhs_cache.append(_next_rhs_binding)
                    _next_rhs_binding = next(rhs_bindings, None)

                if _next_lhs_binding is not None:
                    # if there is a new rhs binding yield valid combinations
                    for combination in self.__followed_by_left_join(
                            _next_lhs_binding, _rhs_cache, ctx):
                        yield combination
                    # update cache
                    _lhs_cache.append(_next_lhs_binding)
                    _next_lhs_binding = next(lhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

    def __followed_by_left_join(self, lhs_binding, rhs_bindings, ctx=None):
        # Yield all valid FOLLOWEDBY joins between a single lhs_binding
        # and a list of rhs_bindings

        # To ensure a satisfying selection of timestamps is possible,
        # we make the most optimistic choices: choose the earliest
        # possible timestamps for LHS bindings and latest possible for
        # RHS bindings.  Then as a shortcut, only ensure proper
        # ordering of the latest LHS timestamp and earliest RHS
        # timestamp.
        latest_lhs_first_timestamp = self.__latest_first_timestamp(lhs_binding)

        for rhs_binding in rhs_bindings:

            if _disjoint(lhs_binding, rhs_binding):
                earliest_rhs_last_timestamp = self.__earliest_last_timestamp(rhs_binding)

                if latest_lhs_first_timestamp <= earliest_rhs_last_timestamp:
                    yield (lhs_binding + rhs_binding)
                elif self.__diagnostics is not None:
                    self.__record_followed_by_failure(
                        ctx, lhs_binding, rhs_binding,
                        latest_lhs_first_timestamp,
                        earliest_rhs_last_timestamp,
                    )
            elif self.__diagnostics is not None:
                self.__record_combination_failure(
                    ctx, u"followedby_observations_not_distinct",
                    lhs_binding, rhs_binding,
                )

    def __followed_by_right_join(self, lhs_bindings, rhs_binding, ctx=None):
        # Yield all valid FOLLOWEDBY joins between a list of lhs_bindings
        # and a single rhs_binding

        earliest_rhs_last_timestamp = self.__earliest_last_timestamp(rhs_binding)

        for lhs_binding in lhs_bindings:

            if _disjoint(lhs_binding, rhs_binding):
                latest_lhs_first_timestamp = self.__latest_first_timestamp(lhs_binding)

                if latest_lhs_first_timestamp <= earliest_rhs_last_timestamp:
                    yield (lhs_binding + rhs_binding)
                elif self.__diagnostics is not None:
                    self.__record_followed_by_failure(
                        ctx, lhs_binding, rhs_binding,
                        latest_lhs_first_timestamp,
                        earliest_rhs_last_timestamp,
                    )
            elif self.__diagnostics is not None:
                self.__record_combination_failure(
                    ctx, u"followedby_observations_not_distinct",
                    lhs_binding, rhs_binding,
                )

    def __record_followed_by_failure(self, ctx, lhs_binding, rhs_binding,
                                     latest_lhs, earliest_rhs):
        """Record a FOLLOWEDBY candidate eliminated due to timestamp order."""
        obs_idxs = []
        for binding in (lhs_binding, rhs_binding):
            for inst_id in binding:
                obs_idx = self.get_obs_index(inst_id)
                if obs_idx is not None and obs_idx not in obs_idxs:
                    obs_idxs.append(obs_idx)

        self.__diagnostics.record(
            DIAG_TEMPORAL_FAILED,
            u"followedby_time_order_violated",
            ctx=ctx,
            obs_idxs=obs_idxs,
            detail={
                u"latest_left_first_observed": latest_lhs,
                u"earliest_right_last_observed": earliest_rhs,
            },
        )

    def __latest_first_timestamp(self, binding):
        return max(
            # time interval is based on the original obs_index
            self.__time_intervals[self.get_obs_index(inst_id)][0]
            for inst_id in binding
            if inst_id is not None
        )

    def __earliest_last_timestamp(self, binding):
        return min(
            # time interval is based on the original obs_index
            self.__time_intervals[self.get_obs_index(inst_id)][1]
            for inst_id in binding
            if inst_id is not None
        )

    def exitObservationExpressionOr(self, ctx):
        """
        Implements the pattern-level OR operator.  If there are two child
        nodes:

        Consumes two generators of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined generator of binding tuples.  This produces a sort of
          outer join: result tuples include the LHS values with all RHS
          values set to None, and vice versa.  Result bindings with values
          from both LHS and RHS are not included, to improve scalability
          (reduces the number of results, without affecting correctness).

        I believe the decision to include only one-sided bindings to be
        justified because binding additional observations here only serves to
        eliminate options for binding those observations to other parts of
        the pattern later.  So it can never enable additional binding
        possibilities, only eliminate them.

        In case you're wondering about repeat-qualified sub-expressions
        ("hey, if you reduce the number of bindings, you might not reach
        the required repeat count for a repeat-qualified sub-expression!"),
        note that none of these additional bindings would be disjoint w.r.t.
        the base set of one-sided bindings.  Therefore, they could never
        be combined with the base set to satisfy an increased repeat count.

        So basically, this base set maximizes binding opportunities elsewhere
        in the pattern, and does not introduce "false negatives".  It will
        result in some possible bindings not being found, but only when it
        would be extra noise anyway.  That improves scalability.
        """
        num_operands = len(ctx.observationExpressionOr())

        if num_operands not in (0, 2):
            # Just in case...
            msg = u"Unexpected number of observationExpressionOr children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 0:
            return

        # num_operands == 2:
        debug_label = u"exitObservationExpressionOr"

        rhs_bindings = self.__pop(debug_label)
        lhs_bindings = self.__pop(debug_label)

        # Compute tuples of None values, for each side (rhs/lhs), whose
        # lengths are equal to the bindings on those sides.  These will
        # be concatenated with actual bindings to produce the results.
        # These are kind of like None'd "placeholder" bindings, since we
        # want each joined binding to include actual bindings from only the
        # left or right side, not both.  We fill in None's for the side
        # we don't want to include.
        #
        # There are special cases when one side has no bindings.
        # We would like the resulting binding sizes to match up to the
        # number of observation expressions in the pattern, but if one
        # side's bindings are empty, we can't easily tell what size they
        # would have been.  So I traverse that part of the subtree to
        # obtain a size.  Algorithm correctness doesn't depend on this
        # "filler", but it helps users understand how the resulting
        # bindings match up with the pattern.
        first_lhs_binding = next(lhs_bindings, None)
        first_rhs_binding = next(rhs_bindings, None)
        if self.__diagnostics is not None:
            self.__diagnostics.record_branch(
                u"OR", ctx,
                first_lhs_binding is not None,
                first_rhs_binding is not None,
                result=(first_lhs_binding is not None or
                        first_rhs_binding is not None),
            )
        if first_lhs_binding is not None:
            lhs_binding_none = (None,) * len(first_lhs_binding)
        else:
            left_binding_size = _compute_expected_binding_size(
                ctx.observationExpressionOr(0))
            lhs_binding_none = (None,) * left_binding_size
        if first_rhs_binding is not None:
            rhs_binding_none = (None,) * len(first_rhs_binding)
        else:
            right_binding_size = _compute_expected_binding_size(
                ctx.observationExpressionOr(0))
            rhs_binding_none = (None,) * right_binding_size

        def joined_bindings():
            _lhs_binding = first_lhs_binding
            _rhs_binding = first_rhs_binding
            while _lhs_binding is not None or _rhs_binding is not None:
                if _lhs_binding is not None:
                    yield _lhs_binding + rhs_binding_none
                    _lhs_binding = next(lhs_bindings, None)
                if _rhs_binding is not None:
                    yield lhs_binding_none + _rhs_binding
                    _rhs_binding = next(rhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

    def exitObservationExpressionAnd(self, ctx):
        """
        Implements the pattern-level AND operator.  If there are two child
        nodes:

        Consumes two generators of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined generator of binding tuples.  All joined tuples are
          produced which include lhs and rhs values without having any
          duplicate observation IDs.
        """
        num_operands = len(ctx.observationExpressionAnd())

        if num_operands not in (0, 2):
            # Just in case...
            msg = u"Unexpected number of observationExpressionAnd children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 0:
            return

        # num_operands == 2:
        debug_label = u"exitObservationExpressionAnd"

        rhs_bindings = self.__pop(debug_label)
        lhs_bindings = self.__pop(debug_label)

        # we need to return the cartesian product of rhs_bindings and lhs_bindings
        # but they are generators: we need to store the generated elements
        def joined_bindings():
            _rhs_cache = []
            _lhs_cache = []
            _report_budget = [20]
            _joined_count = [0]
            _next_rhs_binding = next(rhs_bindings, None)
            _next_lhs_binding = next(lhs_bindings, None)
            if self.__diagnostics is not None and \
                    (_next_lhs_binding is None) != (_next_rhs_binding is None):
                # Exactly one side has no candidates: the rule is only
                # partially satisfied.  If both sides have candidates, any
                # combination failures are recorded below instead.
                self.__diagnostics.record_branch(
                    u"AND", ctx,
                    _next_lhs_binding is not None,
                    _next_rhs_binding is not None,
                    result=False,
                )
            if _next_rhs_binding is None or _next_lhs_binding is None:
                # cache and one generator are empty.  Any reason the missing
                # side has no candidates was already recorded deeper in the
                # expression tree; the branch record above shows which side
                # was empty.
                return
            while _next_rhs_binding is not None or _next_lhs_binding is not None:
                # while there are new bindings to explore
                if _next_rhs_binding is not None:
                    # if there is a new rhs binding
                    for lhs_binding in _lhs_cache:
                        # yield valid combinations
                        if _disjoint(lhs_binding, _next_rhs_binding):
                            _joined_count[0] += 1
                            yield (lhs_binding + _next_rhs_binding)
                        elif self.__diagnostics is not None and \
                                _report_budget[0] > 0:
                            _report_budget[0] -= 1
                            self.__record_combination_failure(
                                ctx, u"observations_not_distinct",
                                lhs_binding, _next_rhs_binding,
                            )
                    # update cache
                    _rhs_cache.append(_next_rhs_binding)
                    _next_rhs_binding = next(rhs_bindings, None)

                if _next_lhs_binding is not None:
                    # if there is a new rhs binding
                    for rhs_binding in _rhs_cache:
                        # yield valid combinations
                        if _disjoint(_next_lhs_binding, rhs_binding):
                            _joined_count[0] += 1
                            yield (_next_lhs_binding + rhs_binding)
                        elif self.__diagnostics is not None and \
                                _report_budget[0] > 0:
                            _report_budget[0] -= 1
                            self.__record_combination_failure(
                                ctx, u"observations_not_distinct",
                                _next_lhs_binding, rhs_binding,
                            )
                    # update cache
                    _lhs_cache.append(_next_lhs_binding)
                    _next_lhs_binding = next(lhs_bindings, None)

            if self.__diagnostics is not None and _joined_count[0] == 0:
                # Both sides had candidates, but no distinct combination
                # existed.  Each side was individually satisfied, so this is
                # a partial satisfaction, not a complete match.
                self.__diagnostics.record_branch(
                    u"AND", ctx, True, True, result=False,
                )

        self.__push(joined_bindings(), debug_label)

    def __record_combination_failure(self, ctx, reason, *bindings):
        """Record a binding combination eliminated by identity constraints."""
        obs_idxs = []
        for binding in bindings:
            for inst_id in binding:
                obs_idx = self.get_obs_index(inst_id)
                if obs_idx is not None and obs_idx not in obs_idxs:
                    obs_idxs.append(obs_idx)

        self.__diagnostics.record(
            DIAG_TEMPORAL_FAILED, reason, ctx=ctx, obs_idxs=obs_idxs,
        )

    def exitObservationExpressionSimple(self, ctx):
        """
        Consumes the results of the inner comparison expression.  See
        exitComparisonExpression().
        Produces: a generator of 1-tuples of the IDs.  At this stage, the root
        Cyber Observable object IDs are no longer needed, and are dropped.

        This is a preparatory transformative step, so that higher-level
        processing has consistent structures to work with (always generator of
        tuples).
        """

        debug_label = u"exitObservationExpression (simple)"
        obs_ids = self.__pop(debug_label)
        # "Unpack" the instances of observables based on `number_observed`
        # field by creating complex instance_id
        obs_id_tuples = ((self.create_instance_id(obs_id, i),) for obs_id in obs_ids.keys()
                         for i in range(0, self.__number_observed[obs_id]))

        self.__push(obs_id_tuples, debug_label)

    # Don't need to do anything for exitObservationExpressionCompound

    def exitObservationExpressionRepeated(self, ctx):
        """
        Consumes a generator of bindings for the qualified observation expression.
        Produces a generator of bindings which account for the repetition. The
        length of each new binding is equal to the length of the old bindings
        times the repeat count.
        """

        rep_count = _literal_terminal_to_python_val(
            ctx.repeatedQualifier().IntPosLiteral()
        )
        debug_label = u"exitObservationExpressionRepeated ({})".format(
            rep_count
        )

        bindings = self.__pop(debug_label)

        # Need to find all 'rep_count'-sized disjoint combinations of
        # bindings.
        if rep_count < 1:
            raise MatcherException(u"Invalid repetition count: {}".format(
                rep_count))
        elif rep_count == 1:
            # As an optimization, if rep_count is 1, we use the bindings
            # as-is.
            filtered_bindings = bindings
        else:
            if self.__diagnostics is None:
                # Normal mode: keep the exact original code path.
                filtered_bindings = _filtered_combinations(
                    bindings, rep_count,
                )
                filtered_bindings = (
                    tuple(itertools.chain.from_iterable(binding))
                    for binding in filtered_bindings
                )
            else:
                # Diagnostic mode: count source candidates lazily so a
                # report can explain insufficient repetition, then flatten
                # exactly as normal mode does.
                candidate_count = [0]

                def counted_bindings():
                    for binding in bindings:
                        candidate_count[0] += 1
                        yield binding

                combinations = _filtered_combinations(
                    counted_bindings(), rep_count,
                )
                flat_bindings = (
                    tuple(itertools.chain.from_iterable(binding))
                    for binding in combinations
                )
                filtered_bindings = self.__check_repeat_sufficiency(
                    candidate_count, rep_count, flat_bindings, ctx,
                )

        self.__push(filtered_bindings, debug_label)

    def __check_repeat_sufficiency(self, candidate_count, rep_count,
                                   flat_bindings, ctx):
        """
        Pass repeated bindings through unchanged, but report when no distinct
        combination of the required size could be found.

        This preserves the lazy behavior of the binding generators: the source
        is only inspected if the combination generator produced nothing, which
        is exactly what normally ends the match attempt.  A generator which is
        abandoned early (e.g. because another OR branch produced the winning
        binding) is not reported.
        """
        produced = False
        exhausted = False
        try:
            for binding in flat_bindings:
                produced = True
                yield binding
            exhausted = True
        finally:
            if exhausted and not produced:
                self.__diagnostics.record(
                    DIAG_TEMPORAL_FAILED, u"repeat_count_not_satisfied",
                    ctx=ctx,
                    detail={
                        u"required_repetitions": rep_count,
                        u"candidate_bindings_seen": candidate_count[0],
                    },
                )

    def exitObservationExpressionWithin(self, ctx):
        """
        Consumes (1) a duration, as a dateutil.relativedelta.relativedelta
          object (see exitWithinQualifier()), and (2) a generator of bindings.
        Produces a generator of bindings which are temporally filtered according
          to the given duration.
        """

        debug_label = u"exitObservationExpressionWithin"

        duration = self.__pop(debug_label)
        bindings = self.__pop(debug_label)

        def check_within(binding):
            return _timestamp_intervals_within(
                [
                    # time interval is based on the original obs_index
                    self.__time_intervals[self.get_obs_index(inst_id)]
                    for inst_id in binding
                    if inst_id is not None
                ],
                duration
            )

        def within_bindings():
            for binding in bindings:
                if check_within(binding):
                    yield binding
                elif self.__diagnostics is not None:
                    self.__record_temporal_binding_failure(
                        ctx, binding, u"within_duration_exceeded",
                        {u"duration_seconds": duration.seconds,
                         u"duration_days": duration.days},
                    )

        filtered_bindings = within_bindings()

        self.__push(filtered_bindings, debug_label)

    def exitObservationExpressionStartStop(self, ctx):
        """
        Consumes (1) a time interval as a pair of datetime.datetime objects,
          and (2) a generator of bindings.
        Produces a generator of bindings which are temporally filtered according
          to the given time interval.  A binding passes the test if it is
          possible to select legal timestamps for all observations which are
          within the start/stop interval, not including the stop value, which
          is disallowed by the spec.  Viewed another way, we require overlap
          with the SDO interval and start/stop interval, including only touching
          at the start point, but not including only touching at the stop
          point.
        """

        debug_label = u"exitObservationExpressionStartStop"

        # In this case, these are start and stop timestamps as
        # datetime.datetime objects (see exitStartStopQualifier()).
        start_time, stop_time = self.__pop(debug_label)
        bindings = self.__pop(debug_label)

        def check_overlap(binding):
            return all(
                    _overlap(start_time, stop_time, *self.__time_intervals[
                        # time interval is based on the original obs_index
                        self.get_obs_index(obs_id)
                    ])
                    in (_OVERLAP, _OVERLAP_TOUCH_OUTER)
                    for obs_id in binding if obs_id is not None
                )

        # If start and stop are equal, the constraint is impossible to
        # satisfy, since a value can't be both >= and < the same number.
        # And of course it's impossible if start > stop.
        if start_time < stop_time:
            def start_stop_bindings():
                for binding in bindings:
                    if check_overlap(binding):
                        yield binding
                    elif self.__diagnostics is not None:
                        self.__record_temporal_binding_failure(
                            ctx, binding, u"start_stop_interval_missed",
                            {u"start": start_time, u"stop": stop_time},
                        )

            filtered_bindings = start_stop_bindings()
        else:
            if self.__diagnostics is not None:
                self.__diagnostics.record(
                    DIAG_TEMPORAL_FAILED, u"invalid_start_stop_interval",
                    ctx=ctx,
                    detail={u"start": start_time, u"stop": stop_time},
                )
            filtered_bindings = iter(())

        self.__push(filtered_bindings, debug_label)

    def __record_temporal_binding_failure(self, ctx, binding, reason, detail):
        """Record a binding eliminated by a temporal qualifier."""
        obs_idxs = []
        for inst_id in binding:
            obs_idx = self.get_obs_index(inst_id)
            if obs_idx is not None and obs_idx not in obs_idxs:
                obs_idxs.append(obs_idx)

        self.__diagnostics.record(
            DIAG_TEMPORAL_FAILED, reason, ctx=ctx, obs_idxs=obs_idxs,
            detail=detail,
        )

    def exitStartStopQualifier(self, ctx):
        """
        Consumes nothing
        Produces a (datetime, datetime) 2-tuple containing the start and stop
          times.
        """

        if self.__stix_version == VARSION_2_1:
            start_dt = _literal_terminal_to_python_val(ctx.TimestampLiteral(0))
            stop_dt = _literal_terminal_to_python_val(ctx.TimestampLiteral(1))
        else:
            start_str = _literal_terminal_to_python_val(ctx.StringLiteral(0))
            stop_str = _literal_terminal_to_python_val(ctx.StringLiteral(1))

            # If the language used timestamp literals here, this could go away...
            try:
                start_dt = _str_to_datetime(start_str)
                stop_dt = _str_to_datetime(stop_str)
            except ValueError as e:
                # re-raise as MatcherException.
                raise six.raise_from(MatcherException(*e.args), e)

        self.__push((start_dt, stop_dt), u"exitStartStopQualifier")

    def exitWithinQualifier(self, ctx):
        """
        Consumes nothing (the unit is always seconds).
        Produces a dateutil.relativedelta.relativedelta object, representing
          the specified interval.
        """

        value = _literal_terminal_to_python_val(ctx.FloatPosLiteral() or ctx.IntPosLiteral())
        debug_label = u"exitWithinQualifier ({})".format(value)
        if value <= 0:
            raise MatcherException(u"Invalid WITHIN value (must be positive): {}".format(value))

        delta = dateutil.relativedelta.relativedelta(seconds=value)

        self.__push(delta, debug_label)

    def exitComparisonExpression(self, ctx):
        """
        Consumes zero or two maps of observation IDs produced by child
          propTest's (see _obs_map_prop_test()) and/or
          sub-comparison-expressions.
        Produces: if one child expression, this callback does nothing.  If
          two, the top two maps on the stack are combined into a single map of
          observation IDs.

          This implements the "OR" operator.  So the maps are merged (union);
          observation IDs which are shared between both operands have their
          Cyber Observable object ID sets unioned in the result.
        """

        debug_label = u"exitComparisonExpression"
        num_or_operands = len(ctx.comparisonExpression())

        # Just in case...
        if num_or_operands not in (0, 2):
            msg = u"Unexpected number of comparisonExpression children: {}"
            raise MatcherInternalError(msg.format(num_or_operands))

        if num_or_operands == 2:
            # The result is collected into obs1.
            obs2 = self.__pop(debug_label)
            obs1 = self.__pop(debug_label)

            if self.__diagnostics is not None:
                self.__diagnostics.record_branch(
                    u"comparison OR", ctx, bool(obs1), bool(obs2),
                    result=bool(obs1) or bool(obs2),
                )

            # We union the observation IDs and their corresponding
            # Cyber Observable object ID sets.
            for obs_id, cyber_obs_obj_ids in six.iteritems(obs2):
                if obs_id in obs1:
                    obs1[obs_id] |= cyber_obs_obj_ids
                else:
                    obs1[obs_id] = cyber_obs_obj_ids

            self.__push(obs1, debug_label)

    def exitComparisonExpressionAnd(self, ctx):
        """
        Consumes zero or two maps of observation IDs produced by child
          propTest's (see _obs_map_prop_test()) and/or
          sub-comparison-expressions.
        Produces: if one child expression, this callback does nothing.  If
          two, the top two maps on the stack are combined into a single map of
          observation IDs.

          This implements the "AND" operator.  So the result map has those IDs
          common to both (intersection); their Cyber Observable object ID sets are also
          intersected.  If this latter intersection is empty, the corresponding
          observation is dropped.
        """

        debug_label = u"exitComparisonExpressionAnd"
        num_and_operands = len(ctx.comparisonExpressionAnd())

        # Just in case...
        if num_and_operands not in (0, 2):
            msg = u"Unexpected number of comparisonExpression children: {}"
            raise MatcherInternalError(msg.format(num_and_operands))

        if num_and_operands == 2:
            # The result is collected into obs1.
            obs2 = self.__pop(debug_label)
            obs1 = self.__pop(debug_label)

            obs1_before = set(obs1)

            # We intersect the observation IDs and their corresponding
            # Cyber Observable object ID sets.  If any of the Cyber Observable object ID set
            # intersections is empty, we drop the observation from the
            # result.
            obs_ids_to_drop = []
            for obs_id, cyber_obs_obj_ids in six.iteritems(obs1):
                if obs_id in obs2:
                    obs1[obs_id] &= obs2[obs_id]
                    if not obs1[obs_id]:
                        obs_ids_to_drop.append(obs_id)
                else:
                    obs_ids_to_drop.append(obs_id)

            # Now drop the ones we found (can't modify as we iterated
            # above, so this needs to be a separate pass).
            for obs_id in obs_ids_to_drop:
                del obs1[obs_id]

            if self.__diagnostics is not None:
                self.__diagnostics.record_branch(
                    u"comparison AND", ctx, bool(obs1_before), bool(obs2),
                    result=bool(obs1),
                )
                if not obs1 and obs1_before and obs2:
                    self.__diagnostics.record(
                        DIAG_COMPARISON_FAILED,
                        u"and_not_satisfied_by_same_object",
                        ctx=ctx,
                        obs_idxs=list(obs1_before),
                        detail={u"observations_dropped": len(obs_ids_to_drop)},
                    )

            self.__push(obs1, debug_label)

    def exitPropTestEqual(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        It's okay if the operands are of different type and comparison is
        not supported: they will compare unequal.  (Note: this would include
        things like pairs of dicts and lists which have the same contents...
        should verify what to do here.)
        """

        # Figure out what literal value was given in the pattern
        literal_node = ctx.primitiveLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_tok = ctx.EQ() or ctx.NEQ()
        debug_label = u"exitPropTestEqual ({}{} {})".format(
            u"NOT " if ctx.NOT() else u"",
            op_tok.getText(),
            literal_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        def _coerce_timestamp(value):
            """Mirror the timestamp coercion done by predicates."""
            if isinstance(literal_value, datetime.datetime) and \
                    isinstance(value, six.text_type):
                try:
                    return _str_to_datetime(value)
                except ValueError:
                    return value
            return value

        def equality_pred(value):

            # timestamp hackage: if we have a timestamp literal from the
            # pattern and a string from the json, try to interpret the json
            # value as a timestamp too.
            if isinstance(literal_value, datetime.datetime) and \
                    isinstance(value, six.text_type):
                try:
                    value = _str_to_datetime(value)
                except ValueError as e:
                    six.raise_from(
                        MatcherException(u"Invalid timestamp in JSON: {}".format(
                            value
                        )), e)

            result = False
            eq_func = _get_table_symmetric(_COMPARE_EQ_FUNCS,
                                           type(literal_value),
                                           type(value))
            if eq_func is not None:
                result = eq_func(value, literal_value)

            if ctx.NEQ():
                result = not result

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            coerced = _coerce_timestamp(value)
            eq_func = _get_table_symmetric(_COMPARE_EQ_FUNCS,
                                           type(literal_value),
                                           type(coerced))
            if eq_func is None:
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"unsupported_comparison_types",
                    u"expected": _type_name(literal_value),
                    u"detail": {u"pattern_type": _type_name(literal_value),
                                u"value_type": _type_name(value)},
                }
            if ctx.NEQ() or ctx.NOT():
                reason = u"negated_equality_test_failed"
            else:
                reason = u"equality_test_failed"
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": reason,
                u"expected": _diagnostic_value(literal_value),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, equality_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitPropTestOrder(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        If operand types are not supported for order-comparison, current
        spec says the result must be False.  But this means that for two
        values for which comparison is not supported, both a < b and
        a >= b would be false.  That's certainly not normal semantics for
        these operators...
        """
        # Figure out what literal value was given in the pattern
        literal_node = ctx.orderableLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_tok = ctx.GT() or ctx.LT() or ctx.GE() or ctx.LE()
        debug_label = u"exitPropTestOrder ({}{} {})".format(
            u"NOT " if ctx.NOT() else u"",
            op_tok.getText(),
            literal_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        def _coerce_timestamp(value):
            """Mirror the timestamp coercion done by predicates."""
            if isinstance(literal_value, datetime.datetime) and \
                    isinstance(value, six.text_type):
                try:
                    return _str_to_datetime(value)
                except ValueError:
                    return value
            return value

        def order_pred(value):

            # timestamp hackage: if we have a timestamp literal from the
            # pattern and a string from the json, try to interpret the json
            # value as a timestamp too.
            if isinstance(literal_value, datetime.datetime) and \
                    isinstance(value, six.text_type):
                try:
                    value = _str_to_datetime(value)
                except ValueError as e:
                    six.raise_from(
                        MatcherException(u"Invalid timestamp in JSON: {}".format(
                            value
                        )), e)

            cmp_func = _get_table_symmetric(_COMPARE_ORDER_FUNCS,
                                            type(literal_value),
                                            type(value))

            if cmp_func is None:
                return False

            try:
                result = cmp_func(value, literal_value)
            except ValueError:
                # The only comparison func that raises ValueError as of this
                # writing is for binary<->string comparisons, when the string is
                # of the wrong form.  Spec says the result must be false.
                result = False
            else:
                if ctx.LT():
                    result = result < 0
                elif ctx.GT():
                    result = result > 0
                elif ctx.LE():
                    result = result <= 0
                elif ctx.GE():
                    result = result >= 0
                else:
                    # shouldn't ever happen, right?
                    raise UnsupportedOperatorError(op_tok.getText())

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            coerced = _coerce_timestamp(value)
            cmp_func = _get_table_symmetric(_COMPARE_ORDER_FUNCS,
                                            type(literal_value),
                                            type(coerced))
            if cmp_func is None:
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"unsupported_comparison_types",
                    u"expected": _type_name(literal_value),
                    u"detail": {u"pattern_type": _type_name(literal_value),
                                u"value_type": _type_name(value)},
                }
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": u"order_test_failed",
                u"expected": _diagnostic_value(literal_value),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, order_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitPropTestSet(self, ctx):
        """
        Consumes (1) a set object from exitSetLiteral(), and (2) an observation
           data map, {obs_id: {...}, ...}, representing selected values from
           Cyber Observable objects in each observation (grouped by observation index and
           root Cyber Observable object ID).  See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().
        """

        debug_label = u"exitPropTestSet{}".format(
            u" (not)" if ctx.NOT() else u""
        )
        s = self.__pop(debug_label)  # pop the set
        obs_values = self.__pop(debug_label)  # pop the observation values

        # Only need to check one member; exitSetLiteral() ensures that all
        # members of the set have the same type.
        is_set_of_timestamps = s and \
            isinstance(next(iter(s)), datetime.datetime)

        def set_pred(value):
            # timestamp hackage: if we have a set of timestamp literals from
            # the pattern and a string from the json, try to interpret the json
            # value as a timestamp too.
            if is_set_of_timestamps and isinstance(value, six.text_type):
                try:
                    value = _str_to_datetime(value)
                except ValueError as e:
                    six.raise_from(
                        MatcherException(u"Invalid timestamp in JSON: {}".format(
                            value
                        )), e)

            result = False
            try:
                result = value in s
            except TypeError:
                # Ignore errors about un-hashability.  Not all values
                # selected from a Cyber Observable object are hashable (e.g.
                # lists and dicts).  Those obviously can't be in the
                # given set!
                pass

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            coerced = value
            if is_set_of_timestamps and isinstance(value, six.text_type):
                try:
                    coerced = _str_to_datetime(value)
                except ValueError:
                    coerced = value
            comparable = any(
                _get_table_symmetric(_COMPARE_EQ_FUNCS,
                                     type(member), type(coerced))
                is not None
                for member in s
            )
            if s and not comparable:
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"unsupported_comparison_types",
                    u"expected": sorted(_type_name(member) for member in s),
                    u"detail": {u"pattern_types":
                                sorted(set(_type_name(m) for m in s)),
                                u"value_type": _type_name(value)},
                }
            if ctx.NOT():
                reason = u"membership_test_failed_negated"
            else:
                reason = u"value_not_in_set"
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": reason,
                u"expected": _diagnostic_value(s),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, set_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitPropTestLike(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """

        operand_str = _literal_terminal_to_python_val(ctx.StringLiteral())
        debug_label = u"exitPropTestLike ({}{})".format(
            u"not " if ctx.NOT() else u"",
            operand_str
        )

        obs_values = self.__pop(debug_label)

        operand_str = unicodedata.normalize("NFC", operand_str)
        regex = _like_to_regex(operand_str)
        # compile and cache this to improve performance
        compiled_re = re.compile(regex)
        is_binary_convertible = all(ord(c) < 256 for c in regex)

        def like_pred(value):
            if isinstance(value, six.binary_type) and is_binary_convertible:
                value = value.decode('utf8')

            # non-strings can't match
            if isinstance(value, six.text_type):
                value = unicodedata.normalize("NFC", value)
                result = compiled_re.match(value)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            if isinstance(value, six.binary_type) and is_binary_convertible:
                return {
                    u"stage": DIAG_COMPARISON_FAILED,
                    u"reason": u"like_pattern_did_not_match",
                    u"expected": _diagnostic_value(operand_str),
                }
            if not isinstance(value, six.text_type):
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"non_string_value",
                    u"expected": u"string_pattern",
                    u"detail": {u"value_type": _type_name(value)},
                }
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": u"like_pattern_did_not_match",
                u"expected": _diagnostic_value(operand_str),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, like_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitPropTestRegex(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """

        regex_terminal = ctx.StringLiteral()
        debug_label = u"exitPropTestRegex ({}{})".format(
            u"not " if ctx.NOT() else u"",
            regex_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        regex = _literal_terminal_to_python_val(regex_terminal)
        regex = unicodedata.normalize("NFC", regex)
        compiled_re = re.compile(regex)

        # Support for binary pattern matching.
        is_binary_convertible = all(ord(c) < 256 for c in regex)
        if is_binary_convertible:
            if six.PY2:
                # This will be a pattern compiled from a unicode string, but
                # python2 doesn't seem to care.  It'll match against a 'str'
                # just fine.
                compiled_bin_re = compiled_re
            else:
                # Python3 requires an actual binary regex.
                bin_regex = six.binary_type(ord(c) for c in regex)
                compiled_bin_re = re.compile(bin_regex)

        def regex_pred(value):
            if isinstance(value, six.text_type):
                value = unicodedata.normalize("NFC", value)
                result = compiled_re.search(value)

            elif isinstance(value, six.binary_type):
                if is_binary_convertible:
                    result = compiled_bin_re.search(value)
                else:
                    result = False

            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            if isinstance(value, six.binary_type) and is_binary_convertible:
                return {
                    u"stage": DIAG_COMPARISON_FAILED,
                    u"reason": u"regex_did_not_match",
                    u"expected": _diagnostic_value(regex),
                }
            if not isinstance(value, (six.text_type, six.binary_type)):
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"non_string_value",
                    u"expected": u"string_pattern",
                    u"detail": {u"value_type": _type_name(value)},
                }
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": u"regex_did_not_match",
                u"expected": _diagnostic_value(regex),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, regex_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitPropTestIsSubset(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """
        subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitPropTestIsSubset ({}{})".format(
            u"not " if ctx.NOT() else u"",
            subnet_str
        )
        obs_values = self.__pop(debug_label)

        def subnet_pred(value):
            if isinstance(value, six.text_type):
                result = _ip_or_cidr_in_subnet(value, subnet_str)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            if not isinstance(value, six.text_type):
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"non_string_value",
                    u"expected": u"cidr_pattern",
                    u"detail": {u"value_type": _type_name(value)},
                }
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": u"subnet_test_failed",
                u"expected": _diagnostic_value(subnet_str),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, subnet_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitPropTestIsSuperset(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """
        ip_or_subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitPropTestIsSuperset ({}{})".format(
            u"not " if ctx.NOT() else u"",
            ip_or_subnet_str
        )
        obs_values = self.__pop(debug_label)

        def contains_pred(value):
            if isinstance(value, six.text_type):
                result = _ip_or_cidr_in_subnet(ip_or_subnet_str, value)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        def classify(value):
            if not isinstance(value, six.text_type):
                return {
                    u"stage": DIAG_TYPE_MISMATCH,
                    u"reason": u"non_string_value",
                    u"expected": u"ip_or_cidr_pattern",
                    u"detail": {u"value_type": _type_name(value)},
                }
            return {
                u"stage": DIAG_COMPARISON_FAILED,
                u"reason": u"superset_test_failed",
                u"expected": _diagnostic_value(ip_or_subnet_str),
            }

        passed_obs = _obs_map_prop_test(
            obs_values, contains_pred, self.__diagnostics, ctx,
            self.__path_text(ctx) if self.__diagnostics else None, classify,
        )

        self.__push(passed_obs, debug_label)

    def exitObjectPath(self, ctx):
        """
        Consumes nothing from the stack
        Produces a mapping:
            {
              observation-idx: {
                  "cyber_obs_obj_id1": [value, value, ...],
                  "cyber_obs_obj_id2": [value, value, ...],
              },
              etc...
            }
          which are the values selected by the path, organized according to
          the the observations they belong to, and the "root" Cyber Observable objects
          which began a chain of dereferences (if any).  These will be used in
          subsequent comparisons to select some of the observations.
          I use observations' indices into the self.__observations list as
          identifiers.

        So this (and descendant rules) is where (the main) stack values come
        into being.
        """

        # We don't actually need to do any post-processing to the top stack
        # value.  But I keep this function here for the sake of documentation.
        pass

    def exitObjectType(self, ctx):
        """
        Consumes nothing from the stack.
        Produces a map, {observation-idx: {...}, ...}, representing those
        Cyber Observable objects with the given type.  See exitObjectPath().
        """
        type_token = ctx.IdentifierWithoutHyphen() or ctx.IdentifierWithHyphen()
        type_ = type_token.getText()

        results = {}
        excluded_type = (
            self.__stix_version == VARSION_2_1 and type_ in TYPES_V21
        )
        if not excluded_type:
            for obs_idx, obs in enumerate(self.__observations):

                if "objects" not in obs:
                    if self.__diagnostics is not None:
                        self.__diagnostics.record(
                            DIAG_PATH_MISSING, u"observation_has_no_objects",
                            ctx=ctx, obs_idx=obs_idx,
                            detail={u"object_type": type_},
                        )
                    continue

                objects_from_this_obs = {}
                iterator = self.__cyber_obs_obj_iterator(obs["objects"])

                for obj_id, obj in iterator:
                    if u"type" in obj and obj[u"type"] == type_:
                        objects_from_this_obs[obj_id] = [obj]

                if len(objects_from_this_obs) > 0:
                    results[obs_idx] = objects_from_this_obs
                elif self.__diagnostics is not None:
                    self.__diagnostics.record(
                        DIAG_PATH_MISSING, u"object_type_not_present",
                        ctx=ctx, obs_idx=obs_idx,
                        detail={u"object_type": type_},
                    )
        elif self.__diagnostics is not None:
            self.__diagnostics.record(
                DIAG_PATH_MISSING, u"object_type_not_searchable",
                ctx=ctx, detail={u"object_type": type_},
            )

        self.__push(results, u"exitObjectType ({})".format(type_))

    def __cyber_obs_obj_iterator(self, objs):
        if self.__stix_version == VARSION_2_1:
            iter_objs = {v['id']: v for v in objs}
        else:
            iter_objs = objs
        iterator = six.iteritems(iter_objs)

        return iterator

    def __dereference_objects(self, prop_name, obs_map, ctx=None):
        """
        If prop_name is a reference property, this "dereferences" it,
        substituting the referenced Cyber Observable object for the reference.  Reference
        properties end in "_ref" or "_refs".  The former must have a string
        value, the latter must be a list of strings.  Any references which
        don't resolve are dropped and don't produce an error.  The references
        are resolved only against the Cyber Observable objects in the same observation as
        the reference.

        If the property isn't a reference, this method does nothing.

        :param prop_name: The property which was just stepped, i.e. the "key"
            in a key path step.
        :param obs_map: The observation data after stepping, but before it
            has been pushed onto the stack.  This method acts as an additional
            "processing" step on that data.
        :param ctx: Parse-tree node used for diagnostic rule locations.
        :return: If prop_name is not a reference property, obs_map is
            returned unchanged.  If it is a reference property, the
            dereferenced observation data is returned.
        """

        if prop_name.endswith(u"_ref"):
            # An object reference.  All top-level values should be
            # string Cyber Observable object IDs.
            dereferenced_obs_map = {}
            for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
                dereferenced_cyber_obs_obj_map = {}
                for cyber_obs_obj_id, references in six.iteritems(cyber_obs_obj_map):
                    dereferenced_cyber_obs_objs = _dereference_cyber_obs_objs(
                        self.__observations[obs_idx]["objects"],
                        references,
                        prop_name,
                        self.__stix_version
                    )

                    if len(dereferenced_cyber_obs_objs) > 0:
                        dereferenced_cyber_obs_obj_map[cyber_obs_obj_id] = \
                            dereferenced_cyber_obs_objs
                    elif self.__diagnostics is not None:
                        for referenced_obj_id in references:
                            self.__diagnostics.record(
                                DIAG_REFERENCE_UNREACHABLE,
                                u"reference_target_absent",
                                ctx=ctx, obs_idx=obs_idx,
                                object_id=cyber_obs_obj_id,
                                path=prop_name,
                                detail={
                                    u"reference": _diagnostic_value(
                                        referenced_obj_id),
                                    u"reference_property": prop_name,
                                },
                            )

                if len(dereferenced_cyber_obs_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cyber_obs_obj_map

            obs_map = dereferenced_obs_map

        elif prop_name.endswith(u"_refs"):
            # A list of object references.  All top-level values should
            # be lists (of Cyber Observable object references).
            dereferenced_obs_map = {}
            for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
                dereferenced_cyber_obs_obj_map = {}
                for cyber_obs_obj_id, reference_lists in six.iteritems(cyber_obs_obj_map):
                    dereferenced_cyber_obs_obj_lists = []
                    for reference_list in reference_lists:
                        if not isinstance(reference_list, list):
                            raise MatcherException(
                                u"The value of reference list property '{}' was not "
                                u"a list!  Got {}".format(
                                    prop_name, reference_list
                                ))

                        dereferenced_cyber_obs_objs = _dereference_cyber_obs_objs(
                            self.__observations[obs_idx]["objects"],
                            reference_list,
                            prop_name,
                            self.__stix_version
                        )

                        if len(dereferenced_cyber_obs_objs) > 0:
                            dereferenced_cyber_obs_obj_lists.append(
                                dereferenced_cyber_obs_objs)
                        elif self.__diagnostics is not None:
                            self.__record_unresolved_refs(
                                ctx, obs_idx, cyber_obs_obj_id, prop_name,
                                reference_list,
                            )

                    if len(dereferenced_cyber_obs_obj_lists) > 0:
                        dereferenced_cyber_obs_obj_map[cyber_obs_obj_id] = \
                            dereferenced_cyber_obs_obj_lists

                if len(dereferenced_cyber_obs_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cyber_obs_obj_map

            obs_map = dereferenced_obs_map

        return obs_map

    def __record_unresolved_refs(self, ctx, obs_idx, cyber_obs_obj_id,
                                 prop_name, reference_list):
        """Record unresolved references from a reference list, for diagnostics."""
        if not reference_list:
            self.__diagnostics.record(
                DIAG_REFERENCE_UNREACHABLE, u"empty_reference_list",
                ctx=ctx, obs_idx=obs_idx, object_id=cyber_obs_obj_id,
                path=prop_name,
                detail={u"reference_property": prop_name},
            )
            return

        for referenced_obj_id in reference_list:
            self.__diagnostics.record(
                DIAG_REFERENCE_UNREACHABLE, u"reference_target_absent",
                ctx=ctx, obs_idx=obs_idx, object_id=cyber_obs_obj_id,
                path=prop_name,
                detail={
                    u"reference": _diagnostic_value(referenced_obj_id),
                    u"reference_property": prop_name,
                },
            )

    def exitFirstPathComponent(self, ctx):
        """
        Consumes the results of exitObjectType.
        Produces a similar structure, but with Cyber Observable objects which
          don't have the given property, filtered out.  For those which
          do have the property, the property value is substituted for
          the object.  If the property was a reference, a second substitution
          occurs: the referent is substituted in place of the reference (if
          the reference resolves).  This enables subsequent path steps to step
          into the referenced Cyber Observable object(s).

          If all Cyber Observable objects from an observation are filtered out, the
          observation is dropped.
        """

        if ctx.IdentifierWithoutHyphen():
            prop_name = ctx.IdentifierWithoutHyphen().getText()
        else:
            prop_name = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitFirstPathComponent ({})".format(prop_name)
        obs_val = self.__pop(debug_label)

        path = ctx.parentCtx.getText() if ctx.parentCtx is not None else None
        filtered_obs_map = _step_filter_observations(
            obs_val, prop_name, self.__diagnostics, ctx, path,
        )
        dereferenced_obs_map = self.__dereference_objects(
            prop_name, filtered_obs_map, ctx,
        )

        self.__push(dereferenced_obs_map, debug_label)

    def exitKeyPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent().
        """
        if ctx.IdentifierWithoutHyphen():
            prop_name = ctx.IdentifierWithoutHyphen().getText()
        else:
            prop_name = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitKeyPathStep ({})".format(prop_name)
        obs_val = self.__pop(debug_label)

        path = ctx.parentCtx.getText() if ctx.parentCtx is not None else None
        filtered_obs_map = _step_filter_observations(
            obs_val, prop_name, self.__diagnostics, ctx, path,
        )
        dereferenced_obs_map = self.__dereference_objects(
            prop_name, filtered_obs_map, ctx,
        )

        self.__push(dereferenced_obs_map, debug_label)

    def exitIndexPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent(), but takes a list index
        step.
        """
        path = ctx.parentCtx.getText() if ctx.parentCtx is not None else None
        if ctx.IntPosLiteral() or ctx.IntNegLiteral():
            index = _literal_terminal_to_python_val(
                ctx.IntPosLiteral() or ctx.IntNegLiteral()
            )
            debug_label = u"exitIndexPathStep ({})".format(index)
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations(
                obs_val, index, self.__diagnostics, ctx, path,
            )

        elif ctx.ASTERISK():
            # In this case, we step into all of the list elements.
            debug_label = u"exitIndexPathStep (*)"
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations_index_star(
                obs_val, self.__diagnostics, ctx, path,
            )

        else:
            # reallly shouldn't happen...
            raise MatcherInternalError(u"Unsupported index path step!")

        self.__push(filtered_obs_map, debug_label)

    def exitSetLiteral(self, ctx):
        """
        Consumes nothing
        Produces a python set object with values from the set literal
        """

        literal_nodes = ctx.primitiveLiteral()

        # Make a python set from the set literal.  Can't go directly to a set
        # though because values of heterogenous types might overwrite each
        # other, e.g. 1 and True (which both hash to 1).  So collect the values
        # to an intermediate list first.
        first_type = None
        has_only_numbers = is_homogenous = True
        python_values = []
        for literal_node in literal_nodes:
            literal_terminal = _get_first_terminal_descendant(literal_node)
            literal_value = _literal_terminal_to_python_val(literal_terminal)

            if first_type is None:
                first_type = type(literal_value)
            elif first_type is not type(literal_value):
                is_homogenous = False

            # bool is a subclass of int!
            if not isinstance(literal_value, (int, float)) or \
                    isinstance(literal_value, bool):
                has_only_numbers = False

            python_values.append(literal_value)

        if python_values:
            if is_homogenous:
                s = set(python_values)
            elif has_only_numbers:
                # If it's mix of just ints and floats, let that pass through.
                # Python treats those more interoperably, e.g. 1.0 == 1, and
                # hash(1.0) == hash(1), so I don't think it's necessary to
                # promote ints to floats.
                s = set(python_values)
                is_homogenous = True

            if not is_homogenous:
                raise MatcherException(u"Nonhomogenous set: {}".format(
                    ctx.getText()))
        else:
            s = set()

        self.__push(s, u"exitSetLiteral ({})".format(ctx.getText()))


class Pattern:
    def __init__(self, pattern_str, stix_version=DEFAULT_VERSION):
        """
        Compile a pattern.

        :param pattern_str: The pattern to compile
        :param stix_version: The stix specification version
        :raises stix2patterns.pattern.ParseException: If there is a parse error
        """
        self.__pattern_str = pattern_str
        self.__stix_version = stix_version
        if self.__stix_version == VARSION_2_1:
            self.__pattern = Stix2Pattern21(pattern_str)
        else:
            self.__pattern = Stix2Pattern20(pattern_str)

    def __getattr__(self, name):
        return self.__pattern.__getattribute__(name)

    def match(self, observed_data_sdos, verbose=False, diagnostics=False):
        """
        Match this pattern against the given observations.  Returns matching
        SDOs.  The matcher can find many bindings; this function returns the
        SDOs corresponding to only the first binding found.

        :param observed_data_sdos: A list of observed-data SDOs, as a list of
            dicts.  STIX JSON should be parsed into native Python structures
            before calling this method.
        :param verbose: Whether to dump detailed info about matcher operation
        :param diagnostics: If False (the default), return the matching SDOs
            exactly as normal.  If True, return a structured
            DiagnosticReport describing which semantic stage eliminated
            non-matching candidates, while the "matched" determination and
            "matches" list remain identical to normal mode.
        :return: Matching SDOs, or a DiagnosticReport if diagnostics is True.
        :raises MatcherException: If an error occurs during matching
        """
        collector = None
        if diagnostics:
            collector = MatchDiagnostics(
                self.__pattern_str, self.__stix_version,
            )

        matcher = MatchListener(
            observed_data_sdos, verbose, stix_version=self.__stix_version,
            diagnostics=collector,
        )
        self.__pattern.walk(matcher)

        first_binding = next(matcher.matched(), [])
        matching_sdos = matcher.get_sdos_from_binding(first_binding)

        if collector is None:
            return matching_sdos

        # matched() has already converted instance IDs to observation
        # indexes, exactly as used by normal mode.
        binding = list(first_binding)

        return collector.build_report(
            bool(first_binding), matching_sdos, binding=binding,
            observation_count=len(matcher.observations),
        )

    def diagnose(self, observed_data_sdos, verbose=False):
        """
        Convenience wrapper for match(..., diagnostics=True).

        :return: DiagnosticReport
        """
        return self.match(observed_data_sdos, verbose, diagnostics=True)


def match(pattern, observed_data_sdos, verbose=False,
          stix_version=DEFAULT_VERSION, diagnostics=False):
    """
    Match the given pattern against the given observations.  Returns matching
    SDOs.  The matcher can find many bindings; this function returns the SDOs
    corresponding to only the first binding found.

    :param pattern: The STIX pattern
    :param observed_data_sdos: A list of observed-data SDOs, as a list of dicts.
        STIX JSON should be parsed into native Python structures before calling
        this function.
    :param verbose: Whether to dump detailed info about matcher operation
    :param stix_version: STIX specification version
    :param diagnostics: If True, return a structured DiagnosticReport instead
        of a bare list.  The determination itself is unchanged; see
        Pattern.match().
    :return: Matching SDOs, or a DiagnosticReport if diagnostics is True.
    :raises stix2patterns.pattern.ParseException: If there is a parse error
    :raises MatcherException: If an error occurs during matching
    """

    compiled_pattern = Pattern(pattern, stix_version)
    return compiled_pattern.match(
        observed_data_sdos, verbose, diagnostics=diagnostics,
    )


def match_with_diagnostics(pattern, observed_data_sdos, verbose=False,
                           stix_version=DEFAULT_VERSION):
    """
    Convenience wrapper for match(..., diagnostics=True).

    :return: DiagnosticReport
    """
    return match(
        pattern, observed_data_sdos, verbose,
        stix_version=stix_version, diagnostics=True,
    )


def main():
    """
    Can be used as a command line tool to test pattern-matcher.
    """
    return_value = 0

    arg_parser = argparse.ArgumentParser(description="Match STIX Patterns to STIX Observed Data")
    arg_parser.add_argument("-p", "--patterns", required=True,  help="""
    Specify a file containing STIX Patterns, one per line.
    """)
    arg_parser.add_argument("-f", "--file", required=True, help="""
    A file containing JSON list of STIX observed-data SDOs to match against.
    """)
    arg_parser.add_argument("-e", "--encoding", default="utf8", help="""
    Set encoding used for reading observation and pattern files.
    Must be an encoding name Python understands.  Default is utf8.
    """)
    arg_parser.add_argument("-s", "--stix_version", default=DEFAULT_VERSION, help="""
    Stix specification version. Default is 2.0.
    """)
    arg_parser.add_argument("-v", "--verbose", action="store_true",
                            help="""Be verbose""")
    arg_parser.add_argument("-q", "--quiet", action="count", help="""
    Run quietly. One -q will only print out NO MATCH information. Two will
    produce no match-related output. This option does not affect the action
    of -v, and error information will still be displayed.""", default=0)
    arg_parser.add_argument("--diagnostics", action="store_true", help="""
    Emit a structured JSON report for non-matching patterns, explaining the
    semantic stage at which candidates were eliminated. The exit status and
    error behavior are unchanged.""")

    args = arg_parser.parse_args()

    try:
        with io.open(args.file, encoding=args.encoding) as json_in:
            observed_data_sdos = json.load(json_in)

        # Support single SDOs by converting to a list.
        if not isinstance(observed_data_sdos, list):
            observed_data_sdos = [observed_data_sdos]

        with io.open(args.patterns, encoding=args.encoding) as patterns_in:
            for pattern in patterns_in:
                pattern = pattern.strip()
                if not pattern:
                    continue  # skip blank lines
                if pattern[0] == u"#":
                    continue  # skip commented out lines
                escaped_pattern = pattern.encode("unicode_escape").decode("ascii")
                if args.diagnostics:
                    report = match(
                        pattern, observed_data_sdos, args.verbose,
                        args.stix_version, diagnostics=True,
                    )
                    if report.matched:
                        if args.quiet < 1:
                            print(u"\nMATCH: ", escaped_pattern)
                    else:
                        if args.quiet < 2:
                            print(u"\nNO MATCH: ", escaped_pattern)
                            print(json.dumps(report, indent=2, default=str))
                        return_value = 1
                elif match(pattern, observed_data_sdos, args.verbose, args.stix_version):
                    if args.quiet < 1:
                        print(u"\nMATCH: ", escaped_pattern)
                else:
                    if args.quiet < 2:
                        print(u"\nNO MATCH: ", escaped_pattern)
                    return_value = 1
    except Exception:
        return_value = 2
        sys.excepthook(*sys.exc_info())
    return return_value


if __name__ == '__main__':
    sys.exit(main())
