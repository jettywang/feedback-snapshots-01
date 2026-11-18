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


def _step_filter_observations(observations, step):
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
        for cyber_obs_obj_id, cyber_obs_objs in six.iteritems(cyber_obs_obj_map):
            filtered_cyber_obs_obj_list = _step_into_objs(cyber_obs_objs, step)

            if len(filtered_cyber_obs_obj_list) > 0:
                filtered_cyber_obs_obj_map[cyber_obs_obj_id] = filtered_cyber_obs_obj_list

        if len(filtered_cyber_obs_obj_map) > 0:
            filtered_obs_map[obs_idx] = filtered_cyber_obs_obj_map

    return filtered_obs_map


def _step_filter_observations_index_star(observations):
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
    for obs_idx, cyber_obs_obj_map in six.iteritems(observations):
        filtered_cyber_obs_obj_map = {}
        for cyber_obs_obj_id, cyber_obs_objs in six.iteritems(cyber_obs_obj_map):
            stepped_cyber_obs_objs = []
            for cyber_obs_obj in cyber_obs_objs:
                if not isinstance(cyber_obs_obj, list):
                    continue

                stepped_cyber_obs_objs.extend(cyber_obs_obj)

            if len(stepped_cyber_obs_objs) > 0:
                filtered_cyber_obs_obj_map[cyber_obs_obj_id] = stepped_cyber_obs_objs

        if filtered_cyber_obs_obj_map:
            filtered_obs_map[obs_idx] = filtered_cyber_obs_obj_map

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


def _obs_map_prop_test(obs_map, predicate):
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
    :return: The transformed and filtered data, according to predicate.
    """
    passed_obs = {}
    for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
        passed_cyber_obs_obj_roots = set()
        for cyber_obs_obj_id, values in six.iteritems(cyber_obs_obj_map):
            for value in values:
                if predicate(value):
                    passed_cyber_obs_obj_roots.add(cyber_obs_obj_id)
                    break

        if passed_cyber_obs_obj_roots:
            passed_obs[obs_idx] = passed_cyber_obs_obj_roots

    return passed_obs


def _set_literal_to_python_value(ctx):
    """
    Convert a set literal parse-tree node to a Python set, using the same
    type-sensitive rules as the matcher callbacks.
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

    return s


class _PropTestSpec(object):
    """
    A reusable description of a property test.  The matcher callbacks and
    the optional witness/explanation code both use this so their semantics
    cannot drift apart.
    """

    def __init__(self, ctx, operator, literal, predicate,
                 literal_text=None, path_ctx=None):
        self.ctx = ctx
        self.operator = operator
        self.literal = literal
        self.predicate = predicate
        self.literal_text = literal_text
        self.path_ctx = path_ctx or ctx.objectPath()


def _build_prop_test_spec(ctx):
    """
    Build the predicate for a property test parse-tree node.  This mirrors
    the behaviour of the individual exitPropTest*() callbacks; those
    callbacks delegate here instead of defining the predicates inline.
    """
    ctx_name = type(ctx).__name__

    if ctx_name == u"PropTestEqualContext":
        literal_node = ctx.primitiveLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_tok = ctx.EQ() or ctx.NEQ()

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

        operator = u"{}{}".format(
            u"NOT " if ctx.NOT() else u"", op_tok.getText()
        )
        return _PropTestSpec(
            ctx, operator, literal_value, equality_pred,
            literal_terminal.getText()
        )

    elif ctx_name == u"PropTestOrderContext":
        literal_node = ctx.orderableLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_tok = ctx.GT() or ctx.LT() or ctx.GE() or ctx.LE()

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
                # writing is for binary<->string comparisons, when the string
                # is of the wrong form.  Spec says the result must be false.
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

        operator = u"{}{}".format(
            u"NOT " if ctx.NOT() else u"", op_tok.getText()
        )
        return _PropTestSpec(
            ctx, operator, literal_value, order_pred,
            literal_terminal.getText()
        )

    elif ctx_name == u"PropTestSetContext":
        s = _set_literal_to_python_value(ctx.setLiteral())
        # Only need to check one member; the set literal is homogeneous.
        is_set_of_timestamps = s and \
            isinstance(next(iter(s)), datetime.datetime)

        def set_pred(value):
            # timestamp hackage: if we have a set of timestamp literals from
            # the pattern and a string from the json, try to interpret the
            # json value as a timestamp too.
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

        operator = u"NOT IN" if ctx.NOT() else u"IN"
        return _PropTestSpec(
            ctx, operator, s, set_pred, ctx.setLiteral().getText()
        )

    elif ctx_name == u"PropTestLikeContext":
        operand_str = _literal_terminal_to_python_val(ctx.StringLiteral())
        operand_str = unicodedata.normalize("NFC", operand_str)
        regex = _like_to_regex(operand_str)
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

        operator = u"NOT LIKE" if ctx.NOT() else u"LIKE"
        return _PropTestSpec(
            ctx, operator, operand_str, like_pred,
            ctx.StringLiteral().getText()
        )

    elif ctx_name == u"PropTestRegexContext":
        regex_terminal = ctx.StringLiteral()
        regex = _literal_terminal_to_python_val(regex_terminal)
        regex = unicodedata.normalize("NFC", regex)
        compiled_re = re.compile(regex)

        # Support for binary pattern matching.
        is_binary_convertible = all(ord(c) < 256 for c in regex)
        compiled_bin_re = None
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

        operator = u"NOT MATCHES" if ctx.NOT() else u"MATCHES"
        return _PropTestSpec(
            ctx, operator, regex, regex_pred, regex_terminal.getText()
        )

    elif ctx_name == u"PropTestIsSubsetContext":
        subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        def subnet_pred(value):
            if isinstance(value, six.text_type):
                result = _ip_or_cidr_in_subnet(value, subnet_str)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        operator = u"NOT ISSUBSET" if ctx.NOT() else u"ISSUBSET"
        return _PropTestSpec(
            ctx, operator, subnet_str, subnet_pred,
            ctx.StringLiteral().getText()
        )

    elif ctx_name == u"PropTestIsSupersetContext":
        ip_or_subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        def contains_pred(value):
            if isinstance(value, six.text_type):
                result = _ip_or_cidr_in_subnet(ip_or_subnet_str, value)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        operator = u"NOT ISSUPERSET" if ctx.NOT() else u"ISSUPERSET"
        return _PropTestSpec(
            ctx, operator, ip_or_subnet_str, contains_pred,
            ctx.StringLiteral().getText()
        )

    raise MatcherInternalError(
        u"Unsupported property test: {}".format(ctx_name)
    )


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
    # The v20 and v21 packages each ship their own generated grammar, so a
    # context cannot be identified with a single imported grammar class.
    # Match on the rule name instead; this keeps binding sizes correct for
    # both STIX versions, which the explanation slot layout relies on.
    if type(ctx).__name__ == u"ComparisonExpressionContext":
        return 1
    elif type(ctx).__name__ == u"ObservationExpressionRepeatedContext":
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


class Witness(dict):
    """
    A single, JSON-friendly witness record.

    A witness is intentionally a plain mapping (with attribute access for
    convenience) so it can be serialized, persisted, and replayed without
    depending on matcher internals.  It never contains a complete input
    bundle; only the objects, paths, values, observation identity, and
    temporal evidence needed to justify one observation-expression binding.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


def _wrap_witness(value):
    """Recursively give explanation mappings attribute access."""
    if isinstance(value, dict):
        return Witness(
            (key, _wrap_witness(item))
            for key, item in six.iteritems(value)
        )
    if isinstance(value, list):
        return [_wrap_witness(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap_witness(item) for item in value)
    return value


class MatchExplanation(list):
    """
    The result of a match when explanations are requested.

    This deliberately subclasses ``list``: it contains the same matching
    observed-data SDOs the default API returns, so existing call sites can
    keep treating the result as the matching-SDO list.  The explanation is
    attached as additional attributes, and string indexing works too::

        result = match(pattern, observations, explain=True)
        result[0]                  # first matching observed-data SDO
        result.witnesses           # tuple of witness mappings
        result["witnesses"]        # same
        result.to_dict()           # JSON-friendly explanation

    ``to_dict()`` is the interchange form; it contains no whole input bundle.
    """

    def __init__(self, sdos, pattern, stix_version, witnesses,
                 time_constraints):
        super(MatchExplanation, self).__init__(sdos)
        self.pattern = pattern
        self.stix_version = stix_version
        self.witnesses = tuple(_wrap_witness(w) for w in witnesses)
        self.time_constraints = tuple(Witness(t) for t in time_constraints)
        self.matched_sdos = self
        self.sdos = self

    @property
    def matched(self):
        return bool(self.witnesses)

    def to_dict(self):
        return {
            u"pattern": self.pattern,
            u"stix_version": self.stix_version,
            u"matched": self.matched,
            u"witnesses": [dict(w) for w in self.witnesses],
            u"time_constraints": [dict(t) for t in self.time_constraints],
        }

    def get(self, key, default=None):
        if key == u"witnesses":
            return list(self.witnesses)
        if key == u"time_constraints":
            return list(self.time_constraints)
        if key == u"matched":
            return self.matched
        if key == u"pattern":
            return self.pattern
        if key == u"stix_version":
            return self.stix_version
        if key == u"sdos":
            return list(self)
        return default

    def keys(self):
        return (
            u"pattern", u"stix_version", u"matched", u"witnesses",
            u"time_constraints"
        )

    def __contains__(self, item):
        if isinstance(item, six.string_types):
            return item in self.keys()
        return super(MatchExplanation, self).__contains__(item)

    def __getitem__(self, key):
        if isinstance(key, six.string_types):
            sentinel = object()
            value = self.get(key, sentinel)
            if value is sentinel:
                raise KeyError(key)
            return value
        return super(MatchExplanation, self).__getitem__(key)

    def __repr__(self):
        return u"MatchExplanation(matched={}, witnesses={}, sdos={})".format(
            self.matched, len(self.witnesses), len(self)
        )

    def verify(self, observed_data_sdos=None, stix_version=None):
        """
        Verify this explanation against the given observations.

        With no observations, this checks structural completeness.  With
        observations, every selected comparison is re-evaluated against the
        current objects, every referenced object must still resolve, and the
        temporal constraints are re-checked.  Mutating a key object used as
        the reason therefore makes verification fail; mutating an object in an
        unselected OR branch does not.
        """
        return verify_explanation(
            self, observed_data_sdos,
            stix_version=stix_version or self.stix_version,
        )


_REQUIRED_WITNESS_KEYS = (
    u"slot", u"expression", u"observation", u"root_sco", u"comparisons",
    u"time",
)


def _source_text(pattern_str, ctx):
    """Return the original pattern text covered by a parse-tree node."""
    try:
        start = ctx.start.start
        stop = ctx.stop.stop
        if start is not None and stop is not None and stop >= start:
            return pattern_str[start:stop + 1]
    except (AttributeError, TypeError):
        pass
    try:
        return ctx.getText()
    except AttributeError:
        return u""


def _json_safe(value):
    """Convert a matched value to a deterministic JSON-friendly value."""
    if isinstance(value, datetime.datetime):
        return value.isoformat().replace(u"+00:00", u"Z")
    if isinstance(value, bytes):
        return {
            u"encoding": u"base64",
            u"data": base64.standard_b64encode(value).decode(u"ascii"),
        }
    if isinstance(value, set):
        return sorted(
            (_json_safe(v) for v in value),
            key=lambda v: repr(v),
        )
    if isinstance(value, dict):
        return dict(
            (six.text_type(k), _json_safe(v))
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _value_type_name(value):
    if isinstance(value, bool):
        return u"bool"
    if isinstance(value, datetime.datetime):
        return u"timestamp"
    if isinstance(value, bytes):
        return u"binary"
    if isinstance(value, six.text_type):
        return u"string"
    if isinstance(value, int):
        return u"integer"
    if isinstance(value, float):
        return u"float"
    if value is None:
        return u"null"
    if isinstance(value, dict):
        return u"object"
    if isinstance(value, (list, tuple)):
        return u"array"
    return type(value).__name__


def _token_attr(ctx, method):
    """Call a generated ANTLR accessor and return its non-None result(s)."""
    accessor = getattr(ctx, method, None)
    if accessor is None:
        return None
    value = accessor()
    if value is None:
        return None
    return value


def _one_token_attr(ctx, method):
    value = _token_attr(ctx, method)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _path_step_contexts(path_ctx):
    """
    Return path steps in textual order.  Consecutive steps are nested in the
    parse tree, so a pre-order traversal of the step nodes preserves order.
    """
    steps = []

    def visit(node):
        name = type(node).__name__
        if name in (u"IndexPathStepContext", u"KeyPathStepContext"):
            steps.append(node)
            return
        for i in range(getattr(node, u"getChildCount", lambda: 0)()):
            child = node.getChild(i)
            if isinstance(child, antlr4.ParserRuleContext):
                visit(child)

    component = _token_attr(path_ctx, u"objectPathComponent")
    if component is not None:
        if isinstance(component, list):
            for c in component:
                visit(c)
        else:
            visit(component)
    return steps


def _path_component_name(ctx):
    if _token_attr(ctx, u"IdentifierWithoutHyphen") is not None:
        return _token_attr(ctx, u"IdentifierWithoutHyphen").getText()
    return _literal_terminal_to_python_val(ctx.StringLiteral())


def _path_parse(path_ctx):
    """
    Parse an object path into a type, a textual path, and path steps.
    """
    type_ = path_ctx.objectType().getText()
    first_ctx = path_ctx.firstPathComponent()
    steps = [{
        u"kind": u"property",
        u"name": _path_component_name(first_ctx),
    }]

    for ctx in _path_step_contexts(path_ctx):
        if type(ctx).__name__ == u"IndexPathStepContext":
            if _token_attr(ctx, u"ASTERISK") is not None:
                steps.append({u"kind": u"index", u"index": None})
            else:
                index = _literal_terminal_to_python_val(
                    ctx.IntPosLiteral() or ctx.IntNegLiteral()
                )
                steps.append({u"kind": u"index", u"index": index})
        else:
            steps.append({
                u"kind": u"key",
                u"name": _path_component_name(ctx),
            })

    return type_, steps


def _observation_objects(sdo, stix_version):
    """
    Return a deterministic list of (object id, object) pairs from a
    normalized observation.
    """
    objects = sdo.get(u"objects")
    if objects is None:
        return []
    if stix_version == VARSION_2_1:
        if isinstance(objects, dict):
            return sorted(six.iteritems(objects), key=lambda kv: six.text_type(kv[0]))
        return [
            (obj.get(u"id"), obj)
            for obj in objects
            if isinstance(obj, dict)
        ]
    return sorted(six.iteritems(objects), key=lambda kv: six.text_type(kv[0]))


def _observation_id(sdo, stix_version):
    if stix_version == VARSION_2_1:
        for obj in sdo.get(u"objects", []):
            if isinstance(obj, dict) and obj.get(u"type") == u"observed-data":
                return obj.get(u"id")
    return sdo.get(u"id")


def _format_timestamp(dt):
    return dt.isoformat().replace(u"+00:00", u"Z")


def _resolve_reference(obs, ref, stix_version):
    """Resolve a reference within one normalized observation."""
    if not isinstance(ref, six.text_type):
        return None
    if stix_version == VARSION_2_1:
        for obj in obs.get(u"objects", []):
            if isinstance(obj, dict) and obj.get(u"id") == ref:
                return ref, obj
        return None
    objects = obs.get(u"objects", {})
    if isinstance(objects, dict) and ref in objects:
        return ref, objects[ref]
    return None


def _apply_path_step(states, step, obs, stix_version):
    next_states = []
    if step[u"kind"] == u"index":
        index = step[u"index"]
        for state in states:
            value = state[u"value"]
            if not isinstance(value, list):
                continue
            if index is None:
                for i, child in enumerate(value):
                    next_states.append({
                        u"value": child,
                        u"tokens": state[u"tokens"] + [{
                            u"kind": u"index", u"index": i,
                        }],
                        u"ref_ids": [state[u"ref_ids"][i]]
                    if state.get(u"ref_ids") else [],
                    })
            elif 0 <= index < len(value):
                next_states.append({
                    u"value": value[index],
                    u"tokens": state[u"tokens"] + [{
                        u"kind": u"index", u"index": index,
                    }],
                    u"ref_ids": [state[u"ref_ids"][index]]
                    if state.get(u"ref_ids") else [],
                })
        return next_states

    # A key/property step.
    name = step[u"name"]
    for state in states:
        value = state[u"value"]
        if not isinstance(value, dict) or name not in value:
            continue

        raw = value[name]
        tokens = state[u"tokens"] + [{
            u"kind": u"property", u"name": name,
        }]

        if name.endswith(u"_ref"):
            if not isinstance(raw, six.text_type):
                raise MatcherException(
                    u"The value of reference property '{}' was not "
                    u"a string!  Got {}".format(name, raw)
                )
            resolved = _resolve_reference(obs, raw, stix_version)
            if resolved is None:
                continue
            target_id, target = resolved
            next_states.append({
                u"value": target,
                u"tokens": tokens + [{
                    u"kind": u"reference",
                    u"property": name,
                    u"target_sco_id": target_id,
                }],
                u"ref_ids": [target_id],
            })
        elif name.endswith(u"_refs"):
            if not isinstance(raw, list):
                raise MatcherException(
                    u"The value of reference list property '{}' was not "
                    u"a list!  Got {}".format(name, raw)
                )
            refs = []
            ref_ids = []
            for ref in raw:
                if not isinstance(ref, six.text_type):
                    raise MatcherException(
                        u"A value of reference property '{}' was not "
                        u"a string!  Got {}".format(name, ref)
                    )
                resolved = _resolve_reference(obs, ref, stix_version)
                if resolved is not None:
                    ref_id, ref_obj = resolved
                    ref_ids.append(ref_id)
                    refs.append(ref_obj)
            if refs:
                # The matcher substitutes the list of resolved referents for
                # the reference list.  Keep that shape for index steps.
                next_states.append({
                    u"value": refs,
                    u"tokens": tokens + [{
                        u"kind": u"references",
                        u"property": name,
                        u"target_sco_ids": ref_ids,
                    }],
                    u"ref_ids": ref_ids,
                })
        else:
            next_states.append({
                u"value": _process_prop_suffix(name, raw),
                u"tokens": tokens,
                u"ref_ids": [],
            })

    return next_states


def _reference_chain(tokens):
    chain = [tokens[0][u"sco_id"]]
    for token in tokens:
        if token[u"kind"] == u"reference":
            chain.append(token[u"target_sco_id"])
        elif token[u"kind"] == u"references":
            chain.extend(token[u"target_sco_ids"])
    return chain


def _finalize_tokens(tokens):
    """
    Collapse a reference-list token plus the index chosen from it into a
    single reference token.  This keeps the witness precise: a list-valued
    reference property does not drag every sibling referent into the reason,
    only the one actually selected.
    """
    result = [dict(tokens[0])]
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token[u"kind"] == u"references" and i + 1 < len(tokens):
            index_token = tokens[i + 1]
            if index_token[u"kind"] == u"index" and \
                    index_token[u"index"] is not None:
                target_ids = token[u"target_sco_ids"]
                index = index_token[u"index"]
                if 0 <= index < len(target_ids):
                    result.append({
                        u"kind": u"reference",
                        u"property": token[u"property"],
                        u"target_sco_id": target_ids[index],
                    })
                    i += 2
                    continue
        result.append(dict(token))
        i += 1
    return result


def _eval_prop_test(spec, obs_idx, obs, pattern_str, stix_version):
    """
    Evaluate one property test for every root SCO in the observation.

    Returns a mapping from root SCO ID to a comparison witness.  Only the
    first passing value per root is recorded, which is enough for an
    existential witness and keeps output deterministic.
    """
    path_ctx = spec.path_ctx
    type_, steps = _path_parse(path_ctx)
    if stix_version == VARSION_2_1 and type_ in TYPES_V21:
        return {}

    path_text = _source_text(pattern_str, path_ctx).split(u":", 1)[-1]
    expression = _source_text(pattern_str, spec.ctx)

    results = {}
    for root_id, root_obj in _observation_objects(obs, stix_version):
        if not isinstance(root_obj, dict) or root_obj.get(u"type") != type_:
            continue

        states = [{
            u"value": root_obj,
            u"tokens": [{
                u"kind": u"root",
                u"sco_id": root_id,
                u"type": type_,
            }],
            u"ref_ids": [],
        }]
        for step in steps:
            states = _apply_path_step(states, step, obs, stix_version)
            if not states:
                break

        for state in states:
            if spec.predicate(state[u"value"]):
                tokens = _finalize_tokens(state[u"tokens"])
                results[root_id] = {
                    u"kind": u"comparison",
                    u"expression": expression,
                    u"path": path_text,
                    u"object_type": type_,
                    u"operator": spec.operator,
                    u"literal": _json_safe(spec.literal),
                    u"literal_text": spec.literal_text,
                    u"value": _json_safe(state[u"value"]),
                    u"value_type": _value_type_name(state[u"value"]),
                    u"tokens": tokens,
                    u"reference_chain": _reference_chain(tokens),
                    u"root_sco": {
                        u"id": root_id,
                        u"type": root_obj.get(u"type"),
                    },
                }
                break

    return results


def _eval_comparison_node(ctx, obs_idx, obs, pattern_str, stix_version):
    """
    Evaluate a comparison-expression subtree, returning root-ID-keyed
    witnesses.

    OR records only the branch that actually justified each root; an
    unsatisfied branch is never included.  AND requires both sides to hold
    for the same root SCO.
    """
    name = type(ctx).__name__

    if name == u"PropTestParenContext":
        return _eval_comparison_node(
            ctx.comparisonExpression(), obs_idx, obs,
            pattern_str, stix_version
        )

    if name.startswith(u"PropTest") and name.endswith(u"Context"):
        spec = _build_prop_test_spec(ctx)
        test_map = _eval_prop_test(
            spec, obs_idx, obs, pattern_str, stix_version
        )
        return dict(
            (root_id, {
                u"kind": u"test",
                u"children": [test],
                u"comparisons": [test],
            })
            for root_id, test in six.iteritems(test_map)
        )

    if name == u"ComparisonExpressionAndContext":
        children = _token_attr(ctx, u"comparisonExpressionAnd")
        if children and len(children) == 2:
            left = _eval_comparison_node(
                children[0], obs_idx, obs, pattern_str, stix_version
            )
            right = _eval_comparison_node(
                children[1], obs_idx, obs, pattern_str, stix_version
            )
            result = {}
            for root_id in sorted(set(left) & set(right), key=six.text_type):
                lw = left[root_id]
                rw = right[root_id]
                result[root_id] = {
                    u"kind": u"and",
                    u"children": [lw, rw],
                    u"comparisons": (
                        list(lw[u"comparisons"]) +
                        list(rw[u"comparisons"])
                    ),
                }
            return result
        prop_test = _one_token_attr(ctx, u"propTest")
        if prop_test is None:
            raise MatcherInternalError(
                u"Unsupported comparison AND node: {}".format(ctx.getText())
            )
        return _eval_comparison_node(
            prop_test, obs_idx, obs, pattern_str, stix_version
        )

    if name == u"ComparisonExpressionContext":
        children = _token_attr(ctx, u"comparisonExpression")
        if children and len(children) == 2:
            left = _eval_comparison_node(
                children[0], obs_idx, obs, pattern_str, stix_version
            )
            right = _eval_comparison_node(
                children[1], obs_idx, obs, pattern_str, stix_version
            )
            result = {}
            for root_id in sorted(set(left) | set(right), key=six.text_type):
                if root_id in left:
                    chosen = left[root_id]
                    branch = 0
                else:
                    chosen = right[root_id]
                    branch = 1
                result[root_id] = {
                    u"kind": u"or",
                    u"selected_branch": branch,
                    u"children": [chosen],
                    u"comparisons": list(chosen[u"comparisons"]),
                }
            return result
        and_ctx = _one_token_attr(ctx, u"comparisonExpressionAnd")
        if and_ctx is None:
            raise MatcherInternalError(
                u"Unsupported comparison expression: {}".format(ctx.getText())
            )
        return _eval_comparison_node(
            and_ctx, obs_idx, obs, pattern_str, stix_version
        )

    raise MatcherInternalError(
        u"Unsupported comparison node: {}".format(name)
    )


def _slot_layout(ctx, pattern_str, stix_version, scopes):
    """
    Build the binding-slot layout for the parse tree.

    Each returned slot corresponds to one position in a binding tuple, in
    exactly the order the matcher produces them.  Qualifier scopes are
    accumulated for later temporal verification.
    """
    name = type(ctx).__name__

    if name == u"PatternContext":
        return _slot_layout(
            ctx.observationExpressions(), pattern_str, stix_version, scopes
        )

    if name == u"ObservationExpressionsContext":
        children = _token_attr(ctx, u"observationExpressions")
        if children and len(children) == 2:
            left = _slot_layout(
                children[0], pattern_str, stix_version, scopes
            )
            right = _slot_layout(
                children[1], pattern_str, stix_version, scopes
            )
            members = left + right
            scope = {
                u"kind": u"followedby",
                u"members": members,
                u"left": left,
                u"right": right,
            }
            scopes.append(scope)
            for slot in members:
                slot[u"scopes"].append(scope)
            return members
        return _slot_layout(
            ctx.observationExpressionOr(), pattern_str, stix_version, scopes
        )

    if name == u"ObservationExpressionOrContext":
        children = _token_attr(ctx, u"observationExpressionOr")
        if children and len(children) == 2:
            return (
                _slot_layout(children[0], pattern_str, stix_version, scopes) +
                _slot_layout(children[1], pattern_str, stix_version, scopes)
            )
        return _slot_layout(
            ctx.observationExpressionAnd(), pattern_str, stix_version, scopes
        )

    if name == u"ObservationExpressionAndContext":
        children = _token_attr(ctx, u"observationExpressionAnd")
        if children and len(children) == 2:
            left = _slot_layout(
                children[0], pattern_str, stix_version, scopes
            )
            right = _slot_layout(
                children[1], pattern_str, stix_version, scopes
            )
            members = left + right
            scope = {
                u"kind": u"and",
                u"members": members,
            }
            scopes.append(scope)
            for slot in members:
                slot[u"scopes"].append(scope)
            return members
        child = _one_token_attr(ctx, u"observationExpression")
        if child is None:
            raise MatcherInternalError(
                u"Unsupported observation AND node: {}".format(ctx.getText())
            )
        return _slot_layout(child, pattern_str, stix_version, scopes)

    if name == u"ObservationExpressionSimpleContext":
        return [{
            u"ctx": ctx,
            u"expression": _source_text(pattern_str, ctx),
            u"scopes": [],
            u"repeats": [],
        }]

    if name == u"ObservationExpressionCompoundContext":
        return _slot_layout(
            ctx.observationExpressions(), pattern_str, stix_version, scopes
        )

    if name == u"ObservationExpressionWithinContext":
        child = _slot_layout(
            ctx.observationExpression(), pattern_str, stix_version, scopes
        )
        value = _literal_terminal_to_python_val(
            ctx.withinQualifier().FloatPosLiteral() or
            ctx.withinQualifier().IntPosLiteral()
        )
        if value <= 0:
            raise MatcherException(
                u"Invalid WITHIN value (must be positive): {}".format(value)
            )
        scope = {
            u"kind": u"within",
            u"seconds": value,
            u"members": child,
        }
        scopes.append(scope)
        for slot in child:
            slot[u"scopes"].append(scope)
        return child

    if name == u"ObservationExpressionStartStopContext":
        child = _slot_layout(
            ctx.observationExpression(), pattern_str, stix_version, scopes
        )
        qualifier = ctx.startStopQualifier()
        if stix_version == VARSION_2_1:
            start_dt = _literal_terminal_to_python_val(
                qualifier.TimestampLiteral(0)
            )
            stop_dt = _literal_terminal_to_python_val(
                qualifier.TimestampLiteral(1)
            )
        else:
            start_str = _literal_terminal_to_python_val(
                qualifier.StringLiteral(0)
            )
            stop_str = _literal_terminal_to_python_val(
                qualifier.StringLiteral(1)
            )
            try:
                start_dt = _str_to_datetime(start_str)
                stop_dt = _str_to_datetime(stop_str)
            except ValueError as e:
                six.raise_from(MatcherException(*e.args), e)
        scope = {
            u"kind": u"start_stop",
            u"start": _format_timestamp(start_dt),
            u"stop": _format_timestamp(stop_dt),
            u"members": child,
        }
        scopes.append(scope)
        for slot in child:
            slot[u"scopes"].append(scope)
        return child

    if name == u"ObservationExpressionRepeatedContext":
        times = _literal_terminal_to_python_val(
            ctx.repeatedQualifier().IntPosLiteral()
        )
        if times < 1:
            raise MatcherException(
                u"Invalid repetition count: {}".format(times)
            )
        members = []
        for repeat_index in range(times):
            # Rebuild the child layout for each repetition so every
            # repetition owns distinct slot objects, and any qualifier scopes
            # inside the repeated expression refer to slots in the final
            # binding (not to discarded layout copies).
            child = _slot_layout(
                ctx.observationExpression(), pattern_str, stix_version,
                scopes,
            )
            for child_slot in child:
                child_slot[u"repeats"] = list(child_slot[u"repeats"]) + [{
                    u"times": times,
                    u"index": repeat_index,
                }]
                members.append(child_slot)
        scope = {
            u"kind": u"repeats",
            u"times": times,
            u"members": members,
        }
        scopes.append(scope)
        for slot in members:
            slot[u"scopes"].append(scope)
        return members

    raise MatcherInternalError(
        u"Unsupported observation expression node: {}".format(name)
    )


def _scope_to_dict(scope):
    result = {
        key: value
        for key, value in six.iteritems(scope)
        if key not in (u"members", u"left", u"right")
    }
    result[u"slots"] = sorted(slot[u"slot"] for slot in scope[u"members"])
    if u"left" in scope:
        result[u"left_slots"] = sorted(
            slot[u"slot"] for slot in scope[u"left"]
        )
        result[u"right_slots"] = sorted(
            slot[u"slot"] for slot in scope[u"right"]
        )
    return result


def _build_explanation(pattern, pattern_str, matcher, raw_binding,
                       stix_version):
    """
    Build a MatchExplanation from a successful (or empty) raw binding.

    The binding contains the instance IDs chosen by the matcher; the witness
    builder independently re-selects the actual root SCO, path, value and
    reference chain from the observation, so the explanation is self-contained
    and does not expose the matcher's debug stack.
    """
    observations = matcher.get_observations()
    tree = pattern.get_parse_tree()
    scopes = []
    slots = _slot_layout(tree, pattern_str, stix_version, scopes)
    for index, slot in enumerate(slots):
        slot[u"slot"] = index

    sorted_scopes = sorted(
        scopes,
        key=lambda s: (
            min(slot[u"slot"] for slot in s[u"members"]),
            s[u"kind"],
        )
    )
    witnesses = []
    for slot in slots:
        slot_index = slot[u"slot"]
        if slot_index >= len(raw_binding):
            continue
        instance_id = raw_binding[slot_index]
        if instance_id is None:
            # The matcher chose the other side of an OR; this slot is not
            # part of the reason.
            continue
        obs_idx, inst_idx = instance_id
        obs = observations[obs_idx]
        leaf_ctx = slot[u"ctx"]
        comparison_ctx = leaf_ctx.comparisonExpression()
        eval_map = _eval_comparison_node(
            comparison_ctx, obs_idx, obs, pattern_str, stix_version
        )
        if not eval_map:
            # The matcher bound this slot, so the selected expression must
            # hold.  If not, the explanation could not be recomputed: refuse
            # to fabricate a reason rather than emitting a misleading one.
            raise MatcherInternalError(
                u"Unable to explain bound observation expression: {}".format(
                    slot[u"expression"]
                )
            )

        root_id = sorted(eval_map, key=six.text_type)[0]
        node = eval_map[root_id]
        comparisons = list(node[u"comparisons"])
        first = comparisons[0] if comparisons else {}

        interval = matcher.get_time_interval(obs_idx)
        observation = {
            u"index": obs_idx,
            u"instance": inst_idx,
            u"id": _observation_id(obs, stix_version),
            u"first_observed": _format_timestamp(interval[0]),
            u"last_observed": _format_timestamp(interval[1]),
            u"number_observed": matcher.get_number_observed(obs_idx),
        }
        qualifiers = [
            _scope_to_dict(scope)
            for scope in slot[u"scopes"]
        ]
        witness = {
            u"slot": slot_index,
            u"expression": slot[u"expression"],
            u"observation": observation,
            u"root_sco": {
                u"id": root_id,
                u"type": first.get(u"object_type"),
            },
            u"sco_id": root_id,
            u"path": first.get(u"path"),
            u"property": first.get(u"path"),
            u"operator": first.get(u"operator"),
            u"literal": first.get(u"literal"),
            u"literal_text": first.get(u"literal_text"),
            u"value": first.get(u"value"),
            u"value_type": first.get(u"value_type"),
            u"comparisons": comparisons,
            u"evaluation": node,
            u"time": {
                u"first_observed": observation[u"first_observed"],
                u"last_observed": observation[u"last_observed"],
                u"instance": inst_idx,
            },
            u"qualifiers": qualifiers,
            u"repeats": list(slot[u"repeats"]),
        }
        witnesses.append(witness)

    witnesses.sort(key=lambda w: w[u"slot"])

    # Only constraints which constrain a selected slot are part of the
    # reason.  A qualifier wholly inside an unselected OR branch is omitted,
    # and a shared qualifier is narrowed to the selected side.
    selected_slots = set(w[u"slot"] for w in witnesses)
    scope_dicts = []
    for scope in sorted_scopes:
        scope_dict = _scope_to_dict(scope)
        scope_dict[u"slots"] = [
            slot for slot in scope_dict[u"slots"]
            if slot in selected_slots
        ]
        if u"left_slots" in scope_dict:
            scope_dict[u"left_slots"] = [
                slot for slot in scope_dict[u"left_slots"]
                if slot in selected_slots
            ]
            scope_dict[u"right_slots"] = [
                slot for slot in scope_dict[u"right_slots"]
                if slot in selected_slots
            ]
            if not scope_dict[u"left_slots"] or \
                    not scope_dict[u"right_slots"]:
                continue
        if not scope_dict[u"slots"]:
            continue
        scope_dicts.append(scope_dict)

    explanation_dict = {
        u"pattern": pattern_str,
        u"stix_version": stix_version,
        u"matched": bool(witnesses),
        u"witnesses": witnesses,
        u"time_constraints": scope_dicts,
    }
    return explanation_dict


def _walk_tokens(tokens, obs, stix_version):
    """
    Replay a witness token path from the current observation data.  Returns
    the selected value, or raises KeyError/MatcherException if it no longer
    resolves.
    """
    if not tokens:
        raise KeyError(u"empty token path")
    root_token = tokens[0]
    if root_token.get(u"kind") != u"root":
        raise KeyError(u"token path does not start at a root SCO")
    resolved = _resolve_reference(
        obs, root_token[u"sco_id"], stix_version
    )
    if resolved is None:
        # v2.0 object keys are not references but local IDs; look them up
        # directly as well.
        objects = obs.get(u"objects", {})
        if isinstance(objects, dict) and root_token[u"sco_id"] in objects:
            value = objects[root_token[u"sco_id"]]
        else:
            raise KeyError(root_token[u"sco_id"])
    else:
        value = resolved[1]

    for token in tokens[1:]:
        kind = token.get(u"kind")
        if kind == u"property":
            if not isinstance(value, dict) or token[u"name"] not in value:
                raise KeyError(token[u"name"])
            value = _process_prop_suffix(token[u"name"], value[token[u"name"]])
        elif kind == u"reference":
            # The previous property step yielded either a raw reference
            # value or (for _refs) the raw reference list.  Resolve the
            # recorded target and confirm it is still reachable.
            target_id = token[u"target_sco_id"]
            candidates = value if isinstance(value, list) else [value]
            matched = None
            for candidate in candidates:
                resolved = _resolve_reference(obs, candidate, stix_version)
                if resolved is not None and resolved[0] == target_id:
                    matched = resolved[1]
                    break
            if matched is None:
                raise KeyError(target_id)
            value = matched
        elif kind == u"references":
            # The previous property step yielded the raw reference list.
            if not isinstance(value, list):
                raise KeyError(token[u"property"])
            resolved_objs = []
            for ref_id in token[u"target_sco_ids"]:
                resolved = _resolve_reference(obs, ref_id, stix_version)
                if resolved is None:
                    raise KeyError(ref_id)
                resolved_objs.append(resolved[1])
            value = resolved_objs
        elif kind == u"index":
            if not isinstance(value, list):
                raise KeyError(u"index")
            index = token[u"index"]
            if index is None:
                return value
            if index < 0 or index >= len(value):
                raise KeyError(index)
            value = value[index]
        else:
            raise KeyError(kind)
    return value


def _comparison_matches(existing, candidate):
    return (
        existing.get(u"path") == candidate.get(u"path") and
        existing.get(u"operator") == candidate.get(u"operator") and
        existing.get(u"literal") == candidate.get(u"literal") and
        existing.get(u"value") == candidate.get(u"value") and
        existing.get(u"value_type") == candidate.get(u"value_type") and
        existing.get(u"reference_chain") == candidate.get(u"reference_chain")
    )


def _verify_time_constraints(witnesses, time_constraints, matcher):
    by_slot = dict((w[u"slot"], w) for w in witnesses)

    for constraint in time_constraints:
        kind = constraint.get(u"kind")
        slots = constraint.get(u"slots", [])
        selected = [by_slot[s] for s in slots if s in by_slot]

        # A scope belonging entirely to an unselected OR branch is not part
        # of the reason, so it is not re-checked.  This is precisely what
        # keeps unselected branches out of the explanation.
        if not selected:
            continue

        if kind in (u"repeats", u"and"):
            pairs = [
                (w[u"observation"][u"index"], w[u"observation"][u"instance"])
                for w in selected
            ]
            if len(pairs) != len(set(pairs)):
                return False
        elif kind == u"within":
            intervals = [
                matcher.get_time_interval(w[u"observation"][u"index"])
                for w in selected
            ]
            duration = dateutil.relativedelta.relativedelta(
                seconds=constraint[u"seconds"]
            )
            if intervals and not _timestamp_intervals_within(
                    intervals, duration):
                return False

        elif kind == u"start_stop":
            start = _str_to_datetime(constraint[u"start"])
            stop = _str_to_datetime(constraint[u"stop"])
            if start >= stop:
                return False
            for witness in selected:
                interval = matcher.get_time_interval(
                    witness[u"observation"][u"index"]
                )
                if _overlap(start, stop, *interval) not in (
                        _OVERLAP, _OVERLAP_TOUCH_OUTER):
                    return False

        elif kind == u"followedby":
            left_slots = constraint.get(u"left_slots", [])
            right_slots = constraint.get(u"right_slots", [])
            left = [by_slot[s] for s in left_slots if s in by_slot]
            right = [by_slot[s] for s in right_slots if s in by_slot]
            if not left or not right:
                return False
            left_instances = set(
                (w[u"observation"][u"index"], w[u"observation"][u"instance"])
                for w in left
            )
            right_instances = set(
                (w[u"observation"][u"index"], w[u"observation"][u"instance"])
                for w in right
            )
            if left_instances & right_instances:
                return False
            latest_left = max(
                matcher.get_time_interval(w[u"observation"][u"index"])[0]
                for w in left
            )
            earliest_right = min(
                matcher.get_time_interval(w[u"observation"][u"index"])[1]
                for w in right
            )
            if latest_left > earliest_right:
                return False

    return True


def _verify_witnesses(pattern_str, stix_version, witnesses,
                      time_constraints, observations):
    """
    Re-evaluate explanation witnesses against observations.  This is the
    independent replay used by MatchExplanation.verify().
    """
    for witness in witnesses:
        for key in _REQUIRED_WITNESS_KEYS:
            if key not in witness:
                return False

    compiled = Pattern(pattern_str, stix_version)
    matcher = MatchListener(
        observations, verbose=False, stix_version=stix_version
    )
    normalized = matcher.get_observations()
    tree = compiled.get_parse_tree()
    scopes = []
    slots = _slot_layout(tree, pattern_str, stix_version, scopes)
    for index, slot in enumerate(slots):
        slot[u"slot"] = index
    slots_by_index = dict((s[u"slot"], s) for s in slots)

    for witness in witnesses:
        slot = slots_by_index.get(witness[u"slot"])
        if slot is None:
            return False
        obs_idx = witness[u"observation"][u"index"]
        if obs_idx < 0 or obs_idx >= len(normalized):
            return False
        obs = normalized[obs_idx]

        # Observation identity and temporal evidence must still agree.
        if witness[u"observation"].get(u"id") is not None:
            if _observation_id(obs, stix_version) != \
                    witness[u"observation"][u"id"]:
                return False
        interval = matcher.get_time_interval(obs_idx)
        if _format_timestamp(interval[0]) != \
                witness[u"time"][u"first_observed"]:
            return False
        if _format_timestamp(interval[1]) != \
                witness[u"time"][u"last_observed"]:
            return False

        # Re-evaluate the exact slot and require the selected branch and
        # comparison evidence to still be present.
        eval_map = _eval_comparison_node(
            slot[u"ctx"].comparisonExpression(),
            obs_idx, obs, pattern_str, stix_version,
        )
        root_id = witness[u"root_sco"][u"id"]
        if root_id not in eval_map:
            return False
        new_comparisons = eval_map[root_id][u"comparisons"]

        for old in witness[u"comparisons"]:
            if not any(
                    _comparison_matches(old, new)
                    for new in new_comparisons):
                return False
            try:
                current_value = _walk_tokens(
                    old[u"tokens"], obs, stix_version
                )
            except (KeyError, MatcherException):
                return False
            if _json_safe(current_value) != old[u"value"]:
                return False
            if _value_type_name(current_value) != old[u"value_type"]:
                return False

    return _verify_time_constraints(
        witnesses, time_constraints, matcher
    )


def verify_explanation(explanation, observed_data_sdos=None,
                       stix_version=None):
    """
    Verify a MatchExplanation (or its to_dict() form) against observations.

    :param explanation: A MatchExplanation, an explanation dict, or a list of
        witness mappings.
    :param observed_data_sdos: The observations to replay against.  If None,
        only structural completeness is checked.
    :param stix_version: Overrides the version recorded in the explanation.
    :return: True if the explanation is complete and still valid.
    """
    if isinstance(explanation, MatchExplanation):
        data = explanation.to_dict()
    elif isinstance(explanation, dict):
        data = explanation
    else:
        data = {u"witnesses": list(explanation)}

    witnesses = list(data.get(u"witnesses", []))
    if any(
            not all(key in witness for key in _REQUIRED_WITNESS_KEYS)
            for witness in witnesses):
        return False

    if observed_data_sdos is None:
        # Structural-only verification: witnesses must carry enough
        # information to replay a comparison.
        for witness in witnesses:
            if not witness.get(u"comparisons"):
                return False
            for comparison in witness[u"comparisons"]:
                if not comparison.get(u"tokens"):
                    return False
        return True

    version = stix_version or data.get(u"stix_version") or DEFAULT_VERSION
    pattern_str = data.get(u"pattern")
    if not pattern_str:
        return False
    return _verify_witnesses(
        pattern_str, version, witnesses,
        list(data.get(u"time_constraints", [])),
        observed_data_sdos,
    )



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

    def __init__(self, observed_data_sdos, verbose=False, stix_version=DEFAULT_VERSION):
        """
        Initialize this match listener.

        :param observed_data_sdos: A list of STIX observed-data SDOs.
        :param verbose: If True, dump detailed information about triggered
            callbacks and stack activity to stdout.  This can provide useful
            information about what the matcher is doing.
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

    def matched(self, raw=False):
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

        :param raw: If True, yield the matcher's internal instance IDs
            (observation index, instance index) instead of collapsing every
            observation to a single slot int.  This is only meant for the
            optional explanation machinery; the default contract is unchanged.
        :return: The found bindings, if any.
        """
        # At the end of the parse, the top stack element will be a generator of
        # all the found bindings (as tuples).  If there is at least one, the
        # pattern matched.  If the tree traversal failed, the top stack element
        # could be anything... so don't call this function in that situation!
        if self.__compute_stack:
            for binding in self.__compute_stack[0]:
                if raw:
                    yield tuple(binding)
                else:
                    # convert back from complex instance_id to obs_index
                    yield tuple(map(self.get_obs_index_filtered, binding))
        return

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

    def get_observations(self):
        """Return the normalized observations used by the matcher."""
        return self.__observations

    def get_time_interval(self, obs_idx):
        """Return the (first_observed, last_observed) interval for an
        observation index."""
        return self.__time_intervals[obs_idx]

    def get_number_observed(self, obs_idx):
        """Return number_observed for an observation index."""
        return self.__number_observed[obs_idx]

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
                # cache and one generator are empty
                return
            while _next_rhs_binding is not None or _next_lhs_binding is not None:
                # while there are new bindings to explore
                if _next_rhs_binding is not None:
                    # if there is a new rhs binding yield valid combinations
                    for combination in self.__followed_by_right_join(_lhs_cache, _next_rhs_binding):
                        yield combination
                    # update cache
                    _rhs_cache.append(_next_rhs_binding)
                    _next_rhs_binding = next(rhs_bindings, None)

                if _next_lhs_binding is not None:
                    # if there is a new rhs binding yield valid combinations
                    for combination in self.__followed_by_left_join(_next_lhs_binding, _rhs_cache):
                        yield combination
                    # update cache
                    _lhs_cache.append(_next_lhs_binding)
                    _next_lhs_binding = next(lhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

    def __followed_by_left_join(self, lhs_binding, rhs_bindings):
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

    def __followed_by_right_join(self, lhs_bindings, rhs_binding):
        # Yield all valid FOLLOWEDBY joins between a list of lhs_bindings
        # and a single rhs_binding

        earliest_rhs_last_timestamp = self.__earliest_last_timestamp(rhs_binding)

        for lhs_binding in lhs_bindings:

            if _disjoint(lhs_binding, rhs_binding):
                latest_lhs_first_timestamp = self.__latest_first_timestamp(lhs_binding)

                if latest_lhs_first_timestamp <= earliest_rhs_last_timestamp:
                    yield (lhs_binding + rhs_binding)

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
                ctx.observationExpressionOr(1))
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
            _next_rhs_binding = next(rhs_bindings, None)
            _next_lhs_binding = next(lhs_bindings, None)
            if _next_rhs_binding is None or _next_lhs_binding is None:
                # cache and one generator are empty
                return
            while _next_rhs_binding is not None or _next_lhs_binding is not None:
                # while there are new bindings to explore
                if _next_rhs_binding is not None:
                    # if there is a new rhs binding
                    for lhs_binding in _lhs_cache:
                        # yield valid combinations
                        if _disjoint(lhs_binding, _next_rhs_binding):
                            yield (lhs_binding + _next_rhs_binding)
                    # update cache
                    _rhs_cache.append(_next_rhs_binding)
                    _next_rhs_binding = next(rhs_bindings, None)

                if _next_lhs_binding is not None:
                    # if there is a new rhs binding
                    for rhs_binding in _rhs_cache:
                        # yield valid combinations
                        if _disjoint(_next_lhs_binding, rhs_binding):
                            yield (_next_lhs_binding + rhs_binding)
                    # update cache
                    _lhs_cache.append(_next_lhs_binding)
                    _next_lhs_binding = next(lhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

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
            # A generator of tuples goes in (bindings)
            filtered_bindings = _filtered_combinations(bindings, rep_count)
            # ... and a generator of tuples of tuples comes out
            # (filtered_bindings).  The following flattens each outer
            # tuple.  I could have also written a generic flattener, but
            # since this structure is predictable, I could do something
            # simpler.  Other code dealing with bindings doesn't expect any
            # nested structure, so I do the flattening here.
            filtered_bindings = (tuple(itertools.chain.from_iterable(binding))
                                 for binding in filtered_bindings)

        self.__push(filtered_bindings, debug_label)

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

        filtered_bindings = (binding for binding in bindings if check_within(binding))

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
            filtered_bindings = (binding for binding in bindings if check_overlap(binding))
        else:
            filtered_bindings = iter(())

        self.__push(filtered_bindings, debug_label)

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

        spec = _build_prop_test_spec(ctx)
        debug_label = u"exitPropTestEqual ({} {})".format(
            spec.operator, spec.literal_text
        )

        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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
        spec = _build_prop_test_spec(ctx)
        debug_label = u"exitPropTestOrder ({} {})".format(
            spec.operator, spec.literal_text
        )

        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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

        spec = _build_prop_test_spec(ctx)
        debug_label = u"exitPropTestSet ({})".format(spec.operator)

        # The set literal is still on the stack; pop it to keep the stack
        # balanced.  The predicate was built from the parse tree above.
        self.__pop(debug_label)
        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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

        spec = _build_prop_test_spec(ctx)
        debug_label = u"exitPropTestLike ({} {})".format(
            spec.operator, spec.literal_text
        )

        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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

        spec = _build_prop_test_spec(ctx)
        debug_label = u"exitPropTestRegex ({} {})".format(
            spec.operator, spec.literal_text
        )

        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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
        spec = _build_prop_test_spec(ctx)

        debug_label = u"exitPropTestIsSubset ({} {})".format(
            spec.operator, spec.literal_text
        )
        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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
        spec = _build_prop_test_spec(ctx)

        debug_label = u"exitPropTestIsSuperset ({} {})".format(
            spec.operator, spec.literal_text
        )
        obs_values = self.__pop(debug_label)

        passed_obs = _obs_map_prop_test(obs_values, spec.predicate)

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
        if not (self.__stix_version == VARSION_2_1 and type_ in TYPES_V21):
            for obs_idx, obs in enumerate(self.__observations):

                if "objects" not in obs:
                    continue

                objects_from_this_obs = {}
                iterator = self.__cyber_obs_obj_iterator(obs["objects"])

                for obj_id, obj in iterator:
                    if u"type" in obj and obj[u"type"] == type_:
                        objects_from_this_obs[obj_id] = [obj]

                if len(objects_from_this_obs) > 0:
                    results[obs_idx] = objects_from_this_obs

        self.__push(results, u"exitObjectType ({})".format(type_))

    def __cyber_obs_obj_iterator(self, objs):
        if self.__stix_version == VARSION_2_1:
            iter_objs = {v['id']: v for v in objs}
        else:
            iter_objs = objs
        iterator = six.iteritems(iter_objs)

        return iterator

    def __dereference_objects(self, prop_name, obs_map):
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

                    if len(dereferenced_cyber_obs_obj_lists) > 0:
                        dereferenced_cyber_obs_obj_map[cyber_obs_obj_id] = \
                            dereferenced_cyber_obs_obj_lists

                if len(dereferenced_cyber_obs_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cyber_obs_obj_map

            obs_map = dereferenced_obs_map

        return obs_map

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

        filtered_obs_map = _step_filter_observations(obs_val, prop_name)
        dereferenced_obs_map = self.__dereference_objects(prop_name,
                                                          filtered_obs_map)

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

        filtered_obs_map = _step_filter_observations(obs_val, prop_name)
        dereferenced_obs_map = self.__dereference_objects(prop_name,
                                                          filtered_obs_map)

        self.__push(dereferenced_obs_map, debug_label)

    def exitIndexPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent(), but takes a list index
        step.
        """
        if ctx.IntPosLiteral() or ctx.IntNegLiteral():
            index = _literal_terminal_to_python_val(
                ctx.IntPosLiteral() or ctx.IntNegLiteral()
            )
            debug_label = u"exitIndexPathStep ({})".format(index)
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations(obs_val, index)

        elif ctx.ASTERISK():
            # In this case, we step into all of the list elements.
            debug_label = u"exitIndexPathStep (*)"
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations_index_star(obs_val)

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
        self.__stix_version = stix_version
        self.__pattern_str = pattern_str
        if self.__stix_version == VARSION_2_1:
            self.__pattern = Stix2Pattern21(pattern_str)
        else:
            self.__pattern = Stix2Pattern20(pattern_str)

    def __getattr__(self, name):
        return self.__pattern.__getattribute__(name)

    def get_stix_version(self):
        """Return the STIX version this pattern was compiled for."""
        return self.__stix_version

    def get_pattern_str(self):
        """Return the original pattern text."""
        return self.__pattern_str

    def get_parse_tree(self):
        """Return the underlying ANTLR parse tree."""
        return self.__pattern._Pattern__parse_tree

    def match(self, observed_data_sdos, verbose=False, explain=False):
        """
        Match this pattern against the given observations.  Returns matching
        SDOs.  The matcher can find many bindings; this function returns the
        SDOs corresponding to only the first binding found.

        :param observed_data_sdos: A list of observed-data SDOs, as a list of
            dicts.  STIX JSON should be parsed into native Python structures
            before calling this method.
        :param verbose: Whether to dump detailed info about matcher operation
        :param explain: If True, return a MatchExplanation instead.  It is a
            list subclass containing the same matching SDOs, with a
            ``witnesses`` attribute describing exactly what satisfied the
            pattern.  The default (False) return contract is unchanged.
        :return: Matching SDOs if the pattern matched; an empty list if it
            didn't match.
        :raises MatcherException: If an error occurs during matching
        """
        matcher = MatchListener(observed_data_sdos, verbose, stix_version=self.__stix_version)
        self.__pattern.walk(matcher)

        first_raw_binding = next(matcher.matched(raw=True), ())
        first_binding = tuple(
            map(MatchListener.get_obs_index_filtered, first_raw_binding)
        )
        matching_sdos = matcher.get_sdos_from_binding(first_binding)

        if explain:
            explanation = _build_explanation(
                self, self.__pattern_str, matcher, first_raw_binding,
                self.__stix_version,
            )
            return MatchExplanation(
                matching_sdos,
                explanation[u"pattern"],
                explanation[u"stix_version"],
                explanation[u"witnesses"],
                explanation[u"time_constraints"],
            )

        return matching_sdos

    def explain(self, observed_data_sdos, verbose=False):
        """
        Match and return a MatchExplanation.  Convenience alias for
        match(..., explain=True).
        """
        return self.match(observed_data_sdos, verbose, explain=True)


def match(pattern, observed_data_sdos, verbose=False, stix_version=DEFAULT_VERSION,
          explain=False):
    """
    Match the given pattern against the given observations.  Returns matching
    SDOs.  The matcher can find many bindings; this function returns the SDOs
    corresponding to only the first binding found.

    :param pattern: The STIX pattern
    :param observed_data_sdos: A list of observed-data SDOs, as a list of dicts.
        STIX JSON should be parsed into native Python structures before calling
        this function.
    :param verbose: Whether to dump detailed info about matcher operation
    :param explain: If True, the result is a MatchExplanation: a list of the
        same matching SDOs, with a ``witnesses`` attribute carrying the
        recomputable explanation.  The default return contract is unchanged.
    :return: Matching SDOs if the pattern matched; an empty list if it didn't
        match.
    :raises stix2patterns.pattern.ParseException: If there is a parse error
    :raises MatcherException: If an error occurs during matching
    """

    compiled_pattern = Pattern(pattern, stix_version)
    return compiled_pattern.match(observed_data_sdos, verbose, explain=explain)


def explain_match(pattern, observed_data_sdos, verbose=False,
                  stix_version=DEFAULT_VERSION):
    """
    Match a pattern and return only the MatchExplanation.

    This is a convenience wrapper for callers who want the witness record
    without also consuming the matching-SDO list.  The explanation object is
    still a list of the matching SDOs.
    """
    return match(
        pattern, observed_data_sdos, verbose=verbose,
        stix_version=stix_version, explain=True,
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
    arg_parser.add_argument("-x", "--explain", action="store_true",
                            help="""Print the witness explanation as JSON.
                            This does not change matching decisions.""")
    arg_parser.add_argument("-q", "--quiet", action="count", help="""
    Run quietly. One -q will only print out NO MATCH information. Two will
    produce no match-related output. This option does not affect the action
    of -v, and error information will still be displayed.""", default=0)

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
                result = match(
                    pattern, observed_data_sdos, args.verbose,
                    args.stix_version, explain=args.explain,
                )
                if result:
                    if args.quiet < 1:
                        print(u"\nMATCH: ", escaped_pattern)
                else:
                    if args.quiet < 2:
                        print(u"\nNO MATCH: ", escaped_pattern)
                    return_value = 1
                if args.explain:
                    print(json.dumps(result.to_dict(), sort_keys=True))
    except Exception:
        return_value = 2
        sys.excepthook(*sys.exc_info())
    return return_value


if __name__ == '__main__':
    sys.exit(main())
