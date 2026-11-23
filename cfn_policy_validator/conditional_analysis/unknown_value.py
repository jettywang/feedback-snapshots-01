"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Markers used by the offline conditional analysis to represent values that cannot be resolved before deployment
because they depend on a CloudFormation parameter whose value has not been supplied.

These markers deliberately never substitute a guessed default value.  An unresolved parameter is carried through
evaluation as an :class:`UnknownValue` so that any policy element that depends on it can be flagged as conditional
instead of being silently treated as the parameter's ``Default`` or an empty string.
"""

import re

UNKNOWN_PLACEHOLDER = '${UnknownParameter}'

# matches ${UnknownParameter}:ParamName wherever it occurs inside a string built by Fn::Sub/Fn::Join
_UNKNOWN_PLACEHOLDER_PATTERN = re.compile(re.escape(UNKNOWN_PLACEHOLDER) + r':([A-Za-z0-9._-]+)')


class UnknownValue(str):
	"""
	A sentinel that stands in for a Ref/Sub/Join value that ultimately depends on an unresolved CloudFormation
	parameter.  It subclasses ``str`` so it passes the ``type: string`` schema checks the parsers apply while
	remaining distinguishable from a real resolved value through ``isinstance`` checks.  It never carries a guessed
	default - its string form is an explicit placeholder naming the unresolved parameter.
	"""

	def __new__(cls, parameter_name):
		obj = str.__new__(cls, f'{UNKNOWN_PLACEHOLDER}:{parameter_name}')
		obj.parameter_name = parameter_name
		return obj

	def __repr__(self):
		return f'UnknownValue({self.parameter_name!r})'

	def __eq__(self, other):
		if isinstance(other, UnknownValue):
			return other.parameter_name == self.parameter_name
		return str.__eq__(self, other)

	def __hash__(self):
		return hash(('UnknownValue', self.parameter_name))

	def to_json(self):
		return str(self)


def collect_unknown_parameters(value):
	"""
	Return the sorted set of unresolved parameter names referenced anywhere within an evaluated structure.

	Markers are detected two ways: directly via :class:`UnknownValue` instances, and via their placeholder text.
	The text check matters because string intrinsics such as Fn::Sub/ Fn::Join build a new plain ``str`` via
	concatenation, which drops the marker subclass while preserving the placeholder.
	"""
	names = set()

	def walk(node):
		if isinstance(node, UnknownValue):
			names.add(node.parameter_name)
			return
		if isinstance(node, str):
			# the placeholder can be embedded inside a larger string produced by Fn::Sub/Fn::Join
			names.update(_UNKNOWN_PLACEHOLDER_PATTERN.findall(node))
			return
		if isinstance(node, dict):
			for child in node.values():
				walk(child)
		elif isinstance(node, list) or isinstance(node, tuple):
			for child in node:
				walk(child)

	walk(value)
	return sorted(names)


def contains_unknown(value):
	"""
	Recursively determine whether an evaluated structure contains any unresolved parameter, either as an
	:class:`UnknownValue` marker or as the placeholder text left behind by a string intrinsic.
	"""
	return len(collect_unknown_parameters(value)) > 0


def default_to_json(obj):
	"""
	``json.dumps`` default serializer that renders UnknownValue markers as stable placeholder strings instead of
	raising a TypeError.
	"""
	if isinstance(obj, UnknownValue):
		return str(obj)
	raise TypeError(f'Object of type {type(obj).__name__} is not JSON serializable')
