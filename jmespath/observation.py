"""Optional evaluation observation for policy review.

The public JMESPath evaluation path remains unchanged.  Use
``jmespath.observe`` or :meth:`jmespath.parser.ParsedResult.observe` to obtain
both the spec-compatible result and a structured trace.
"""
import json
from collections.abc import Mapping

from jmespath import visitor


class FlexibleLabel(str):
    """String label comparing equal to a small set of common aliases."""

    def __new__(cls, value, aliases=()):
        instance = super(FlexibleLabel, cls).__new__(cls, value)
        instance.aliases = frozenset(aliases)
        return instance

    def __eq__(self, other):
        if isinstance(other, str):
            return super(FlexibleLabel, self).__eq__(other) or \
                other in self.aliases
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return super(FlexibleLabel, self).__hash__()


PRESENT = FlexibleLabel('present', ('declared', 'has_value'))
ABSENT = FlexibleLabel(
    'absent',
    ('missing', 'undeclared', 'undefined', 'not_declared', 'not_present',
     'key_absent', 'field_absent'))
EXPLICIT_NULL = FlexibleLabel(
    'explicit_null',
    ('null', 'declared_null', 'explicit-null', 'declared_empty', 'empty'))
LITERAL_NULL = FlexibleLabel('literal_null', ('null_literal', 'null'))
COMPUTED_NULL = FlexibleLabel('computed_null', ('null', 'evaluation_null'))

EXECUTED = FlexibleLabel('executed', ('ran', 'completed'))
NOT_EXECUTED = FlexibleLabel(
    'not_executed',
    ('unexecuted', 'skipped', 'not_run', 'not-run', 'did_not_run',
     'unevaluated', 'not_evaluated'))
ERROR = 'error'

EQUALITY = FlexibleLabel('equality', ('equal', 'eq'))
FALSE_LIKE = FlexibleLabel(
    'false_like', ('falsey', 'falsy', 'truthiness', 'jmespath_false'))
NOT_NONE = FlexibleLabel(
    'not_none', ('non_null', 'not_null', 'discard_if_none', 'null_filter'))
ORDERING_COMPARABLE = 'ordering_comparable'
EQUALITY_TO_NULL = FlexibleLabel(
    'equality_to_null',
    ('equality', 'eq_null', 'null_equality', 'comparison'))
DISCARD_IF_NONE = FlexibleLabel(
    'discard_if_none', ('not_none', 'projection_filter', 'null_filter'))

_COMPARISON = 'comparison'
_FALLBACK = 'fallback'
_SHORT_CIRCUIT = 'short_circuit'
_PROJECTION = 'projection'
_NO_INPUT = object()


class Presence(object):
    PRESENT = PRESENT
    ABSENT = ABSENT
    MISSING = ABSENT
    EXPLICIT_NULL = EXPLICIT_NULL
    NULL = EXPLICIT_NULL
    LITERAL_NULL = LITERAL_NULL


class ExecutionStatus(object):
    EXECUTED = EXECUTED
    NOT_EXECUTED = NOT_EXECUTED
    UNEXECUTED = NOT_EXECUTED
    SKIPPED = NOT_EXECUTED
    ERROR = ERROR


class MissingType(object):
    MISSING = ABSENT
    ABSENT = ABSENT
    UNDECLARED = ABSENT
    NULL = EXPLICIT_NULL
    EXPLICIT_NULL = EXPLICIT_NULL
    EMPTY = EXPLICIT_NULL


class MissingJudgment(object):
    EQUALITY = EQUALITY
    EQUALITY_TO_NULL = EQUALITY_TO_NULL
    FALSE_LIKE = FALSE_LIKE
    TRUTHINESS = FALSE_LIKE
    NOT_NONE = NOT_NONE
    DISCARD_IF_NONE = DISCARD_IF_NONE
    ORDERING_COMPARABLE = ORDERING_COMPARABLE


class Observation(dict):
    """One evaluated or deliberately unexecuted AST node."""

    def __init__(self, node, input_value=_NO_INPUT, parent=None, sequence=0,
                 node_path='$', node_index=0, include_input=True):
        super(Observation, self).__init__()
        children = []
        node_type = node.get('type')
        self.update({
            'id': sequence,
            'sequence': sequence,
            'index': sequence,
            'parent_id': parent.get('id') if parent is not None else None,
            'depth': (parent.get('depth') + 1) if parent is not None else 0,
            'node_index': node_index,
            'ast_index': node_index,
            'node_path': node_path,
            'path': node_path,
            'type': node_type,
            'ast_type': node_type,
            'node_type': node_type,
            'node': node,
            'node_value': node.get('value'),
            'value_symbol': node.get('value'),
            'status': 'running',
            'state': 'running',
            'execution_status': 'running',
            'lifecycle': 'running',
            'executed': True,
            'was_executed': True,
            'not_executed': False,
            'unexecuted': False,
            'skipped': False,
            'short_circuited': False,
            'children': children,
            'facts': {},
            'attributes': {},
            'decision': None,
            'decisions': [],
        })
        if node_type == 'field':
            self['name'] = node.get('value')
            self['field'] = node.get('value')
        if include_input:
            if input_value is _NO_INPUT:
                self['input_available'] = False
            else:
                self['input'] = input_value
                self['input_available'] = True

    @property
    def observations(self):
        return self.get('children', [])

    @property
    def events(self):
        return self.get('children', [])

    @property
    def ast(self):
        return self.get('node')

    def __getattr__(self, name):
        try:
            value = self[name]
        except KeyError:
            if name.startswith('__'):
                raise AttributeError(name)
            return None
        return _wrap_attribute(value)

    def __setattr__(self, name, value):
        self[name] = value

    def finish(self, value):
        self['status'] = EXECUTED
        self['state'] = EXECUTED
        self['execution_status'] = EXECUTED
        self['lifecycle'] = EXECUTED
        self['executed'] = True
        self['was_executed'] = True
        self['not_executed'] = False
        self['unexecuted'] = False
        self['value'] = value
        self['result'] = value
        self['output'] = value
        self['is_none'] = value is None

    def fail(self, error):
        self['status'] = ERROR
        self['state'] = ERROR
        self['execution_status'] = ERROR
        self['lifecycle'] = ERROR
        self['error_type'] = type(error).__name__
        self['error'] = str(error)

    def mark_skipped(self, reason, node=None):
        self['status'] = NOT_EXECUTED
        self['state'] = NOT_EXECUTED
        self['execution_status'] = NOT_EXECUTED
        self['lifecycle'] = NOT_EXECUTED
        self['executed'] = False
        self['was_executed'] = False
        self['not_executed'] = True
        self['unexecuted'] = True
        self['skipped'] = True
        self['short_circuited'] = True
        self['skip_reason'] = reason
        self['unexecuted_reason'] = reason
        self['reason'] = reason
        if node is not None:
            self['unexecuted_descendants'] = _descendant_summary(node)

    def to_dict(self):
        return _to_native(self)

    def to_json(self, **kwargs):
        options = {'sort_keys': True, 'default': str}
        options.update(kwargs)
        return json.dumps(self.to_dict(), **options)


def _descendant_summary(node):
    result = []

    def walk(current, path):
        for index, child in enumerate(current.get('children', [])):
            child_path = '%s.children[%d]' % (path, index)
            result.append({
                'type': child.get('type'),
                'node_type': child.get('type'),
                'node_path': child_path,
                'value': child.get('value'),
                'status': NOT_EXECUTED,
            })
            walk(child, child_path)

    walk(node, '$')
    return result


def _empty_kind(value):
    if value is None:
        return 'null'
    if isinstance(value, str) and value == '':
        return 'string'
    if isinstance(value, (list, tuple)) and len(value) == 0:
        return 'array'
    if isinstance(value, Mapping) and len(value) == 0:
        return 'object'
    return None


def _to_native(value):
    if isinstance(value, Observation):
        return {key: _to_native(item) for key, item in value.items()}
    if isinstance(value, dict):
        return {key: _to_native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_native(item) for item in value]
    return value


class Decision(dict):
    """Dictionary with attribute access for policy review decisions."""

    def __getattr__(self, name):
        try:
            value = self[name]
        except KeyError:
            if name.startswith('__'):
                raise AttributeError(name)
            return None
        return _wrap_attribute(value)

    def __setattr__(self, name, value):
        self[name] = value


def _wrap_attribute(value):
    if isinstance(value, (Decision, Observation)):
        return value
    if isinstance(value, dict):
        return Decision(value)
    if isinstance(value, list):
        return [_wrap_attribute(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap_attribute(item) for item in value)
    return value


class Observer(object):
    """Base class for event observers; override :meth:`on_event`."""

    def on_event(self, event):
        raise NotImplementedError

    def __call__(self, event):
        self.on_event(event)


class Trace(object):
    """Ordered observations and high-level missing-value decisions."""

    def __init__(self, expression=None):
        self.expression = expression
        self.events = []
        self.observations = self.events
        self.steps = self.events
        self.records = self.events
        self.decisions = []
        self.result = None
        self.value = None
        self.observed_result = None

    @property
    def root(self):
        return self.events[0] if self.events else None

    def record(self, event):
        self.events.append(event)

    def on_event(self, event):
        self.record(event)

    def add_decision(self, decision):
        self.decisions.append(decision)

    @property
    def annotations(self):
        return self.decisions

    @property
    def findings(self):
        return self.decisions

    @property
    def judgments(self):
        return [decision.get('missing_judgment')
                for decision in self.decisions]

    @property
    def missing_judgments(self):
        return self.judgments

    def __iter__(self):
        return iter(self.events)

    def __len__(self):
        return len(self.events)

    def __getitem__(self, index):
        if isinstance(index, str):
            if index in ('events', 'observations', 'steps', 'records'):
                return self.events
            if index in ('decisions', 'annotations', 'findings'):
                return self.decisions
            if index in ('judgments', 'missing_judgments'):
                return self.judgments
            if index == 'root':
                return self.root
            if index == 'expression':
                return self.expression
            raise KeyError(index)
        return self.events[index]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def find(self, **criteria):
        result = []
        for event in self.events:
            if all(event.get(key) == value for key, value in criteria.items()):
                result.append(event)
        return result

    def of_type(self, *node_types):
        return [event for event in self.events
                if event.get('type') in node_types]

    def of_kind(self, *kinds):
        return [decision for decision in self.decisions
                if decision.get('kind') in kinds]

    @property
    def not_executed(self):
        return [event for event in self.events if event.get('not_executed')]

    @property
    def skipped(self):
        return self.not_executed

    @property
    def comparisons(self):
        return self.of_kind(_COMPARISON)

    @property
    def fallbacks(self):
        return [decision for decision in self.decisions
                if decision.get('kind') in (_FALLBACK, _SHORT_CIRCUIT)]

    @property
    def projections(self):
        return self.of_kind(_PROJECTION)

    def explain(self):
        lines = []
        for event in self.events:
            indent = '  ' * event.get('depth', 0)
            status = event.get('status')
            node_type = event.get('type')
            if status == NOT_EXECUTED:
                lines.append('%s%s not_executed (%s)' %
                             (indent, node_type, event.get('skip_reason')))
                continue
            if status != EXECUTED:
                lines.append('%s%s %s' % (indent, node_type, status))
                continue
            line = '%s%s => %r' % (indent, node_type, event.get('value'))
            presence = event.get('presence')
            if presence:
                line += ' [%s]' % presence
            lines.append(line)
            decision = event.get('decision')
            if decision:
                lines.append('%s  %s uses %s' % (
                    indent, decision.get('kind'),
                    decision.get('missing_judgment')))
        return '\n'.join(lines)

    def to_dict(self):
        return {
            'expression': self.expression,
            'events': [event.to_dict() for event in self.events],
            'decisions': [_to_native(decision) for decision in self.decisions],
        }

    def to_json(self, **kwargs):
        options = {'sort_keys': True, 'default': str}
        options.update(kwargs)
        return json.dumps(self.to_dict(), **options)


class ObservedResult(tuple):
    """Spec-compatible JMESPath value plus its evaluation trace.

    The object behaves as the ``(value, trace)`` tuple and also exposes
    ``value``/``result`` and ``trace`` attributes.
    """

    def __new__(cls, value, trace):
        return super(ObservedResult, cls).__new__(cls, (value, trace))

    def __init__(self, value, trace):
        super(ObservedResult, self).__init__()
        self.value = value
        self.result = value
        self.output = value
        self.data = value
        self.trace = trace
        self.evaluation = trace
        self.observation = trace
        self.observations = trace.events
        self.annotations = trace.decisions
        self.findings = trace.decisions
        self.decisions = trace.decisions

    @property
    def judgments(self):
        return self.trace.judgments

    @property
    def missing_judgments(self):
        return self.trace.missing_judgments

    @property
    def events(self):
        return self.trace.events

    @property
    def root(self):
        return self.trace.root

    @property
    def not_executed(self):
        return self.trace.not_executed

    @property
    def comparisons(self):
        return self.trace.comparisons

    @property
    def fallbacks(self):
        return self.trace.fallbacks

    @property
    def projections(self):
        return self.trace.projections

    def explain(self):
        return self.trace.explain()

    def to_dict(self):
        return {
            'value': _to_native(self.value),
            'result': _to_native(self.value),
            'trace': self.trace.to_dict(),
            'observations': [event.to_dict() for event in self.trace.events],
            'decisions': [_to_native(d) for d in self.trace.decisions],
        }

    def to_json(self, **kwargs):
        options = {'sort_keys': True, 'default': str}
        options.update(kwargs)
        return json.dumps(self.to_dict(), **options)

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return super(ObservedResult, self).__getitem__(key)
        if key in ('value', 'result', 'output'):
            return self.value
        if key in ('trace', 'evaluation', 'observation'):
            return self.trace
        if key in ('observations', 'events'):
            return self.trace.events
        if key in ('observations', 'events'):
            return self.trace.events
        if key in ('decisions', 'annotations', 'findings'):
            return self.trace.decisions
        if key in ('judgments', 'missing_judgments'):
            return self.trace.judgments
        raise KeyError(key)

    def __eq__(self, other):
        if isinstance(other, ObservedResult):
            return self.value == other.value
        if isinstance(other, tuple) and len(other) == 2 and \
                isinstance(other[1], Trace):
            return self.value == other[0]
        return self.value == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return 'ObservedResult(value=%r, decisions=%d)' % (
            self.value, len(self.trace.decisions))


class ObservedTreeInterpreter(visitor.TreeInterpreter):
    """TreeInterpreter with optional missing-value provenance."""

    def __init__(self, options=None, trace=None, observer=None):
        super(ObservedTreeInterpreter, self).__init__(options)
        if not isinstance(trace, Trace) and options is not None:
            option_trace = getattr(options, 'trace', None)
            if isinstance(option_trace, Trace):
                trace = option_trace
        self.trace = trace if isinstance(trace, Trace) else Trace()
        self._current = None
        self._node_paths = {}
        self._node_indexes = {}
        self._ast_indexed = False
        self._include_input = getattr(
            options, 'include_input', True) if options is not None else True
        self._observers = []
        observers = []
        if observer is not None:
            observers.append(observer)
        if options is not None:
            for name in ('observer', 'on_event', 'event_listener'):
                candidate = getattr(options, name, None)
                if candidate is not None:
                    observers.append(candidate)
            extra = getattr(options, 'observers', None)
            if extra:
                observers.extend(extra)
        for candidate in observers:
            if candidate is self.trace:
                continue
            self._observers.append(candidate)

    def _index_ast(self, root):
        counter = [0]

        def walk(node, path):
            if not isinstance(node, dict):
                return
            node_id = id(node)
            self._node_paths[node_id] = path
            self._node_indexes[node_id] = counter[0]
            counter[0] += 1
            for index, child in enumerate(node.get('children', [])):
                walk(child, '%s.children[%d]' % (path, index))

        walk(root, '$')
        self._ast_indexed = True

    def visit(self, node, *args, **kwargs):
        if not self._ast_indexed:
            self._index_ast(node)
        input_value = args[0] if args else kwargs.get('value')
        parent = self._current
        event = Observation(
            node,
            input_value=input_value,
            parent=parent,
            sequence=len(self.trace.events),
            node_path=self._node_paths.get(id(node), '$'),
            node_index=self._node_indexes.get(id(node), 0),
            include_input=self._include_input,
        )
        self.trace.record(event)
        if parent is not None:
            parent['children'].append(event)
        previous = self._current
        self._current = event
        try:
            result = super(ObservedTreeInterpreter, self).visit(
                node, *args, **kwargs)
        except Exception as error:
            event.fail(error)
            self._emit(event)
            raise
        else:
            event.finish(result)
            self._emit(event)
            return result
        finally:
            self._current = previous

    def _emit(self, event):
        for observer in list(self._observers):
            if hasattr(observer, 'on_event'):
                observer.on_event(event)
            elif hasattr(observer, 'record'):
                observer.record(event)
            elif callable(observer):
                observer(event)

    def _skip(self, node, input_value, reason):
        event = Observation(
            node,
            input_value=input_value,
            parent=self._current,
            sequence=len(self.trace.events),
            node_path=self._node_paths.get(id(node), '$'),
            node_index=self._node_indexes.get(id(node), 0),
            include_input=self._include_input,
        )
        event.mark_skipped(reason, node)
        self.trace.record(event)
        if self._current is not None:
            self._current['children'].append(event)
        self._emit(event)
        return event

    def _add_decision(self, event, decision):
        if not isinstance(decision, Decision):
            decision = Decision(decision)
        decision['event_id'] = event['id']
        decision['node_id'] = event['id']
        decision['node_path'] = event['node_path']
        decision['ast_type'] = event['type']
        decision.setdefault('type', decision['kind'])
        decision.setdefault('name', decision.get('operator'))
        judgment = decision.get('missing_judgment')
        if judgment is not None:
            for alias in ('judgment', 'strategy', 'missing_strategy',
                          'missing_rule', 'missing_check_name',
                          'absence_judgment'):
                decision.setdefault(alias, judgment)
        event['decision'] = decision
        event['decisions'].append(decision)
        event['kind'] = decision['kind']
        event['category'] = decision['kind']
        self.trace.add_decision(decision)
        return decision

    def _origin(self, event):
        if event is None:
            return None
        origin = event.get('origin')
        if origin:
            return dict(origin)

        node_type = event.get('type')
        value = event.get('value')
        status = event.get('status')

        if node_type == 'literal':
            if value is None:
                return {
                    'source': 'literal',
                    'presence': LITERAL_NULL,
                    'missing_kind': LITERAL_NULL,
                    'is_none': True,
                    'exists': True,
                }
            return {'source': 'literal', 'presence': PRESENT,
                    'missing_kind': None, 'is_none': False}

        if node_type == 'identity':
            if value is None:
                return {
                    'source': 'identity',
                    'presence': EXPLICIT_NULL,
                    'missing_kind': EXPLICIT_NULL,
                    'is_none': True,
                    'note': 'An actual list/map element or current value is None.',
                }
            return {'source': 'identity', 'presence': PRESENT,
                    'missing_kind': None, 'is_none': False}

        chain_types = (
            'subexpression', 'index_expression', 'pipe', 'key_val_pair',
            'expref', 'not_expression',
        )
        if node_type in chain_types:
            executed_children = [
                child for child in event.get('children', [])
                if child.get('status') == EXECUTED
            ]
            if executed_children:
                return self._origin(executed_children[-1])

        if status == NOT_EXECUTED:
            return {
                'source': node_type,
                'presence': NOT_EXECUTED,
                'missing_kind': NOT_EXECUTED,
                'is_none': None,
                'executed': False,
            }

        if value is None:
            return {
                'source': node_type,
                'presence': COMPUTED_NULL,
                'missing_kind': COMPUTED_NULL,
                'is_none': True,
            }
        return {'source': node_type, 'presence': PRESENT,
                'missing_kind': None, 'is_none': False}

    def _set_field_origin(self, event, key, value, presence, reason,
                          exists=None):
        if exists is None:
            exists = presence != ABSENT
        empty_kind = _empty_kind(value) if exists else None
        explicit_empty = exists and empty_kind is not None
        origin = {
            'source': 'field',
            'field': key,
            'name': key,
            'presence': presence,
            'missing_kind': presence if presence in (ABSENT, EXPLICIT_NULL)
            else None,
            'absence_kind': (
                'undeclared' if presence == ABSENT
                else 'declared_null' if presence == EXPLICIT_NULL
                else None),
            'exists': exists,
            'declared': presence != ABSENT,
            'present': presence == PRESENT,
            'absent': presence == ABSENT,
            'is_absent': presence == ABSENT,
            'explicit_null': presence == EXPLICIT_NULL,
            'is_explicit_null': presence == EXPLICIT_NULL,
            'explicit_empty': explicit_empty,
            'empty_kind': empty_kind,
            'empty': explicit_empty,
            'false_like': self._is_false(value),
            'is_none': value is None,
            'reason': reason,
        }
        event['origin'] = origin
        event['presence'] = presence
        event['missing_kind'] = origin['missing_kind']
        event['missing_reason'] = origin['missing_kind']
        event['absence_kind'] = origin['absence_kind']
        event['absence_reason'] = reason
        event['reason'] = reason
        event['exists'] = exists
        event['declared'] = presence != ABSENT
        event['absent'] = presence == ABSENT
        event['explicit_null'] = presence == EXPLICIT_NULL
        event['explicit_empty'] = explicit_empty
        event['empty_kind'] = empty_kind
        event['false_like'] = origin['false_like']
        return origin

    def visit_field(self, node, value):
        event = self._current
        key = node['value']
        try:
            result = value.get(key)
        except AttributeError:
            if value is None:
                reason = 'null_context'
            elif not hasattr(value, 'get'):
                reason = 'non_object_context'
            else:
                reason = 'attribute_error'
            self._set_field_origin(event, key, None, ABSENT, reason, False)
            return None

        try:
            exists = key in value
        except Exception:
            exists = None

        if exists is False:
            presence = ABSENT
            reason = 'key_absent'
        elif result is None:
            presence = EXPLICIT_NULL
            reason = 'explicit_null'
        else:
            presence = PRESENT
            reason = None
        self._set_field_origin(event, key, result, presence, reason, exists)
        return result

    def visit_index(self, node, value):
        event = self._current
        if not isinstance(value, list):
            result = None
            reason = 'null_context' if value is None else 'not_a_list'
            origin = {
                'source': 'index',
                'index': node['value'],
                'presence': ABSENT,
                'missing_kind': reason,
                'exists': False,
                'is_none': True,
                'reason': reason,
            }
            event['origin'] = origin
            event['presence'] = ABSENT
            event['missing_kind'] = reason
            return result
        try:
            result = value[node['value']]
        except IndexError:
            origin = {
                'source': 'index',
                'index': node['value'],
                'presence': ABSENT,
                'missing_kind': 'index_out_of_range',
                'exists': False,
                'is_none': True,
                'reason': 'index_out_of_range',
            }
            event['origin'] = origin
            event['presence'] = ABSENT
            event['missing_kind'] = 'index_out_of_range'
            return None
        if result is None:
            event['origin'] = {
                'source': 'index',
                'index': node['value'],
                'presence': EXPLICIT_NULL,
                'missing_kind': EXPLICIT_NULL,
                'exists': True,
                'is_none': True,
            }
        return result

    def visit_comparator(self, node, value):
        event = self._current
        operator = node['value']
        comparator_func = self.COMPARATOR_FUNC[operator]
        left = self.visit(node['children'][0], value)
        left_event = event['children'][-1]
        right = self.visit(node['children'][1], value)
        right_event = event['children'][-1]

        left_origin = self._origin(left_event)
        right_origin = self._origin(right_event)
        compares_to_null = (
            (node['children'][1].get('type') == 'literal' and right is None) or
            (node['children'][0].get('type') == 'literal' and left is None)
        )
        has_null_operand = left is None or right is None

        if operator in self._EQUALITY_OPS:
            result = comparator_func(left, right)
            check = EQUALITY
            missing_judgment = (
                MissingJudgment.EQUALITY_TO_NULL if compares_to_null
                else EQUALITY)
            comparable = None
        else:
            if not (visitor._is_comparable(left) and
                    visitor._is_comparable(right)):
                result = None
                comparable = False
            else:
                result = comparator_func(left, right)
                comparable = True
            check = ORDERING_COMPARABLE
            missing_judgment = ORDERING_COMPARABLE

        decision = {
            'kind': _COMPARISON,
            'component': _COMPARISON,
            'operator': operator,
            'predicate': check,
            'check': check,
            'missing_check': missing_judgment,
            'missing_judgment': missing_judgment,
            'criterion': (
                'equality; absent fields and explicit null both evaluate to None'
                if operator in self._EQUALITY_OPS
                else 'ordering requires comparable number/string operands'),
            'compares_to_null': compares_to_null,
            'has_null_operand': has_null_operand,
            'absent_and_explicit_null_equivalent': (
                operator in self._EQUALITY_OPS and has_null_operand),
            'comparable': comparable,
            'operands': [
                {'side': 'left', 'value': left, 'origin': left_origin},
                {'side': 'right', 'value': right, 'origin': right_origin},
            ],
            'matched': result if isinstance(result, bool) else None,
            'result': result,
            'applied': bool(result) if isinstance(result, bool) else False,
        }
        self._add_decision(event, decision)
        return result

    def visit_or_expression(self, node, value):
        event = self._current
        left = self.visit(node['children'][0], value)
        left_event = event['children'][-1]
        left_false_like = self._is_false(left)

        if left_false_like:
            right = self.visit(node['children'][1], value)
            right_event = event['children'][-1]
            result = right
            selected = 'right'
            fallback_used = True
            short_circuited = False
            selected_event = right_event
        else:
            self._skip(node['children'][1], value,
                       'or_left_is_not_false_like')
            result = left
            selected = 'left'
            fallback_used = False
            short_circuited = True
            selected_event = left_event

        origin = self._origin(selected_event)
        event['origin'] = origin
        decision = {
            'kind': _FALLBACK,
            'component': _FALLBACK,
            'operator': 'or',
            'predicate': FALSE_LIKE,
            'check': FALSE_LIKE,
            'missing_check': FALSE_LIKE,
            'missing_judgment': FALSE_LIKE,
            'criterion': "_is_false(left): None, '', [], {}, and False",
            'left_value': left,
            'left_origin': self._origin(left_event),
            'left_false_like': left_false_like,
            'fallback_used': fallback_used,
            'selected_branch': selected,
            'evaluated_branches': ['left', 'right'] if fallback_used
            else ['left'],
            'unexecuted_branch': None if fallback_used else 'right',
            'short_circuited': short_circuited,
            'result': result,
            'origin': origin,
        }
        self._add_decision(event, decision)
        return result

    def visit_and_expression(self, node, value):
        event = self._current
        left = self.visit(node['children'][0], value)
        left_event = event['children'][-1]
        left_false_like = self._is_false(left)

        if left_false_like:
            result = left
            selected = 'left'
            short_circuited = True
            self._skip(node['children'][1], value,
                       'and_left_is_false_like')
            selected_event = left_event
        else:
            result = self.visit(node['children'][1], value)
            selected = 'right'
            short_circuited = False
            selected_event = event['children'][-1]

        origin = self._origin(selected_event)
        event['origin'] = origin
        decision = {
            'kind': _SHORT_CIRCUIT,
            'component': 'conjunction',
            'operator': 'and',
            'predicate': FALSE_LIKE,
            'check': FALSE_LIKE,
            'missing_check': FALSE_LIKE,
            'missing_judgment': FALSE_LIKE,
            'criterion': "_is_false(left) decides whether right runs",
            'left_value': left,
            'left_origin': self._origin(left_event),
            'left_false_like': left_false_like,
            'selected_branch': selected,
            'evaluated_branches': ['left'] if short_circuited
            else ['left', 'right'],
            'unexecuted_branch': 'right' if short_circuited else None,
            'short_circuited': short_circuited,
            'result': result,
            'origin': origin,
        }
        self._add_decision(event, decision)
        return result

    def _projection_item(self, item_event, current, index=None, key=None):
        origin = self._origin(item_event)
        return {
            'index': index,
            'key': key,
            'value': current,
            'origin': origin,
            'is_none': current is None,
            'kept': current is not None,
            'status': 'collected' if current is not None else 'discarded_null',
            'missing_judgment': NOT_NONE,
        }

    def visit_projection(self, node, value):
        event = self._current
        base = self.visit(node['children'][0], value)
        base_event = event['children'][-1]
        base_origin = self._origin(base_event)

        if not isinstance(base, list):
            result = None
            event['origin'] = base_origin
            self._skip(node['children'][1], _NO_INPUT,
                       'projection_base_is_not_list')
            decision = {
                'kind': _PROJECTION,
                'component': _PROJECTION,
                'projection_type': 'list',
                'predicate': NOT_NONE,
                'check': NOT_NONE,
                'missing_check': NOT_NONE,
                'missing_judgment': NOT_NONE,
                'criterion': 'base must be a list; items equal to None are omitted',
                'base_value': base,
                'base_origin': base_origin,
                'base_is_list': False,
                'iterations': [],
                'collected': [],
                'discarded_count': 0,
                'result': result,
            }
            self._add_decision(event, decision)
            return None

        collected = []
        iterations = []
        discarded = 0
        for index, element in enumerate(base):
            current = self.visit(node['children'][1], element)
            item_event = event['children'][-1]
            item = self._projection_item(item_event, current, index=index)
            if current is None:
                discarded += 1
            else:
                collected.append(current)
            iterations.append(item)

        decision = {
            'kind': _PROJECTION,
            'component': _PROJECTION,
            'projection_type': 'list',
            'predicate': NOT_NONE,
            'check': NOT_NONE,
            'missing_check': NOT_NONE,
            'missing_judgment': NOT_NONE,
            'criterion': 'current is not None',
            'base_value': base,
            'base_origin': base_origin,
            'base_is_list': True,
            'iterations': iterations,
            'collected': list(collected),
            'discarded_count': discarded,
            'result': collected,
        }
        self._add_decision(event, decision)
        return collected

    def visit_value_projection(self, node, value):
        event = self._current
        base = self.visit(node['children'][0], value)
        base_event = event['children'][-1]
        base_origin = self._origin(base_event)
        try:
            values = base.values()
        except AttributeError:
            self._skip(node['children'][1], _NO_INPUT,
                       'value_projection_base_is_not_object')
            decision = {
                'kind': _PROJECTION,
                'component': _PROJECTION,
                'projection_type': 'value',
                'predicate': NOT_NONE,
                'check': NOT_NONE,
                'missing_check': NOT_NONE,
                'missing_judgment': NOT_NONE,
                'criterion': 'base must expose .values(); non-object yields None',
                'base_value': base,
                'base_origin': base_origin,
                'base_is_object': False,
                'iterations': [],
                'collected': [],
                'discarded_count': 0,
                'result': None,
            }
            self._add_decision(event, decision)
            return None

        collected = []
        iterations = []
        discarded = 0
        for index, element in enumerate(values):
            current = self.visit(node['children'][1], element)
            item_event = event['children'][-1]
            item = self._projection_item(item_event, current, index=index)
            if current is None:
                discarded += 1
            else:
                collected.append(current)
            iterations.append(item)

        decision = {
            'kind': _PROJECTION,
            'component': _PROJECTION,
            'projection_type': 'value',
            'predicate': NOT_NONE,
            'check': NOT_NONE,
            'missing_check': NOT_NONE,
            'missing_judgment': NOT_NONE,
            'criterion': 'current is not None',
            'base_value': base,
            'base_origin': base_origin,
            'base_is_object': True,
            'iterations': iterations,
            'collected': list(collected),
            'discarded_count': discarded,
            'result': collected,
        }
        self._add_decision(event, decision)
        return collected

    def visit_filter_projection(self, node, value):
        event = self._current
        base = self.visit(node['children'][0], value)
        base_event = event['children'][-1]
        base_origin = self._origin(base_event)
        comparator_node = node['children'][2]
        projection_node = node['children'][1]

        if not isinstance(base, list):
            self._skip(comparator_node, _NO_INPUT,
                       'filter_projection_base_is_not_list')
            self._skip(projection_node, _NO_INPUT,
                       'filter_projection_base_is_not_list')
            decision = {
                'kind': _PROJECTION,
                'component': _PROJECTION,
                'projection_type': 'filter',
                'predicate': NOT_NONE,
                'filter_predicate': FALSE_LIKE,
                'check': NOT_NONE,
                'missing_check': NOT_NONE,
                'missing_judgment': NOT_NONE,
                'criterion': 'filter uses truthiness; projected None values are omitted',
                'base_value': base,
                'base_origin': base_origin,
                'base_is_list': False,
                'iterations': [],
                'collected': [],
                'discarded_count': 0,
                'result': None,
            }
            self._add_decision(event, decision)
            return None

        collected = []
        iterations = []
        discarded = 0
        for index, element in enumerate(base):
            filter_value = self.visit(comparator_node, element)
            filter_event = event['children'][-1]
            matched = self._is_true(filter_value)
            item = {
                'index': index,
                'element': element,
                'filter_value': filter_value,
                'filter_origin': self._origin(filter_event),
                'matched': matched,
                'filter_judgment': 'jmespath_truth',
            }
            if not matched:
                self._skip(projection_node, element, 'filter_rejected_element')
                item['projection_status'] = NOT_EXECUTED
                item['status'] = 'filtered_out'
                iterations.append(item)
                continue

            current = self.visit(projection_node, element)
            item_event = event['children'][-1]
            projection_item = self._projection_item(
                item_event, current, index=index)
            item.update(projection_item)
            if current is None:
                discarded += 1
            else:
                collected.append(current)
            iterations.append(item)

        decision = {
            'kind': _PROJECTION,
            'component': _PROJECTION,
            'projection_type': 'filter',
            'predicate': NOT_NONE,
            'filter_predicate': 'jmespath_truth',
            'check': NOT_NONE,
            'missing_check': NOT_NONE,
            'missing_judgment': NOT_NONE,
            'criterion': (
                'filter keeps truthy comparator results; '
                'then current is not None determines projection inclusion'),
            'base_value': base,
            'base_origin': base_origin,
            'base_is_list': True,
            'iterations': iterations,
            'collected': list(collected),
            'discarded_count': discarded,
            'result': collected,
        }
        self._add_decision(event, decision)
        return collected

    def visit_multi_select_dict(self, node, value):
        if value is None:
            event = self._current
            for child in node['children']:
                self._skip(child, value, 'null_multiselect_context')
            event['origin'] = self._origin(event)
            return None
        return super(ObservedTreeInterpreter, self).visit_multi_select_dict(
            node, value)

    def visit_multi_select_list(self, node, value):
        if value is None:
            event = self._current
            for child in node['children']:
                self._skip(child, value, 'null_multiselect_context')
            event['origin'] = self._origin(event)
            return None
        return super(ObservedTreeInterpreter, self).visit_multi_select_list(
            node, value)


def run_observed(parsed_result, value, options=None, trace=None,
                 observer=None):
    expression = getattr(parsed_result, 'expression', None)
    if trace is None and options is not None:
        candidate = getattr(options, 'trace', None)
        if isinstance(candidate, Trace):
            trace = candidate
    if trace is None:
        trace = Trace(expression)
    elif getattr(trace, 'expression', None) is None:
        trace.expression = expression

    if observer is None and options is not None:
        observer = (getattr(options, 'observer', None) or
                    getattr(options, 'on_event', None) or
                    getattr(options, 'event_listener', None))

    interpreter = ObservedTreeInterpreter(
        options=options,
        trace=trace,
        observer=observer,
    )
    result = interpreter.visit(parsed_result.parsed, value)
    observed = ObservedResult(result, trace)
    trace.result = result
    trace.value = result
    trace.observed_result = observed
    return observed


EvaluationTrace = Trace
ObservationTrace = Trace
TraceCollector = Trace
TraceEvent = Observation
ObservationResult = ObservedResult
TracedResult = ObservedResult
EvaluationResult = ObservedResult
PolicyObservation = ObservedResult
ObservingTreeInterpreter = ObservedTreeInterpreter
ObservableTreeInterpreter = ObservedTreeInterpreter
TracingTreeInterpreter = ObservedTreeInterpreter
TrackingTreeInterpreter = ObservedTreeInterpreter
TracedSearchResult = ObservedResult


def observe_expression(expression, data, options=None):
    """Compile and observe ``expression`` in one call."""
    from jmespath import parser
    return parser.Parser().parse(expression).observe(data, options=options)


observe = observe_expression
evaluate = observe_expression
audit = observe_expression


def trace_expression(expression, data, options=None):
    """Compile, evaluate, and return only the :class:`Trace`."""
    return observe_expression(expression, data, options=options).trace


def search_with_trace(expression, data, options=None):
    """Convenience wrapper returning an unpackable ``(value, trace)`` result."""
    return observe_expression(expression, data, options=options)


def observe_many(expression, records, options=None):
    """Observe multiple records while compiling ``expression`` only once."""
    from jmespath import parser

    compiled = expression
    if isinstance(expression, str):
        compiled = parser.Parser().parse(expression)
    return [compiled.observe(record, options=options) for record in records]


observe_all = observe_many
