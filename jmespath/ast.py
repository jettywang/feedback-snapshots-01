# AST nodes have this structure:
# {"type": <node type>", children: [], "value": ""}
#
# Nodes are plain dicts for backwards compatibility.  The ``Node`` subclass
# optionally carries a source span as an attribute instead of a key so that
# equality with the historical dict representation is preserved.


class Node(dict):
    """A dict AST node with an optional source span attribute."""

    def __init__(self, value, span=None, name_span=None):
        super(Node, self).__init__(value)
        self.span = span
        self.name_span = name_span


def _node(value, span=None, name_span=None):
    return Node(value, span=span, name_span=name_span)


def comparator(name, first, second, span=None):
    return _node({'type': 'comparator', 'children': [first, second],
                  'value': name}, span)


def current_node(span=None):
    return _node({'type': 'current', 'children': []}, span)


def expref(expression, span=None):
    return _node({'type': 'expref', 'children': [expression]}, span)


def function_expression(name, args, span=None, name_span=None):
    return _node({'type': 'function_expression', 'children': args,
                  'value': name}, span, name_span=name_span)


def field(name, span=None):
    return _node({"type": "field", "children": [], "value": name}, span)


def filter_projection(left, right, comparator, span=None):
    return _node({'type': 'filter_projection',
                  'children': [left, right, comparator]}, span)


def flatten(node, span=None):
    return _node({'type': 'flatten', 'children': [node]}, span)


def identity(span=None):
    return _node({"type": "identity", 'children': []}, span)


def index(index, span=None):
    return _node({"type": "index", "value": index, "children": []}, span)


def index_expression(children, span=None):
    return _node({"type": "index_expression", 'children': children}, span)


def key_val_pair(key_name, node, span=None):
    return _node({"type": "key_val_pair", 'children': [node],
                  "value": key_name}, span)


def literal(literal_value, span=None):
    return _node({'type': 'literal', 'value': literal_value,
                  'children': []}, span)


def multi_select_dict(nodes, span=None):
    return _node({"type": "multi_select_dict", "children": nodes}, span)


def multi_select_list(nodes, span=None):
    return _node({"type": "multi_select_list", "children": nodes}, span)


def or_expression(left, right, span=None):
    return _node({"type": "or_expression", "children": [left, right]}, span)


def and_expression(left, right, span=None):
    return _node({"type": "and_expression", "children": [left, right]}, span)


def not_expression(expr, span=None):
    return _node({"type": "not_expression", "children": [expr]}, span)


def pipe(left, right, span=None):
    return _node({'type': 'pipe', 'children': [left, right]}, span)


def projection(left, right, span=None):
    return _node({'type': 'projection', 'children': [left, right]}, span)


def subexpression(children, span=None):
    return _node({"type": "subexpression", 'children': children}, span)


def slice(start, end, step, span=None):
    return _node({"type": "slice", "children": [start, end, step]}, span)


def value_projection(left, right, span=None):
    return _node({'type': 'value_projection', 'children': [left, right]},
                 span)
