from jmespath import parser
from jmespath import policy
from jmespath.visitor import Options
from jmespath.policy import (
    Policy,
    PolicySnapshot,
    AuditLog,
    ExtensionRevokedError,
)

__version__ = '1.1.0'


def compile(expression):
    return parser.Parser().parse(expression)


def search(expression, data, options=None, policy=None, audit=None,
           query_id=None):
    return parser.Parser().parse(expression).search(
        data, options=options, policy=policy, audit=audit,
        query_id=query_id)
