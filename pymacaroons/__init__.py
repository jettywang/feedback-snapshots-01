from .access import (
    RequestContext,
    canonicalize_path,
    expires_caveat,
    method_caveat,
    resource_caveat,
    restrict,
)
from .caveat import Caveat
from .macaroon import Macaroon
from .macaroon import MACAROON_V1
from .macaroon import MACAROON_V2
from .verifier import Verifier


__all__ = [
    'Macaroon',
    'Caveat',
    'Verifier',
    'MACAROON_V1',
    'MACAROON_V2',
    'RequestContext',
    'canonicalize_path',
    'resource_caveat',
    'method_caveat',
    'expires_caveat',
    'restrict',
]


__author__ = 'Evan Cordell'

__version__ = "0.13.0"
__version_info__ = tuple(__version__.split('.'))
__short_version__ = __version__
