"""Alias module for :mod:`olefile.ole_native`.

The canonical implementation lives in ``olefile/ole_native.py``; this module
exists so callers can use either spelling.
"""

from .ole_native import *  # noqa: F401,F403
from .ole_native import __all__  # noqa: F401
