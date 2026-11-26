from .delegation import *  # noqa: F401,F403
from . import delegation as _delegation

for _name in (n for n in vars(_delegation) if not n.startswith("_")):
    globals()[_name] = getattr(_delegation, _name)
