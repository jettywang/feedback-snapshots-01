"""Minimal local stand-in for the third-party `faker` package used by tests/factories.py.

The full faker dependency is not installable in this offline sandbox; this module only exposes the tiny API
surface (hostname()/ipv4_private()) that the test factories rely on. If the real faker package becomes
available again, deleting this file and its registration in tests/conftest.py restores the original behavior.
"""

import itertools
import random
import sys
import types


class _InternetProvider:
    _tlds = ("com", "org", "net", "io", "dev")
    _words = ("example", "test", "sslyze", "scan", "demo", "host", "node", "tls")

    def hostname(self, levels: int = 2) -> str:
        parts = [random.choice(self._words) for _ in range(max(1, levels))]
        return "-".join(parts) + "." + random.choice(self._tlds)

    def ipv4_private(self) -> str:
        # 10.x.x.x is a private range and never requires a real network lookup in the tests
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


class Faker:
    def __init__(self, *args, **kwargs) -> None:
        self._counter = itertools.count(1)
        self._internet = _InternetProvider()

    def add_provider(self, *args, **kwargs) -> None:
        return None

    def hostname(self) -> str:
        return f"host-{next(self._counter)}.{self._internet.hostname()}"

    def ipv4_private(self) -> str:
        return self._internet.ipv4_private()


def install() -> None:
    """Register this module under the top-level `faker` name if no real faker is installed."""
    try:
        import faker  # noqa: F401
    except ModuleNotFoundError:
        module = types.ModuleType("faker")
        module.Faker = Faker

        providers = types.ModuleType("faker.providers")
        providers.internet = _InternetProvider()
        module.providers = providers

        sys.modules["faker"] = module
        sys.modules["faker.providers"] = providers
