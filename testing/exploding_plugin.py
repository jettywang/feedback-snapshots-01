from typing import Generator

from detect_secrets.plugins.base import BasePlugin


class ExplodingDetector(BasePlugin):
    """A detector that raises on a marked line but works normally otherwise.

    Its error message deliberately embeds the whole scanned line, so the protective
    tests can assert a plugin failure never leaks the line's plaintext across the
    serial or multiprocessing scan boundaries. Lines without the marker are returned
    as findings through the standard ``BasePlugin.analyze_line`` path.
    """

    secret_type = 'Exploding Detector'
    CRASH_MARKER = 'detonator'

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        if self.CRASH_MARKER in string:
            raise RuntimeError('unable to analyze line: {0}'.format(string))

        yield string.strip()
