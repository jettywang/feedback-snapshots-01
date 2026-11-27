"""Fenced, atomic writes for the Node exporter textfile collector directory.

Two services that publish to the same ``*.prom`` path can race each other.
The plain :func:`prometheus_client.write_to_textfile` helper only guarantees
that an individual write is atomic; a publisher whose credentials have been
revoked can still overwrite a newer file produced by the publisher that
replaced it.

This module adds an *optional* safe commit on top of the same temporary file
plus rename mechanism.  Every commit is tagged with a monotonically increasing
fencing generation issued by a :class:`GenerationAuthority`.  The highest
generation that has successfully committed is persisted in a sidecar next to
the metrics file, so a process that was revoked (that is, holds a generation
below the one currently in force) can never install its output, even if it
finishes after its replacement.

The result of every attempt is a :class:`CommitReceipt` whose status
distinguishes a revoked publisher, a filesystem failure and a normal
publication; exceptions are reported on the receipt instead of propagating.
"""

from contextlib import contextmanager
import json
import os
import threading
from typing import Callable, Dict, Iterator, Optional

from .exposition import generate_latest
from .openmetrics import exposition as openmetrics
from .registry import Collector

__all__ = (
    'CommitReceipt',
    'CommitStatus',
    'EligibilityCheck',
    'GenerationAuthority',
    'safe_write_to_textfile',
)

# msvcrt.locking raises after a short busy wait instead of blocking, so the
# Windows lock path retries for roughly ten seconds before giving up.
_LOCK_RETRY_DELAY_SECONDS = 0.05
_LOCK_ATTEMPTS = 200

if os.name == 'nt':  # pragma: no cover - exercised only on Windows
    import msvcrt
else:
    import fcntl


class CommitStatus:
    """Outcome of a safe commit attempt.

    The three states are deliberately distinct so callers can tell a policy
    rejection (revocation) apart from an I/O problem.
    """

    COMMITTED = 'committed'
    REVOKED = 'revoked'
    FAILED = 'failed'


class CommitReceipt:
    """Result of :func:`safe_write_to_textfile`.

    Attributes:
        path: Destination metrics file the attempt targeted.
        publisher: Identifier of the publisher that made the attempt.
        generation: Fencing generation the attempt presented, or ``None`` if
            the publisher was already revoked before staging began.
        status: One of the :class:`CommitStatus` constants.
        error: Exception raised while staging or committing, or ``None`` for
            successful or revoked attempts.
        committed_generation: Highest generation recorded for ``path`` after
            the attempt, regardless of whether this attempt committed it.
    """

    __slots__ = (
        'path', 'publisher', 'generation', 'status', 'error',
        'committed_generation',
    )

    def __init__(
        self,
        path: str,
        publisher: str,
        generation: Optional[int],
        status: str,
        committed_generation: Optional[int],
        error: Optional[Exception] = None,
    ) -> None:
        self.path = path
        self.publisher = publisher
        self.generation = generation
        self.status = status
        self.error = error
        self.committed_generation = committed_generation

    @property
    def committed(self) -> bool:
        """Whether this attempt installed its metrics file."""
        return self.status == CommitStatus.COMMITTED

    def __repr__(self) -> str:
        return (
            'CommitReceipt('
            f'path={self.path!r}, publisher={self.publisher!r}, '
            f'generation={self.generation!r}, status={self.status!r}, '
            f'committed_generation={self.committed_generation!r}, '
            f'error={self.error!r})'
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CommitReceipt):
            return NotImplemented
        return (
            self.path == other.path
            and self.publisher == other.publisher
            and self.generation == other.generation
            and self.status == other.status
            and self.committed_generation == other.committed_generation
            and self.error.__class__ == other.error.__class__
            and str(self.error) == str(other.error)
        )


# An eligibility callback maps a publisher identifier to its current fencing
# generation.  Returning ``None`` means the publisher is not authorized.
EligibilityCheck = Callable[[str], Optional[int]]


class GenerationAuthority:
    """In-process registry of publisher fencing generations.

    The authority is the policy object that decides which publisher is
    currently allowed to write.  When a publisher is rotated in,
    :meth:`grant` hands it a generation strictly greater than every
    generation issued before; :meth:`revoke` removes it again.

    One authority instance coordinates the threads of a process.  When
    several processes publish to the same directory they may each hold an
    authority as long as generations are coordinated (for example by a
    leader-election service) so that newer publishers always receive larger
    numbers.  Durable protection across processes comes from the generation
    sidecar persisted next to the metrics file.
    """

    def __init__(self) -> None:
        self._generations: Dict[str, int] = {}
        self._next_generation = 1

    def grant(self, publisher: str) -> int:
        """Authorize ``publisher`` and return a fresh fencing generation."""
        generation = self._next_generation
        self._next_generation += 1
        self._generations[publisher] = generation
        return generation

    def revoke(self, publisher: str) -> None:
        """Remove every authorization held by ``publisher``."""
        self._generations.pop(publisher, None)

    def generation_for(self, publisher: str) -> Optional[int]:
        """Return the live generation of ``publisher``, or ``None``."""
        return self._generations.get(publisher)

    def as_check(self) -> EligibilityCheck:
        """Return a callback suitable for ``safe_write_to_textfile``."""
        return self.generation_for


def _sidecar_path(path: str) -> str:
    return f'{path}.generation'


def _lock_path(path: str) -> str:
    return f'{path}.lock'


@contextmanager
def _file_lock(path: str) -> Iterator[None]:
    """Serialize commits of one metrics path across processes and threads."""
    lock_fd = os.open(_lock_path(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == 'nt':  # pragma: no cover - exercised only on Windows
            import time
            for _ in range(_LOCK_ATTEMPTS):
                try:
                    msvcrt.locking(  # type: ignore[attr-defined]
                        lock_fd, msvcrt.LK_NBLCK, 1,  # type: ignore[attr-defined]
                    )
                    break
                except OSError:
                    time.sleep(_LOCK_RETRY_DELAY_SECONDS)
            else:
                raise OSError(f'Could not acquire lock for {path!r}')
            try:
                yield
            finally:
                msvcrt.locking(  # type: ignore[attr-defined]
                    lock_fd, msvcrt.LK_UNLCK, 1,  # type: ignore[attr-defined]
                )
        else:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _read_sidecar(path: str) -> Optional[int]:
    """Return the committed generation recorded beside ``path``."""
    try:
        with open(_sidecar_path(path), encoding='utf-8') as handle:
            record = json.load(handle)
    except FileNotFoundError:
        return None
    generation = record.get('generation')
    # bool is a subclass of int but must not be accepted as a generation.
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise ValueError(f'Invalid generation sidecar for {path!r}')
    return generation


def _stage_file(target: str, payload: bytes) -> str:
    """Write ``payload`` to a temp file and return its path."""
    tmp_path = (
        f'{target}.tmp.{os.getpid()}.{threading.current_thread().ident}'
    )
    with open(tmp_path, 'wb') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return tmp_path


def _write_sidecar(path: str, publisher: str, generation: int) -> None:
    """Persist the new committed generation atomically."""
    target = _sidecar_path(path)
    payload = json.dumps(
        {'generation': generation, 'publisher': publisher},
    ).encode('utf-8')
    tmp_path = _stage_file(target, payload)
    os.replace(tmp_path, target)


def _tmp_metrics_path(path: str, tmpdir: Optional[str]) -> str:
    filename = os.path.basename(path)
    directory = tmpdir if tmpdir is not None else os.path.dirname(path) or '.'
    return (
        f'{os.path.join(directory, filename)}.'
        f'{os.getpid()}.{threading.current_thread().ident}'
    )


def safe_write_to_textfile(
    path: str,
    registry: Collector,
    publisher: str,
    eligibility: EligibilityCheck,
    escaping: str = openmetrics.ALLOWUTF8,
    tmpdir: Optional[str] = None,
    payload: Optional[bytes] = None,
) -> CommitReceipt:
    """Atomically publish metrics unless ``publisher`` has been revoked.

    The function keeps the temporary-file-plus-rename behaviour of
    :func:`prometheus_client.write_to_textfile` and adds a fencing check.
    ``eligibility(publisher)`` is consulted twice: before any work and again
    while holding the commit lock, so a revocation that happens while the
    metrics are being generated or staged still takes effect.

    Args:
        path: Destination ``.prom`` file for the textfile collector.
        registry: Collector whose metrics are serialized. Ignored when
            ``payload`` is supplied.
        publisher: Stable identifier of the publishing service.
        eligibility: Callable returning the current fencing generation of
            ``publisher`` and ``None`` once it has been revoked.
        escaping: Text-format escaping scheme, identical to the one accepted
            by :func:`prometheus_client.write_to_textfile`.
        tmpdir: Optional directory for the staging temp file. Must live on
            the same filesystem as ``path`` so the rename stays atomic.
        payload: Pre-rendered metrics bytes. When given, registry
            serialization is skipped; the safe-commit machinery is unchanged.

    Returns:
        A :class:`CommitReceipt`. ``status`` is ``COMMITTED`` on success,
        ``REVOKED`` when the publisher is no longer eligible or its
        generation is older than one already committed, and ``FAILED`` when
        staging or renaming raised an exception (attached as ``error``).
    """
    generation = eligibility(publisher)
    if generation is None:
        return CommitReceipt(
            path, publisher, None, CommitStatus.REVOKED, _read_sidecar(path),
        )

    tmp_path = _tmp_metrics_path(path, tmpdir)
    try:
        if payload is None:
            payload = generate_latest(registry, escaping)
        with open(tmp_path, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        with _file_lock(path):
            current_generation = eligibility(publisher)
            committed_generation = _read_sidecar(path)
            if current_generation is None or (
                committed_generation is not None
                and current_generation < committed_generation
            ):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                return CommitReceipt(
                    path,
                    publisher,
                    generation,
                    CommitStatus.REVOKED,
                    committed_generation,
                )

            # rename(2) is atomic but fails on Windows if the target exists.
            if os.name == 'nt':  # pragma: no cover - POSIX rename semantics
                os.replace(tmp_path, path)
            else:
                os.rename(tmp_path, path)
            _write_sidecar(path, publisher, current_generation)
            return CommitReceipt(
                path,
                publisher,
                generation,
                CommitStatus.COMMITTED,
                current_generation,
            )
    except Exception as error:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        return CommitReceipt(
            path,
            publisher,
            generation,
            CommitStatus.FAILED,
            _safe_read_sidecar(path),
            error,
        )


def _safe_read_sidecar(path: str) -> Optional[int]:
    try:
        return _read_sidecar(path)
    except (OSError, ValueError):
        return None
