"""Signer implementation that delegates signing to a local subprocess.

The private key material never enters the calling process: it lives in a
dedicated helper process, and this signer only submits payloads to it over
a strict, length- and time-bounded line protocol on stdin/stdout.

Protocol (newline-delimited JSON, one request and exactly one response per
signing operation):

* Request:  ``{"id": <int>, "payload": <base64>}``
* Response: ``{"id": <int>, "sig": <hex>}``

The subprocess' stderr is drained for logging only and never takes part in
the protocol.

The helper executable and its argument vector are configured explicitly by
the caller. They are never derived from a (potentially untrusted) private
key URI, and the helper is always spawned directly, never through a shell.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
from itertools import count
from queue import Empty, Queue
from typing import NoReturn

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64enc
from securesystemslib.signer._key import Key
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

logger = logging.getLogger(__name__)


class SubprocessSignerError(exceptions.Error):
    """Subprocess signer protocol or session failure."""


class SubprocessSigner(Signer):
    """Signer that delegates signing to a dedicated local subprocess.

    The subprocess is expected to read signing requests from stdin and write
    exactly one response per request to stdout, using the line protocol
    described in the module docstring. stderr output is logged and ignored.

    Safeguards:

    * The helper is spawned from an explicitly configured executable and
      argument array, never through a shell and never from a URI.
    * Payload size, response size and response time are bounded.
    * Each request gets exactly one response, matched by request id.
    * The returned signature is verified against the expected public key
      before it is handed to the caller.
    * On timeout, premature subprocess exit, response id mismatch or any
      other protocol violation the session is torn down: the subprocess is
      killed and the signer cannot be used anymore.

    *Constructor arguments are also instance attributes.*

    Attributes:
        public_key: The related public key instance.
        executable: Resolved path of the helper executable.
        args: Argument vector passed to the helper (no shell strings).
        timeout: Maximum seconds to wait for one response.
        max_payload_size: Maximum payload size in bytes.
        max_response_size: Maximum response line size in bytes.
    """

    SCHEME = "subprocess"
    # NOTE: SCHEME is deliberately not registered in SIGNER_FOR_URI_SCHEME:
    # a private key URI must never be used to construct a command line.

    DEFAULT_TIMEOUT = 10.0
    DEFAULT_MAX_PAYLOAD_SIZE = 4 * 1024 * 1024
    DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024
    _MAX_STDERR_CAPTURE = 4096

    def __init__(  # noqa: PLR0913
        self,
        public_key: Key,
        executable: str,
        args: list[str] | tuple[str, ...] | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
        env: dict[str, str] | None = None,
    ):
        if not isinstance(public_key, Key):
            raise ValueError("expected a Key instance for public_key")

        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")

        resolved = executable
        if not os.path.isabs(resolved):
            found = shutil.which(resolved)
            if found is not None:
                resolved = found
        if not os.path.isfile(resolved):
            raise ValueError(f"executable not found: {executable}")

        if args is None:
            args = []
        if not isinstance(args, list | tuple) or not all(
            isinstance(arg, str) for arg in args
        ):
            raise ValueError("args must be a list of strings, not a shell string")

        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_payload_size <= 0 or max_response_size <= 0:
            raise ValueError("size limits must be positive")

        self._public_key = public_key
        self.executable = resolved
        self.args = list(args)
        self.timeout = timeout
        self.max_payload_size = max_payload_size
        self.max_response_size = max_response_size

        self._lock = threading.Lock()
        self._error: SubprocessSignerError | None = None
        self._request_ids = count()
        self._responses: Queue = Queue()

        # Never shell=True: the command line is the explicit argv array only.
        argv = [self.executable, *self.args]
        self._process = subprocess.Popen(
            argv,  # noqa: S603
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> SubprocessSigner:
        raise ValueError(
            "SubprocessSigner cannot be loaded from a private key URI: "
            "configure the executable and argument array explicitly instead"
        )

    def _read_stdout(self) -> None:
        """Push bounded stdout lines (or terminal events) to the queue."""
        limit = self.max_response_size + 1  # account for newline
        try:
            while True:
                line = self._process.stdout.readline(limit + 1)
                if line == b"":
                    self._responses.put(("eof", None))
                    return
                if len(line) > limit or not line.endswith(b"\n"):
                    self._responses.put(
                        (
                            "error",
                            f"response exceeds {self.max_response_size} bytes",
                        )
                    )
                    return
                self._responses.put(("line", line))
        except (OSError, ValueError) as e:
            self._responses.put(("error", f"failed to read response: {e}"))

    def _drain_stderr(self) -> None:
        """Log stderr output; it never takes part in the protocol."""
        captured = 0
        try:
            while True:
                chunk = self._process.stderr.readline(4097)
                if chunk == b"":
                    return
                if captured < self._MAX_STDERR_CAPTURE:
                    captured += len(chunk)
                    logger.debug("signer subprocess stderr: %r", chunk.rstrip())
        except (OSError, ValueError):
            pass

    def _terminate(self) -> None:
        """Kill the helper process and reap it."""
        proc = self._process
        if proc.stdin:
            try:
                proc.stdin.close()
            except OSError:
                pass
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass

    def _fail(self, message: str) -> NoReturn:
        """Tear down the session and raise: caller must hold the lock."""
        if self._error is None:
            self._error = SubprocessSignerError(message)
        self._terminate()
        raise self._error

    def close(self) -> None:
        """Terminate the helper process. The signer becomes unusable."""
        with self._lock:
            if self._error is None:
                self._error = SubprocessSignerError("signer is closed")
            self._terminate()

    def __enter__(self) -> SubprocessSigner:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self._terminate()
        except Exception as e:  # pragma: no cover
            logger.debug("failed to terminate signer subprocess: %s", e)

    def sign(self, payload: bytes) -> Signature:
        """Sign payload in the helper subprocess and verify the result.

        Raises:
            ValueError: Invalid payload.
            SubprocessSignerError: Protocol violation, timeout, premature
                subprocess exit, or a previously failed session.
            securesystemslib.exceptions.UnverifiedSignatureError: The
                subprocess returned a signature that does not verify with
                the expected public key.
        """
        if not isinstance(payload, bytes):
            raise ValueError("payload must be bytes")
        if len(payload) > self.max_payload_size:
            raise ValueError(f"payload exceeds {self.max_payload_size} bytes")

        with self._lock:
            if self._error is not None:
                raise self._error

            request_id = next(self._request_ids)
            request = (
                json.dumps({"id": request_id, "payload": b64enc(payload)}).encode(
                    "utf-8"
                )
                + b"\n"
            )
            try:
                self._process.stdin.write(request)
                self._process.stdin.flush()
            except (OSError, ValueError) as e:
                self._fail(f"failed to send request to subprocess: {e}")

            try:
                kind, data = self._responses.get(timeout=self.timeout)
            except Empty:
                self._fail(f"subprocess did not respond within {self.timeout} seconds")

            if kind == "eof":
                self._fail("subprocess exited before responding")
            if kind == "error":
                self._fail(f"protocol error: {data}")

            try:
                response = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                self._fail("subprocess returned malformed response")

            if not isinstance(response, dict) or not isinstance(
                response.get("sig"), str
            ):
                self._fail("subprocess returned malformed response")

            if response.get("id") != request_id:
                self._fail(
                    "subprocess response id does not match request id: "
                    "session is out of sync"
                )

            # Exactly one result per request is allowed.
            try:
                self._responses.get_nowait()
                self._fail("subprocess returned more than one result")
            except Empty:
                pass

            try:
                bytes.fromhex(response["sig"])
            except ValueError:
                self._fail("subprocess returned a non-hex signature")

            signature = Signature(self._public_key.keyid, response["sig"])

        # Never accept a signature that does not match the expected key.
        try:
            self._public_key.verify_signature(signature, payload)
        except exceptions.UnverifiedSignatureError:
            with self._lock:
                if self._error is None:
                    self._error = SubprocessSignerError(
                        "subprocess signature failed verification: session torn down"
                    )
                self._terminate()
            raise

        return signature
