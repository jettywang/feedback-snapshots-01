#!/usr/bin/env python
"""
Run one fixed, trusted command on a remote host and collect bounded output.

The command is supplied by the caller and is expected to be a constant; this
script is about safely handling the *output*, which is untrusted.  It drains
stdout and stderr concurrently so a chatty command cannot fill the SSH
channel window and wedge the receiving thread, and it enforces both a
combined byte budget and an overall deadline.

Usage::

    python examples/bounded_exec.py host --user automation -- \
        /usr/local/bin/fixed-check --json

Exit codes: 0 complete + exit 0, 1 complete + non-zero remote exit, 2 result
failed (for example output limit), 3 result unknown (deadline, cancellation,
disconnect, missing exit-status).

The command line after ``--`` is executed as a *single* remote command line
via the server's shell.  Do not pass untrusted arguments here; the example
is for fixed, trusted remote checks.
"""

import argparse
import os
import signal
import sys
import threading

import paramiko
from paramiko.bounded import ResultStatus, collect_bounded

CANCELLED = threading.Event()


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default=os.environ.get("USER"))
    parser.add_argument("--password", default=None)
    parser.add_argument("--key", default=None, help="private key file")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1024 * 1024,
        help="combined stdout+stderr budget (default: 1 MiB)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="overall deadline in seconds (default: 30)",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="fixed command to run (must be trusted and constant)",
    )
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a fixed remote command is required after --")
    if args.max_bytes <= 0 or args.timeout <= 0:
        parser.error("--max-bytes and --timeout must be positive")
    return args


def remote_command(words):
    """Join a fixed argv into the one command string SSH will execute."""
    # This example intentionally does not attempt general shell quoting.  The
    # caller is responsible for supplying a fixed, trusted command; if a
    # quoting layer is needed, add one here explicitly and keep it separate
    # from untrusted data.
    return " ".join(words)


def report(result):
    label = result.status.value
    print(
        f"status={label} reason={result.reason.value} "
        f"exit={result.exit_status} "
        f"stdout={len(result.stdout)}B stderr={len(result.stderr)}B "
        f"truncated={result.truncated}",
        file=sys.stderr,
    )
    if result.error is not None:
        print(f"error={result.error!r}", file=sys.stderr)
    if result.stdout:
        print("--- stdout ---", file=sys.stderr)
        sys.stderr.buffer.write(result.stdout)
        if not result.stdout.endswith(b"\n"):
            sys.stderr.buffer.write(b"\n")
    if result.stderr:
        print("--- stderr ---", file=sys.stderr)
        sys.stderr.buffer.write(result.stderr)
        if not result.stderr.endswith(b"\n"):
            sys.stderr.buffer.write(b"\n")


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        key_filename=args.key,
        look_for_keys=not bool(args.key),
        timeout=args.timeout,
    )
    channel = client.get_transport().open_session(timeout=args.timeout)
    try:
        channel.exec_command(remote_command(args.command))
        result = collect_bounded(
            channel,
            max_bytes=args.max_bytes,
            timeout=args.timeout,
            cancel=CANCELLED,
        )
        report(result)
        if result.status is ResultStatus.COMPLETE:
            return 0 if result.exit_status == 0 else 1
        if result.status is ResultStatus.FAILED:
            return 2
        return 3
    finally:
        client.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: CANCELLED.set())
    signal.signal(signal.SIGTERM, lambda *_: CANCELLED.set())
    sys.exit(main())
