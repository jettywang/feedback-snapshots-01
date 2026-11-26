"""Offline regressions pinning the MSAL device-code polling contract.

The desktop app maps device-code polling onto user facing notifications
("still waiting for the sign-in", "MFA confirmation pending", "service is
throttling us", "login cancelled", "sign-in confirmed"). Those mappings are
only safe if four non-success behaviours stay distinguishable:

1. ``authorization_pending`` before the user acts   -> waiting for the user
2. repeated ``authorization_pending`` during MFA     -> keep waiting (MFA)
3. ``slow_down``                                     -> throttle / back off +5s
4. the caller setting ``flow["expires_at"] = 0``     -> user cancelled

and an access token is returned and cached *only* after the synthetic identity
provider's explicit confirmation gate opens.

Everything here is offline.  A thread safe virtual clock replaces
``time.time`` / ``time.sleep`` (the :mod:`msal.oauth2cli.oauth2` module looks
those up on the shared :mod:`time` module lazily), and a per-device scripted
server supplies synthetic responses.  The tests still call the real
``PublicClientApplication.initiate_device_flow`` /
``acquire_token_by_device_flow`` code path (the real polling loop) and the
real ``SerializableTokenCache`` entry point.

Two logins run concurrently against fully independent sessions.  Device A is
throttled (``slow_down``) and then cancelled; device B keeps polling through
MFA and succeeds once confirmation completes.  Every device owns an
independent :class:`DeviceTrace` (every poll, its computed interval, wait
ticks and the end reason), so a contract failure can name the device and the
exact step that violated the agreement.  A matched no-throttle control (device
C) isolates the ``slow_down`` ``+5s`` interval effect.
"""

import base64
import json
import threading
import time as stdlib_time
from threading import get_ident
from unittest.mock import patch

from msal import PublicClientApplication, SerializableTokenCache
from tests import unittest
from tests.http_client import MinimalResponse
from tests.test_token_cache import build_id_token


CLIENT_ID = "device-flow-regression-client"
SCOPES = ["User.Read"]
HOST = "login.microsoftonline.com"
TENANT = "contoso"
AUTHORITY = "https://{}/{}".format(HOST, TENANT)
DEVICE_AUTHORIZATION_ENDPOINT = "{}/oauth2/v2.0/devicecode".format(AUTHORITY)
TOKEN_ENDPOINT = "{}/oauth2/v2.0/token".format(AUTHORITY)

DISCOVERY = {
    "authorization_endpoint": "{}/oauth2/v2.0/authorize".format(AUTHORITY),
    "token_endpoint": TOKEN_ENDPOINT,
    "device_authorization_endpoint": DEVICE_AUTHORIZATION_ENDPOINT,
    "issuer": "https://{}/{}/v2.0".format(HOST, TENANT),
}


# ---------------------------------------------------------------------------
# Distinguishable notification states (the contract consumed by the notifier)
# ---------------------------------------------------------------------------

AWAIT_USER = "awaiting_user_action"
AWAIT_MFA = "awaiting_mfa_confirmation"
THROTTLED = "service_throttled_backoff"
CONFIRMED = "login_confirmed"
SERVER_TERMINAL = "server_terminal_error"

REASON_SUCCESS = "success:confirmation-complete"
REASON_USER_CANCELLED = "ended:user-cancelled"
REASON_FLOW_EXPIRED = "ended:flow-expired"
REASON_SERVER_ERROR = "ended:server-error"
REASON_WORKER_ERROR = "ended:harness-worker-error"
REASON_UNKNOWN = "ended:unknown"


def classify_poll(outcome, phase):
    """Map one token-endpoint poll onto a notification state.

    This is the tiny seam the desktop notification adapter relies on.  In
    particular ``slow_down`` maps to :data:`THROTTLED`, never to
    :data:`CONFIRMED`.
    """
    if outcome == "access_token":
        return CONFIRMED
    if outcome == "slow_down":
        return THROTTLED
    if outcome == "authorization_pending":
        return AWAIT_MFA if phase == "mfa_confirm" else AWAIT_USER
    return SERVER_TERMINAL


# ---------------------------------------------------------------------------
# Controllable clock
# ---------------------------------------------------------------------------

class VirtualClock(object):
    """Monotonic-ish fake clock shared by the concurrent device flows."""

    def __init__(self, start=None):
        self._lock = threading.RLock()
        self._now = stdlib_time.time() if start is None else start

    def now(self):
        with self._lock:
            return self._now

    def advance(self, seconds):
        with self._lock:
            self._now += int(seconds)
            return self._now


# ---------------------------------------------------------------------------
# Synthetic identity provider
# ---------------------------------------------------------------------------

class Reply(object):
    def __init__(self, name, http_status, body):
        self.name = name
        self.http_status = http_status
        self.body = body


def pending(phase):
    return Reply(phase, 400, {
        "error": "authorization_pending",
        "error_description": "synthetic response: {}".format(phase),
        "test_outcome": "authorization_pending",
        "test_phase": phase,
        "test_step": phase,
    })


def slow_down():
    return Reply("slow_down", 400, {
        "error": "slow_down",
        "error_description": "synthetic throttling signal",
        "test_outcome": "slow_down",
        "test_phase": "throttled",
        "test_step": "slow_down",
    })


def _token_body(label):
    uid = "uid-{}".format(label)
    utid = "utid-contoso"
    id_token = build_id_token(
        iss=DISCOVERY["issuer"], aud=CLIENT_ID,
        oid=uid, tid=utid, sub="sub-{}".format(label),
        preferred_username="{}@contoso.com".format(label),
        name=label.upper())
    client_info = base64.b64encode(json.dumps(
        {"uid": uid, "utid": utid}).encode("utf-8")).decode("utf-8")
    return {
        "token_type": "Bearer",
        "scope": "User.Read",
        "expires_in": 3600,
        "access_token": "AT-{}-issued-only-after-confirmation".format(label),
        "refresh_token": "RT-{}".format(label),
        "id_token": id_token,
        "client_info": client_info,
        "test_phase": "confirmed",
        "test_step": "confirmed",
    }


def successful_reply(label):
    return Reply("confirmed", 200, _token_body(label))


def gated_success(server, poll_number):
    """Script entry: token iff the human confirmation gate has opened."""
    if server.confirmed.is_set():
        return successful_reply(server.label)
    with server.lock:
        server.success_blocked_before_confirm += 1
    return pending("mfa_confirm")


class ScriptedDeviceServer(object):
    """Per-device synthetic IdP.  Also usable as the app's ``http_client``."""

    def __init__(self, label, device_code, script):
        self.label = label
        self.device_code = device_code
        self.script = script
        self.lock = threading.RLock()
        self.confirmed = threading.Event()
        self.init_count = 0
        self.wire_polls = 0
        self.wire_poll_log = []
        self.wrong_device_codes = []
        self.success_blocked_before_confirm = 0
        self.overrun = False

    def confirm(self):
        self.confirmed.set()

    def post(self, url, data=None, **kwargs):
        data = data or {}
        if url == DEVICE_AUTHORIZATION_ENDPOINT:
            with self.lock:
                self.init_count += 1
            return MinimalResponse(status_code=200, text=json.dumps({
                "device_code": self.device_code,
                "user_code": "USER-{}".format(self.label),
                "verification_uri": "https://device.example.com/login",
                "expires_in": 900,
                "interval": 5,
                "message": "synthetic device authorization",
            }))

        if url != TOKEN_ENDPOINT:
            raise AssertionError(
                "device={!r}: POST to unexpected endpoint {!r}".format(
                    self.label, url))

        with self.lock:
            self.wire_polls += 1
            poll_number = self.wire_polls
            sent_code = data.get("device_code") or data.get("code")
            self.wire_poll_log.append({
                "poll": poll_number,
                "device_code": sent_code,
                "grant_type": data.get("grant_type"),
            })
            if sent_code != self.device_code:
                self.wrong_device_codes.append((poll_number, sent_code))
            entry = self.script[poll_number - 1] \
                if poll_number - 1 < len(self.script) else None

        if entry is None:
            # Non-retriable sentinel so a broken cancel can never hang.
            self.overrun = True
            reply = Reply("script-exhausted", 400, {
                "error": "expired_token", "test_phase": "overrun",
                "test_step": "script-exhausted"})
        elif callable(entry):
            reply = entry(self, poll_number)
        else:
            reply = entry
        return MinimalResponse(
            status_code=reply.http_status, text=json.dumps(reply.body))

    def get(self, url, **kwargs):  # pragma: no cover - defensive
        raise AssertionError(
            "device={!r}: unexpected GET {!r}".format(self.label, url))

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Independent per-device trace
# ---------------------------------------------------------------------------

class PollRecord(object):
    def __init__(self, index, flow, result, interval_after, at_offset):
        self.index = index
        self.outcome = "access_token" if "access_token" in result \
            else result.get("error", "unknown")
        self.phase = result.get("test_phase")
        self.name = result.get("test_step") or self.phase or self.outcome
        self.step = "poll#{}:{}".format(index, self.name)
        self.interval_after = interval_after
        self.at_offset = at_offset
        self.device_code = flow.get("device_code")

    @property
    def state(self):
        return classify_poll(self.outcome, self.phase)


class TickRecord(object):
    def __init__(self, index, after_poll, seconds, planned_interval, at_offset):
        self.index = index
        self.after_poll = after_poll
        self.seconds = seconds
        self.planned_interval = planned_interval
        self.at_offset = at_offset


class DeviceTrace(object):
    def __init__(self, device, role):
        self.device = device
        self.role = role
        self.polls = []
        self.ticks = []
        self.wait_checks = 0
        self.exit_trip_check = None
        self.end_reason = None
        self.termination_step = "end"
        self.terminal_error = None
        self.wire_polls = 0
        self.cache_adds = []
        self.cached_access_tokens = []
        self.cached_accounts = []
        self.silent_cache_hit = False
        self.silent_token_source = None
        self.silent_detail = None
        self.worker_error = None
        self.cancel_requested = False
        self.wrong_device_codes = []

    def notification_events(self, classifier=classify_poll):
        events = [(p.step, classifier(p.outcome, p.phase)) for p in self.polls]
        if self.end_reason == REASON_USER_CANCELLED:
            events.append((self.termination_step, "user_cancelled"))
        elif self.end_reason == REASON_SUCCESS:
            events.append((self.termination_step, "session_succeeded"))
        return events

    def report(self):
        lines = []
        lines.append("Device {!r} ({})".format(self.device, self.role))
        lines.append("  end_reason={} at {}".format(
            self.end_reason, self.termination_step))
        if self.worker_error:
            lines.append("  WORKER ERROR: {}".format(self.worker_error))
        for poll in self.polls:
            lines.append(
                "  {:<26} outcome={:<22} notification={:<28} "
                "interval_next={}s".format(
                    poll.step, poll.outcome, poll.state, poll.interval_after))
            group = [t for t in self.ticks if t.after_poll == poll.index]
            if group:
                lines.append(
                    "      `- waited {} one-second tick(s) of the planned "
                    "{}s backoff".format(len(group), group[0].planned_interval))
        lines.append(
            "  totals: polls={} wire_polls={} sleep_ticks={} "
            "exit_checks={} cache_adds={} cached_AT={} silent_cache_hit={}".format(
                len(self.polls), self.wire_polls, len(self.ticks),
                self.wait_checks, len(self.cache_adds),
                len(self.cached_access_tokens), self.silent_cache_hit))
        events = [state for _, state in self.notification_events()]
        lines.append("  notification_sequence={}".format(events))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Contract assertions with device + step attribution
# ---------------------------------------------------------------------------

class ContractViolation(AssertionError):
    def __init__(self, device, step, detail, trace=None):
        self.device = device
        self.step = step
        message = (
            "Device-flow agreement violated by device={!r} at step={!r}: {}"
        ).format(device, step, detail)
        if trace is not None:
            message += "\n---- {} trace ----\n".format(device) + trace.report()
        super(ContractViolation, self).__init__(message)


class DeviceContract(object):
    """Assert the per-device agreement; every failure names device and step."""

    def __init__(self, trace):
        self.trace = trace

    def require(self, condition, step, detail):
        if not condition:
            raise ContractViolation(
                self.trace.device, step, detail, self.trace)

    def expect_poll(self, index, *, outcome, interval, state=None, name=None):
        if index > len(self.trace.polls):
            last = self.trace.polls[-1].step if self.trace.polls else "none"
            raise ContractViolation(
                self.trace.device, "poll#{}".format(index),
                "expected poll #{} but only {} poll(s) happened; last step={}; "
                "end={}".format(
                    index, len(self.trace.polls), last,
                    self.trace.end_reason),
                self.trace)
        poll = self.trace.polls[index - 1]
        step = poll.step
        if name is not None:
            self.require(poll.name == name, step,
                         "expected phase {!r}, got {!r}".format(
                             name, poll.name))
        self.require(poll.outcome == outcome, step,
                     "expected token outcome {!r}, got {!r}".format(
                         outcome, poll.outcome))
        self.require(poll.interval_after == interval, step,
                     "computed next interval expected {}s but was {}s".format(
                         interval, poll.interval_after))
        if state is not None:
            self.require(poll.state == state, step,
                         "notification classifier produced {!r}, expected "
                         "{!r}".format(poll.state, state))

    def expect_no_more_polls(self, count):
        self.require(len(self.trace.polls) == count,
                     "poll#{}".format(count + 1),
                     "flow must stop after {} poll(s), but poll #{} happened "
                     "(cancellation/confirmation was not honoured)".format(
                         count, len(self.trace.polls)))

    def expect_ticks_after_poll(self, index, ticks, planned_interval=None):
        group = [t for t in self.trace.ticks if t.after_poll == index]
        step = "wait-after {}".format(self.trace.polls[index - 1].step)
        self.require(len(group) == ticks, step,
                     "expected {} elapsed sleep tick(s) here, got {}".format(
                         ticks, len(group)))
        if planned_interval is not None and group:
            self.require(group[0].planned_interval == planned_interval, step,
                         "planned backoff {}s, observed flow interval {}s"
                         .format(planned_interval, group[0].planned_interval))

    def expect_end(self, reason):
        self.require(self.trace.end_reason == reason,
                     self.trace.termination_step,
                     "expected end reason {!r}, got {!r}".format(
                         reason, self.trace.end_reason))

    def expect_wire_polls_match(self):
        self.require(self.trace.wire_polls == len(self.trace.polls),
                     "http-entry",
                     "recorded {} poll(s) but synthetic server saw {} wire "
                     "poll(s) (cache/retry dedup?)".format(
                         len(self.trace.polls), self.trace.wire_polls))

    def expect_no_wrong_device_code(self):
        self.require(not self.trace.wrong_device_codes,
                     "http-entry:device_code",
                     "polls carried another device_code: {}".format(
                         self.trace.wrong_device_codes))

    def expect_cache_success(self, access_token):
        added_tokens = [c.get("access_token") for c in self.trace.cache_adds]
        self.require(access_token in added_tokens,
                     "cache-entry:SerializableTokenCache.add",
                     "cache.add did not receive the confirmed access token; "
                     "added={}".format(added_tokens))
        self.require(len(self.trace.cached_access_tokens) >= 1,
                     "cache-entry:SerializableTokenCache.add",
                     "successful token response was not written to the cache")
        grants = [c.get("grant_type") for c in self.trace.cache_adds]
        self.require("urn:ietf:params:oauth:grant-type:device_code" in grants,
                     "cache-entry:SerializableTokenCache.add",
                     "cache.add was not invoked by the device_code grant; "
                     "calls={}".format(grants))
        self.require(self.trace.silent_cache_hit,
                     "cache-entry:acquire_token_silent",
                     "could not read the cached token back silently: {} "
                     "source={!r}".format(
                         self.trace.silent_detail,
                         self.trace.silent_token_source))


# ---------------------------------------------------------------------------
# Per-device session (own app, cache, flow, cancel state and trace)
# ---------------------------------------------------------------------------

class DeviceSession(object):
    def __init__(self, label, role, script, clock, *, verify_cache_hit=False):
        self.label = label
        self.role = role
        self.clock = clock
        self.device_code = "device-code-for-{}".format(label)
        self.trace = DeviceTrace(label, role)
        self.server = ScriptedDeviceServer(label, self.device_code, script)
        self.cache = SerializableTokenCache()
        self.app = PublicClientApplication(
            CLIENT_ID, authority=AUTHORITY,
            http_client=self.server, token_cache=self.cache)
        self.flow = None
        self.result = None
        self.worker_error = None
        self.poll_hook = None
        self.cancel_requested = False
        self.verify_cache_hit = verify_cache_hit
        self._armed = None
        self._t0 = clock.now()
        self._install_cache_spy()
        self._install_poll_recorder()

    # -- wiring -------------------------------------------------------------

    def _install_cache_spy(self):
        trace = self.trace
        original_add = self.cache.add

        def spy_add(event):
            response = event.get("response", {}) if isinstance(event, dict) else {}
            trace.cache_adds.append({
                "grant_type": event.get("grant_type") if isinstance(event, dict) else None,
                "access_token": response.get("access_token"),
            })
            return original_add(event)

        self.cache.add = spy_add

    def _install_poll_recorder(self):
        session = self
        original = self.app.client._obtain_token_by_device_flow

        def recording(flow, **kwargs):
            result = original(flow, **kwargs)
            session._record_poll(flow, result)
            return result

        self.app.client._obtain_token_by_device_flow = recording

    # -- user / environment actions ----------------------------------------

    def arm_cancel_after_ticks(self, ticks):
        self._armed = ("cancel", ticks, 0)

    def arm_confirm_after_ticks(self, ticks):
        self._armed = ("confirm", ticks, 0)

    def request_cancel(self):
        """The documented cancellation mechanism: expire this flow now."""
        self.cancel_requested = True
        self.trace.cancel_requested = True
        if self.flow is not None:
            self.flow["expires_at"] = 0

    # -- flow ---------------------------------------------------------------

    def initiate(self):
        self._t0 = self.clock.now()
        self.flow = self.app.initiate_device_flow(SCOPES)
        return self.flow

    def exit_condition(self, flow):
        # Mirrors the library default exactly:
        # flow.get("expires_at", 0) < time.time()
        self.trace.wait_checks += 1
        expired = flow.get("expires_at", 0) < self.clock.now()
        if expired and self.trace.exit_trip_check is None:
            self.trace.exit_trip_check = self.trace.wait_checks
        return expired

    def on_sleep(self, seconds):
        tick_index = len(self.trace.ticks) + 1
        after_poll = len(self.trace.polls)
        interval = self.flow.get("interval") if self.flow else None
        self.trace.ticks.append(TickRecord(
            tick_index, after_poll, seconds, interval,
            self.clock.now() - self._t0))
        if self._armed is not None:
            kind, after, count = self._armed
            count += 1
            self._armed = (kind, after, count)
            if count >= after:
                self._armed = None
                if kind == "cancel":
                    self.request_cancel()
                else:
                    self.server.confirm()

    def _record_poll(self, flow, result):
        record = PollRecord(
            len(self.trace.polls) + 1, flow, result,
            flow.get("interval"), self.clock.now() - self._t0)
        self.trace.polls.append(record)
        if self.poll_hook is not None:
            self.poll_hook(self, record)

    def run_polling_loop(self):
        # No post= seam: polls traverse the app's real (throttle-wrapped)
        # http_client, so the wire/poll equality check proves the throttling
        # layer never deduplicates device-flow polls.
        return self.app.acquire_token_by_device_flow(
            self.flow, exit_condition=self.exit_condition)

    def check_silent_cache_hit(self):
        trace = self.trace
        try:
            accounts = self.app.get_accounts()
            if len(accounts) != 1:
                trace.silent_detail = \
                    "expected exactly 1 account, found {}".format(len(accounts))
                return

            def forbid_post(*args, **kwargs):
                raise AssertionError(
                    "acquire_token_silent must be a cache hit; an HTTP POST "
                    "was attempted")

            result = self.app.acquire_token_silent(
                SCOPES, accounts[0], post=forbid_post)
            source = (result or {}).get(self.app._TOKEN_SOURCE)
            trace.silent_token_source = source
            trace.silent_cache_hit = (
                source == self.app._TOKEN_SOURCE_CACHE
                and bool((result or {}).get("access_token")))
            if not trace.silent_cache_hit:
                trace.silent_detail = \
                    "source={!r} result_keys={}".format(
                        source, sorted((result or {}).keys()))
        except Exception as exc:  # pragma: no cover - diagnostic path
            trace.silent_detail = "{}: {}".format(type(exc).__name__, exc)

    def finish(self, result=None, worker_error=None):
        if result is not None:
            self.result = result
        if worker_error is not None:
            self.worker_error = worker_error
            self.trace.worker_error = worker_error
        trace = self.trace
        trace.wire_polls = self.server.wire_polls
        trace.wrong_device_codes = list(self.server.wrong_device_codes)
        if self.worker_error is not None:
            trace.end_reason = REASON_WORKER_ERROR
        elif isinstance(self.result, dict) and "access_token" in self.result:
            trace.end_reason = REASON_SUCCESS
        elif self.cancel_requested:
            trace.end_reason = REASON_USER_CANCELLED
        elif self.flow is not None and \
                self.clock.now() >= self.flow.get("expires_at", 0):
            trace.end_reason = REASON_FLOW_EXPIRED
        elif isinstance(self.result, dict) and self.result.get("error"):
            trace.end_reason = REASON_SERVER_ERROR
            trace.terminal_error = self.result.get("error")
        else:
            trace.end_reason = REASON_UNKNOWN

        if trace.end_reason == REASON_USER_CANCELLED and self.trace.polls:
            last = self.trace.polls[-1].step
            trip = self.trace.exit_trip_check
            trace.termination_step = \
                "wait-after {} (exit_condition check #{})".format(
                    last, trip)
        elif self.trace.polls:
            trace.termination_step = "end-after {}".format(
                self.trace.polls[-1].step)

        try:
            serialized = json.loads(self.cache.serialize())
            trace.cached_access_tokens = list(
                serialized.get("AccessToken", {}).keys())
            trace.cached_accounts = list(
                serialized.get("Account", {}).keys())
        except Exception as exc:  # pragma: no cover
            trace.silent_detail = "cache serialize failed: {}".format(exc)

        if self.verify_cache_hit and trace.end_reason == REASON_SUCCESS:
            self.check_silent_cache_hit()
        return trace


# ---------------------------------------------------------------------------
# Concurrent experiment runner
# ---------------------------------------------------------------------------

class Experiment(object):
    """Run one or more sessions against one virtual clock, simultaneously."""

    def __init__(self, sessions, clock=None):
        self.sessions = sessions
        self.clock = clock or VirtualClock()
        self.barrier = threading.Barrier(len(sessions))
        self._session_by_ident = {}
        self.alive = []

    def fake_sleep(self, seconds):
        self.clock.advance(seconds)
        session = self._session_by_ident.get(get_ident())
        if session is not None:
            session.on_sleep(seconds)

    def _worker(self, session):
        self._session_by_ident[get_ident()] = session
        try:
            self.barrier.wait(timeout=10)  # simultaneous polling start
            result = session.run_polling_loop()
            session.finish(result=result)
        except Exception as exc:  # capture, never hang the experiment
            import traceback
            session.finish(worker_error="{}\n{}".format(
                exc, traceback.format_exc()))

    def run(self, join_timeout=30):
        with patch.object(stdlib_time, "time", self.clock.now), \
                patch.object(stdlib_time, "sleep", self.fake_sleep):
            for session in self.sessions:
                session.initiate()
            threads = []
            for session in self.sessions:
                thread = threading.Thread(
                    target=self._worker, args=(session,), daemon=True)
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join(join_timeout)
            self.alive = [
                session.label for session, thread in zip(self.sessions, threads)
                if thread.is_alive()]
        return [session.trace for session in self.sessions]


# ---------------------------------------------------------------------------
# Scenario scripts and user-action wiring
# ---------------------------------------------------------------------------

SCRIPT_A_THROTTLE_CANCEL = [
    pending("await_user"),   # poll #1: user has not acted yet
    slow_down(),             # poll #2: service asks for +5s backoff
]


def hook_a_cancel_on_slow_down(session, record):
    if record.outcome == "slow_down":
        # The user hits cancel shortly after the throttle signal arrives.
        session.arm_cancel_after_ticks(2)


SCRIPT_B_MFA_SUCCESS = [
    pending("await_user"),   # poll #1: waiting for the user
    pending("mfa_confirm"),  # poll #2: first factor done, MFA pending
    pending("mfa_confirm"),  # poll #3: still waiting for MFA confirmation
    gated_success,           # poll #4: token iff confirmation completed
]


def hook_b_confirm_during_second_mfa_wait(session, record):
    if record.index == 3 and record.phase == "mfa_confirm":
        # Human approves the notification / MFA a couple of ticks later.
        session.arm_confirm_after_ticks(2)


SCRIPT_C_NO_THROTTLE_CONTROL = [
    pending("await_user"),   # poll #1
    pending("await_user"),   # poll #2: same slot as A's slow_down, no throttle
]


def hook_c_cancel_on_second_poll(session, record):
    if record.index == 2:
        session.arm_cancel_after_ticks(2)


def build_device_a(clock):
    session = DeviceSession(
        "device-A", "slow_down then user cancel",
        SCRIPT_A_THROTTLE_CANCEL, clock)
    session.poll_hook = hook_a_cancel_on_slow_down
    return session


def build_device_b(clock):
    session = DeviceSession(
        "device-B", "MFA wait then confirm then success",
        SCRIPT_B_MFA_SUCCESS, clock, verify_cache_hit=True)
    session.poll_hook = hook_b_confirm_during_second_mfa_wait
    return session


def build_device_c(clock):
    session = DeviceSession(
        "device-C", "no-throttle matched control",
        SCRIPT_C_NO_THROTTLE_CONTROL, clock)
    session.poll_hook = hook_c_cancel_on_second_poll
    return session


def render_report(traces):
    bar = "=" * 78
    chunks = [bar, "MSAL device-code flow - offline experiment report", bar]
    for trace in traces:
        chunks.append(trace.report())
        chunks.append("-" * 78)
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class DeviceFlowNotificationContractTest(unittest.TestCase):

    def setUp(self):
        patcher = patch(
            "msal.authority.tenant_discovery", return_value=DISCOVERY)
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- main concurrent scenario ------------------------------------------

    def test_two_logins_start_together_throttle_cancel_and_mfa_success(self):
        clock = VirtualClock()
        device_a = build_device_a(clock)
        device_b = build_device_b(clock)
        experiment = Experiment([device_a, device_b], clock)
        traces = experiment.run()

        self.assertEqual(
            experiment.alive, [],
            "worker threads did not terminate: {}\n{}".format(
                experiment.alive, render_report(traces)))
        for session in (device_a, device_b):
            self.assertIsNone(
                session.trace.worker_error,
                "{} worker failed:\n{}".format(
                    session.label, session.trace.worker_error))

        contract_a = DeviceContract(device_a.trace)
        contract_b = DeviceContract(device_b.trace)

        # Device A: await user -> throttled -> user cancels during backoff.
        contract_a.expect_wire_polls_match()
        contract_a.expect_no_wrong_device_code()
        contract_a.expect_poll(
            1, outcome="authorization_pending", state=AWAIT_USER, interval=5)
        contract_a.expect_poll(
            2, outcome="slow_down", state=THROTTLED, interval=10)
        contract_a.expect_no_more_polls(2)
        contract_a.expect_ticks_after_poll(1, 5, planned_interval=5)
        contract_a.expect_ticks_after_poll(2, 2, planned_interval=10)
        contract_a.expect_end(REASON_USER_CANCELLED)
        contract_a.require(
            not device_a.trace.cache_adds
            and not device_a.trace.cached_access_tokens,
            "cache-entry",
            "cancelled device A must not cache any token")

        # Device B: await user -> MFA continues -> MFA continues -> confirmed.
        contract_b.expect_wire_polls_match()
        contract_b.expect_no_wrong_device_code()
        contract_b.expect_poll(
            1, outcome="authorization_pending", state=AWAIT_USER, interval=5)
        contract_b.expect_poll(
            2, outcome="authorization_pending", state=AWAIT_MFA, interval=5)
        contract_b.expect_poll(
            3, outcome="authorization_pending", state=AWAIT_MFA, interval=5)
        contract_b.expect_poll(
            4, outcome="access_token", state=CONFIRMED, interval=5)
        contract_b.expect_no_more_polls(4)
        contract_b.expect_ticks_after_poll(1, 5, planned_interval=5)
        contract_b.expect_ticks_after_poll(2, 5, planned_interval=5)
        contract_b.expect_end(REASON_SUCCESS)
        contract_b.require(
            device_b.server.confirmed.is_set(), "poll#4:confirmed",
            "success was served before the confirmation gate opened")
        contract_b.require(
            device_b.server.success_blocked_before_confirm == 0,
            "synthetic-server:confirmation-gate",
            "happy path should only request the token after confirmation")
        contract_b.expect_cache_success(
            "AT-device-B-issued-only-after-confirmation")

        # The key isolation property: cancelling A must not cancel B.
        contract_b.require(
            device_b.trace.end_reason == REASON_SUCCESS,
            "isolation:cancel-state",
            "device A's cancellation leaked into device B")
        self.assertNotEqual(
            device_a.device_code, device_b.device_code,
            "the two device flows must not share a device_code")

        # Distinguishable notification sequences.
        states_a = [state for _, state in
                    device_a.trace.notification_events()]
        states_b = [state for _, state in
                    device_b.trace.notification_events()]
        self.assertEqual(
            [AWAIT_USER, THROTTLED, "user_cancelled"], states_a)
        self.assertEqual(
            [AWAIT_USER, AWAIT_MFA, AWAIT_MFA, CONFIRMED,
             "session_succeeded"], states_b)
        self.assertNotIn(CONFIRMED, states_a)
        self.assertNotEqual(THROTTLED, CONFIRMED)

        print("\n" + render_report(traces))

    # -- no-throttle control ------------------------------------------------

    def test_no_throttle_control_keeps_base_interval(self):
        throttled_clock = VirtualClock()
        device_a = build_device_a(throttled_clock)
        Experiment([device_a], throttled_clock).run()

        control_clock = VirtualClock()
        device_c = build_device_c(control_clock)
        Experiment([device_c], control_clock).run()

        contract_a = DeviceContract(device_a.trace)
        contract_c = DeviceContract(device_c.trace)
        contract_a.expect_poll(
            1, outcome="authorization_pending", interval=5)
        contract_a.expect_poll(2, outcome="slow_down", interval=10)
        contract_a.expect_end(REASON_USER_CANCELLED)

        # Control has the same shape but no slow_down: interval stays 5s.
        contract_c.expect_wire_polls_match()
        contract_c.expect_poll(
            1, outcome="authorization_pending", state=AWAIT_USER, interval=5)
        contract_c.expect_poll(
            2, outcome="authorization_pending", state=AWAIT_USER, interval=5)
        contract_c.expect_no_more_polls(2)
        contract_c.expect_ticks_after_poll(1, 5, planned_interval=5)
        contract_c.expect_ticks_after_poll(2, 2, planned_interval=5)
        contract_c.expect_end(REASON_USER_CANCELLED)

        intervals_a = [p.interval_after for p in device_a.trace.polls]
        intervals_c = [p.interval_after for p in device_c.trace.polls]
        self.assertEqual([5, 10], intervals_a)
        self.assertEqual([5, 5], intervals_c)

        comparison = [
            "",
            "No-throttle control vs throttled run:",
            "  device-A (slow_down)      intervals_after_poll={} end={}".format(
                intervals_a, device_a.trace.end_reason),
            "  device-C (no throttle)    intervals_after_poll={} end={}".format(
                intervals_c, device_c.trace.end_reason),
            "  => the only difference is the RFC slow_down +5s adjustment.",
        ]
        print("\n".join(comparison) + "\n" + render_report(
            [device_a.trace, device_c.trace]))

    # -- confirmation gate --------------------------------------------------

    def test_stub_refuses_success_until_confirmation_completes(self):
        server = ScriptedDeviceServer(
            "gate", "code-gate", [gated_success])
        before = gated_success(server, 1)
        self.assertEqual(400, before.http_status)
        self.assertEqual(
            "authorization_pending", before.body["error"])
        self.assertEqual("mfa_confirm", before.body["test_phase"])
        self.assertEqual(1, server.success_blocked_before_confirm)

        server.confirm()
        after = gated_success(server, 1)
        self.assertEqual(200, after.http_status)
        self.assertIn("access_token", after.body)

    def test_without_confirmation_flow_never_reaches_cache(self):
        clock = VirtualClock()
        script = [pending("mfa_confirm") for _ in range(4)]
        session = DeviceSession(
            "device-N", "never confirmed", script, clock)
        # No poll hook: confirmation never happens.
        Experiment([session], clock).run()

        contract = DeviceContract(session.trace)
        contract.expect_poll(
            1, outcome="authorization_pending", state=AWAIT_MFA, interval=5)
        contract.expect_end(REASON_SERVER_ERROR)
        self.assertEqual(
            "expired_token", session.trace.terminal_error,
            "script overrun should terminate with a non-retriable error")
        self.assertFalse(
            session.trace.cache_adds,
            "no token may be cached while confirmation is incomplete")

    # -- diagnostics for the two dangerous mutations ------------------------

    def test_diagnostic_names_device_and_step_if_slow_down_is_confirmation(self):
        clock = VirtualClock()
        device_a = build_device_a(clock)
        Experiment([device_a], clock).run()

        # The correct classifier never raises.
        self.assert_no_false_confirmation(device_a.trace, classify_poll)

        def buggy_classifier(outcome, phase):
            # MUTATION: a notifier wrongly treats slow_down as the user
            # confirming the sign-in.
            if outcome == "slow_down":
                return CONFIRMED
            return classify_poll(outcome, phase)

        with self.assertRaises(ContractViolation) as caught:
            self.assert_no_false_confirmation(
                device_a.trace, buggy_classifier)
        message = str(caught.exception)
        self.assertEqual("device-A", caught.exception.device)
        self.assertIn("poll#2", caught.exception.step)
        self.assertIn("slow_down", caught.exception.step)
        self.assertIn("device-A", message)
        self.assertIn("poll#2:slow_down", message)

    def test_diagnostic_names_victim_device_and_step_if_cancel_state_shared(self):
        shared = SharedCancelState()
        clock = VirtualClock()
        device_b = build_device_b(clock)
        # Replace the healthy confirmation wiring with the shared-cancel bug.
        device_b.poll_hook = lambda session, record: (
            shared.cancel_from("device-A") if record.index == 2 else None)
        shared.bind(device_b)

        Experiment([device_b], clock).run()

        # The shared flag cancels B during the wait after its second poll.
        # The end contract must name device-B and the exact interrupted step.
        contract = DeviceContract(device_b.trace)
        contract.expect_poll(
            1, outcome="authorization_pending", interval=5)
        contract.expect_poll(
            2, outcome="authorization_pending", interval=5)

        with self.assertRaises(ContractViolation) as caught:
            contract.expect_end(REASON_SUCCESS)
        violation = caught.exception
        self.assertEqual("device-B", violation.device)
        self.assertIn("poll#2", violation.step)
        self.assertIn("wait-after", violation.step)
        message = str(violation)
        self.assertIn("device-B", message)
        self.assertIn("poll#2:mfa_confirm", message)

        # The missing continuation is attributable too: expecting poll #3
        # reports the exact poll that the leaked cancel stole from B.
        with self.assertRaises(ContractViolation) as missing:
            contract.expect_poll(
                3, outcome="authorization_pending", interval=5)
        self.assertEqual("device-B", missing.exception.device)
        self.assertEqual("poll#3", missing.exception.step)

        self.assertEqual(
            REASON_USER_CANCELLED, device_b.trace.end_reason,
            "the injected shared state should have cancelled device B")

    def test_concurrent_shared_cancel_state_is_pinned_on_victim_device(self):
        # MUTATION under real concurrency: A and B are started together but
        # are wired to ONE shared cancel object.  A's throttle-triggered
        # cancel must leak into B.  Deterministic events hold B inside its
        # poll#2 hook until A has cancelled, so the attribution is stable.
        shared = SharedCancelState()
        clock = VirtualClock()
        device_a = build_device_a(clock)
        device_b = build_device_b(clock)
        shared.bind(device_a)
        shared.bind(device_b)

        b_reached_poll2 = threading.Event()
        release_b_hook = threading.Event()

        def coordinated_hook_a(session, record):
            if record.outcome == "slow_down":
                self.assertTrue(
                    b_reached_poll2.wait(5),
                    "test coordination timed out waiting for device-B poll#2")
                shared.cancel_from("device-A")
                release_b_hook.set()

        def coordinated_hook_b(session, record):
            if record.index == 2:
                b_reached_poll2.set()
                self.assertTrue(
                    release_b_hook.wait(5),
                    "test coordination timed out waiting for shared cancel")

        device_a.poll_hook = coordinated_hook_a
        device_b.poll_hook = coordinated_hook_b

        experiment = Experiment([device_a, device_b], clock)
        traces = experiment.run()
        self.assertEqual([], experiment.alive)
        for session in (device_a, device_b):
            self.assertIsNone(session.trace.worker_error)

        self.assertEqual(
            REASON_USER_CANCELLED, device_a.trace.end_reason)
        self.assertEqual(
            REASON_USER_CANCELLED, device_b.trace.end_reason,
            "shared cancel state leaked from A into B")

        # The exact contract used for the healthy concurrent run now fails
        # while naming the wronged device and the interrupted step.
        contract_b = DeviceContract(device_b.trace)
        with self.assertRaises(ContractViolation) as caught:
            contract_b.expect_poll(
                1, outcome="authorization_pending", interval=5)
            contract_b.expect_poll(
                2, outcome="authorization_pending", interval=5)
            contract_b.expect_end(REASON_SUCCESS)
        self.assertEqual("device-B", caught.exception.device)
        self.assertIn("poll#2", caught.exception.step)
        self.assertIn("device-B", str(caught.exception))
        print("\n" + render_report(traces))

    # -- helper -------------------------------------------------------------

    @staticmethod
    def assert_no_false_confirmation(trace, classifier):
        for poll in trace.polls:
            state = classifier(poll.outcome, poll.phase)
            if state == CONFIRMED and poll.outcome != "access_token":
                raise ContractViolation(
                    trace.device, poll.step,
                    "poll outcome {!r} was classified as login confirmation; "
                    "slow_down / authorization_pending are control signals, "
                    "not user confirmation".format(poll.outcome),
                    trace)


class SharedCancelState(object):
    """Deliberate bug stand-in: one cancel flag shared across devices."""

    def __init__(self):
        self.sessions = []
        self.cancelled = False

    def bind(self, session):
        self.sessions.append(session)

    def cancel_from(self, actor):
        self.cancelled = True
        for session in self.sessions:
            # The actor's cancel leaks into every bound device flow.
            session.request_cancel()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
