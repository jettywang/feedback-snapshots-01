"""Trackable claims-challenge interactive upgrades.

This module stores the state, receipts, and timeline for one independently
tracked interactive upgrade.  ``msal.application.PublicClientApplication`` owns
the broker/browser execution; this module deliberately does not import
``application`` to avoid an import cycle.
"""

import hashlib
import json
import logging
import threading
import time
import uuid

from .oauth2cli.oidc import decode_part
from .token_cache import _parse_claims_or_raise


logger = logging.getLogger(__name__)

# A pseudonymous marker placed in request ``data`` so that the token cache can
# isolate a claims-challenge credential from ordinary silent-cache entries.
# The marker value is a hash, never the original challenge.  The oauth2 layer
# strips this cache-key-only marker from the wire body.
CLAIMS_CHALLENGE_CACHE_KEY = "msal_claims_challenge_sha256"


class InteractionStatus(object):
    """Status values exposed to the application/business layer."""

    NORMAL = "normal"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"


class ClaimsChallengeUpgradeError(Exception):
    """A programmer error in the claims-challenge upgrade API."""


_CANCELLATION_MARKERS = (
    "cancel",
    "canceled",
    "cancelled",
    "abort",
    "user_cancelled",
    "user_canceled",
    "interaction_cancelled",
    "interaction_canceled",
)

def canonicalize_claims_challenge(claims_challenge):
    """Return a stable JSON representation of a claims challenge."""
    parsed = _parse_claims_or_raise(claims_challenge)
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def claims_challenge_sha256(claims_challenge):
    return hashlib.sha256(
        canonicalize_claims_challenge(claims_challenge).encode("utf-8")
    ).hexdigest()


def challenge_cache_data(claims_challenge):
    """Return the cache-key-only data for a challenge-bound token."""
    return {CLAIMS_CHALLENGE_CACHE_KEY: claims_challenge_sha256(claims_challenge)}


def normalize_scopes(scopes):
    """Return the caller-facing resource scope set in stable order."""
    return sorted(set(scopes or []))


def text_contains_any(text, markers):
    lower = text.lower()
    return any(marker in lower for marker in markers)


def is_cancellation_response(response):
    if not isinstance(response, dict):
        return False
    values = []
    for key in ("error", "error_description", "_broker_status",
                "_broker_error_code", "_broker_tag"):
        value = response.get(key)
        if value is not None:
            values.append(str(value))
    return text_contains_any(" ".join(values), _CANCELLATION_MARKERS)


def is_cancellation_exception(exc):
    if isinstance(exc, KeyboardInterrupt):
        return True
    name = type(exc).__name__
    if "Timeout" in name:
        return True
    return text_contains_any("{} {}".format(name, exc), _CANCELLATION_MARKERS)


def _decode_client_info_home_account_id(response):
    client_info = response.get("client_info")
    if not client_info:
        return None
    try:
        decoded = json.loads(decode_part(client_info))
    except Exception:
        return None
    if "uid" in decoded and "utid" in decoded:
        return "{uid}.{utid}".format(**decoded)
    return None


def response_home_account_id(response):
    """Best-effort identity of a broker/browser token response."""
    if not isinstance(response, dict):
        return None
    home_account_id = _decode_client_info_home_account_id(response)
    if home_account_id:
        return home_account_id
    id_token_claims = response.get("id_token_claims")
    if not id_token_claims and response.get("id_token"):
        try:
            parts = response["id_token"].split(".")
            if len(parts) >= 2:
                id_token_claims = json.loads(decode_part(parts[1]))
        except Exception:
            id_token_claims = None
    if isinstance(id_token_claims, dict):
        oid = id_token_claims.get("oid") or id_token_claims.get("sub")
        tid = id_token_claims.get("tid")
        if oid and tid:
            return "{}.{}".format(oid, tid)
        if oid:
            return oid
    return None


def response_identity(response):
    home_account_id = response_home_account_id(response)
    claims = (response or {}).get("id_token_claims") or {}
    username = claims.get("preferred_username") or claims.get("upn")
    return home_account_id, username


def account_identity(account):
    if not account:
        return None, None
    home_account_id = account.get("home_account_id")
    if not home_account_id and account.get("local_account_id") and account.get("realm"):
        home_account_id = "{}.{}".format(
            account["local_account_id"], account["realm"])
    username = account.get("username")
    return home_account_id, username


def _accounts_match(account, response):
    """Return True when the response is not evidence of another account."""
    if not account:
        return True
    expected_home, expected_username = account_identity(account)
    actual_home, actual_username = response_identity(response)
    if expected_home and actual_home and expected_home.lower() != actual_home.lower():
        return False
    expected_local = account.get("local_account_id")
    actual_local = (response or {}).get("_account_id")
    if expected_local and actual_local and expected_local != actual_local:
        return False
    if expected_username and actual_username and (
        expected_username.lower() != actual_username.lower()
    ):
        return False
    return True


def receipt_expires_on(response):
    if not isinstance(response, dict) or "expires_in" not in response:
        return None
    try:
        return int(time.time() + int(response["expires_in"]))
    except (TypeError, ValueError):
        return None


class ClaimsChallengeReceipt(dict):
    """A dict-like, condition-bound proof of a completed upgrade.

    A receipt binds the original account, the requested resource scopes, and
    the canonical claims challenge.  It is only valid for that combination and
    only for the upgrade attempt that produced it.
    """

    def matches(self, account=None, scopes=None, claims_challenge=None):
        if self.get("status") != InteractionStatus.CONFIRMED:
            return False
        if claims_challenge is not None:
            try:
                challenge_hash = claims_challenge_sha256(claims_challenge)
            except ValueError:
                return False
            if challenge_hash != self.get("claims_challenge_sha256"):
                return False
        if scopes is not None and normalize_scopes(scopes) != self.get("scopes"):
            return False
        if account is not None:
            expected_home, expected_username = account_identity(account)
            if expected_home and self.get("home_account_id") and (
                expected_home.lower() != self["home_account_id"].lower()
            ):
                return False
            if expected_username and self.get("username") and (
                expected_username.lower() != self["username"].lower()
            ):
                return False
        expires_on = self.get("expires_on")
        if expires_on is not None:
            try:
                expired = int(expires_on) <= int(time.time())
            except (TypeError, ValueError):
                return False
            if expired:
                return False
        return True


def build_receipt(
        upgrade_id, attempt_id, account, scopes, claims_challenge,
        source, response):
    """Build a receipt from a validated successful token response."""
    actual_home, actual_username = response_identity(response)
    expected_home, expected_username = account_identity(account)
    receipt = ClaimsChallengeReceipt({
        "upgrade_id": upgrade_id,
        "attempt_id": attempt_id,
        "status": InteractionStatus.CONFIRMED,
        "source": source,
        "token_source": response.get("token_source"),
        "home_account_id": actual_home or expected_home,
        "username": actual_username or expected_username,
        "scopes": normalize_scopes(scopes),
        "claims_challenge": canonicalize_claims_challenge(claims_challenge),
        "claims_challenge_sha256": claims_challenge_sha256(claims_challenge),
        "issued_at": int(time.time()),
    })
    expires_on = receipt_expires_on(response)
    if expires_on is not None:
        receipt["expires_on"] = expires_on
    for key in ("access_token", "token_type", "id_token"):
        value = response.get(key)
        if isinstance(value, str) and value:
            receipt[key] = value
    return receipt


class ClaimsChallengeUpgrade(object):
    """A resumable, independently tracked claims-challenge upgrade.

    Each execution of :meth:`start`/:meth:`reopen` creates a new attempt id
    (generation).  Receipts from an older generation are recorded for
    inspection but can never mutate the current generation.
    """

    def __init__(self, owner, scopes, account, claims_challenge, **options):
        self._owner = owner
        self._lock = threading.RLock()
        self.upgrade_id = str(uuid.uuid4())
        self.scopes = normalize_scopes(scopes)
        self.account = dict(account) if account else None
        self.claims_challenge = canonicalize_claims_challenge(claims_challenge)
        self.claims_challenge_sha256 = claims_challenge_sha256(claims_challenge)
        self.options = dict(options)
        self.status = InteractionStatus.CONFIRMATION_REQUIRED
        self.receipt = None
        self.result = None
        self.timeline = []
        self._generation = 0
        self._attempt_id = None
        self._attempts = {}
        self._stale_receipts = []
        self._new_attempt()

    def _new_attempt(self):
        self._generation += 1
        self._attempt_id = "{}-{}".format(self.upgrade_id, self._generation)
        self._attempts[self._attempt_id] = {
            "attempt_id": self._attempt_id,
            "generation": self._generation,
            "status": InteractionStatus.CONFIRMATION_REQUIRED,
            "source": None,
            "receipt": None,
            "started_at": int(time.time()),
        }
        self.status = InteractionStatus.CONFIRMATION_REQUIRED
        return self._attempt_id

    @property
    def attempt_id(self):
        with self._lock:
            return self._attempt_id

    @property
    def generation(self):
        with self._lock:
            return self._generation

    def _record(self, event, **details):
        entry = {
            "event": event,
            "upgrade_id": self.upgrade_id,
            "attempt_id": self._attempt_id,
            "generation": self._generation,
            "at": int(time.time()),
        }
        entry.update(details)
        self.timeline.append(entry)
        logger.debug("claims-challenge timeline: %s", entry)
        return entry

    def snapshot(self):
        with self._lock:
            return {
                "upgrade_id": self.upgrade_id,
                "attempt_id": self._attempt_id,
                "generation": self._generation,
                "status": self.status,
                "account": dict(self.account) if self.account else None,
                "scopes": list(self.scopes),
                "claims_challenge_sha256": self.claims_challenge_sha256,
                "receipt": dict(self.receipt) if self.receipt else None,
                "result_status": (self.result or {}).get("interaction_status"),
                "timeline": [dict(item) for item in self.timeline],
                "attempts": [dict(item) for item in self._attempts.values()],
                "stale_receipts": [dict(item) for item in self._stale_receipts],
            }

    def start(self, **options):
        """Run the current attempt, trying broker and then a configured fallback."""
        with self._lock:
            merged = dict(self.options)
            merged.update(options)
            self.options = merged
            if self.status == InteractionStatus.CONFIRMED:
                return self._result_with_metadata(self.receipt)
            if self.status == InteractionStatus.CANCELLED:
                # Calling start() on a cancelled session is an explicit re-open.
                self._record("reopened_by_start")
                self._new_attempt()
            self._record("attempt_started")
        return self._owner._execute_claims_challenge_upgrade(self)

    def reopen(self, **options):
        """Create a fresh attempt after a cancellation or failed completion."""
        with self._lock:
            previous_generation = self._generation
            merged = dict(self.options)
            merged.update(options)
            self.options = merged
            self._new_attempt()
            self.receipt = None
            self.result = None
            self._record("reopened", previous_generation=previous_generation)
        return self._owner._execute_claims_challenge_upgrade(self)

    def cancel(self, reason="user_cancelled", source="caller", attempt_id=None):
        with self._lock:
            if attempt_id and attempt_id != self._attempt_id:
                self._record(
                    "stale_attempt_result_ignored",
                    reason="cancellation_from_old_attempt",
                    attempt_id=attempt_id,
                )
                return self._result_with_metadata(
                    interaction_status=self.status)
            attempt = self._attempts.get(self._attempt_id)
            if attempt is not None:
                attempt["status"] = InteractionStatus.CANCELLED
                attempt["source"] = source
                attempt["reason"] = reason
            self.status = InteractionStatus.CANCELLED
            self._record("cancelled", reason=reason, source=source)
            result = {
                "error": "interaction_cancelled",
                "error_description": reason,
                "interaction_status": InteractionStatus.CANCELLED,
                "upgrade_id": self.upgrade_id,
                "attempt_id": self._attempt_id,
                "claims_challenge_upgrade": self.snapshot(),
            }
            self.result = result
            return result

    def submit_receipt(self, receipt):
        """Offer a receipt to this session, ignoring stale generations."""
        with self._lock:
            if not isinstance(receipt, dict):
                raise ClaimsChallengeUpgradeError("receipt must be a dict")
            receipt_attempt_id = receipt.get("attempt_id")
            if receipt.get("upgrade_id") != self.upgrade_id:
                self._stale_receipts.append(dict(receipt))
                self._record(
                    "stale_receipt_ignored",
                    reason="foreign_upgrade_id",
                    receipt_attempt_id=receipt_attempt_id,
                )
                return False
            if receipt_attempt_id != self._attempt_id:
                self._stale_receipts.append(dict(receipt))
                self._record(
                    "stale_receipt_ignored",
                    reason="stale_attempt",
                    receipt_attempt_id=receipt_attempt_id,
                )
                return False
            if receipt.get("status") != InteractionStatus.CONFIRMED:
                self._record("receipt_rejected", reason="not_confirmed")
                return False
            if not ClaimsChallengeReceipt(receipt).matches(
                    account=self.account, scopes=self.scopes,
                    claims_challenge=self.claims_challenge):
                self._record("receipt_rejected", reason="conditions_mismatch")
                return False
            self.receipt = ClaimsChallengeReceipt(receipt)
            self.status = InteractionStatus.CONFIRMED
            attempt = self._attempts.get(self._attempt_id)
            if attempt is not None:
                attempt["status"] = InteractionStatus.CONFIRMED
                attempt["receipt"] = dict(self.receipt)
            self._record(
                "receipt_accepted",
                source=self.receipt.get("source"),
                token_source=self.receipt.get("token_source"),
            )
            return True

    def accept_result(self, response, source, attempt_id=None):
        """Validate, cache, and convert a response into a receipt."""
        with self._lock:
            if attempt_id and attempt_id != self._attempt_id:
                self._record(
                    "stale_attempt_result_ignored",
                    reason="result_from_old_attempt",
                    attempt_id=attempt_id,
                    source=source,
                )
                return None
            return self._accept_result_locked(response, source)

    def _accept_result_locked(self, response, source):
        if is_cancellation_response(response):
            self._record_attempt_result(
                InteractionStatus.CANCELLED, source, reason="user_cancelled")
            self.status = InteractionStatus.CANCELLED
            self._record("cancelled", reason="user_cancelled", source=source)
            result = {
                "error": "interaction_cancelled",
                "error_description": response.get("error_description")
                    or response.get("error") or "user_cancelled",
                "interaction_status": InteractionStatus.CANCELLED,
                "upgrade_id": self.upgrade_id,
                "attempt_id": self._attempt_id,
                "claims_challenge_upgrade": self.snapshot(),
            }
            self.result = result
            return result
        if not _accounts_match(self.account, response):
            self._record(
                "receipt_rejected",
                reason="account_mismatch",
                source=source,
                response_home_account_id=response_home_account_id(response),
            )
            return None
        receipt = build_receipt(
            self.upgrade_id, self._attempt_id, self.account,
            self.scopes, self.claims_challenge, source, response)
        self.receipt = receipt
        self.status = InteractionStatus.CONFIRMED
        attempt = self._attempts.get(self._attempt_id)
        if attempt is not None:
            attempt["status"] = InteractionStatus.CONFIRMED
            attempt["source"] = source
            attempt["receipt"] = dict(receipt)
        self._record(
            "receipt_accepted",
            source=source,
            token_source=response.get("token_source"),
        )
        return receipt

    def note_attempt_failure(self, source, response, fallback=False, attempt_id=None):
        with self._lock:
            if attempt_id and attempt_id != self._attempt_id:
                self._record(
                    "stale_attempt_result_ignored",
                    reason="failure_from_old_attempt",
                    attempt_id=attempt_id,
                    source=source,
                )
                return
            attempt = self._attempts.get(self._attempt_id)
            if attempt is not None:
                attempt["source"] = source
                attempt["reason"] = (
                    (response or {}).get("error_description")
                    or (response or {}).get("error")
                    or "failed"
                )
                attempt["status"] = InteractionStatus.CONFIRMATION_REQUIRED
            self._record(
                "broker_failed" if source == "broker" else "browser_failed",
                source=source,
                error=(response or {}).get("error"),
                fallback=bool(fallback),
            )

    def note_attempt_started(self, source, attempt_id=None):
        with self._lock:
            if attempt_id and attempt_id != self._attempt_id:
                self._record(
                    "stale_attempt_result_ignored",
                    reason="start_from_old_attempt",
                    attempt_id=attempt_id,
                    source=source,
                )
                return
            attempt = self._attempts.get(self._attempt_id)
            if attempt is not None:
                attempt["source"] = source
            self._record("attempt_source", source=source)

    def _record_attempt_result(self, status, source=None, reason=None):
        attempt = self._attempts.get(self._attempt_id)
        if attempt is not None:
            attempt["status"] = status
            attempt["source"] = source
            if reason:
                attempt["reason"] = reason

    def _result_with_metadata(self, receipt=None, base=None, **extra):
        status = extra.pop("interaction_status", self.status)
        if status != InteractionStatus.CONFIRMED:
            receipt = None
        elif receipt is None:
            receipt = self.receipt
        result = dict(base or {})
        if receipt:
            for key in ("access_token", "token_type", "id_token", "token_source"):
                if receipt.get(key) is not None:
                    result.setdefault(key, receipt[key])
        result.update({
            "interaction_status": status,
            "upgrade_id": self.upgrade_id,
            "attempt_id": self._attempt_id,
            "claims_challenge_receipt": dict(receipt) if receipt else None,
            "claims_challenge_upgrade": self.snapshot(),
        })
        result.update(extra)
        self.result = result
        return result

    def result_with_metadata(self, receipt=None, base=None, **extra):
        with self._lock:
            return self._result_with_metadata(receipt, base, **extra)
