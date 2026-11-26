"""Opt-in, safe and order-independent merging for MSAL serializable caches.

Why this module exists
----------------------
Several processes can each load the same persisted
:class:`~msal.SerializableTokenCache` JSON, mutate it independently and write
the whole blob back. A last-writer-wins write would silently lose the other
process' updates and -- worse -- resurrect an account that one process had
confirmed signed out, because the other process still holds a stale copy of it.

This module provides an *optional* merge entry point. Applications that want
safe concurrency call :meth:`msal.SerializableTokenCache.safe_merge` (or the
:func:`merge_cache_states` helper) before persisting.

Guarantees
----------
* The existing on-disk format keeps loading unchanged; the merge metadata is
  stored under a namespaced top-level key and old MSAL versions simply ignore
  it.
* Independent records (different accounts / different cache keys) coexist.
* Merging snapshot *A* with *B* produces the same accounts, new entries,
  conflict identities and merged state as merging *B* with *A*.
* A *confirmed sign-out* is represented by a tombstone. By default tombstones
  are sticky: a stale snapshot can never bring the signed-out account back as a
  selectable account or as usable silent credentials.
* A same-key collision that cannot be adjudicated (typically divergent legacy
  records without a trustworthy timestamp/version) is not silently dropped: it
  is returned as a :class:`CacheConflict` carrying a human-readable ``reason``
  and both candidate values.

The module deliberately depends only on the standard library so it can be
imported without an import cycle with :mod:`msal.token_cache`.
"""

import copy
import json
import logging
import time


logger = logging.getLogger(__name__)

#: Namespaced top-level key holding safe-merge metadata (tombstones, ...).
#: It starts with ``__`` and never collides with an MSAL credential section.
MERGE_METADATA_KEY = "__safe_merge__"
TOMBSTONES_KEY = "tombstones"
MERGE_VERSION = 1

#: The record-bearing top-level sections of the unified MSAL cache schema.
KNOWN_SECTIONS = (
    "AccessToken",
    "RefreshToken",
    "IdToken",
    "Account",
    "AppMetadata",
)

#: Sections whose records carry ``home_account_id`` and can therefore belong
#: to a signed-out account.
_ACCOUNT_BEARING_SECTIONS = (
    "AccessToken", "RefreshToken", "IdToken", "Account")

#: Fields that can indicate record ordering. First match wins.
_ORDERING_FIELDS = (
    "last_modification_time",  # RefreshToken
    "cached_at",               # AccessToken
    "issued_at",
    "iat",
    "timestamp",
    "version",
)

_SECRET_FIELDS = ("secret",)

_MISSING = object()


class _Record(dict):
    """A dict that also exposes its keys as attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __repr__(self):
        # Redact secrets because "added" records embed the full entry.
        return "{}({})".format(type(self).__name__, _safe_repr(self))


def _redact(value):
    """Deep-copy *value* masking credential secrets, for safe logging/repr."""
    if isinstance(value, dict):
        return {
            k: ("********" if k in _SECRET_FIELDS and v else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def _safe_repr(record):
    return repr(_redact(dict(record)))


class CacheConflict(_Record):
    """An unresolvable same-key collision between two cache snapshots.

    Keys/attributes:
        ``section``  -- cache section, e.g. ``"RefreshToken"`` (or ``"$"``).
        ``key``      -- the record key inside the section.
        ``code``     -- stable machine-readable reason code.
        ``reason``   -- human-readable explanation of why it cannot be decided.
        ``resolution`` -- the deterministic fallback that was applied.
        ``chosen``   -- the value retained in :attr:`CacheMergeReport.merged`.
        ``candidates`` -- both differing values, deterministically ordered.

    ``repr()`` masks the ``secret`` field so tokens do not leak into logs; the
    raw values remain available as attributes for callers that need them.
    """

    def __repr__(self):
        return "CacheConflict(section={!r}, key={!r}, code={!r}, reason={!r})".format(
            self.get("section"), self.get("key"), self.get("code"),
            self.get("reason"))

    def __str__(self):
        return self.__repr__()

    def redacted(self):
        """Return a plain dict copy with credential secrets masked."""
        return _redact(dict(self))


class CacheMergeReport(_Record):
    """Result of :func:`merge_states` / :meth:`SerializableTokenCache.safe_merge`.

    The object is both an attribute object and a plain ``dict`` (so
    ``report.conflicts`` and ``report["conflicts"]`` both work).
    """

    def __init__(self):
        super().__init__()
        self._live_cache = None
        self.update({
            "merged": {},
            "conflicts": [],
            "conflict_records": [],
            "unresolved_conflicts": [],
            "conflicting_records": [],
            "resolved": [],
            "resolved_conflicts": [],
            "added": [],
            "new_entries": [],
            "independent_entries": [],
            "independent_new_entries": [],
            "added_entries": [],
            "incoming_added": [],
            "base_only": [],
            "suppressed": [],
            "blocked": [],
            "identical": [],
            "unrecognized": [],
            "warnings": [],
            "accounts": [],
            "login_accounts": [],
            "merged_accounts": [],
            "available_accounts": [],
            "tombstones": [],
            "stats": {},
            "ok": True,
            "has_conflicts": False,
        })

    @property
    def merged_state(self):
        """The merged cache serialized as the standard MSAL JSON string."""
        return json.dumps(self["merged"], indent=4, sort_keys=True)

    @property
    def cache(self):
        """A :class:`SerializableTokenCache` holding the merged state.

        When the merge was performed by
        :meth:`SerializableTokenCache.safe_merge`, this is that same mutated
        cache instance. Otherwise a fresh cache is built lazily.
        """
        if self._live_cache is not None:
            return self._live_cache
        from .token_cache import SerializableTokenCache  # local: avoid cycle

        cache = SerializableTokenCache()
        cache._cache = copy.deepcopy(self["merged"])
        cache.has_state_changed = True
        self._live_cache = cache
        return cache

    def redacted(self):
        """JSON-friendly report copy with credential secrets masked."""
        return _redact({
            k: v for k, v in self.items() if k != "cache"
        })


def coerce_cache_state(state):
    """Coerce a JSON string / dict / cache object into a plain state dict.

    The returned dict is a deep copy and is safe for the merge to own.
    """
    if state is None:
        return {}
    if isinstance(state, str):
        return json.loads(state) if state.strip() else {}
    if isinstance(state, (bytes, bytearray)):
        if not state.strip():
            return {}
        return json.loads(state.decode("utf-8"))
    if isinstance(state, dict):
        return copy.deepcopy(state)
    # A TokenCache/SerializableTokenCache instance.
    inner = getattr(state, "_cache", None)
    if isinstance(inner, dict):
        return copy.deepcopy(inner)
    serialize = getattr(state, "serialize", None)
    if callable(serialize):
        text = serialize()
        return json.loads(text) if text else {}
    raise TypeError(
        "Cannot merge object of type {!r}: expected a JSON string, a state "
        "dict, or a SerializableTokenCache.".format(type(state).__name__))


def _canonical(value):
    """Stable string form used for equality and deterministic ordering."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str)


def _as_number(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ordering_marker(entry):
    """Return ``(field_name, numeric_value)`` of the first usable marker."""
    if not isinstance(entry, dict):
        return None, None
    for field in _ORDERING_FIELDS:
        if field in entry:
            number = _as_number(entry[field])
            if number is not None:
                return field, number
    return None, None


def _entry_time(entry):
    """Best-effort trustworthy ordering marker (epoch seconds) for a record."""
    return _ordering_marker(entry)[1]


def _identity(entry):
    if not isinstance(entry, dict):
        return None, None, None
    home = entry.get("home_account_id")
    env = entry.get("environment")
    realm = entry.get("realm")
    return (
        home,
        env.lower() if isinstance(env, str) else env,
        realm,
    )


def make_tombstone(
        account=None, *, home_account_id=None, environment=None, realm=None,
        reason="signed_out", at=None, client_id=None):
    """Build a normalized sign-out tombstone from an account dict or ids."""
    if isinstance(account, dict):
        home_account_id = home_account_id or account.get("home_account_id")
        environment = environment or account.get("environment")
        client_id = client_id or account.get("client_id")
        # NOTE: realm is intentionally NOT inherited from the account. MSAL
        # sign-out is realm-independent (it removes RTs/ATs/IDTs across all
        # tenants), and RefreshToken entries carry no realm field, so a
        # realm-scoped tombstone would fail to match realm-less tokens.
    tombstone = {
        "home_account_id": home_account_id,
        "reason": reason or "signed_out",
        "at": at if at is not None else time.time(),
    }
    if environment is not None:
        tombstone["environment"] = environment
    if realm is not None:
        tombstone["realm"] = realm
    if client_id is not None:
        tombstone["client_id"] = client_id
    return tombstone


def _tombstone_key(tombstone):
    return (
        str(tombstone.get("home_account_id") or ""),
        str(tombstone.get("environment") or "").lower(),
    )


def _collect_tombstones(state):
    found = []
    if not isinstance(state, dict):
        return found
    meta = state.get(MERGE_METADATA_KEY)
    if isinstance(meta, dict) and isinstance(meta.get(TOMBSTONES_KEY), list):
        for item in meta[TOMBSTONES_KEY]:
            if isinstance(item, dict):
                found.append(item)
    # Tolerate a simple top-level "tombstones" list as well.
    direct = state.get(TOMBSTONES_KEY)
    if isinstance(direct, list):
        for item in direct:
            if isinstance(item, dict):
                found.append(item)
    return found


def _union_tombstones(tombstones):
    merged = {}
    for raw in tombstones:
        tombstone = make_tombstone(raw) if "at" not in raw else dict(raw)
        key = _tombstone_key(tombstone)
        previous = merged.get(key)
        if previous is None or _as_number(tombstone.get("at") or 0) > \
                _as_number(previous.get("at") or 0):
            merged[key] = tombstone
    return merged


def _tombstone_matches(entry, tombstone, key=None):
    """Whether *entry* (or its cache *key*) belongs to the signed-out account.

    Matching the key as a fallback matters for legacy/malformed token records
    that omit ``home_account_id``/``environment`` fields: MSAL keys for all
    user-bearing sections start with ``"<home_account_id>-<environment>-..."``.
    """
    home = tombstone.get("home_account_id")
    if not home:
        return False
    entry_home, entry_env, entry_realm = _identity(entry)
    if entry_home is not None:
        if entry_home != home:
            return False
        tomb_env = tombstone.get("environment")
        if tomb_env and entry_env and tomb_env.lower() != entry_env:
            return False
        tomb_realm = tombstone.get("realm")
        if tomb_realm is not None and entry_realm != tomb_realm:
            return False
        return True

    # Field identity unavailable -> recognize the key prefix, fail closed.
    if not isinstance(key, str):
        return False
    lowered_key = key.lower()
    home_prefix = home.lower() + "-"
    if not lowered_key.startswith(home_prefix):
        return False
    tomb_env = tombstone.get("environment")
    if tomb_env:
        env_prefix = home.lower() + "-" + tomb_env.lower() + "-"
        if not lowered_key.startswith(env_prefix):
            return False
    return True


def _find_tombstone(entry, tombstones, key=None):
    for tombstone in tombstones:
        if _tombstone_matches(entry, tombstone, key=key):
            return tombstone
    return None


def _candidate_is_newer_than_signout(a, b, tombstone):
    """True only when a candidate unambiguously post-dates the sign-out.

    Used solely for the non-default ``sticky_tombstones=False`` mode so a
    proven re-authentication can pass; stale or undated legacy records never
    qualify.
    """
    signed_out_at = _as_number(tombstone.get("at"))
    if signed_out_at is None:
        return False
    for candidate in (a, b):
        record_time = _entry_time(candidate)
        if record_time is not None and record_time > signed_out_at:
            return True
    return False


def _ordered_pair(a, b):
    """Return ``(smaller_canonical, larger_canonical)`` deep copies."""
    ca, cb = _canonical(a), _canonical(b)
    if ca <= cb:
        return copy.deepcopy(a), copy.deepcopy(b)
    return copy.deepcopy(b), copy.deepcopy(a)


def _deterministic_winner(a, b):
    lo, hi = _ordered_pair(a, b)
    # The larger canonical form is an arbitrary but symmetric tie-break.
    return hi, lo, hi


def _symmetric_union(a, b):
    """Union two same-secret record dicts without depending on argument order."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return a if _canonical(a) >= _canonical(b) else b
    result = {}
    for key in sorted(set(a) | set(b)):
        if key not in a:
            result[key] = copy.deepcopy(b[key])
        elif key not in b:
            result[key] = copy.deepcopy(a[key])
        elif isinstance(a[key], dict) and isinstance(b[key], dict):
            result[key] = _symmetric_union(a[key], b[key])
        elif a[key] == b[key]:
            result[key] = copy.deepcopy(a[key])
        else:
            ca, cb = _canonical(a[key]), _canonical(b[key])
            result[key] = copy.deepcopy(a[key] if ca >= cb else b[key])
    return result


def _undecidable_reason(section, key, a, b, ta, tb):
    different_secret = (
        isinstance(a, dict) and isinstance(b, dict)
        and a.get("secret") is not None
        and a.get("secret") != b.get("secret"))
    if different_secret:
        core = ("the cached credentials (secret) differ and there is no "
                "trustworthy modification time/version to tell which is newer")
    elif ta is None or tb is None:
        core = ("the records disagree and at least one legacy copy has no "
                "trustworthy modification time/version")
    else:
        core = ("the records disagree but report equivalent ordering markers")
    return (
        "Cannot safely merge legacy cache record '{section}/{key}': {core}. "
        "Kept one copy using a deterministic tie-break and retained both "
        "candidate values in this conflict for manual review.".format(
            section=section, key=key, core=core))


def _adjudicate_collision(section, key, a, b, report):
    """Resolve a same-key collision or record an unresolved conflict."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        lo, hi = _ordered_pair(a, b)
        conflict = CacheConflict({
            "section": section,
            "key": key,
            "code": "non_object_record",
            "reason": (
                "Record '{section}/{key}' is not a JSON object in both "
                "snapshots (legacy or corrupt value), so its fields cannot be "
                "merged safely. Kept one value using a deterministic tie-break "
                "and retained both candidates.".format(
                    section=section, key=key)),
            "resolution": "kept_deterministic_tie_break",
            "chosen": hi,
            "candidates": [lo, hi],
        })
        report["conflicts"].append(conflict)
        return hi

    same_secret = (
        a.get("secret") is not None and a.get("secret") == b.get("secret"))
    if same_secret:
        merged_entry = _symmetric_union(a, b)
        report["resolved"].append(_Record({
            "section": section,
            "key": key,
            "code": "same_credential_unioned",
            "reason": "Both copies carry the same credential secret; disjoint "
                      "fields were unioned.",
            "resolution": "unioned_equal_secret",
        }))
        return merged_entry

    ta, tb = _entry_time(a), _entry_time(b)
    if ta is not None and tb is not None and ta != tb:
        winner = copy.deepcopy(a if ta > tb else b)
        ordering_field = _ordering_marker(a if ta > tb else b)[0]
        report["resolved"].append(_Record({
            "section": section,
            "key": key,
            "code": "newer_record_wins",
            "reason": "Copies differ but carry distinct trustworthy ordering "
                      "markers; the strictly newer record was kept.",
            "resolution": "kept_newer_by_ordering_marker",
            "ordering_field": ordering_field,
        }))
        return winner

    # Undecidable: report with a reason + deterministic fallback.
    lo, hi = _ordered_pair(a, b)
    conflict = CacheConflict({
        "section": section,
        "key": key,
        "code": "undecidable_legacy_record",
        "reason": _undecidable_reason(section, key, a, b, ta, tb),
        "resolution": "kept_deterministic_tie_break",
        "chosen": hi,
        "candidates": [lo, hi],
    })
    report["conflicts"].append(conflict)
    return hi


def _merge_known_section(
        section, left_value, right_value, in_left, in_right,
        tombstones, report, sticky_tombstones):
    left_map = left_value if isinstance(left_value, dict) else None
    right_map = right_value if isinstance(right_value, dict) else None

    if (in_left and left_map is None) or (in_right and right_map is None):
        return _merge_malformed_section(
            section, left_value, right_value, in_left, in_right, report)

    left_map = left_map or {}
    right_map = right_map or {}
    merged = {}

    for key in sorted(set(left_map) | set(right_map), key=str):
        has_left = key in left_map
        has_right = key in right_map
        a = left_map[key] if has_left else _MISSING
        b = right_map[key] if has_right else _MISSING

        probe = a if isinstance(a, dict) else (
            b if isinstance(b, dict) else None)
        tombstone = _find_tombstone(probe, tombstones, key=key)
        if tombstone is not None:
            proven_reauth = (
                not sticky_tombstones
                and _candidate_is_newer_than_signout(a, b, tombstone))
            if not proven_reauth:
                report["suppressed"].append(_Record({
                    "section": section,
                    "key": key,
                    "code": "signed_out_account_tombstone",
                    "home_account_id": tombstone.get("home_account_id"),
                    "environment": tombstone.get("environment"),
                    "reason": (
                        "Record belongs to a home_account_id with a confirmed "
                        "sign-out tombstone; it was withheld so the signed-out "
                        "account cannot reappear as a selectable account or "
                        "issue silent credentials."),
                }))
                continue
            report["resolved"].append(_Record({
                "section": section,
                "key": key,
                "code": "newer_record_postdates_tombstone",
                "reason": (
                    "Record carries an ordering marker strictly newer than "
                    "the sign-out tombstone, so it is treated as a proven "
                    "re-authentication (non-sticky mode)."),
                "resolution": "allowed_newer_than_tombstone",
            }))

        if has_left and not has_right:
            merged[key] = copy.deepcopy(a)
            record = _Record({
                "section": section, "key": key, "entry": copy.deepcopy(a)})
            report["added"].append(record)
            report["base_only"].append(record)
        elif has_right and not has_left:
            merged[key] = copy.deepcopy(b)
            record = _Record({
                "section": section, "key": key, "entry": copy.deepcopy(b)})
            report["added"].append(record)
            report["incoming_added"].append(record)
        else:
            if _canonical(a) == _canonical(b):
                merged[key] = copy.deepcopy(a)
                report["identical"].append(
                    _Record({"section": section, "key": key}))
            else:
                merged[key] = _adjudicate_collision(
                    section, key, a, b, report)
    return merged


def _merge_malformed_section(
        section, a, b, in_left, in_right, report):
    if in_left and in_right:
        if _canonical(a) == _canonical(b):
            report["unrecognized"].append(_Record({
                "section": section,
                "key": None,
                "code": "non_object_cache_section",
                "severity": "warning",
                "reason": (
                    "Known cache section '{section}' is not a JSON object of "
                    "records in either snapshot; the identical legacy value "
                    "was preserved but cannot be merged record-by-record."
                    .format(section=section)),
            }))
            return copy.deepcopy(a)
        lo, hi = _ordered_pair(a, b)
        report["conflicts"].append(CacheConflict({
            "section": section,
            "key": None,
            "code": "malformed_section_conflict",
            "reason": (
                "Known cache section '{section}' is not a JSON object of "
                "records and its two legacy values differ; it cannot be "
                "merged record-by-record. Kept one value using a deterministic "
                "tie-break and retained both candidates.".format(
                    section=section)),
            "resolution": "kept_deterministic_tie_break",
            "chosen": hi,
            "candidates": [lo, hi],
        }))
        return hi

    present = a if in_left else b
    report["unrecognized"].append(_Record({
        "section": section,
        "key": None,
        "code": "malformed_section",
        "severity": "warning",
        "reason": (
            "Known cache section '{section}' is not a JSON object of records "
            "in one snapshot; the legacy value was preserved but cannot be "
            "validated or merged record-by-record.".format(section=section)),
    }))
    return copy.deepcopy(present)


def _merge_opaque_top_level(key, a, b, in_left, in_right, report):
    if in_left and in_right:
        if _canonical(a) == _canonical(b):
            return copy.deepcopy(a)
        lo, hi = _ordered_pair(a, b)
        report["conflicts"].append(CacheConflict({
            "section": "$",
            "key": key,
            "code": "opaque_value_conflict",
            "reason": (
                "Top-level cache key '{key}' is not an MSAL credential "
                "section and holds two different opaque JSON values; MSAL "
                "cannot infer how to merge application-defined data. Kept one "
                "value using a deterministic tie-break and retained both "
                "candidates.".format(key=key)),
            "resolution": "kept_deterministic_tie_break",
            "chosen": hi,
            "candidates": [lo, hi],
        }))
        return hi

    present = a if in_left else b
    report["unrecognized"].append(_Record({
        "section": "$",
        "key": key,
        "code": "unknown_top_level_key",
        "severity": "info",
        "reason": (
            "Top-level cache key '{key}' is application-defined or unknown to "
            "this MSAL version; its value was preserved opaquely but cannot "
            "be semantically validated or merged record-by-record."
            .format(key=key)),
    }))
    return copy.deepcopy(present)


def _merge_metadata(left_meta, right_meta, tombstones):
    extras = {}
    for meta in (left_meta if isinstance(left_meta, dict) else {},
                 right_meta if isinstance(right_meta, dict) else {}):
        for key, value in meta.items():
            if key == TOMBSTONES_KEY:
                continue
            if key not in extras:
                extras[key] = value
            elif _canonical(extras[key]) != _canonical(value):
                lo, hi = _ordered_pair(extras[key], value)
                extras[key] = hi
    merged = {"version": MERGE_VERSION}
    for key in sorted(extras):
        if key != "version":
            merged[key] = extras[key]
    merged[TOMBSTONES_KEY] = sorted(
        tombstones,
        key=lambda t: (
            str(t.get("home_account_id") or ""),
            str(t.get("environment") or ""),
            str(t.get("reason") or ""),
            _canonical(t.get("at"))))
    return merged


def merge_states(base, incoming, *, sticky_tombstones=True, **options):
    """Merge two parsed cache-state dicts.

    Pure: neither *base* nor *incoming* is mutated. Returns a
    :class:`CacheMergeReport` whose ``merged`` key is the new state dict.

    Set ``sticky_tombstones=False`` only if you intentionally want a record
    that carries a strictly newer ordering marker than its sign-out tombstone
    to be reconsidered (for example a proven re-authentication). The default
    is fail-closed: a confirmed sign-out always wins.
    """
    if not isinstance(base, dict) or not isinstance(incoming, dict):
        raise TypeError(
            "merge_states expects parsed dict states; use "
            "merge_cache_states() for JSON strings or cache objects.")

    left = copy.deepcopy(base)
    right = copy.deepcopy(incoming)

    tombstone_index = _union_tombstones(
        _collect_tombstones(left) + _collect_tombstones(right))
    tombstones = list(tombstone_index.values())

    report = CacheMergeReport()
    merged = {}
    for key in sorted(set(left) | set(right), key=str):
        if key == MERGE_METADATA_KEY:
            continue
        in_left, in_right = key in left, key in right
        a = left.get(key, _MISSING)
        b = right.get(key, _MISSING)
        if key in KNOWN_SECTIONS:
            merged[key] = _merge_known_section(
                key, a, b, in_left, in_right, tombstones, report,
                sticky_tombstones)
        else:
            merged[key] = _merge_opaque_top_level(
                key, a, b, in_left, in_right, report)

    left_meta = left.get(MERGE_METADATA_KEY)
    right_meta = right.get(MERGE_METADATA_KEY)
    if tombstones or isinstance(left_meta, dict) or isinstance(right_meta, dict):
        merged[MERGE_METADATA_KEY] = _merge_metadata(
            left_meta, right_meta, tombstones)

    # Deterministic ordering of report buckets.
    for bucket in ("conflicts", "resolved", "added", "suppressed",
                   "identical", "unrecognized"):
        report[bucket].sort(key=lambda r: (
            str(r.get("section")), str(r.get("key")), str(r.get("code"))))

    report["merged"] = merged
    account_section = merged.get("Account", {})
    report["accounts"] = list(account_section.values()) if isinstance(
        account_section, dict) else []
    report["tombstones"] = merged.get(
        MERGE_METADATA_KEY, {}).get(TOMBSTONES_KEY, [])
    report["has_conflicts"] = bool(report["conflicts"])
    report["ok"] = not report["conflicts"]
    report["stats"] = {
        "accounts": len(report["accounts"]),
        "added": len(report["added"]),
        "conflicts": len(report["conflicts"]),
        "resolved": len(report["resolved"]),
        "suppressed": len(report["suppressed"]),
        "identical": len(report["identical"]),
        "unrecognized": len(report["unrecognized"]),
        "tombstones": len(report["tombstones"]),
    }
    # Keep all human-friendly aliases pointing at the finalized lists.
    for conflict in report["conflicts"]:
        conflict.setdefault("message", conflict.get("reason"))
    report["conflict_records"] = report["conflicts"]
    report["unresolved_conflicts"] = report["conflicts"]
    report["conflicting_records"] = report["conflicts"]
    report["resolved_conflicts"] = report["resolved"]
    report["new_entries"] = report["added"]
    report["independent_entries"] = report["added"]
    report["independent_new_entries"] = report["added"]
    report["added_entries"] = report["added"]
    report["blocked"] = report["suppressed"]
    report["warnings"] = report["unrecognized"]
    report["login_accounts"] = report["accounts"]
    report["merged_accounts"] = report["accounts"]
    report["available_accounts"] = report["accounts"]
    return report


def merge_cache_states(left, right, **options):
    """Merge two cache snapshots given as JSON strings, dicts or caches.

    Returns a :class:`CacheMergeReport`. This is the most flexible functional
    entry point; applications that already hold a
    :class:`~msal.SerializableTokenCache` usually call its
    :meth:`~msal.SerializableTokenCache.safe_merge` method instead.
    """
    return merge_states(
        coerce_cache_state(left), coerce_cache_state(right), **options)


# Readable aliases for callers discovering the API by name.
safe_merge_states = merge_cache_states
safe_merge_caches = merge_cache_states
safe_merge = merge_cache_states
