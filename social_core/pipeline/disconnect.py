from __future__ import annotations

from typing import TYPE_CHECKING

from social_core.exceptions import AuthPolicyError, AuthProviderError

if TYPE_CHECKING:
    from social_core.storage import RevocationRecord, UserMixin, UserProtocol
    from social_core.strategy import BaseStrategy


def allowed_to_disconnect(
    strategy: BaseStrategy[object],
    user: UserProtocol | None,
    name,
    user_storage,
    association_id=None,
    *args,
    **kwargs,
) -> None:
    if not user_storage.allowed_to_disconnect(user, name, association_id):
        raise AuthPolicyError(code="disconnect_disallowed", stage="disconnect")


def get_entries(
    strategy: BaseStrategy[object],
    user: UserProtocol | None,
    name,
    user_storage,
    association_id=None,
    *args,
    **kwargs,
):
    return {
        "entries": user_storage.get_social_auth_for_user(user, name, association_id)
    }


def _revoke_entry_token(
    strategy: BaseStrategy[object], entry: UserMixin, access_token: str
) -> RevocationRecord:
    backend = entry.get_backend_instance(strategy)
    revoked = False
    if backend is not None:
        try:
            revoked = bool(backend.revoke_token(access_token, entry.uid))
        except AuthProviderError:
            # Transport or provider boundary failure: revocation cannot be
            # confirmed, leave the token to the compensation process.
            revoked = False
    record: RevocationRecord = {
        "provider": entry.provider,
        "uid": entry.uid,
        "status": "revoked" if revoked else "pending",
    }
    if not revoked:
        record["access_token"] = access_token
    return record


def revoke_tokens(
    strategy: BaseStrategy[object], entries, user_storage=None, *args, **kwargs
) -> dict[str, list[RevocationRecord]] | None:
    """Revoke stored access tokens and record the outcome per association.

    Confirmed revocations leave a plain receipt; transport errors and
    providers that cannot confirm revocation leave a pending receipt that
    keeps the token for the controlled compensation process
    (``social_core.actions.retry_pending_revocations``). Receipts are
    persisted when the user storage implements ``RevocationStorageMixin``
    and are always exposed to later pipeline steps as
    ``revocation_records``.
    """
    revoke_tokens_on_disconnect = strategy.setting("REVOKE_TOKENS_ON_DISCONNECT", False)
    if not revoke_tokens_on_disconnect:
        return None
    records = []
    record_revocation = getattr(user_storage, "record_revocation", None)
    for entry in entries:
        access_token = entry.extra_data.get("access_token")
        if not access_token:
            continue
        record = _revoke_entry_token(strategy, entry, access_token)
        records.append(record)
        if callable(record_revocation):
            record_revocation(record)
    return {"revocation_records": records}


def disconnect(
    strategy: BaseStrategy[object], entries, user_storage, *args, **kwargs
) -> None:
    for entry in entries:
        user_storage.disconnect(entry)
