"""Models mixins for Social Auth"""

from __future__ import annotations

import base64
import re
import uuid
from abc import abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import time as _time
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from openid.association import Association as OpenIdAssociation

from .exceptions import AuthConfigurationError, AuthCredentialError, AuthResponseError
from .utils import social_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from social_core.backends.base import BaseAuth, ResponseT_co
    from social_core.strategy import BaseStrategy

NO_ASCII_REGEX = re.compile(r"[^\x00-\x7F]+")
NO_SPECIAL_REGEX = re.compile(r"[^\w.@+_-]+", re.UNICODE)


class UserProtocol(Protocol):
    @property
    def id(self, /) -> int: ...
    @property
    def username(self, /) -> str: ...
    @property
    def is_active(self, /) -> bool | Callable[[], bool]: ...
    @property
    def is_authenticated(self, /) -> bool | Callable[[], bool]: ...


class PipelineUserProtocol(UserProtocol, Protocol):
    # Set in BaseAuth.pipeline
    social_user: UserMixin | None
    is_new: bool


RefreshStatus = Literal[
    "saved",
    "unchanged",
    "superseded",
    "save_failed",
    "skipped",
]
RefreshSaveOutcome = Literal["saved", "unchanged", "superseded"]
RefreshRetryOperation = Literal["none", "save"]


@dataclass(frozen=True)
class RefreshResult:
    """Outcome of a token renewal and of persisting its new credentials.

    ``status`` is the authoritative, machine-readable result:

    ``saved``
        The provider exchange and the credential save both completed.
    ``unchanged``
        The exchange completed without changing any stored value.
    ``superseded``
        The exchange completed, but the stored record had already moved to a
        newer authorized state, so the stale result was intentionally dropped.
    ``save_failed``
        The exchange completed but the credentials could not be persisted.
        Retry only the save: the provider may already have rotated the
        refresh token, so repeating the exchange can invalidate the account.
        This status is reported only by storages that opt into
        ``supports_atomic_refresh_save``; other storages keep raising the
        original save exception.
    ``skipped``
        No provider exchange was attempted.

    ``retry_operation`` states which operation, if any, may be retried:
    ``"save"`` for ``save_failed`` and ``"none"`` for every other status.
    """

    status: RefreshStatus
    retry_operation: RefreshRetryOperation = "none"
    # Credential payloads are never rendered; routine logging and exception
    # formatting must not disclose access or refresh tokens.
    base_extra_data: dict[str, Any] = field(default_factory=dict, repr=False)
    refreshed_extra_data: dict[str, Any] = field(default_factory=dict, repr=False)
    error: Exception | None = field(default=None, repr=False)

    @property
    def refresh_completed(self) -> bool:
        """Return whether the provider returned refreshed credentials."""
        return self.status in ("saved", "unchanged", "superseded", "save_failed")

    @property
    def can_retry(self) -> bool:
        """Return whether the caller may retry the failed persistence step."""
        return self.retry_operation != "none"


class UserMixin:
    # Consider tokens that expire in 5 seconds as already expired
    ACCESS_TOKEN_EXPIRED_THRESHOLD = 5
    # Opt-in marker for storages whose save_refresh_result() is a conditional,
    # atomic compare-and-swap rather than a last-writer-wins save.
    supports_atomic_refresh_save = False
    provider = ""
    id_key = ""
    uid: str
    user: UserProtocol
    extra_data: dict[str, Any]

    @abstractmethod
    def save(self): ...

    def get_backend(
        self, strategy: BaseStrategy[ResponseT_co]
    ) -> type[BaseAuth[ResponseT_co]]:
        return strategy.get_backend_class(self.provider)

    def get_backend_instance(
        self, strategy: BaseStrategy[ResponseT_co]
    ) -> BaseAuth[ResponseT_co] | None:
        try:
            return strategy.get_backend(self.provider)
        except AuthConfigurationError as error:
            if error.code == "backend_missing":
                return None
            raise

    @property
    def access_token(self) -> str | None:
        """Return access_token stored in extra_data or None"""
        return self.extra_data.get("access_token")

    def refresh_token(
        self, strategy: BaseStrategy[object], *args, **kwargs
    ) -> RefreshResult:
        """Renew stored credentials using the backend's selected token.

        Missing renewal credentials require reauthentication only when the
        stored access token is known to have expired. Otherwise no request is
        sent. Backends without a refresh method are left unchanged.

        The returned :class:`RefreshResult` reports whether the refreshed
        credentials were saved, were unnecessary, were dropped because a newer
        authorization won, or failed to persist. A save failure is reported,
        not raised, so callers can retry only the persistence step; repeating
        the provider exchange could reuse an already rotated refresh token.
        """
        backend = self.get_backend_instance(strategy)
        if backend is None:
            return RefreshResult(status="skipped")
        refresh_token = getattr(backend, "refresh_token", None)
        if not callable(refresh_token):
            return RefreshResult(status="skipped")
        token = backend.get_refresh_token(self.extra_data)
        if not token:
            if self.access_token_expired():
                raise AuthCredentialError(
                    backend, code="reauthentication_required", stage="refresh"
                )
            return RefreshResult(status="skipped")
        if self.supports_atomic_refresh_save and (
            type(self).save_refresh_result is UserMixin.save_refresh_result
        ):
            raise AuthConfigurationError(
                backend,
                "supports_atomic_refresh_save requires overriding save_refresh_result",
                code="invalid_setting",
                parameter="save_refresh_result",
                stage="refresh",
            )
        base_extra_data = dict(self.extra_data or {})
        refresh_kwargs = backend.get_refresh_token_kwargs(self.extra_data)
        refresh_kwargs.update(kwargs)
        response = cast(
            "dict[str, Any]", refresh_token(token, *args, **refresh_kwargs)
        )
        refreshed_extra_data = backend.extra_data(
            self.user, self.uid, response, self.extra_data or {}, {}
        )
        return self._save_refreshed_credentials(base_extra_data, refreshed_extra_data)

    def _save_refreshed_credentials(
        self,
        base_extra_data: dict[str, Any],
        refreshed_extra_data: dict[str, Any],
    ) -> RefreshResult:
        """Persist a completed renewal without exposing credential values."""
        previous_extra_data = dict(self.extra_data or {})
        try:
            outcome = self.save_refresh_result(base_extra_data, refreshed_extra_data)
        # pylint: disable-next=broad-exception-caught
        except Exception as error:
            # Storages without the atomic contract keep propagating save
            # failures: they have no conditional retry, so swallowing the
            # error would silently lose the refreshed credentials.
            if not self.supports_atomic_refresh_save:
                raise
            # Leave the in-memory record on its pre-refresh baseline so a save
            # retry starts from the same snapshot and does not pose as saved.
            if isinstance(self.extra_data, dict):
                self.extra_data.clear()
                self.extra_data.update(previous_extra_data)
            # Log only stable metadata: provider names and status values are
            # safe, while exception text or payloads may contain tokens.
            social_logger.warning(
                "refresh: credential save failed for provider %s; retry save only",
                self.provider,
            )
            return RefreshResult(
                status="save_failed",
                retry_operation="save",
                base_extra_data=base_extra_data,
                refreshed_extra_data=refreshed_extra_data,
                error=error,
            )
        if outcome == "superseded":
            social_logger.info(
                "refresh: discarded stale credentials for provider %s",
                self.provider,
            )
        elif outcome == "saved" and isinstance(self.extra_data, dict):
            # Keep the in-memory record consistent with the persisted value so
            # atomic implementations only need to make the conditional write.
            self.extra_data.clear()
            self.extra_data.update(
                self.merge_extra_data(base_extra_data, refreshed_extra_data)
            )
        return RefreshResult(
            status=outcome,
            base_extra_data=base_extra_data,
            refreshed_extra_data=refreshed_extra_data,
        )

    @staticmethod
    def merge_extra_data(
        base_extra_data: Mapping[str, Any],
        refreshed_extra_data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return the stored value after applying refreshed credentials."""
        merged = dict(base_extra_data)
        merged.update(refreshed_extra_data)
        return merged

    def retry_refresh_save(self, result: RefreshResult) -> RefreshResult:
        """Retry only the failed save of an already completed renewal.

        A ``save_failed`` result carries the exact credential snapshot an
        atomic implementation compares against, so the conditional write can
        be retried without another provider request. Other statuses are
        returned unchanged because retrying the exchange may reuse a rotated
        refresh token.
        """
        if result.status != "save_failed":
            return result
        return self._save_refreshed_credentials(
            result.base_extra_data, result.refreshed_extra_data
        )

    def save_refresh_result(
        self,
        base_extra_data: dict[str, Any],
        refreshed_extra_data: dict[str, Any],
    ) -> RefreshSaveOutcome:
        """Persist refreshed credentials and report whether they won.

        This is the optional atomic-save contract. The default implementation
        keeps the historical last-writer-wins behavior, so existing storages
        remain compatible without changes. A storage that can compare and swap
        sets ``supports_atomic_refresh_save = True`` and overrides this method
        to perform the comparison and write as one operation, returning
        ``"superseded"`` when the stored record no longer matches
        ``base_extra_data``. Implementations must not modify stored or
        in-memory credentials until the conditional write succeeds, and should
        return ``"unchanged"`` without writing when the merged value equals
        ``base_extra_data``. ``merge_extra_data()`` computes the default merge
        so the comparison and the write use identical values.
        """
        if self.set_extra_data(dict(refreshed_extra_data)):
            self.save()
            return "saved"
        return "unchanged"

    def _compute_expiration_from_timestamp(
        self, value: int | str, field_name: str = "expires"
    ) -> timedelta:
        """Compute expiration timedelta from an absolute timestamp."""
        try:
            timestamp = int(value)
        except (ValueError, TypeError) as e:
            raise AuthResponseError(
                None,
                value,
                parameter=field_name,
                code="invalid_expiry",
                stage="unknown",
            ) from e

        try:
            now = datetime.now(UTC)
            expiry_time = datetime.fromtimestamp(timestamp, tz=UTC)
            return expiry_time - now
        except (OSError, ValueError) as e:
            raise AuthResponseError(
                None,
                value,
                parameter=field_name,
                code="invalid_expiry",
                stage="unknown",
            ) from e

    def _compute_expiration_from_relative(
        self, value: int | str, field_name: str = "expires"
    ) -> timedelta:
        """Compute expiration timedelta from relative seconds."""
        try:
            seconds = int(value)
        except (ValueError, TypeError) as e:
            raise AuthResponseError(
                None,
                value,
                parameter=field_name,
                code="invalid_expiry",
                stage="unknown",
            ) from e

        auth_time = self.extra_data.get("auth_time")
        if auth_time:
            try:
                auth_timestamp = int(auth_time)
            except (ValueError, TypeError):
                # Invalid auth_time value, fall back to treating as seconds from now
                pass
            else:
                try:
                    now = datetime.now(UTC)
                    reference = datetime.fromtimestamp(auth_timestamp, tz=UTC)
                    return (reference + timedelta(seconds=seconds)) - now
                except (OSError, ValueError):
                    # auth_time timestamp out of range, fall back to treating as seconds from now
                    pass
        # If no auth_time or invalid auth_time, treat as seconds from now
        return timedelta(seconds=seconds)

    def expiration_timedelta(self) -> timedelta | None:
        """Return provider session live seconds.

        Returns a timedelta ready to use with session.set_expiry().
        If provider returns a timestamp instead of session seconds to live, the
        timedelta is inferred from current time (using UTC timezone).

        Handles three types of expiration data:
        - expires_on: Always treated as absolute timestamp
        - expires_in: Always treated as relative seconds from auth_time
        - expires: Uses heuristic (>63072000 = 2 years) to distinguish timestamp vs relative
        """
        if not self.extra_data:
            return None

        # Check for expires_on (absolute timestamp)
        expires_on = self.extra_data.get("expires_on")
        if expires_on is not None:
            return self._compute_expiration_from_timestamp(expires_on, "expires_on")

        # Check for expires_in (relative seconds from auth_time)
        expires_in = self.extra_data.get("expires_in")
        if expires_in is not None:
            return self._compute_expiration_from_relative(expires_in, "expires_in")

        # Check for expires (use heuristic to determine type)
        return self._handle_expires_field()

    def _handle_expires_field(self) -> timedelta | None:
        """Handle the generic expires field using heuristic."""
        expires = self.extra_data.get("expires")
        if expires is None:
            return None

        try:
            expires_int = int(expires)
        except (ValueError, TypeError) as e:
            raise AuthResponseError(
                None,
                expires,
                parameter="expires",
                code="invalid_expiry",
                stage="unknown",
            ) from e

        # Use 2 years (63072000 seconds) as threshold to distinguish
        # absolute timestamps from relative seconds
        # Most tokens expire in hours/days/months, timestamps are much larger
        TIMESTAMP_THRESHOLD = 63072000

        if expires_int > TIMESTAMP_THRESHOLD:
            # Likely an absolute timestamp, try treating as expires_on
            return self._compute_expiration_from_timestamp(expires_int, "expires")

        # Treat as relative seconds (like expires_in)
        return self._compute_expiration_from_relative(expires_int, "expires")

    def expiration_datetime(self):
        # backward compatible alias
        return self.expiration_timedelta()

    def access_token_expired(self):
        """Return true / false if access token is already expired"""
        expiration = self.expiration_timedelta()
        return (
            expiration
            and expiration.total_seconds() <= self.ACCESS_TOKEN_EXPIRED_THRESHOLD
        )

    def get_access_token(self, strategy: BaseStrategy[object]) -> str | None:
        """Returns a valid access token."""
        if self.access_token_expired():
            result = self.refresh_token(strategy)
            if result.status == "save_failed":
                # Do not hand out the old token or silently swallow the loss.
                raise AuthCredentialError(
                    None,
                    code="refresh_save_failed",
                    stage="refresh",
                    context={"retry_operation": result.retry_operation},
                )
        return self.access_token

    def set_extra_data(self, extra_data: dict[str, Any] | None = None) -> bool:
        if extra_data and self.extra_data != extra_data:
            if self.extra_data and not isinstance(self.extra_data, str):
                self.extra_data.update(extra_data)
            else:
                self.extra_data = extra_data
            return True
        return False

    @classmethod
    def clean_username(cls, value: str) -> str:
        """Clean username removing any unsupported character"""
        value = NO_ASCII_REGEX.sub("", value)
        return NO_SPECIAL_REGEX.sub("", value)

    @classmethod
    def changed(cls, user: UserProtocol) -> None:
        """The given user instance is ready to be saved"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def changed_fields(cls, user: UserProtocol, fields: set[str]) -> None:
        """Save user attributes changed by the pipeline.

        Storage implementations can use the field names to avoid writing
        unrelated values. The default preserves the existing changed() contract.
        """
        cls.changed(user)

    @classmethod
    def get_username(cls, user: UserProtocol) -> str:
        """Return the username for given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def user_model(cls) -> type[UserProtocol]:
        """Return the user model"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def username_max_length(cls) -> int:
        """Return the max length for username"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def allowed_to_disconnect(
        cls, user: UserProtocol, backend_name: str, association_id=None
    ) -> bool:
        """Return if it's safe to disconnect the social account for the
        given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def disconnect(cls, entry):
        """Disconnect the social account for the given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def user_exists(cls, *args, **kwargs) -> bool:
        """
        Return True/False if a User instance exists with the given arguments.
        Arguments are directly passed to filter() manager method.
        """
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def create_user(cls, *args, **kwargs):
        """Create a user instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_user(cls, pk):
        """Return user instance for given id"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_users_by_email(cls, email: str):
        """Return users instances for given email address"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_social_auth(cls, provider: str, uid: str, id_key: str | None = None):
        """Return UserSocialAuth for given provider and uid"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_social_auth_by_extra_data(
        cls, provider: str, key: str, value: str, id_key: str = ""
    ):
        """Return an unambiguous association matching stored provider data."""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_social_auth_for_user(
        cls,
        user: UserProtocol,
        provider: str | None = None,
        # pylint: disable-next=redefined-builtin
        id: int | None = None,
    ):
        """Return all the UserSocialAuth instances for given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def create_social_auth(
        cls, user: UserProtocol, uid: str, provider: str, id_key: str = ""
    ):
        """Create a UserSocialAuth instance for given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def migrate_social_auth(
        cls, social, uid: str, id_key: str, *, evidence_key: str | None = None
    ):
        """Atomically replace identifiers, revalidating supplied evidence under lock."""
        raise NotImplementedError("Implement in subclass")


class NonceMixin:
    """One-use values scoped by ``server_url`` (a legacy field name).

    The scope can be a provider URL or a protocol-specific identifier.
    """

    server_url = ""
    timestamp = 0
    salt = ""

    @classmethod
    def use(cls, server_url: str, timestamp, salt: str):
        """Create a Nonce instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get(cls, server_url: str, salt: str):
        """Retrieve a Nonce instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def delete(cls, nonce):
        """Delete a Nonce instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def consume(cls, server_url: str, timestamp: int, salt: str) -> bool:
        """Atomically remove exactly one nonce matching all three fields."""
        raise NotImplementedError("Implement in subclass")


class AssociationMixin:
    """OpenId account association"""

    server_url = ""
    handle = ""
    secret: str | bytes = ""
    issued = 0
    lifetime = 0
    assoc_type = ""

    def is_expired(self, now: int | None = None) -> bool:
        """Return whether the association's lifetime has elapsed."""
        if now is None:
            now = int(_time())
        return self.lifetime <= 0 or now >= self.issued + self.lifetime

    @classmethod
    def oids(cls, server_url, handle=None):
        kwargs = {"server_url": server_url}
        if handle is not None:
            kwargs["handle"] = handle
        return sorted(
            ((assoc.id, cls.openid_association(assoc)) for assoc in cls.get(**kwargs)),
            key=lambda x: x[1].issued,
            reverse=True,
        )

    @classmethod
    def openid_association(cls, assoc):
        secret = assoc.secret
        if not isinstance(secret, bytes):
            secret = secret.encode()
        return OpenIdAssociation(
            assoc.handle,
            base64.decodebytes(secret),
            assoc.issued,
            assoc.lifetime,
            assoc.assoc_type,
        )

    @classmethod
    def store(cls, server_url, association):
        """Create an Association instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get(cls, server_url: str | None = None, handle: str | None = None):
        """Get an Association instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def remove(cls, ids_to_delete):
        """Remove an Association instance"""
        raise NotImplementedError("Implement in subclass")


class CodeMixin:
    email = ""
    code = ""
    verified = False
    timestamp: datetime | None = None

    @abstractmethod
    def save(self): ...

    def verify(self) -> None:
        self.verified = True
        self.save()

    def is_expired(self, seconds: int) -> bool:
        """Return whether the code has reached its lifetime, or has no timestamp."""
        if self.timestamp is None:
            return True
        timestamp = self.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        timestamp = timestamp.astimezone(UTC)
        return datetime.now(UTC) >= timestamp + timedelta(seconds=seconds)

    @classmethod
    def generate_code(cls):
        return uuid.uuid4().hex

    @classmethod
    def make_code(cls, email: str) -> CodeMixin:
        code = cls()
        code.email = email
        code.code = cls.generate_code()
        code.verified = False
        code.timestamp = datetime.now(UTC)
        code.save()
        return code

    @classmethod
    def get_code(cls, code):
        raise NotImplementedError("Implement in subclass")


class PartialMixin:
    token = ""
    data: dict[str, Any] = {}
    next_step: int
    backend = ""

    @property
    def args(self):
        return self.data.get("args", [])

    @args.setter
    def args(self, value) -> None:
        self.data["args"] = value

    @abstractmethod
    def save(self): ...

    @property
    def kwargs(self):
        return self.data.get("kwargs", {})

    @kwargs.setter
    def kwargs(self, value) -> None:
        self.data["kwargs"] = value

    def extend_kwargs(self, values) -> None:
        self.data["kwargs"].update(values)

    @property
    def pipeline_type(self) -> str:
        """Legacy partials may resume authentication, but never disconnect."""
        return self.data.get("pipeline_type", "authentication")

    @property
    def request_data(self) -> Mapping[str, Any] | None:
        """Effective data for a resume, including legacy partial snapshots."""
        data = self.data.get("request_data", self.kwargs.get("request"))
        return data if isinstance(data, Mapping) else None

    @request_data.setter
    def request_data(self, value: Mapping[str, Any]) -> None:
        self.data["request_data"] = value

    @classmethod
    def generate_token(cls) -> str:
        return uuid.uuid4().hex

    @classmethod
    def load(cls, token: str) -> PartialMixin | None:
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def destroy(cls, token: str):
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def prepare(
        cls, backend: str, next_step: int, data: dict[str, Any]
    ) -> PartialMixin:
        partial = cls()
        partial.backend = backend
        partial.next_step = next_step
        partial.data = data
        partial.token = cls.generate_token()
        return partial

    @classmethod
    def store(cls, partial: PartialMixin) -> PartialMixin:
        partial.save()
        return partial


class BaseStorage:
    user = UserMixin
    nonce = NonceMixin
    association = AssociationMixin
    code = CodeMixin
    partial = PartialMixin

    @classmethod
    def is_integrity_error(cls, exception) -> bool:
        """Check if given exception flags an integrity error in the DB"""
        raise NotImplementedError("Implement in subclass")
