"""Generation-aware rotation for confidential-client assertions.

The helpers in this module are intentionally optional.  They correlate a
prepared client assertion with the generation of signing material that created
it, while leaving MSAL's access-token cache key untouched.  Consequently, an
access token that was issued before a certificate rotation remains usable from
cache until its own expiry.

Diagnostic records produced here contain only a public, non-secret key marker
and a phase name.  They never contain a private key, a client assertion, or an
access token.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class SigningRotationError(RuntimeError):
    """Base class for signing-generation coordination failures."""

    def __init__(
            self,
            message: str,
            *,
            key_tag: Optional[str] = None,
            phase: Optional[str] = None,
            ):
        super().__init__(message)
        self.key_tag = key_tag
        self.phase = phase


class UnboundClientAssertionError(SigningRotationError):
    """Raised when strict review receives an assertion not issued by a policy."""


class GenerationBoundAssertion(str):
    """A string assertion carrying non-secret signing-generation metadata."""

    __slots__ = (
        "generation", "key_tag", "prepared_at", "expires_at",
        "audience", "assertion_id",
    )

    generation: Any
    key_tag: str
    prepared_at: float
    expires_at: Optional[float]
    audience: Optional[str]
    assertion_id: str

    def __new__(
            cls,
            value: Union[str, bytes],
            *,
            generation: Any,
            key_tag: str,
            prepared_at: float,
            expires_at: Optional[float] = None,
            audience: Optional[str] = None,
            assertion_id: Optional[str] = None,
            ):
        if isinstance(value, bytes):
            value = value.decode("ascii")
        obj = str.__new__(cls, value)
        obj.generation = generation
        obj.key_tag = key_tag
        obj.prepared_at = prepared_at
        obj.expires_at = expires_at
        obj.audience = audience
        obj.assertion_id = assertion_id or str(uuid.uuid4())
        return obj


@dataclass
class SigningGeneration:
    """One generation of public/private signing material."""

    name: Any
    signer: Any
    key_tag: str
    created_at: float
    rotated_at: Optional[float] = None
    grace_until: Optional[float] = None
    retired: bool = False


@dataclass(frozen=True)
class PreparedAssertion:
    """An assertion that has been signed and is waiting to be sent."""

    assertion: GenerationBoundAssertion
    generation: Any
    key_tag: str
    prepared_at: float
    expires_at: Optional[float]
    audience: Optional[str]

    @property
    def value(self) -> str:
        return self.assertion


class RecordingSigner:
    """A signer double which records calls and returns an opaque assertion.

    The double performs no real cryptography and is therefore safe in offline
    tests.  A real signer can be supplied to :class:`SigningRotationPolicy`
    directly; this class is useful when a test only needs to prove which
    generation signed each prepared assertion.
    """

    def __init__(
            self,
            generation: Any,
            key_tag: Optional[str] = None,
            *,
            delegate: Any = None,
            token_prefix: str = "recording-assertion",
            ):
        self.generation = generation
        self.key_tag = key_tag or "public-key:{}".format(generation)
        self.delegate = delegate
        self.token_prefix = token_prefix
        self.records: List[Dict[str, Any]] = []
        self.calls = self.records  # Convenient alias for test code.

    def sign_assertion(self, audience: Optional[str] = None, **kwargs: Any) -> str:
        sequence = len(self.records) + 1
        record = {
            "phase": "sign",
            "generation": self.generation,
            "key_tag": self.key_tag,
            "audience": audience,
            "sequence": sequence,
        }
        self.records.append(record)
        if self.delegate is not None:
            sign = getattr(self.delegate, "sign_assertion", None)
            if callable(sign):
                return sign(audience=audience, **kwargs)
            return self.delegate(audience=audience, **kwargs)
        return "{}-{}-{}".format(self.token_prefix, self.generation, sequence)

    # Common callable protocol used by small signer fakes.
    def __call__(self, audience: Optional[str] = None, **kwargs: Any) -> str:
        return self.sign_assertion(audience, **kwargs)


class SigningRotationPolicy:
    """Track active signing generation and an optional old-generation window.

    New assertions are always signed by the current generation.  An assertion
    already prepared by an older generation may still be sent while that
    generation is inside its configured transition window.  Once the generation
    is retired or the window is closed, review at the actual send boundary
    selects the current generation and prepares a replacement assertion.
    """

    def __init__(
            self,
            *,
            transition_window: float = 600.0,
            clock: Optional[Callable[[], float]] = None,
            strict_unbound: bool = False,
            max_issued_assertions: int = 4096,
            ):
        self.transition_window = float(transition_window)
        self._clock = clock or time.time
        self.strict_unbound = strict_unbound
        self.max_issued_assertions = max_issued_assertions
        self._generations: Dict[Any, SigningGeneration] = {}
        self._order: List[Any] = []
        self._current: Any = None
        self._issued: Dict[str, GenerationBoundAssertion] = {}
        self.diagnostics: List[Dict[str, str]] = []

    def now(self, at: Optional[float] = None) -> float:
        return float(self._clock() if at is None else at)

    def add_generation(
            self,
            generation: Any,
            signer: Any,
            *,
            key_tag: Optional[str] = None,
            at: Optional[float] = None,
            grace_until: Optional[float] = None,
            retired: bool = False,
            activate: bool = True,
            ) -> SigningGeneration:
        now = self.now(at)
        tag = key_tag or getattr(signer, "key_tag", None)
        if not tag:
            tag = public_key_tag(getattr(signer, "public_key", None)) \
                if getattr(signer, "public_key", None) is not None \
                else "public-key:{}".format(generation)
        material = SigningGeneration(
            name=generation,
            signer=signer,
            key_tag=tag,
            created_at=now,
            grace_until=grace_until,
            retired=retired,
        )
        self._generations[generation] = material
        if generation not in self._order:
            self._order.append(generation)
        if activate or self._current is None:
            self._current = generation
        return material

    @property
    def current_generation(self) -> SigningGeneration:
        if self._current is None:
            raise SigningRotationError("No signing generation is registered")
        return self._generations[self._current]

    def generation(self, name: Any) -> SigningGeneration:
        try:
            return self._generations[name]
        except KeyError:
            raise SigningRotationError(
                "Unknown signing generation: {!r}".format(name))

    def rotate(
            self,
            generation: Any = None,
            signer: Any = None,
            *,
            key_tag: Optional[str] = None,
            at: Optional[float] = None,
            transition_window: Optional[float] = None,
            ) -> SigningGeneration:
        """Make *generation* current and open a window for the previous one."""

        now = self.now(at)
        if generation is None:
            generation = "g{}".format(len(self._order) + 1)
        if signer is None and generation in self._generations:
            material = self._generations[generation]
            material.retired = False
        else:
            material = self.add_generation(
                generation,
                signer if signer is not None else RecordingSigner(generation, key_tag),
                key_tag=key_tag,
                at=now,
                activate=False,
            )
        if transition_window is not None:
            self.transition_window = float(transition_window)
        previous = self._current
        if previous is not None and previous != generation:
            old = self._generations[previous]
            old.rotated_at = now
            old.retired = self.transition_window <= 0
            # Do not freeze the deadline unless a generation was explicitly
            # registered with grace_until. Deriving it from the current
            # configured window lets an operator close all open windows by
            # changing transition_window to zero.
            for older_name in self._order[:-1]:
                if older_name == previous:
                    break
                older = self._generations[older_name]
                older.retired = True
                older.grace_until = now
        self._current = generation
        self._diagnose(material, "rotation")
        return material

    def retire(
            self,
            generation: Any = None,
            *,
            at: Optional[float] = None,
            ) -> SigningGeneration:
        """Immediately retire one generation (default: the previous one)."""

        now = self.now(at)
        if generation is None:
            current_index = self._order.index(self._current)
            if current_index <= 0:
                raise SigningRotationError("No previous signing generation")
            generation = self._order[current_index - 1]
        material = self.generation(generation)
        material.retired = True
        material.grace_until = now
        self._diagnose(material, "retire")
        return material

    close_transition_window = retire

    def configure_transition_window(
            self,
            transition_window: float,
            *,
            close_existing: bool = False,
            at: Optional[float] = None,
            ) -> None:
        """Set the configured old-generation window, optionally closing it now."""

        self.transition_window = float(transition_window)
        if close_existing:
            now = self.now(at)
            for name in self._order:
                if name != self._current:
                    material = self._generations[name]
                    material.retired = True
                    material.grace_until = now
                    self._diagnose(material, "transition_window_closed")

    def _deadline(self, material: SigningGeneration) -> Optional[float]:
        if material.grace_until is not None:
            return material.grace_until
        if material.rotated_at is not None:
            return material.rotated_at + self.transition_window
        return None

    def allows_in_flight(
            self,
            generation: Any,
            *,
            at: Optional[float] = None,
            assertion: Optional[GenerationBoundAssertion] = None,
            ) -> bool:
        """Whether an already-prepared assertion may still be sent."""

        material = self.generation(generation)
        now = self.now(at)
        if material.retired:
            return False
        if assertion is not None and assertion.expires_at is not None \
                and now > assertion.expires_at:
            return False
        if material.name == self._current:
            return True
        deadline = self._deadline(material)
        return deadline is not None and now <= deadline

    def prepare(
            self,
            audience: Optional[str] = None,
            *,
            at: Optional[float] = None,
            expires_in: float = 600.0,
            phase: str = "assertion.prepare",
            ) -> PreparedAssertion:
        """Sign a fresh short-lived assertion using the current generation."""

        material = self.current_generation
        now = self.now(at)
        sign = getattr(material.signer, "sign_assertion", material.signer)
        raw = sign(audience=audience, expires_in=expires_in)
        expires_at = now + float(expires_in) if expires_in is not None else None
        bound = GenerationBoundAssertion(
            raw,
            generation=material.name,
            key_tag=material.key_tag,
            prepared_at=now,
            expires_at=expires_at,
            audience=audience,
        )
        self._issued[bound] = bound
        if len(self._issued) > self.max_issued_assertions:
            self._issued.pop(next(iter(self._issued)))
        self._diagnose(material, phase)
        return PreparedAssertion(
            assertion=bound,
            generation=material.name,
            key_tag=material.key_tag,
            prepared_at=now,
            expires_at=expires_at,
            audience=audience,
        )

    def review(
            self,
            value: Union[PreparedAssertion, GenerationBoundAssertion, str, bytes, None],
            *,
            at: Optional[float] = None,
            phase: str = "send",
            audience: Optional[str] = None,
            ) -> Union[GenerationBoundAssertion, str, bytes, None]:
        """Review the actual send value and rebind it when necessary.

        A still-valid old generation returns the same bound assertion object.
        A closed/retired/expired generation is reassessed to the current
        generation and a newly signed assertion is returned.
        """

        if value is None:
            return None
        prepared: Optional[PreparedAssertion] = None
        if isinstance(value, PreparedAssertion):
            prepared = value
            bound = value.assertion
        elif isinstance(value, GenerationBoundAssertion):
            bound = value
        else:
            key = value.decode("ascii") if isinstance(value, bytes) else value
            bound = self._issued.get(key)
            if bound is None:
                if self.strict_unbound:
                    raise UnboundClientAssertionError(
                        "Refusing to send an assertion with no generation binding",
                        phase=phase)
                return value
            if isinstance(value, bytes):
                # Keep the caller's wire type when it supplied bytes.
                return value if self.allows_in_flight(
                    bound.generation, at=at, assertion=bound) \
                    else self.review(
                        bound, at=at, phase=phase, audience=audience).encode("ascii")
        material = self.generation(bound.generation)
        if self.allows_in_flight(bound.generation, at=at, assertion=bound):
            self._diagnose(material, phase)
            return bound
        self._diagnose(material, phase + ".reassess")
        replacement = self.prepare(
            audience=audience or bound.audience,
            at=at,
            expires_in=(bound.expires_at - bound.prepared_at)
                if bound.expires_at is not None else 600.0,
            phase=phase + ".resign",
        ).assertion
        self._diagnose(self.current_generation, phase + ".replaced")
        return replacement

    def review_request_data(
            self,
            data: Any,
            *,
            at: Optional[float] = None,
            phase: str = "http.send",
            key: str = "client_assertion",
            ) -> Any:
        """Review and possibly replace an assertion inside an OAuth data dict."""

        if not isinstance(data, dict) or not data.get(key):
            return None
        reviewed = self.review(data[key], at=at, phase=phase)
        if reviewed is not data[key]:
            data[key] = reviewed
        return reviewed

    def assertion_callback(
            self,
            context: Optional[Dict[str, Any]] = None,
            *,
            expires_in: float = 600.0,
            ) -> GenerationBoundAssertion:
        """Callback compatible with MSAL's callable ``client_assertion``."""

        audience = None
        if isinstance(context, dict):
            audience = context.get("token_endpoint")
        prepared = self.prepare(audience=audience, expires_in=expires_in)
        return prepared.assertion

    def assertion_provider(
            self,
            *,
            expires_in: float = 600.0,
            ):
        """Return an MSAL context-aware client-assertion callback."""

        def client_assertion(context: Dict[str, Any]):
            return self.assertion_callback(context, expires_in=expires_in)

        return client_assertion

    # Descriptive aliases for common client-credential vocabulary.
    client_assertion = assertion_callback
    get_client_assertion = assertion_callback

    def guard_http_client(
            self,
            http_client: Any,
            *,
            phase: str = "http.send",
            ) -> "RotationGuardedHttpClient":
        return RotationGuardedHttpClient(http_client, self, phase=phase)

    def generation_for_wire_value(self, value: Any) -> Any:
        """Return the generation recorded for a wire assertion, if available."""

        if isinstance(value, GenerationBoundAssertion):
            return value.generation
        if isinstance(value, PreparedAssertion):
            return value.generation
        key = value.decode("ascii") if isinstance(value, bytes) else value
        bound = self._issued.get(key) if isinstance(key, str) else None
        return bound.generation if bound is not None else None

    def _diagnose(self, material: SigningGeneration, phase: str) -> None:
        event = {"key_tag": material.key_tag, "phase": phase}
        self.diagnostics.append(event)
        logger.debug(
            "client assertion signing phase=%s key_tag=%s",
            phase, material.key_tag)


class RotationGuardedHttpClient:
    """HTTP client wrapper that reviews assertions immediately before send."""

    def __init__(
            self,
            http_client: Any,
            policy: SigningRotationPolicy,
            *,
            phase: str = "http.send",
            ):
        self.http_client = http_client
        self.policy = policy
        self.phase = phase

    def post(self, url: str, data: Any = None, **kwargs: Any) -> Any:
        self.policy.review_request_data(data, phase=self.phase)
        return self.http_client.post(url, data=data, **kwargs)

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.http_client.get(url, **kwargs)

    def close(self) -> None:
        close = getattr(self.http_client, "close", None)
        if callable(close):
            close()

    def __getattr__(self, item: str) -> Any:
        return getattr(self.http_client, item)


def public_key_tag(public_key: Any = None, *, pem: Union[str, bytes, None] = None) -> str:
    """Return a non-secret SHA-256 marker for a public key."""

    from cryptography.hazmat.primitives import serialization

    if pem is not None:
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        public_key = load_pem_public_key(pem)
    if public_key is None:
        raise ValueError("Provide a public key object or PEM data")
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + __import__("hashlib").sha256(der).hexdigest()


# Descriptive aliases for callers and tests using different terminology.
SigningGenerationRegistry = SigningRotationPolicy
SigningGenerationPolicy = SigningRotationPolicy
GenerationRotationPolicy = SigningRotationPolicy
RotationWindowPolicy = SigningRotationPolicy
SigningMaterialRegistry = SigningRotationPolicy
GenerationPolicy = SigningRotationPolicy
SigningRotationHttpClient = RotationGuardedHttpClient
GuardedSigningHttpClient = RotationGuardedHttpClient
