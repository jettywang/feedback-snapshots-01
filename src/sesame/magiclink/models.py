from django.db import models
from django.utils import timezone

__all__ = ["MagicLink"]


class MagicLink(models.Model):
    """
    A stateful, single-use authentication link bound to a business scope.

    The raw token only exists while the link is issued and is delivered by
    email. Only a hash of it is stored, so reading the database doesn't grant
    the ability to log in.

    The status column makes the lifecycle of a link observable:

    * :attr:`ISSUED` — waiting to be used;
    * :attr:`CLAIMED` — a request is currently consuming the link;
    * :attr:`CONSUMED` — the link produced a valid session exactly once;
    * :attr:`REVOKED` — the link was invalidated before it could be consumed.

    ``user_id`` stores the primary key of the target user rather than a foreign
    key. The link remains meaningful even if the user is later removed, and it
    can live in a different database than the user table.

    """

    ISSUED = "issued"
    CLAIMED = "claimed"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    STATUS_CHOICES = [
        (ISSUED, "Issued"),
        (CLAIMED, "Claimed"),
        (CONSUMED, "Consumed"),
        (REVOKED, "Revoked"),
    ]

    user_id = models.CharField(max_length=255)
    scope = models.CharField(max_length=255)
    # Random per-link value mixed into the cryptographic scope so two links for
    # the same user and scope never produce the same token.
    nonce = models.CharField(max_length=64, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=ISSUED,
        db_index=True,
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user_id", "scope"]),
            models.Index(fields=["status", "expires_at"]),
        ]

    def __str__(self):
        return f"Magic link {self.pk} for user {self.user_id} in scope {self.scope!r}"

    @property
    def is_expired(self):
        return self.expires_at is not None and self.expires_at <= timezone.now()
