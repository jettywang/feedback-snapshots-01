import django
from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

_APPROVAL_STATUS_CONSTRAINT = (
    models.CheckConstraint(
        condition=models.Q(status__in=("pending", "consumed", "withdrawn")),
        name="approvalgrant_valid_status",
    )
    if django.VERSION >= (5, 1)
    else models.CheckConstraint(
        check=models.Q(status__in=("pending", "consumed", "withdrawn")),
        name="approvalgrant_valid_status",
    )
)


class OutstandingToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )

    jti = models.CharField(unique=True, max_length=255)
    token = models.TextField()

    created_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = _("Outstanding Token")
        verbose_name_plural = _("Outstanding Tokens")
        # Work around for a bug in Django:
        # https://code.djangoproject.com/ticket/19422
        #
        # Also see corresponding ticket:
        # https://github.com/encode/django-rest-framework/issues/705
        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )
        ordering = ("user",)

    def __str__(self) -> str:
        return _("Token for %(user)s (%(jti)s)") % {
            "user": self.user,
            "jti": self.jti,
        }


class ApprovalGrant(models.Model):
    """
    A temporary, single-use authorization for one business operation.

    A grant is issued after a step-up confirmation and is only valid for the
    operation identifier and amount it was issued for.  It can be withdrawn
    until the moment it is consumed, and consuming it is a compare-and-set
    that exactly one caller can win.  Grants are deliberately separate from
    access/refresh tokens: refreshing ordinary credentials never mints or
    extends one.
    """

    PENDING = "pending"
    CONSUMED = "consumed"
    WITHDRAWN = "withdrawn"
    STATUS_CHOICES = (
        (PENDING, _("Pending")),
        (CONSUMED, _("Consumed")),
        (WITHDRAWN, _("Withdrawn")),
    )

    id = models.BigAutoField(primary_key=True, serialize=False)
    token_id = models.CharField(unique=True, max_length=64)
    token = models.TextField(null=True, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )

    operation = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=20, decimal_places=4)

    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=PENDING, db_index=True
    )
    result = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _("Approval Grant")
        verbose_name_plural = _("Approval Grants")
        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("user", "status")),
            models.Index(fields=("operation", "status")),
        ]
        constraints = [_APPROVAL_STATUS_CONSTRAINT]

    def __str__(self) -> str:
        return _("Approval grant %(id)s for %(operation)s (%(status)s)") % {
            "id": self.token_id,
            "operation": self.operation,
            "status": self.status,
        }

    @property
    def is_live(self) -> bool:
        from ..utils import aware_utcnow

        return self.status == self.PENDING and self.expires_at > aware_utcnow()


class BlacklistedToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    token = models.OneToOneField(OutstandingToken, on_delete=models.CASCADE)

    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("Blacklisted Token")
        verbose_name_plural = _("Blacklisted Tokens")
        # Work around for a bug in Django:
        # https://code.djangoproject.com/ticket/19422
        #
        # Also see corresponding ticket:
        # https://github.com/encode/django-rest-framework/issues/705
        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )

    def __str__(self) -> str:
        return _("Blacklisted token for %(user)s") % {"user": self.token.user}
