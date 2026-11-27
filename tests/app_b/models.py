from django.db import models


class User(models.Model):
    """A user row owned by test application B."""

    username = models.CharField(max_length=150, unique=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        app_label = "app_b"

    def __str__(self) -> str:
        return self.username

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False
