from django.apps import AppConfig


class MagicLinkConfig(AppConfig):
    name = "sesame.magiclink"
    label = "sesame_magiclink"
    default_auto_field = "django.db.models.BigAutoField"
    verbose_name = "Magic links"
