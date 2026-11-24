from django.apps import AppConfig


class FieldVisibilityDemoConfig(AppConfig):
    name = 'tests.field_visibility_demo'
    label = 'field_visibility_demo'
    default_auto_field = 'django.db.models.AutoField'
