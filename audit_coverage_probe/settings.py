import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = "probe"
DEBUG = True
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "auditlog",
    "probe",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "probe.sqlite3"),
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# 全模型注册 + 排除项 + 单模型规则
AUDITLOG_INCLUDE_ALL_MODELS = True
AUDITLOG_EXCLUDE_TRACKING_MODELS = ("probe.Excluded",)
AUDITLOG_INCLUDE_TRACKING_MODELS = (
    {"model": "probe.Secret", "exclude_fields": ["password"]},
)
