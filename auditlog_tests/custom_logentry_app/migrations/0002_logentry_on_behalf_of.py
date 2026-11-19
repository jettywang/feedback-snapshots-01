from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("custom_logentry_app", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="customlogentrymodel",
            name="on_behalf_of",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
                verbose_name="on behalf of",
                help_text=(
                    "The user on whose behalf the action was performed, when "
                    "the actor was acting as their representative."
                ),
            ),
        ),
        migrations.AddField(
            model_name="customlogentrymodel",
            name="on_behalf_of_email",
            field=models.CharField(
                blank=True,
                max_length=254,
                null=True,
                verbose_name="on behalf of email",
            ),
        ),
    ]
