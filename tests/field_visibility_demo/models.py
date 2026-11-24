from django.db import models


class CaseRecord(models.Model):
    """
    A synthetic record used to demonstrate field-level visibility.

    ``dataset`` only partitions the two synthetic datasets; it is never
    exposed through the API. Public and internal fields live side by side on
    the same model so that two records can be identical on every public field
    while differing only on the internal, staff-only fields.
    """

    DATASET_ALPHA = 'alpha'
    DATASET_BETA = 'beta'
    DATASET_CHOICES = ((DATASET_ALPHA, 'Alpha'), (DATASET_BETA, 'Beta'))

    dataset = models.CharField(max_length=10, choices=DATASET_CHOICES)

    # Public fields: visible to every authenticated caller.
    name = models.CharField(max_length=50)
    category = models.CharField(max_length=30)
    status = models.CharField(max_length=20)

    # Internal fields: visible to staff/admins only.
    internal_note = models.CharField(max_length=120, default='')
    risk_score = models.IntegerField(default=0)

    class Meta:
        app_label = 'field_visibility_demo'
        ordering = ['id']

    def __str__(self):
        return self.name
