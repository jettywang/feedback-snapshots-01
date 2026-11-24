from django.conf import settings
from django.db import models


class ProjectQuerySet(models.QuerySet):
    def approved(self):
        return self.filter(status=Project.STATUS_APPROVED)

    def visible_to(self, user):
        if not user.is_authenticated:
            return self.none()
        return self.filter(memberships__user=user).distinct()

    def bindable_for(self, user):
        """
        The single role-conditional entry point: only *approved* projects on
        which the user holds the binding (manager) role may be associated with
        an employee record. Merely being able to browse a project is not
        enough to bind records to it.
        """
        if not user.is_authenticated:
            return self.none()
        return self.filter(
            status=Project.STATUS_APPROVED,
            memberships__user=user,
            memberships__role=ProjectMembership.ROLE_MANAGER,
        ).distinct()


class Project(models.Model):
    STATUS_DRAFT = 'draft'
    STATUS_APPROVED = 'approved'
    STATUS_CHOICES = (
        (STATUS_DRAFT, 'Draft'),
        (STATUS_APPROVED, 'Approved'),
    )

    name = models.CharField(max_length=100)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT
    )

    objects = ProjectQuerySet.as_manager()

    class Meta:
        ordering = ('id',)

    def __str__(self):
        return self.name


class ProjectMembership(models.Model):
    ROLE_VIEWER = 'viewer'
    ROLE_MANAGER = 'manager'
    ROLE_CHOICES = (
        (ROLE_VIEWER, 'Viewer'),
        (ROLE_MANAGER, 'Manager'),
    )

    project = models.ForeignKey(
        Project, related_name='memberships', on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='project_memberships',
        on_delete=models.CASCADE,
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    class Meta:
        unique_together = ('project', 'user')
        ordering = ('id',)

    def __str__(self):
        return '%s is %s of %s' % (self.user_id, self.role, self.project_id)


class EmployeeRecord(models.Model):
    title = models.CharField(max_length=100)
    project = models.ForeignKey(
        Project, related_name='employee_records',
        null=True, blank=True, on_delete=models.SET_NULL
    )

    class Meta:
        ordering = ('id',)

    def __str__(self):
        return self.title
