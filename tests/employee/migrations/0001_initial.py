from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('status', models.CharField(choices=[('draft', 'Draft'), ('approved', 'Approved')], default='draft', max_length=20)),
            ],
            options={'ordering': ('id',)},
        ),
        migrations.CreateModel(
            name='ProjectMembership',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(choices=[('viewer', 'Viewer'), ('manager', 'Manager')], max_length=20)),
                ('project', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='memberships', to='employee.project')),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='project_memberships', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ('id',), 'unique_together': {('project', 'user')}},
        ),
        migrations.CreateModel(
            name='EmployeeRecord',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100)),
                ('project', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='employee_records', to='employee.project')),
            ],
            options={'ordering': ('id',)},
        ),
    ]
