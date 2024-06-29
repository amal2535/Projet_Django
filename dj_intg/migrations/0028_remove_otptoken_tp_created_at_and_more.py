# Generated by Django 5.0.6 on 2024-06-25 13:45

import datetime
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dj_intg', '0027_alter_otptoken_otp_code'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='otptoken',
            name='tp_created_at',
        ),
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(max_length=6),
        ),
        migrations.AlterField(
            model_name='otptoken',
            name='otp_expires_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 6, 25, 13, 55, 3, 42698, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='otptoken',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]