# Generated by Django 5.0.6 on 2024-06-29 20:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dj_intg', '0004_progress_in_progress_progress_taken_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='progress',
            name='in_progress',
        ),
        migrations.RemoveField(
            model_name='progress',
            name='taken',
        ),
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='5d5d9b', max_length=6),
        ),
    ]