# Generated by Django 4.2.13 on 2024-06-13 11:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dj_intg', '0015_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='78de43', max_length=6),
        ),
    ]
