# Generated by Django 5.0.6 on 2024-06-12 14:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dj_intg', '0009_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='b66874', max_length=6),
        ),
    ]
