# Generated by Django 5.0.6 on 2024-06-11 18:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dj_intg', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='0aec07', max_length=6),
        ),
    ]