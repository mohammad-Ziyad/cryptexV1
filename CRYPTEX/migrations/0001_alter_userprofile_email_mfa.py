# Generated by Django 5.1.7 on 2025-05-11 17:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CRYPTEX', '000X_make_email_unique'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='email_mfa',
            field=models.EmailField(default=1, max_length=254, unique=True),
            preserve_default=False,
        ),
    ]
