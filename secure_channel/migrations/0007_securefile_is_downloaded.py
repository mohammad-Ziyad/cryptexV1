# Generated by Django 5.1.7 on 2025-04-18 14:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secure_channel', '0006_remove_securefile_timestamp_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='securefile',
            name='is_downloaded',
            field=models.BooleanField(default=False),
        ),
    ]
