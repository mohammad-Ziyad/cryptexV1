# Generated by Django 5.1.7 on 2025-05-12 11:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secure_channel', '0026_remove_securefile_encrypted_aes_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='securefile',
            name='encrypted_aes_key',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
