from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),  # for auth_user table
        ('CRYPTEX', '0006_userprofile_email_mfa'),  # 🧠 your last migration in this app
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                ALTER TABLE auth_user
                ADD CONSTRAINT unique_email UNIQUE (email);
            """,
            reverse_sql="""
                ALTER TABLE auth_user
                DROP CONSTRAINT IF EXISTS unique_email;
            """
        )
    ]
