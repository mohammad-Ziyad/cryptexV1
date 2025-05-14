from django.apps import AppConfig

class SecureChannelConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'secure_channel'

    def ready(self):
        import secure_channel.signals  # ✅ Register signal for RSA generation

