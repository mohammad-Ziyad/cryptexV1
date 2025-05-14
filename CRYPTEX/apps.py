# cryptex/CRYPTEX/apps.py

from django.apps import AppConfig

class CryptexConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'CRYPTEX'

    def ready(self):
        import CRYPTEX.signals  # 👈 this line activates signals
