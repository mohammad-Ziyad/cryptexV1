from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import RSAKeyPair
from Crypto.PublicKey import RSA

@receiver(post_save, sender=User)
def create_rsa_keypair(sender, instance, created, **kwargs):
    if created:
        key = RSA.generate(2048)
        RSAKeyPair.objects.create(
            user=instance,
            private_key=key.export_key().decode(),
            public_key=key.publickey().export_key().decode()
        )

# Optional: keep this if you still want to log IPs only
from django.contrib.auth.signals import user_logged_in

@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    ip = get_client_ip(request)
    print(f"[Cryptex] User {user.username} logged in from {ip}")  # ✅ Logging without AI

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")
