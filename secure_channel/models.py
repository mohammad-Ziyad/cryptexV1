from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

def default_expiry():
    return timezone.now() + timedelta(minutes=30)

class RSAKeyPair(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    private_key = models.TextField()  # Encrypt or keep external in production

class SecureChannel(models.Model):
    sender = models.ForeignKey(User, related_name='channels_sent', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='channels_received', on_delete=models.CASCADE)
    encrypted_aes_key = models.BinaryField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class BufferedFile(models.Model):
    channel = models.ForeignKey(SecureChannel, on_delete=models.CASCADE)
    encrypted_file = models.FileField(upload_to='secure_buffer/')
    encrypted_description = models.TextField()  # ✅ CORRECT for base64-encoded string
    timestamp = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=default_expiry)
    is_downloaded = models.BooleanField(default=False)




from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

# 🔐 Secure default expiration function (used instead of lambda)
def get_expiration_time():
    return timezone.now() + timedelta(minutes=30)

class SecureFile(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_files')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_files')
    file = models.FileField(upload_to='secure_uploads/')
    encrypted_description = models.TextField(blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True, null=True)  # Optional: Keep for fallback (or remove)
    expired_at = models.DateTimeField(default=get_expiration_time)
    is_downloaded = models.BooleanField(default=False)  # ✅ Add this line
    channel = models.ForeignKey(SecureChannel, on_delete=models.CASCADE, null=True, blank=True)
    file_hash = models.CharField(max_length=256, blank=True, null=True)
    original_filename = models.CharField(max_length=255, blank=True, null=True)
    encryption_version = models.CharField(max_length=10, default="v1")
    nonce = models.BinaryField(blank=True, null=True)
    tag = models.BinaryField(blank=True, null=True)
    desc_nonce = models.BinaryField(blank=True, null=True)
    desc_tag = models.BinaryField(blank=True, null=True)
    encrypted_aes_key = models.BinaryField(blank=True, null=True)




    # ✅ Secure + Indexed + Migration-Friendly
    def is_expired(self):
        """Check if the file has expired."""
        return timezone.now() > self.expired_at

    def __str__(self):
        return f"File {self.file.name} from {self.sender} to {self.receiver}"


import hashlib
def calculate_hash(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()



#AI modell
from django.contrib.auth.models import User

class LoginRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.ip_address} at {self.timestamp}"



from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import random

def generate_otp():
    return str(random.randint(100000, 999999))

class EmailOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6, default=generate_otp)
    created_at = models.DateTimeField(auto_now_add=True)
    attempt_count = models.IntegerField(default=0)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)
