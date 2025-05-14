import random
import string
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# ✅ Collision-safe friend code generator
def generate_unique_code():
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if not UserProfile.objects.filter(unique_code=code).exists():
            return code

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    unique_code = models.CharField(max_length=6, unique=True, default=generate_unique_code)
    friends = models.ManyToManyField('self', blank=True, symmetrical=True)
    email_mfa = models.EmailField(unique=True)



    def __str__(self):
        return self.user.username

   