from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from CRYPTEX.models import UserProfile


from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']  # ✅ No email_mfa here




from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

from django import forms
from django.contrib.auth import authenticate, get_user_model

User = get_user_model()

class UsernameLoginForm(forms.Form):
    username = forms.CharField(label="Username or Email")
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        raw_input = cleaned_data.get("username")
        password = cleaned_data.get("password")

        print(f"🔍 Raw input: {raw_input}")
        print(f"🔍 Password input: {password}")

        # Try resolving username from email
        try:
            user_obj = User.objects.get(email=raw_input)
            actual_username = user_obj.username
            print(f"📧 Email resolved to username: {actual_username}")
        except User.DoesNotExist:
            actual_username = raw_input
            print(f"👤 Treating input as username: {actual_username}")

        try:
            user = authenticate(username=actual_username, password=password)
        except Exception as e:
            print(f"🔥 authenticate() raised: {e}")
            user = None

        if not user:
            print("❌ Final auth result: Failed")
            raise forms.ValidationError("❌ Invalid username or password")

        print("✅ Final auth result: Success")
        cleaned_data["user"] = user
        return cleaned_data

