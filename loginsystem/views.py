from django.shortcuts import render
from loginsystem.forms import CustomUserCreationForm

from django.urls import reverse 
from django.shortcuts import HttpResponseRedirect
from django.contrib.auth import login,authenticate,logout
from django.contrib.auth.decorators import login_required
from friends.models import FriendRequest
# Create your views here.
from CRYPTEX.models import UserProfile 

from django.shortcuts import render
from loginsystem.forms import CustomUserCreationForm
from django.urls import reverse
from django.shortcuts import HttpResponseRedirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from CRYPTEX.models import UserProfile

from django.contrib.auth import get_user_model
User = get_user_model()

def signup(request):
    form = CustomUserCreationForm()
    isvalid = False

    if request.method == "POST":
        form = CustomUserCreationForm(data=request.POST)
        email = request.POST.get("email", "").strip().lower()

        # ❌ Email already taken
        if User.objects.filter(email=email).exists():
            messages.error(request, "⚠️ This email is already registered. Try logging in.")
            return render(request, 'signup.html', {'form': form, 'isvalid': False})

        if form.is_valid():
            user = form.save(commit=False)
            user.email = email

            # ✅ Only deactivate if it's truly a brand new user
            is_new_user = not User.objects.filter(username=user.username).exists()
            if is_new_user:
                user.is_active = False  # Force email verification only on first creation

            user.save()

            # ✅ Create associated profile
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.email_mfa = email
            profile.save()

            # 🔗 Create activation URL
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            verify_url = request.build_absolute_uri(
                reverse("auth:activate", kwargs={"uidb64": uid, "token": token})
            )

            # 📩 Send email
            context = {"user": user, "verify_url": verify_url}
            subject = "Verify your Cryptex Account"
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = [email]

            text_body = f"Hi {user.username}, please verify your account: {verify_url}"
            html_body = render_to_string("emails/verify_email.html", context)

            email_msg = EmailMultiAlternatives(subject, text_body, from_email, to_email)
            email_msg.attach_alternative(html_body, "text/html")
            email_msg.send()

            messages.success(request, "✅ Check your email to activate your account!")
            return HttpResponseRedirect(reverse('auth:signin'))
        else:
            print("❌ Signup form errors:", form.errors)

    return render(request, 'signup.html', {'form': form, 'isvalid': isvalid})


def home(request):
    return render(request, 'home.html')

from friends.models import FriendRequest
from friends.views import get_friends

from django.shortcuts import render
from django.utils.timezone import localtime, now  # import 'now' directly
from django.contrib.auth.decorators import login_required
from secure_channel.models import SecureFile

@login_required
def dashboard(request):
    # Get current time in the user's local timezone
    current_time = localtime(now())  # Use now() from the timezone module
    hour = current_time.hour

    # Determine the greeting based on the time of day
    if hour < 12:
        greeting = "Good Morning"
    elif 12 <= hour < 18:
        greeting = "Good Afternoon"
    else:
        greeting = "Good Evening"

    # Get the list of friends and pending requests
    friends = get_friends(request.user)
    pending_requests = FriendRequest.objects.filter(to_user=request.user, status='pending')
    has_received_files = SecureFile.objects.filter(receiver=request.user).exists() 
    received_files = SecureFile.objects.filter(receiver=request.user).order_by('-uploaded_at')

    # Pass greeting and user data to the template
    return render(request, 'dashboard.html', {
        'friends': friends,
        'pending_requests': pending_requests,
        'greeting': greeting,  # Pass greeting to the template
        'user_name': request.user.username,  # Pass the logged-in user's name
        'has_received_files': has_received_files,
        'received_files': received_files,
    })



from secure_channel.models import EmailOTP
from django.core.mail import send_mail
from django.conf import settings

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from django.core.mail import send_mail
from secure_channel.models import EmailOTP, LoginRecord
from django.contrib.auth.models import User
from sklearn.ensemble import IsolationForest
import joblib
import os

from .forms import UsernameLoginForm  # ✅ use this instead


def login_page(request):
    form = UsernameLoginForm()
    error = None

    if request.method == 'POST':
        form = UsernameLoginForm(request.POST)
        if form.is_valid():
            user = form.cleaned_data['user']
            login(request, user)
            return redirect("auth:dashboard")  # ✅ this points to the view you defined

        else:
            print("❌ Login failed:", form.errors)  # ⬅️ Add this
            error = form.errors

    return render(request, 'signin.html', {
        'form': form,
        'error': error,
    })


def get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded.split(',')[0] if x_forwarded else request.META.get('REMOTE_ADDR')


def about(request):
    return render(request, 'about.html')  



@login_required()
def logout_user(request):
    logout(request)
    
    return HttpResponseRedirect(reverse('auth:signin'))



from django.shortcuts import render, redirect
from secure_channel.models import EmailOTP
from django.contrib.auth import login
from django.contrib.auth.models import User

def verify_otp(request):
    user_id = request.session.get("otp_user_id")
    if not user_id:
        return redirect("auth:signin")

    user = User.objects.get(id=user_id)
    otp_obj = EmailOTP.objects.filter(user=user).first()

    error = None
    if request.method == "POST":
        code = request.POST.get("code")

        if not otp_obj or otp_obj.is_expired():
            if otp_obj:
                otp_obj.delete()  # 🔐 Cleanup to prevent reuse
            error = "Code expired. Please login again."
            return redirect("auth:signin")

        if otp_obj.code == code:
            otp_obj.delete()
            login(request, user)
            if "otp_user_id" in request.session:
                del request.session["otp_user_id"]
            return redirect("home")

        else:
            otp_obj.attempt_count += 1
            otp_obj.save()
            if otp_obj.attempt_count >= 2:
                otp_obj.delete()
                error = "Too many failed attempts. Please login again."
                return redirect("auth:signin")
            error = "Incorrect code. Try again."

    return render(request, "verify_otp.html", {"error": error})


from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator

from django.shortcuts import render

def activate_user(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, "activation_success.html", {"user": user})  # ✅ Show success page
    else:
        messages.error(request, "❌ Invalid or expired activation link.")
        return redirect("auth:signup")
