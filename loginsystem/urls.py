from django.urls import path
from . import views
app_name='auth'
from loginsystem.views import verify_otp
from loginsystem.views import activate_user


urlpatterns = [
    path('',views.home,name='home'),
    path('signup/',views.signup,name='signup'),
    path('signin/',views.login_page,name='signin'),
    path('logout/',views.logout_user,name='logout'),
    path('about/',views.about,name='about'),
    path('dashboard/',views.dashboard,name='dashboard'),
    path("verify-otp/", verify_otp, name="verify_otp"),
    path("activate/<uidb64>/<token>/", activate_user, name="activate"),


]