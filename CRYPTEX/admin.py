from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from CRYPTEX.models import UserProfile

# Inline to show the user's profile info inside the User page
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'User Profile'

# Extend the default UserAdmin
class CustomUserAdmin(UserAdmin):
    inlines = (UserProfileInline,)
    list_display = ['username', 'email', 'get_unique_code', 'is_staff', 'is_active']
    search_fields = ['username', 'userprofile__unique_code']

    def get_unique_code(self, obj):
        return obj.userprofile.unique_code
    get_unique_code.short_description = 'Friend Code'  # Column label

# Unregister default User and register custom one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

