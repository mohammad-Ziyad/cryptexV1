from django.contrib import admin
from .models import SecureFile
from django.utils import timezone
import os 

@admin.action(description='🧹 Delete expired files now')
def delete_expired_files_now(modeladmin, request, queryset):
    for file in SecureFile.objects.filter(expired_at__lt=timezone.now()):
        try:
            if file.file and file.file.path and os.path.exists(file.file.path):
                os.remove(file.file.path)
            file.delete()
        except Exception as e:
            print(f"Error during force delete: {e}")

@admin.register(SecureFile)
class SecureFileAdmin(admin.ModelAdmin):
    actions = [delete_expired_files_now]
