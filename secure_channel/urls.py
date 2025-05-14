from django.urls import path
from . import views

urlpatterns = [
    path('start/<int:friend_id>/', views.start_secure_channel, name='start_channel'),
    path('channel/', views.channel_home, name='channel_home'), 
    path('upload/', views.upload_secure_file, name='upload_secure_file'),
    path('secure/delete/', views.delete_secure_file, name='delete_secure_file'),
    path('receiver_dashboard/', views.receiver_dashboard, name='receiver_dashboard'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
]
