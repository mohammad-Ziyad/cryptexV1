from django.urls import path
from . import views

urlpatterns = [
    path('', views.friends_list_view, name='friends_list'),
    path('add/', views.send_friend_request, name='send_friend_request'),
    path('accept/<int:request_id>/', views.accept_friend_request, name='accept_friend_request'),
    path('remove/<int:friend_id>/', views.remove_friend, name='remove_friend'),
    path('reject_friend_request/<int:request_id>/', views.reject_friend_request, name='reject_friend_request'),
    

]