from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User  # <- you're using default auth_user
from CRYPTEX.models import UserProfile
from friends.models import FriendRequest



def send_friend_request(request):
    if request.method == 'POST':
        code = request.POST.get('unique_code')

        # Look up UserProfile by unique_code, then get the user
        profile = get_object_or_404(UserProfile, unique_code=code)
        to_user = profile.user

        if to_user == request.user:
            messages.error(request, "You can't add yourself.")
        elif FriendRequest.objects.filter(from_user=request.user, to_user=to_user).exists():
            messages.warning(request, "Friend request already sent or exists.")
        else:
            FriendRequest.objects.create(from_user=request.user, to_user=to_user)
            messages.success(request, "Friend request sent.")

    return redirect('auth:dashboard')  # Redirect to the dashboard




def accept_friend_request(request, request_id):
    f_request = get_object_or_404(FriendRequest, id=request_id, to_user=request.user)
    f_request.status = 'accepted'
    f_request.save()
    return redirect('friends_list')


User = User

def get_friends(user):
    # All users who sent a request to you and you accepted
    sent_to_me = User.objects.filter(
        sent_requests__to_user=user,
        sent_requests__status='accepted'
    )

    # All users you sent a request to and they accepted
    received_from_me = User.objects.filter(
        received_requests__from_user=user,
        received_requests__status='accepted'
    )

    # Combine both querysets (union)
    return sent_to_me.union(received_from_me)


def friends_list_view(request):
    friends = get_friends(request.user)
    pending_requests = FriendRequest.objects.filter(to_user=request.user, status='pending')
    return render(request, 'friends_list.html', {
        'friends': friends,
        'pending_requests': pending_requests
    })


from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages

@login_required
def remove_friend(request, friend_id):
    # Get the friend object from the database
    friend = get_object_or_404(User, id=friend_id)

    # Ensure both users are friends before attempting to remove
    if friend.userprofile in request.user.userprofile.friends.all():
        # Remove both users from each other's friend lists
        request.user.userprofile.friends.remove(friend.userprofile)
        friend.userprofile.friends.remove(request.user.userprofile)
        messages.success(request, f'You have successfully removed {friend.username} as a friend.')
    else:
        messages.warning(request, f'{friend.username} is not in your friends list.')

    # Redirect to the dashboard
    return redirect('auth:dashboard')

def reject_friend_request(request, request_id):
    # Get the friend request object
    f_request = get_object_or_404(FriendRequest, id=request_id, to_user=request.user)

    # Mark the request as rejected (optional, depending on your model)
    f_request.status = 'rejected'
    f_request.save()

    # Optionally, you could delete the FriendRequest object if you don't need it anymore
    # f_request.delete()

    messages.success(request, "Friend request rejected.")
    return redirect('friends_list')  # Redirect to the friends list view


def friends_list_view(request):
    # Fetching friends and pending requests
    friends = get_friends(request.user)
    pending_requests = FriendRequest.objects.filter(to_user=request.user, status='pending')
    
    # Render the dashboard (or this page) with friends data
    return render(request, 'dashboard.html', {
        'friends': friends,
        'pending_requests': pending_requests,
        'greeting': 'Hello',  # example greeting, customize it
        'user_name': request.user.username,  # example user name
    })


