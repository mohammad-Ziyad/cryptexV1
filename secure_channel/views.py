from .models import SecureChannel, RSAKeyPair
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from Crypto.PublicKey import RSA
from django.http import JsonResponse
from .encryption import generate_aes_key, encrypt_aes_key  # Assuming you have this
import os
import uuid
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import SecureFile
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
def get_or_create_rsa_keypair(user):
    rsa_pair, created = RSAKeyPair.objects.get_or_create(user=user)
    if created:
        key = RSA.generate(2048)
        rsa_pair.public_key = key.publickey().export_key().decode()
        rsa_pair.private_key = key.export_key().decode()
        rsa_pair.save()
    return rsa_pair


@login_required
def start_secure_channel(request, friend_id):
    friend = get_object_or_404(User, id=friend_id)

    # Get or create RSA key for the receiver
    friend_rsa = get_or_create_rsa_keypair(friend)

    # Optional: create key for the sender too (for 2-way encryption)
    get_or_create_rsa_keypair(request.user)

    # Check if channel already exists
    if SecureChannel.objects.filter(sender=request.user, receiver=friend).exists():
        return redirect('channel_home')  # Replace with your actual view name

    # Generate AES key
    aes_key = generate_aes_key()

    # Encrypt AES key with friend's public key
    encrypted_key = encrypt_aes_key(aes_key, friend_rsa.public_key)

    # Save new channel
    SecureChannel.objects.create(
        sender=request.user,
        receiver=friend,
        aes_key_encrypted=encrypted_key
    )

    return JsonResponse({'status': 'ok'})


from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def channel_home(request):
    return render(request, 'channel_home.html')


from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.http import HttpResponse
from .models import SecureFile, SecureChannel  # Adjust if different
import os
from .tasks import process_secure_upload
from django.core.files.storage import default_storage

import os
import uuid
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils.text import get_valid_filename
from .tasks import process_secure_upload
from django.contrib.auth.models import User

  # Optional: if you're manually handling CSRF in JavaScript, else remove


# views.py


from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.core.files.storage import default_storage
from django.utils.text import get_valid_filename

import os, uuid
from .models import SecureFile, SecureChannel, RSAKeyPair
from django.contrib.auth.models import User
from .tasks import process_secure_upload
from .encryption import generate_aes_key, encrypt_aes_key
from .views import get_or_create_rsa_keypair


@csrf_exempt
@login_required
def upload_secure_file(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

    try:
        file = request.FILES.get('file')
        receiver_id = request.POST.get('receiver_id')
        description = request.POST.get('description', '')[:200]
        chunk_index = int(request.POST.get('chunk_index', 0))
        total_chunks = int(request.POST.get('total_chunks', 1))
        original_filename = request.POST.get('original_filename', 'unknown')
        print("📥 request.POST:", dict(request.POST))
        print("📦 request.FILES:", dict(request.FILES))

        if not file or not receiver_id:
            return JsonResponse({'status': 'error', 'message': 'Missing required data'}, status=400)

        if chunk_index < 0 or chunk_index >= total_chunks:
            return JsonResponse({'status': 'error', 'message': 'Invalid chunk index'}, status=400)

        receiver = get_object_or_404(User, id=receiver_id)

        safe_filename = get_valid_filename(original_filename)
        chunk_folder = os.path.join(settings.MEDIA_ROOT, 'secure_uploads')
        os.makedirs(chunk_folder, exist_ok=True)
        final_file_name = f"{uuid.uuid4().hex}_{safe_filename}"
        final_file_path = os.path.join(chunk_folder, final_file_name)
        original_filename = safe_filename

        with open(final_file_path, 'ab') as f:
            for chunk in file.chunks():
                f.write(chunk)

        if chunk_index == total_chunks - 1:
            # ✅ Reuse or create SecureChannel
            channel, created = SecureChannel.objects.get_or_create(
                sender=request.user,
                receiver=receiver,
                defaults={
                    'encrypted_aes_key': encrypt_aes_key(
                        generate_aes_key(),
                        get_or_create_rsa_keypair(receiver).public_key
                    )
                }
            )

            # ✅ Send file to Celery with channel ID
            process_secure_upload.delay(
                final_file_path,
                request.user.id,
                receiver.id,
                description,
                original_filename,
                channel.id
            )

            return JsonResponse({
                'status': 'success',
                'message': 'File uploaded successfully!',
                'filename': final_file_name,
                'original_filename': original_filename,
                'description': description
            })

        return JsonResponse({
            'status': 'success',
            'message': f'Chunk {chunk_index + 1} uploaded successfully.'
        })

    except Exception as e:
        print(f"[ERROR] Secure upload failed: {e}")
        return JsonResponse({'status': 'error', 'message': 'Upload failed'}, status=500)






from django.views.decorators.http import require_POST
from django.http import JsonResponse
from .models import SecureFile

@csrf_exempt
@login_required
@require_POST
def delete_secure_file(request):
    file_id = request.POST.get("file_id")
    try:
        file = SecureFile.objects.get(id=file_id, sender=request.user)
        file.file.delete(save=False)  # Delete file from disk
        file.delete()  # Delete DB entry
        return JsonResponse({'status': 'success'})
    except SecureFile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'File not found'}, status=404)



from django.utils.timezone import now
from .encryption import decrypt_description, decrypt_aes_key


from django.shortcuts import render
from .models import SecureFile, RSAKeyPair
from .encryption import decrypt_description, decrypt_aes_key
from django.utils import timezone
from django.contrib.auth.decorators import login_required


@login_required
def receiver_dashboard(request):
    try:
        received_files = SecureFile.objects.filter(
            receiver=request.user,
            expired_at__gt=timezone.now(),
            is_downloaded=False
        ).select_related("sender", "channel").order_by("-uploaded_at")

        archived_files = SecureFile.objects.filter(
            receiver=request.user,
            is_downloaded=True
        ).select_related("sender", "channel").order_by("-uploaded_at")

        file_data = []
        archive_data = []

        rsa = RSAKeyPair.objects.get(user=request.user)

        # ✅ Process received files
        for file in received_files:
            try:
                aes_key = decrypt_aes_key(file.channel.encrypted_aes_key, rsa.private_key)
                decrypted_desc = None
                if file.encrypted_description and file.desc_nonce and file.desc_tag:
                    decrypted_desc = decrypt_description(
                        file.encrypted_description,
                        aes_key,
                        file.desc_nonce,
                        file.desc_tag
                    )
            except Exception as e:
                print(f"[❌] Error decrypting received file ID {file.id}: {e}")
                decrypted_desc = None

            file_data.append({"file": file, "decrypted_description": decrypted_desc})

        # ✅ Process archived files
        for file in archived_files:
            try:
                aes_key = decrypt_aes_key(file.channel.encrypted_aes_key, rsa.private_key)
                decrypted_desc = None
                if file.encrypted_description and file.desc_nonce and file.desc_tag:
                    decrypted_desc = decrypt_description(
                        file.encrypted_description,
                        aes_key,
                        file.desc_nonce,
                        file.desc_tag
                    )
            except Exception as e:
                print(f"[❌] Error decrypting archived file ID {file.id}: {e}")
                decrypted_desc = None

            archive_data.append({"file": file, "decrypted_description": decrypted_desc})

        return render(request, "receiver_dashboard.html", {
            "received_files": file_data,
            "archived_files": archive_data
        })

    except Exception as e:
        print(f"[💥] CRITICAL dashboard error: {e}")
        return HttpResponse("Server error loading dashboard.", status=500)


# Views for file deletion (optional to trigger manually or automatically)
@login_required
def delete_secure_file(request):
    file_id = request.POST.get("file_id")
    try:
        file = SecureFile.objects.get(id=file_id, sender=request.user)
        file.file.delete(save=False)  # Delete file from disk
        file.delete()  # Delete DB entry
        return JsonResponse({'status': 'success'})
    except SecureFile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'File not found'}, status=404)


# In views.py or a utils.py file
import uuid

def generate_unique_filename(original_filename):
    """
    Generates a unique filename using UUID and preserves the file extension.
    """
    extension = original_filename.split('.')[-1]  # Get the file extension
    unique_filename = f"{uuid.uuid4().hex}.{extension}"
    return unique_filename


# In views.py (or utils.py)

import os

def ensure_unique_file_path(file_path):
    """
    Ensure that the file path is unique by checking if the file already exists.
    If it exists, append a counter to the file name.
    """
    base, extension = os.path.splitext(file_path)
    counter = 1
    while os.path.exists(file_path):
        file_path = f"{base}_{counter}{extension}"
        counter += 1
    return file_path



from django.http import HttpResponse, Http404
from django.contrib.auth.decorators import login_required
from django.conf import settings
import mimetypes

from django.http import FileResponse, HttpResponseForbidden, Http404
from django.contrib.auth.decorators import login_required
from .models import SecureFile
from .tasks import prepare_decrypted_file
import os
from mimetypes import guess_type

@login_required
def download_file(request, file_id):
    try:
        secure_file = SecureFile.objects.get(id=file_id, receiver=request.user)

        if secure_file.is_expired():
            return HttpResponseForbidden("This file has expired.")

        if secure_file.is_downloaded:
            return HttpResponseForbidden("This file has already been downloaded.")

        # Prepare decrypted file
        temp_path = prepare_decrypted_file(file_id)
        if not temp_path or not os.path.exists(temp_path):
            raise Http404("File not available or decryption failed.")

        # Mark as downloaded
        secure_file.is_downloaded = True
        secure_file.save()

        # Guess MIME type
        mime_type, _ = guess_type(secure_file.original_filename or secure_file.file.name)
        mime_type = mime_type or 'application/octet-stream'

        # Serve file
        response = FileResponse(open(temp_path, 'rb'), content_type=mime_type)
        response['Content-Disposition'] = f'attachment; filename="{secure_file.original_filename or os.path.basename(secure_file.file.name)}"'

        # Clean up temp file after response
        def cleanup():
            if os.path.exists(temp_path):
                os.remove(temp_path)

        response.close = lambda *args, **kwargs: (cleanup(), FileResponse.close(response, *args, **kwargs))

        return response

    except SecureFile.DoesNotExist:
        raise Http404("File not found.")
    except Exception as e:
        print(f"[❌] Download failed: {e}")
        return HttpResponseForbidden("Decryption failed or file is unavailable.")




    



from django.utils import timezone
from .models import SecureFile
from celery import shared_task


@shared_task
def delete_expired_files():
    expired_files = SecureFile.objects.filter(expired_at__lt=timezone.now())
    for f in expired_files:
        try:
            f.file.delete(save=False)
            f.delete()
            print(f"[✓] Deleted expired file: {f.file.name}")
        except Exception as e:
            print(f"[X] Error deleting {f.file.name}: {e}")




import traceback
import tempfile
import uuid
import os
from django.http import StreamingHttpResponse, Http404, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from .models import SecureFile, RSAKeyPair
from .encryption import decrypt_aes_key, decrypt_file_with_aes, sha256_hash_file

class FileWrapper:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file = open(file_path, 'rb')

    def __iter__(self):
        return iter(lambda: self.file.read(8192), b'')

    def close(self):
        try:
            self.file.close()
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
                print(f"[🧹] Deleted temp file: {self.file_path}")
        except Exception as e:
            print(f"[⚠️] Error deleting file: {e}")



import atexit

@login_required
def download_file(request, file_id):
    try:
        secure_file = SecureFile.objects.select_related("channel", "receiver").get(id=file_id, receiver=request.user)

        if not secure_file.channel:
            raise Http404("Missing encryption metadata.")

        if secure_file.is_expired():
            return HttpResponseForbidden("This file has expired.")

        if secure_file.is_downloaded:
            return HttpResponseForbidden("This file has already been downloaded.")

        receiver_rsa = RSAKeyPair.objects.get(user=request.user)
        aes_key = decrypt_aes_key(secure_file.channel.encrypted_aes_key
, receiver_rsa.private_key)
        encrypted_path = os.path.join(settings.MEDIA_ROOT, secure_file.file.name)

        if not secure_file.nonce or not secure_file.tag:
            print(f"[❌] Missing nonce or tag for file ID {secure_file.id}")
            return HttpResponseForbidden("Missing encryption metadata. Cannot decrypt file.")

        decrypted_bytes = decrypt_file_with_aes(
          encrypted_path,
            aes_key,
            secure_file.nonce,
            secure_file.tag
        )


        # Write decrypted bytes to a temp file
        temp_dir = tempfile.gettempdir()
        filename = f"decrypted_{uuid.uuid4()}_{os.path.basename(secure_file.file.name)}"
        temp_path = os.path.join(temp_dir, filename)
        with open(temp_path, 'wb') as tmp:
            tmp.write(decrypted_bytes)

        atexit.register(lambda: os.path.exists(temp_path) and os.remove(temp_path))

        # ✅ Integrity Check
        actual_hash = sha256_hash_file(temp_path)
        if actual_hash != secure_file.file_hash:
            os.remove(temp_path)
            return HttpResponseForbidden("⚠️ Integrity check failed. File has been tampered with or corrupted.")

        # ✅ Mark as downloaded
        secure_file.is_downloaded = True
        secure_file.save()

        # ✅ Stream response
        file_wrapper = FileWrapper(temp_path)
        response = StreamingHttpResponse(file_wrapper, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(secure_file.file.name)}"'

        # ✅ Auto-clean after streaming
        original_close = response.close
        def custom_close():
            file_wrapper.close()
            if original_close:
                original_close()
        response.close = custom_close

        return response

    except SecureFile.DoesNotExist:
        raise Http404("File not found.")
    except Exception as e:
        print(f"[❌] Download failed: {e}")
        traceback.print_exc()
        return HttpResponseForbidden("⚠️ Decryption failed: file integrity could not be verified.")




from django.http import JsonResponse
from django.utils import timezone
from .models import SecureFile

@login_required
def check_new_files(request):
    has_new = SecureFile.objects.filter(
        receiver=request.user,
        is_downloaded=False,
        expired_at__gt=timezone.now()
    ).exists()
    return JsonResponse({'new_files': has_new})



