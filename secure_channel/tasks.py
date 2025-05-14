from celery import shared_task
from .models import SecureFile, RSAKeyPair, SecureChannel
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from pathlib import Path
import base64
import os

from .encryption import (
    generate_aes_key,
    encrypt_file_with_aes,
    encrypt_aes_key,
    encrypt_description,
    sha256_hash_file
)

from django.core.files.base import File
from django.core.mail import send_mail


@shared_task(name="secure_channel.tasks.process_secure_upload")
def process_secure_upload(file_path, sender_id, receiver_id, description, original_filename, channel_id=None):
    print("[🚀] Celery task started")

    file_hash = sha256_hash_file(file_path)
    sender = User.objects.get(id=sender_id)
    receiver = User.objects.get(id=receiver_id)

    # AES Key Generation
    aes_key = generate_aes_key()
    print(f"[🔑] AES key generated.")

    # Encrypt file
    encrypted_path, nonce, tag = encrypt_file_with_aes(file_path, aes_key)
    print(f"[💾] File encrypted and saved to: {encrypted_path}")
    print(f"[🧪] AES nonce: {nonce}")
    print(f"[🧪] AES tag: {tag}")

    # Encrypt description (if present)
    encrypted_desc = None
    desc_nonce = None
    desc_tag = None
    if isinstance(description, str) and description.strip():
        result = encrypt_description(description.strip(), aes_key)
        encrypted_desc = base64.b64encode(result['ciphertext']).decode('utf-8')
        desc_nonce = result['nonce']
        desc_tag = result['tag']

        print(f"[🧪] desc_nonce type: {type(desc_nonce)}")
        print(f"[🧪] desc_tag type: {type(desc_tag)}")
    else:
        print("[⚠️] Skipped description encryption — empty or whitespace only.")

    # Encrypt AES key with receiver's public RSA key
    receiver_rsa = RSAKeyPair.objects.get(user=receiver)
    encrypted_aes_key = encrypt_aes_key(aes_key, receiver_rsa.public_key)

    # Handle SecureChannel creation
    channel = None
    if channel_id:
     channel = SecureChannel.objects.get(id=channel_id)
     channel.encrypted_aes_key = encrypted_aes_key  # ✅ set it anyway
     channel.save()
    else:
     channel = SecureChannel.objects.create(
        sender=sender,
        receiver=receiver,
        encrypted_aes_key=encrypted_aes_key
    )

    print(f"[🔐] New secure channel created for {sender.username} to {receiver.username}.")


    print("🔍 TYPE CHECKS BEFORE SAVE:")
    print("encrypted_aes_key:", type(encrypted_aes_key))
    print("desc_nonce:", type(desc_nonce))
    print("desc_tag:", type(desc_tag))
    print("nonce:", type(nonce))
    print("tag:", type(tag))

    # Save encrypted file to DB
    with open(encrypted_path, 'rb') as f:
        from django.conf import settings
        relative_name = os.path.relpath(encrypted_path, settings.MEDIA_ROOT).replace("\\", "/")
        file_for_django = File(f, name=relative_name)
        SecureFile.objects.create(
             sender=sender,
             receiver=receiver,
             channel=channel,
             file=file_for_django,
             encrypted_description=encrypted_desc,  # ✅ already a base64-encoded string
             desc_nonce=desc_nonce,                 # ✅ raw bytes (BinaryField)
             desc_tag=desc_tag,                     # ✅ raw bytes (BinaryField)
             encrypted_aes_key=encrypted_aes_key,   # ✅ usually base64 str, so TextField
             nonce=nonce,                           # ✅ raw bytes
             tag=tag,                               # ✅ raw bytes
             expired_at=timezone.now() + timedelta(minutes=30),
             is_downloaded=False,
             file_hash=file_hash,
             original_filename=original_filename
        )


    print(f"[💾] Encrypted file saved to database: {original_filename}")

    # Delete temp file
    try:
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
            print(f"[🧹] Deleted encrypted temp file: {encrypted_path}")
    except Exception as cleanup_err:
        print(f"[⚠️] Cleanup failed: {cleanup_err}")
    try:
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
            print(f"[🧹] Deleted encrypted temp file: {encrypted_path}")
    except Exception as cleanup_err:
        print(f"[⚠️] Cleanup failed: {cleanup_err}")
    # Delete original raw file
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"[🧹] Deleted original raw file: {file_path}")
    except Exception as raw_cleanup_err:
        print(f"[⚠️] Failed to delete raw file: {raw_cleanup_err}")


    # Notify receiver
    try:
        if receiver.email:
            send_mail(
                subject='📥 You received a secure file on Cryptex',
                message=(
                    f"Hi {receiver.username},\n\n"
                    f"You’ve received a secure file from {sender.username} on Cryptex.\n\n"
                    f"📄 File Name: {original_filename}\n"
                    f"⏳ Expires in: 30 minutes\n\n"
                    f"🔗 Access it via your Cryptex dashboard.\n"
                    f"https://your-cryptex-domain.com/dashboard\n\n"
                    f"Stay encrypted,\n— Cryptex Team"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[receiver.email],
                fail_silently=False,
            )
            print(f"[📩] Email sent to {receiver.email}")
        else:
            print(f"[⚠️] No email set for {receiver.username}")
    except Exception as e:
        print(f"[❌] Email sending failed: {e}")

    print("[💾] SecureFile linked and saved successfully.")

from celery import shared_task
from .models import SecureFile, RSAKeyPair
from .encryption import decrypt_file_with_aes, decrypt_aes_key
from django.conf import settings
import os
import tempfile
import traceback

import zipfile
import shutil
import uuid


from .models import SecureFile, RSAKeyPair
from .encryption import decrypt_aes_key, decrypt_file_with_aes
import os
import tempfile
import base64
import atexit

from django.conf import settings

def prepare_decrypted_file(file_id):
    try:
        secure_file = SecureFile.objects.get(id=file_id)
        user = secure_file.receiver

        # Get full encrypted file path
        encrypted_path = os.path.join(settings.MEDIA_ROOT, secure_file.file.name)

        # Decrypt AES key with receiver's private key
        rsa_keys = RSAKeyPair.objects.get(user=user)
        aes_key = decrypt_aes_key(secure_file.channel.encrypted_aes_key, rsa_keys.private_key)

        # Decrypt the file using stored nonce and tag
        plaintext = decrypt_file_with_aes(encrypted_path, aes_key, secure_file.nonce, secure_file.tag)

        # Save decrypted content to a temporary file
        fd, temp_path = tempfile.mkstemp()
        with os.fdopen(fd, 'wb') as tmp_file:
            tmp_file.write(plaintext)
        atexit.register(lambda: os.path.exists(temp_path) and os.remove(temp_path))

        actual_hash = sha256_hash_file(temp_path)
        if actual_hash != secure_file.file_hash:
            os.remove(temp_path)
            raise ValueError("Integrity check failed! File may have been tampered with.")


        return temp_path

    except Exception as e:
        print(f"[❌] Decryption failed in prepare_decrypted_file: {e}")
        return None


@shared_task
def delete_expired_files():
    expired_files = SecureFile.objects.filter(expired_at__lt=timezone.now())
    print(f"[🧹] Found {expired_files.count()} expired files to delete.")

    for file in expired_files:
        try:
            file_path = file.file.path
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[🗑️] Deleted file: {file_path}")
            else:
                print(f"[⚠️] File not found: {file_path}")
        except Exception as e:
            print(f"[❌] Error deleting file {file_path}: {e}")
        file.delete()
        print(f"[🗂️] Deleted DB entry for file ID {file.id}")
        


from celery.schedules import crontab
from django_celery_beat.models import PeriodicTask, IntervalSchedule

def create_expiry_task():
    schedule, _ = IntervalSchedule.objects.get_or_create(every=1, period=IntervalSchedule.MINUTES)
    PeriodicTask.objects.get_or_create(
        interval=schedule,
        name='Delete expired files',
        task='secure_channel.tasks.delete_expired_files',
    )