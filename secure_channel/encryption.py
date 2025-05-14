from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# AES Key Generation
def generate_aes_key():
    return get_random_bytes(32)  # AES-256

# Encrypt AES key with RSA Public key
def encrypt_aes_key(aes_key, public_key_str):
    public_key = RSA.import_key(public_key_str.encode("utf-8"))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key)  # ✅ GOOD: returns bytes


# Decrypt AES key with RSA Private key
from django.core.exceptions import SuspiciousOperation
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

def decrypt_aes_key(encrypted_key_raw, private_key_str):
    try:
        # 🔐 Sanity check first
        if encrypted_key_raw is None:
            raise ValueError("Encrypted AES key is missing (None). Check channel integrity.")

        # Normalize and import RSA private key
        normalized_key = private_key_str.replace('\r\n', '\n').strip()
        private_key = RSA.import_key(normalized_key.encode('utf-8'))

        # ✅ Normalize all supported BinaryField types
        if isinstance(encrypted_key_raw, memoryview):
            encrypted_key_bytes = encrypted_key_raw.tobytes()
        elif isinstance(encrypted_key_raw, bytes):
            encrypted_key_bytes = encrypted_key_raw
        else:
            raise TypeError(f"Encrypted AES key must be bytes or memoryview, got {type(encrypted_key_raw)}")

        encrypted_key = base64.b64decode(encrypted_key_bytes)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)

        print("[✅] AES key decrypted successfully.")
        return aes_key

    except Exception as e:
        print(f"[❌] AES key decryption failed: {e}")
        raise





# AES file encryption (AES-EAX Mode)
import uuid
import os 
def encrypt_file_with_aes(file_path, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Generate unique filename
    encrypted_path = os.path.join(
        os.path.dirname(file_path),
        f"{uuid.uuid4().hex}.encrypted"
    )

    # ✅ Save only the ciphertext — don't write nonce + tag into the file
    with open(encrypted_path, 'wb') as f:
        f.write(ciphertext)

    print(f"Encrypted file saved to: {encrypted_path}")
    return encrypted_path, cipher.nonce, tag


# AES file decryption (AES-EAX Mode)
import base64
from Crypto.Cipher import AES

def decrypt_file_with_aes(file_path, aes_key, nonce, tag):
    try:
        with open(file_path, 'rb') as f:
            ciphertext = f.read()
       

        print(f"\n[🔓 FILE DECRYPTION]")
        print(f"[🧪] AES key length: {len(aes_key)}")
        print(f"[🧪] File size (ciphertext): {len(ciphertext)} bytes")
        print(f"[🧪] Nonce (from DB): {base64.b64encode(nonce).decode()}")
        print(f"[🧪] Tag (from DB): {base64.b64encode(tag).decode()}")
        print(f"[🧪] Ciphertext preview: {base64.b64encode(ciphertext[:32]).decode()}...\n")

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        print(f"[✅] File decrypted successfully.\n")
        return plaintext

    except ValueError as e:
        print(f"[❌] MAC check failed: {e}")
        raise Exception("MAC check failed during decryption!")
    except Exception as ex:
        print(f"[❌] Decryption error: {ex}")
        raise ex

# AES-based description encryption
def encrypt_description(description, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(description.encode('utf-8'))
    return {
        'ciphertext': ciphertext,
        'nonce': cipher.nonce,  # ✅ bytes
        'tag': tag              # ✅ bytes
    }

from Crypto.Cipher import AES
import base64


def decrypt_description(encrypted_b64, aes_key, nonce, tag):
    try:
        ciphertext = base64.b64decode(encrypted_b64)
        print(f"[🔓 DESC] Decrypting with nonce: {base64.b64encode(nonce).decode()}")
        print(f"[🔓 DESC] Decrypting with tag: {base64.b64encode(tag).decode()}")
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"[❌] Description decryption failed: {e}")
        return None




import hashlib

def sha256_hash_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
