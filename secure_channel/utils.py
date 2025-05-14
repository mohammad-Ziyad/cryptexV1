# secure_channel/utils.py
from django.core.mail import send_mail
from django.conf import settings

def send_admin_alert(username, ip):
    subject = '[Cryptex Alert] Suspicious Login Detected'
    message = (
        f'🚨 Cryptex Alert!\n\n'
        f'User "{username}" was locked due to a suspicious login from IP address: {ip}.\n\n'
        f'Take action immediately.'
    )
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [settings.ADMIN_EMAIL]

    send_mail(subject, message, from_email, recipient_list)
