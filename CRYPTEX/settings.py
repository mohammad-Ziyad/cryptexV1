from pathlib import Path
import os
from base64 import b64encode, b64decode
# SECRET_ENCRYPTION_KEY = os.getenv('SSH_KEY_ENCRYPTION_KEY', 'my_32_byte_secure_key_123!ABCD')
SECRET_ENCRYPTION_KEY = os.getenv('SSH_KEY_ENCRYPTION_KEY', '1234567890abcdef1234567890abcdef')

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-o1%_1g+c-9a)k&&l2(mhqjd0iq=p*ydhcj*@n$n*04j@=ii!c&'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'crispy_forms',
    'crispy_bootstrap5',
    'CRYPTEX',
    'loginsystem',
    'friends',
    'secure_channel',
    "django_celery_beat",
  
]



# settings.py
CELERY_WORKER_POOL = "solo"



# Celery Configuration
CELERY_BROKER_URL = 'redis://localhost:6379/0'  # Use Redis as the broker
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'  # Redis to store results

CRISPY_ALLOWED_TEMPLATE_PACKS = 'bootstrap5'
CRISPY_TEMPLATE_PACK = 'bootstrap5'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'CRYPTEX.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],  # ✅ Important!
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'CRYPTEX.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'cryptex_db',
        'USER': 'mohammad',
        'PASSWORD': '123',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'
# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

Q_CLUSTER = {
    'name': 'DjangoQ',    # Name of the cluster
    'workers': 4,         # Number of parallel worker processes
    'timeout': 60,        # Maximum execution time per task (in seconds)
    'retry': 120,         # Time (in seconds) before retrying failed tasks
    'queue_limit': 50,    # Maximum number of tasks in the queue
    'bulk': 10,           # Number of tasks fetched from the database in one go
    'orm': 'default',     # ✅ Uses PostgreSQL (or other DBs in Django settings)
}

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'



# Session settings for proper user isolation
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # Database-backed sessions (default)
SESSION_COOKIE_NAME = 'cryptex_sessionid'  # Unique session cookie name
SESSION_COOKIE_AGE = 3600  # 🔐 No automatic expiry ever
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Expire session when the browser is closed

CSRF_COOKIE_NAME = 'cryptex_csrf_token'
CSRF_COOKIE_HTTPONLY = True

LOGIN_URL = '/CRYPTEX/signin/'



from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

STATICFILES_DIRS = [
    BASE_DIR / "static",
]

STATIC_URL = "/static/"

# Auth backend (required for authenticate() to work)
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]



# 📩 Email configuration for alert system
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True

EMAIL_HOST_USER = 'hassan.alibishtawi@gmail.com'           # 👈 Replace with your Gmail address
EMAIL_HOST_PASSWORD = 'ysbdaoztvnklbasn'

DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
ADMIN_EMAIL = 'youradmin@gmail.com'               # 👈 Where alerts will be sent


