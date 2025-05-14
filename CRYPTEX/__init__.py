# secure_channel/__init__.py

from __future__ import absolute_import, unicode_literals

# Import Celery app to ensure tasks are discovered
from .celery import app as celery_app

__all__ = ('celery_app',)
