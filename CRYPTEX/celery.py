from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CRYPTEX.settings')

app = Celery('CRYPTEX')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'delete-expired-files': {
        'task': 'secure_channel.tasks.delete_expired_files',
        'schedule': crontab(minute=0, hour='*/1'),
    }
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
