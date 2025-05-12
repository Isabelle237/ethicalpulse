from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Définir les paramètres par défaut de Django pour Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EthicalPulse.settings')

app = Celery('EthicalPulse')

# Charger les paramètres de configuration depuis Django
app.config_from_object('django.conf:settings', namespace='CELERY')

# Découvrir automatiquement les tâches dans les applications installées
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')