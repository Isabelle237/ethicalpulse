from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_wifite_scan
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction

def handle_wifite_scan(project, option, request):
    """Gère le lancement d'un scan Wifite"""
    try:
        if not project.mac_address:
            raise ValueError(f"Aucune adresse MAC définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='WIFITE',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_wifite_scan.delay(scan_instance.id, option))
        return True, f"Scan Wifite lancé pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan Wifite : {e}")
        return False, str(e)
