from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction


def handle_aircrack_scan(project, option, request):
    """Gère le scan Aircrack-ng"""
    try:
        if not project.mac_address:
            raise ValueError(f"Aucune adresse MAC définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='AIRCRACK',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_aircrack_scan.delay(scan_instance.id, option))
        return True, f"Scan Aircrack-ng lancé pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement d'Aircrack-ng : {e}")
        return False, str(e)
