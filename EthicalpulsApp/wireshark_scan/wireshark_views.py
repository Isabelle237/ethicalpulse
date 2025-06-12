from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_wireshark_capture
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction

def handle_wireshark_scan(project, option, request):
    """Gère la capture Wireshark"""
    try:
        if not project.interface:
            raise ValueError(f"Aucune interface réseau définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='WIRESHARK',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_wireshark_capture.delay(scan_instance.id, option))
        return True, f"Capture Wireshark lancée pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement de Wireshark : {e}")
        return False, str(e)
