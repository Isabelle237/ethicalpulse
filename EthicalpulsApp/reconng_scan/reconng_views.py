from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_reconng_scan
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction

def handle_reconng_scan(project, option, request):
    """Gère le scan Recon-ng"""
    try:
        if not project.domain:
            raise ValueError(f"Aucun domaine défini pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='RECONNG',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_reconng_scan.delay(scan_instance.id, option))
        return True, f"Scan Recon-ng lancé pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement de Recon-ng : {e}")
        return False, str(e)
