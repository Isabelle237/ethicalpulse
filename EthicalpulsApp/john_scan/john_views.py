from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_john_scan
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction


def handle_john_scan(project, option, request):
    """Gère l'analyse John The Ripper"""
    try:
        if not project.hash_file:
            raise ValueError(f"Aucun fichier de hash défini pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='JOHN',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_john_scan.delay(scan_instance.id, option))
        return True, f"Analyse John The Ripper lancée pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement de John The Ripper : {e}")
        return False, str(e)

