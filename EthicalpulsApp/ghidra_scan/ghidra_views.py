from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_ghidra_analysis
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction

def handle_ghidra_scan(project, option, request):
    """Gère l'analyse avec Ghidra"""
    try:
        if not project.binary_file:
            raise ValueError(f"Aucun fichier binaire défini pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='GHIDRA',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_ghidra_analysis.delay(scan_instance.id, option))
        return True, f"Analyse Ghidra lancée pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement de Ghidra : {e}")
        return False, str(e)
