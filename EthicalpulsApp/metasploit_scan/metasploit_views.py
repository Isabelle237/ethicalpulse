from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_metasploit_scan
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction

def handle_metasploit_scan(project, option, request):
    """Gère le scan Metasploit"""
    try:
        if not project.ip_address and not project.url:
            raise ValueError(f"Aucune cible (IP ou URL) définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='METASPLOIT',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_metasploit_scan.delay(scan_instance.id, option))
        return True, f"Scan Metasploit lancé pour le projet '{project.name}'"
    except Exception as e:
        logger.error(f"Erreur lors du lancement de Metasploit : {e}")
        return False, str(e)

