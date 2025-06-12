from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_zap_scan
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction

def handle_zap_scan(project, option, request):
    """Gère le lancement d'un scan OWASP ZAP"""
    try:
        valid_options = [opt[0] for opt in OwaspZapResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour ZAP : '{option}'")

        if not project.url:
            raise ValueError(f"Aucune URL définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='ZAP',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_zap_scan.delay(scan_instance.id, option))
        return True, f"Scan ZAP lancé pour le projet '{project.name}'"
    except ValueError as e:
        return False, str(e)
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan ZAP : {e}")
        return False, f"Erreur inattendue : {str(e)}"
