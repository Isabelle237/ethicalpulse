from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils import run_beef_scan, run_sqlmap_scan
from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction


def handle_sqlmap_scan(project, option, request):
    """Gère le lancement d'un scan SQLMap"""
    try:
        valid_options = [opt[0] for opt in SqlmapResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour SQLMap : '{option}'")

        if not project.url:
            raise ValueError(f"Aucune URL définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='SQLMAP',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_sqlmap_scan.delay(scan_instance.id, option))
        return True, f"Scan SQLMap lancé pour le projet '{project.name}'"
    except ValueError as e:
        return False, str(e)
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan SQLMap : {e}")
        return False, f"Erreur inattendue : {str(e)}"
