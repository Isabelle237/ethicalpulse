from venv import logger
import logging
from django.utils import timezone

from EthicalpulsApp.utils.run_aircrack_scan import run_aircrack_scan
logger = logging.getLogger(__name__)
from EthicalpulsApp.models import *
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from django.db import transaction


def handle_netcat_scan(project, option, target_port, request):
    """Gère le lancement d'un scan Netcat"""
    try:
        # Validation des options
        valid_options = [opt[0] for opt in NetcatResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Netcat : '{option}'")

        # Validation du port pour l'option -lvp
        if option == '-lvp' and not target_port.isdigit():
            raise ValueError("Port invalide pour l'écoute Netcat.")

        # Création du scan
        scan_instance = Scan.objects.create(
            project=project,
            tool='NETCAT',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        # Lancement du scan en arrière-plan
        transaction.on_commit(lambda: run_netcat_scan.delay(
            scan_instance.id, 
            option,
            target_port=target_port if target_port else None
        ))

        return True, f"Scan Netcat lancé pour le projet '{project.name}' avec l'option '{option}'"
    except ValueError as e:
        return False, str(e)
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan Netcat : {e}")
        return False, f"Erreur inattendue : {str(e)}"
