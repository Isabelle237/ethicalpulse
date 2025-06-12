import os
import subprocess
import logging
import shutil
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from EthicalpulsApp.models import *

logger = logging.getLogger(__name__)

# Configuration Aircrack-ng
AIRCRACK_PATH = shutil.which(getattr(settings, 'AIRCRACK_PATH', 'aircrack-ng'))
AIRODUMP_PATH = shutil.which(getattr(settings, 'AIRODUMP_PATH', 'airodump-ng'))
AIREPLAY_PATH = shutil.which(getattr(settings, 'AIREPLAY_PATH', 'aireplay-ng'))
AIRCRACK_TIMEOUT = getattr(settings, 'AIRCRACK_TIMEOUT', 3600)

# Options disponibles pour Aircrack-ng
AIRCRACK_OPTION_MAP = {
    'scan': {
        'cmd': [AIRODUMP_PATH, '--output-format', 'csv'],
        'description': 'Scanner les réseaux WiFi'
    },
    'capture': {
        'cmd': [AIRODUMP_PATH, '--bssid', '{bssid}', '--channel', '{channel}', '--write', '{output}'],
        'description': 'Capturer le trafic'
    },
    'deauth': {
        'cmd': [AIREPLAY_PATH, '--deauth', '10', '-a', '{bssid}'],
        'description': 'Déauthentification'
    },
    'crack': {
        'cmd': [AIRCRACK_PATH, '-w', '{wordlist}', '{capfile}'],
        'description': 'Cracker une capture'
    }
}

def parse_aircrack_output(output, option):
    """Parse la sortie d'Aircrack-ng"""
    parsed = {
        "networks": [],
        "clients": [],
        "captured_handshakes": [],
        "cracked_passwords": [],
        "errors": []
    }

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if 'handshake' in line.lower():
            parsed["captured_handshakes"].append(line)
        elif 'key found' in line.lower():
            parsed["cracked_passwords"].append(line)
        elif 'bssid' in line.lower() and 'channel' in line.lower():
            parsed["networks"].append(line)
        elif 'station' in line.lower():
            parsed["clients"].append(line)
        elif any(err in line.lower() for err in ['failed', 'error', 'warning']):
            parsed["errors"].append(line)

    return parsed

@shared_task(bind=True)
def run_aircrack_scan(self, scan_id, option):
    """Exécute un scan Aircrack-ng"""
    scan = None
    temp_files = []
    try:
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        if not all([AIRCRACK_PATH, AIRODUMP_PATH, AIREPLAY_PATH]):
            raise FileNotFoundError("Outils Aircrack-ng non trouvés dans le PATH")

        if not project.mac_address:
            raise ValueError(f"Aucune adresse MAC définie pour le projet '{project.name}'")

        # Création du dossier temporaire
        output_dir = f"/tmp/aircrack_{scan_id}"
        os.makedirs(output_dir, exist_ok=True)
        temp_files.append(output_dir)

        scan.status = 'in_progress'
        scan.save()

        # Configuration de la commande
        cmd_config = AIRCRACK_OPTION_MAP.get(option)
        if not cmd_config:
            raise ValueError(f"Option invalide pour Aircrack-ng : {option}")

        cmd = cmd_config['cmd'].copy()
        # Remplacement des paramètres
        cmd = [arg.format(
            bssid=project.mac_address,
            channel='1',  # À adapter selon les besoins
            output=f"{output_dir}/capture",
            wordlist='/usr/share/wordlists/rockyou.txt',  # À adapter
            capfile=f"{output_dir}/capture-01.cap"
        ) for arg in cmd]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=AIRCRACK_TIMEOUT
            )
            output = result.stdout + "\n" + result.stderr
            scan_success = result.returncode == 0

        except subprocess.TimeoutExpired:
            output = f"Timeout après {AIRCRACK_TIMEOUT} secondes"
            scan_success = False

        # Analyse des résultats
        parsed = parse_aircrack_output(output, option)

        # Mise à jour du scan
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = 'completed' if scan_success else 'failed'
        scan.save()

        # Création du résultat
        AircrackngResult.objects.create(
            scan=scan,
            option=option,
            raw_output=output,
            target_mac=project.mac_address,
            networks_found="\n".join(parsed["networks"]),
            clients_found="\n".join(parsed["clients"]),
            handshakes_captured="\n".join(parsed["captured_handshakes"]),
            passwords_cracked="\n".join(parsed["cracked_passwords"]),
            errors="\n".join(parsed["errors"]),
            scan_completed=scan_success,
            total_networks=len(parsed["networks"]),
            total_clients=len(parsed["clients"]),
            total_handshakes=len(parsed["captured_handshakes"])
        )

        # Envoi d'email
        if scan.created_by and scan.created_by.email:
            subject = f"[EthicalPulse] Scan Aircrack-ng terminé pour {project.name}"
            message = (
                f"Le scan est terminé. Statut : {scan.status.upper()}\n"
                f"Durée : {scan.duration:.2f} secondes\n"
                f"Cible : {project.mac_address}\n"
                f"Option : {option}\n\n"
                f"Résumé :\n"
                f"- Réseaux trouvés : {len(parsed['networks'])}\n"
                f"- Clients : {len(parsed['clients'])}\n"
                f"- Handshakes capturés : {len(parsed['captured_handshakes'])}\n"
                f"- Mots de passe crackés : {len(parsed['cracked_passwords'])}\n"
                f"- Erreurs : {len(parsed['errors'])}"
            )
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [scan.created_by.email])

    except Exception as e:
        logger.exception(f"Erreur lors du scan Aircrack-ng : {e}")
        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        raise

    finally:
        # Nettoyage des fichiers temporaires
        for path in temp_files:
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    import shutil
                    shutil.rmtree(path)
            except Exception as e:
                logger.error(f"Erreur lors du nettoyage des fichiers temporaires : {e}")