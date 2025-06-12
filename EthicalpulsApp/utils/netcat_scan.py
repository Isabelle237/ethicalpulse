import os
import shutil
import subprocess
import logging
import re
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from EthicalpulsApp.models import NetcatResult, Scan

logger = logging.getLogger(__name__)

# Configuration Netcat
NETCAT_PATH = shutil.which(getattr(settings, 'NETCAT_PATH', 'nc'))
NETCAT_TIMEOUT = getattr(settings, 'NETCAT_TIMEOUT', 300)  # 5 minutes

# Options disponibles pour Netcat avec leurs arguments
NETCAT_OPTION_MAP = {
    '-lvp': ['-lvp'],  # Listener
    '-v': ['-v'],      # Connexion verbose
    '-z': ['-z'],      # Scanner de ports
    '-e': ['-e'],      # Exécution
    '-u': ['-u'],      # Mode UDP
}

def parse_netcat_output(output, target):
    """Parse la sortie de Netcat."""
    parsed = {
        "target": target,
        "ports": [],
        "connections": [],
        "errors": [],
        "status": "completed",
        "details": []
    }

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Parse les connexions
        if "connect to" in line.lower():
            parsed["connections"].append(line)
        # Parse les ports ouverts
        elif "open" in line.lower():
            try:
                port = re.search(r"port (\d+)", line)
                if port:
                    parsed["ports"].append(int(port.group(1)))
            except ValueError:
                continue
        # Parse les erreurs
        elif any(err in line.lower() for err in ["failed", "error", "refused"]):
            parsed["errors"].append(line)
        # Autres détails
        else:
            parsed["details"].append(line)

    return parsed

@shared_task(bind=True)
def run_netcat_scan(self, scan_id, option, target_port=None):
    scan = None
    try:
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        if not NETCAT_PATH:
            raise FileNotFoundError("Netcat (nc) non trouvé dans le PATH")

        # Validation de l'option
        if option and option not in NETCAT_OPTION_MAP:
            raise ValueError(f"Option Netcat invalide : '{option}'")

        # Détermination de la cible
        target = project.ip_address or project.domain
        if not target:
            raise ValueError("Aucune cible valide (IP ou domaine) spécifiée")

        scan.status = 'in_progress'
        scan.start_time = timezone.now()
        scan.save()

        # Construction de la commande Netcat
        cmd = [NETCAT_PATH]
        if option:
            cmd.extend(NETCAT_OPTION_MAP[option])

        # Ajout des paramètres spécifiques selon l'option
        if option == '-lvp':
            if not target_port:
                target_port = 4444  # Port par défaut pour l'écoute
            cmd.append(str(target_port))
        elif option == '-z':
            cmd.extend(['-v', target])
            if target_port:
                if '-' in str(target_port):  # Plage de ports
                    start, end = map(int, target_port.split('-'))
                    cmd.extend([str(start), str(end)])
                else:
                    cmd.append(str(target_port))
        else:
            cmd.extend([target, str(target_port or 80)])

        logger.info(f"Exécution de la commande Netcat : {' '.join(cmd)}")
        full_output = f"--- Scan Netcat sur {target} ---\nCommande : {' '.join(cmd)}\n"

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=NETCAT_TIMEOUT
            )
            output = result.stdout + "\n" + result.stderr
            full_output += output

            scan_success = result.returncode == 0
            if not scan_success:
                logger.warning(f"Netcat a retourné un code non nul ({result.returncode})")
                full_output += f"\n[!] Attention : Scan terminé avec code {result.returncode}\n"

        except subprocess.TimeoutExpired:
            scan_success = False
            msg = f"[!] Timeout : le scan Netcat a dépassé {NETCAT_TIMEOUT} secondes."
            logger.error(msg)
            full_output = msg

        # Mise à jour du scan
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = 'completed' if scan_success else 'failed'
        scan.save()

        # Parsing et sauvegarde des résultats
        parsed = parse_netcat_output(full_output, target)

        # Création du résultat
        NetcatResult.objects.create(
            scan=scan,
            option=option or "",
            target=target,
            port=target_port or 0,
            raw_output=full_output,
            parsed_output="\n".join(parsed["details"]),
            open_ports=",".join(map(str, parsed["ports"])),
            connections="\n".join(parsed["connections"]),
            errors="\n".join(parsed["errors"]),
            status=scan.status,
            success=scan_success
        )

        # Envoi d'email si configuré
        if scan.user and scan.user.email:
            subject = f"[EthicalPulse] Scan Netcat terminé pour {scan.project.name}"
            message = (
                f"Le scan est terminé. Statut : {scan.status.upper()}.\n"
                f"Durée : {scan.duration:.2f} secondes.\n"
                f"Option utilisée : {option or 'Scan standard'}\n"
                f"Cible : {target}\n"
                f"Port(s) : {target_port or 'N/A'}\n\n"
                f"Ports ouverts :\n{', '.join(map(str, parsed['ports'])) or 'Aucun'}"
            )
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [scan.user.email])

    except Exception as e:
        logger.exception(f"[!] Échec du scan Netcat : {e}")
        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        raise