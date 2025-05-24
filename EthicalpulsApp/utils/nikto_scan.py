import os
import shutil
import subprocess
import logging
import re
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from EthicalpulsApp.models import NiktoResult, Scan

logger = logging.getLogger(__name__)


def parse_nikto_output(output, target):
    parsed = {
        "server": "Non disponible",
        "ssl_subject": "Non disponible",
        "ssl_issuer": "Non disponible",
        "ssl_altnames": "Non disponible",
        "ssl_cipher": "Non disponible",
        "x_powered_by": "Non disponible",
        "x_frame_options": "Non disponible",
        "link_headers": [],
        "via_header": "Non disponible",
        "content_security_policy": "Non disponible",
        "strict_transport_security": "Non disponible",
        "referrer_policy": "Non disponible",
        "content_type": "Non disponible",
        "cache_control": "Non disponible",
        "expires": "Non disponible",
        "pragma": "Non disponible",
        "set_cookie": [],
        "location_header": "Non disponible",
        "vulnerabilities": [],
        "uri": f"http://{target}",
        "target_hostname": target,
        "target_port": 443 if "https" in target.lower() else 80
    }

    for line in output.splitlines():
        line = line.strip()
        if re.match(r"Server:", line, re.I):
            parsed["server"] = line.split(":", 1)[1].strip()
        elif "SSL Info:" in line:
            for key, pattern in [
                ("ssl_subject", r"Subject:\s*([^;]+)"),
                ("ssl_issuer", r"Issuer:\s*([^;]+)"),
                ("ssl_altnames", r"AltNames:\s*([^;]+)"),
                ("ssl_cipher", r"Cipher:\s*([^;]+)")
            ]:
                match = re.search(pattern, line)
                if match:
                    parsed[key] = match.group(1).strip()
        elif re.match(r"X-Powered-By:", line, re.I):
            parsed["x_powered_by"] = line.split(":", 1)[1].strip()
        elif re.match(r"X-Frame-Options:", line, re.I):
            parsed["x_frame_options"] = line.split(":", 1)[1].strip()
        elif re.match(r"Link:", line, re.I):
            parsed["link_headers"].append(line)
        elif re.match(r"Via:", line, re.I):
            parsed["via_header"] = line.split(":", 1)[1].strip()
        elif re.match(r"Content-Security-Policy:", line, re.I):
            parsed["content_security_policy"] = line.split(":", 1)[1].strip()
        elif re.match(r"Strict-Transport-Security:", line, re.I):
            parsed["strict_transport_security"] = line.split(":", 1)[1].strip()
        elif re.match(r"Referrer-Policy:", line, re.I):
            parsed["referrer_policy"] = line.split(":", 1)[1].strip()
        elif re.match(r"Content-Type:", line, re.I):
            parsed["content_type"] = line.split(":", 1)[1].strip()
        elif re.match(r"Cache-Control:", line, re.I):
            parsed["cache_control"] = line.split(":", 1)[1].strip()
        elif re.match(r"Expires:", line, re.I):
            parsed["expires"] = line.split(":", 1)[1].strip()
        elif re.match(r"Pragma:", line, re.I):
            parsed["pragma"] = line.split(":", 1)[1].strip()
        elif re.match(r"Set-Cookie:", line, re.I):
            parsed["set_cookie"].append(line)
        elif re.match(r"Location:", line, re.I):
            parsed["location_header"] = line.split(":", 1)[1].strip()
        elif line.startswith('+') and not any(x in line.lower() for x in ['server', 'nikto']):
            parsed["vulnerabilities"].append(line[1:].strip())
        elif line.lower().startswith("uri:"):
            parsed["uri"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("target host:") or line.lower().startswith("host:"):
            parsed["target_hostname"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("target port:") or line.lower().startswith("port:"):
            port_str = line.split(":", 1)[1].strip()
            try:
                parsed["target_port"] = int(port_str)
            except ValueError:
                pass

    if not parsed["vulnerabilities"]:
        parsed["vulnerabilities"].append("Aucune vulnérabilité détectée")

    for key in ["link_headers", "set_cookie", "vulnerabilities"]:
        parsed[key] = "\n".join(parsed[key]) if parsed[key] else "Non disponible"

    if not parsed["uri"]:
        parsed["uri"] = f"http://{parsed['target_hostname']}:{parsed['target_port']}"

    return parsed


def send_scan_notification(scan, project, message, subject):
    """Helper function to send scan notifications with error handling"""
    if scan.created_by and scan.created_by.email:
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [scan.created_by.email],
                fail_silently=True  # Don't raise exceptions on email failures
            )
        except Exception as e:
            logger.error(f"Échec de l'envoi de l'email pour le scan {scan.id}: {str(e)}")


def build_nikto_command(target, option=None):
    """Construit la commande Nikto comme on la taperait dans le terminal"""

    # Enlever le protocole s'il existe déjà
    if target.startswith('http://'):
        target = target[len('http://'):]
    elif target.startswith('https://'):
        target = target[len('https://'):]

    cmd = ['nikto', '-h', target]

    # Choix du port selon option
    if option == '-ssl':
        port = 443
        cmd.append('-ssl')
    else:
        port = 80
        if option == '-nossl':
            cmd.append('-nossl')

    cmd.extend(['-port', str(port)])

    # Options spécifiques
    if option == '-Tuning 9':
        cmd.extend(['-Tuning', '9'])
    elif option == '-Tuning 4':
        cmd.extend(['-Tuning', '4'])
    elif option == '-Cgidirs all':
        cmd.extend(['-Cgidirs', 'all'])

    # Options communes (sans -Format txt, pour éviter l'erreur de fichier de sortie)
    cmd.extend([
        '-Display', '1234EP',  # Afficher erreurs/progrès
        '-nointeractive'       # Mode non interactif
    ])

    return cmd

NIKTO_TIMEOUT = getattr(settings, 'NIKTO_TIMEOUT', 3600)  # 1 heure par défaut


logger = logging.getLogger(__name__)
NIKTO_TIMEOUT = getattr(settings, 'NIKTO_TIMEOUT', 3600)  # 1h par défaut

@shared_task(bind=True)
def run_nikto_scan(self, scan_id, option):
    """Exécute un scan Nikto et enregistre les résultats"""
    scan = None
    try:
        # Récupération du scan et du projet
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        # Sélection de la cible
        target = project.url or project.domain or str(project.ip_address)
        if not target:
            raise ValueError("Aucune cible valide pour Nikto.")

        # Validation de l'option
        valid_options = [opt[0] for opt in NiktoResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Nikto : {option}")

        # Construction de la commande
        cmd = build_nikto_command(target, option)

        # Mise à jour du scan
        scan.status = 'in_progress'
        scan.start_time = timezone.now()
        scan.save()

        command_str = ' '.join(cmd)
        logger.info(f"Commande Nikto : {command_str}")
        full_output = f"--- Scan Nikto sur {target} ---\nCommande : {command_str}\n"

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=NIKTO_TIMEOUT,
                encoding='utf-8'
            )
            output = result.stdout + "\n" + result.stderr
            full_output += output

            all_vulns = [
                line[1:].strip() for line in output.splitlines()
                if line.startswith('+') and not any(x in line.lower() for x in ['nikto', 'server'])
            ]
            scan_success = result.returncode == 0
            if not scan_success:
                logger.warning(f"Nikto a retourné un code non nul ({result.returncode})")
                full_output += f"\n[!] Attention : Le scan a retourné un code d'erreur {result.returncode}\n"
        except subprocess.TimeoutExpired:
            scan_success = False
            msg = f"[!] Timeout : le scan Nikto a dépassé {NIKTO_TIMEOUT} secondes."
            logger.error(msg)
            full_output = msg
            all_vulns = ["Scan interrompu - Timeout"]

        # Mise à jour du scan après exécution
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = 'completed' if scan_success else 'failed'
        scan.save()

        # Parsing et enregistrement du résultat
        parsed = parse_nikto_output(full_output, target)

        NiktoResult.objects.create(
            scan=scan,
            option=option or "",
            nikto_raw_output=full_output,
            vulnerability="\n".join(all_vulns or ["Aucune vulnérabilité détectée"]),
            description=full_output,
            uri=parsed.get("uri", f"http://{target}"),
            target_hostname=parsed.get("target_hostname", target),
            target_port=parsed.get("target_port", 443 if option == '-ssl' else 80),
            server=parsed.get("server"),
            ssl_subject=parsed.get("ssl_subject"),
            ssl_issuer=parsed.get("ssl_issuer"),
            ssl_altnames=parsed.get("ssl_altnames"),
            ssl_cipher=parsed.get("ssl_cipher"),
            x_powered_by=parsed.get("x_powered_by"),
            x_frame_options=parsed.get("x_frame_options"),
            link_headers=parsed.get("link_headers"),
            via_header=parsed.get("via_header"),
            content_security_policy=parsed.get("content_security_policy"),
            strict_transport_security=parsed.get("strict_transport_security"),
            referrer_policy=parsed.get("referrer_policy"),
            content_type=parsed.get("content_type"),
            cache_control=parsed.get("cache_control"),
            expires=parsed.get("expires"),
            pragma=parsed.get("pragma"),
            set_cookie=parsed.get("set_cookie"),
            location_header=parsed.get("location_header"),
            parsed_vulnerabilities=parsed.get("vulnerabilities", "Aucune vulnérabilité"),
            scan_completed=scan_success,
            total_requests=len(all_vulns),
            percent_complete=100.0
        )

        # Envoi de la notification
        subject = f"[EthicalPulse] Scan Nikto terminé pour {project.name}"
        message = (
            f"Le scan est terminé. Statut : {scan.status.upper()}.\n"
            f"Durée : {scan.duration:.2f} secondes.\n"
            f"Option utilisée : {option or 'Scan standard'}\n"
            f"Cible : {target}\n\n"
            f"Résumé des vulnérabilités :\n{chr(10).join(all_vulns[:5] or ['Aucune vulnérabilité détectée'])}"
        )
        send_scan_notification(scan, project, message, subject)

        return scan_success

    except Exception as e:
        logger.exception(f"[!] Échec du scan Nikto : {e}")
        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        raise

    """Exécute un scan Nikto et enregistre les résultats"""
    scan = None
    try:
        # Récupération du scan et du projet
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        # Sélection de la cible
        target = None
        if project.url:
            target = project.url
        elif project.domain:
            target = project.domain
        elif project.ip_address:
            target = str(project.ip_address)

        if not target:
            raise ValueError("Aucune cible valide pour Nikto.")

        # Validation de l'option
        valid_options = [opt[0] for opt in NiktoResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Nikto : {option}")

        # Construction de la commande
        cmd = build_nikto_command(target, option)
        
        # Mise à jour du statut initial
        scan.status = 'in_progress'
        scan.start_time = timezone.now()
        scan.save()

        # Log de la commande
        command_str = ' '.join(cmd)
        logger.info(f"Commande Nikto : {command_str}")
        full_output = f"--- Scan Nikto sur {target} ---\nCommande : {command_str}\n"

        try:
            # Exécution du scan
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=NIKTO_TIMEOUT,
                encoding='utf-8'
            )
            output = result.stdout + "\n" + result.stderr
            full_output += output

            # Extraction des vulnérabilités
            all_vulns = [
                line[1:].strip() for line in output.splitlines()
                if line.startswith('+') and not any(x in line.lower() for x in ['nikto', 'server'])
            ]

            scan_success = result.returncode == 0
            if not scan_success:
                logger.warning(f"Nikto a retourné un code non nul ({result.returncode})")
                full_output += f"\n[!] Attention : Le scan a retourné un code d'erreur {result.returncode}\n"

        except subprocess.TimeoutExpired:
            scan_success = False
            msg = f"[!] Timeout : le scan Nikto a dépassé {NIKTO_TIMEOUT} secondes."
            logger.error(msg)
            full_output = msg
            all_vulns = ["Scan interrompu - Timeout"]

        # Mise à jour du scan
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = 'completed' if scan_success else 'failed'
        scan.save()

        # Parsing et sauvegarde des résultats
        parsed = parse_nikto_output(full_output, target)
        
        # Création du résultat détaillé
        NiktoResult.objects.create(
            scan=scan,
            option=option or "",
            nikto_raw_output=full_output,
            vulnerability="\n".join(all_vulns or ["Aucune vulnérabilité détectée"]),
            description=full_output,
            uri=parsed.get("uri", f"http://{target}"),
            target_hostname=parsed.get("target_hostname", target),
            target_port=parsed.get("target_port", 443 if option == '-ssl' else 80),
            server=parsed.get("server"),
            ssl_subject=parsed.get("ssl_subject"),
            ssl_issuer=parsed.get("ssl_issuer"),
            ssl_altnames=parsed.get("ssl_altnames"),
            ssl_cipher=parsed.get("ssl_cipher"),
            x_powered_by=parsed.get("x_powered_by"),
            x_frame_options=parsed.get("x_frame_options"),
            link_headers=parsed.get("link_headers"),
            via_header=parsed.get("via_header"),
            content_security_policy=parsed.get("content_security_policy"),
            strict_transport_security=parsed.get("strict_transport_security"),
            referrer_policy=parsed.get("referrer_policy"),
            content_type=parsed.get("content_type"),
            cache_control=parsed.get("cache_control"),
            expires=parsed.get("expires"),
            pragma=parsed.get("pragma"),
            set_cookie=parsed.get("set_cookie"),
            location_header=parsed.get("location_header"),
            parsed_vulnerabilities=parsed.get("vulnerabilities", "Aucune vulnérabilité"),
            scan_completed=scan_success,
            total_requests=len(all_vulns),
            percent_complete=100.0
        )

        # Préparation et envoi de la notification
        subject = f"[EthicalPulse] Scan Nikto terminé pour {project.name}"
        message = (
            f"Le scan est terminé. Statut : {scan.status.upper()}.\n"
            f"Durée : {scan.duration:.2f} secondes.\n"
            f"Option utilisée : {option or 'Scan standard'}\n"
            f"Cible : {target}\n\n"
            f"Résumé des vulnérabilités :\n{chr(10).join(all_vulns[:5] or ['Aucune vulnérabilité détectée'])}"
        )
        send_scan_notification(scan, project, message, subject)

        return scan_success

    except Exception as e:
        logger.exception(f"[!] Échec du scan Nikto : {e}")
        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        raise
    scan = None
    try:
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        # Sélection de la cible
        target = None
        if project.url:
            target = project.url
        elif project.domain:
            target = project.domain
        elif project.ip_address:
            target = str(project.ip_address)

        if not target:
            raise ValueError("Aucune cible valide pour Nikto.")

        # Construction de la commande
        cmd = build_nikto_command(target, option)
        
        # Log de la commande exacte
        command_str = ' '.join(cmd)
        logger.info(f"Commande Nikto : {command_str}")
        full_output = f"--- Scan Nikto sur {target} ---\nCommande : {' '.join(cmd)}\n"

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1200,
                encoding='utf-8'
            )
            output = result.stdout + "\n" + result.stderr
            full_output += output

            # Extraction des vulnérabilités
            all_vulns = [
                line[1:].strip() for line in output.splitlines()
                if line.startswith('+') and not any(x in line.lower() for x in ['nikto', 'server'])
            ]

            scan_success = result.returncode == 0
            if not scan_success:
                logger.warning(f"Nikto a retourné un code non nul ({result.returncode})")
                full_output += f"\n[!] Attention : Le scan a retourné un code d'erreur {result.returncode}\n"

        except subprocess.TimeoutExpired:
            scan_success = False
            msg = f"[!] Timeout : le scan Nikto a dépassé {NIKTO_TIMEOUT} secondes."
            logger.error(msg)
            full_output = msg
            all_vulns = ["Scan interrompu - Timeout"]

        # Mise à jour du scan
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = 'completed' if scan_success else 'failed'
        scan.save()

        # Parsing et sauvegarde des résultats
        parsed = parse_nikto_output(full_output, target)
        
        # Création du résultat
        NiktoResult.objects.create(
            scan=scan,
            option=option or "",
            nikto_raw_output=full_output,
            vulnerability="\n".join(all_vulns or ["Aucune vulnérabilité détectée"]),
            description=full_output,
            uri=parsed.get("uri", f"http://{target}"),
            target_hostname=parsed.get("target_hostname", target),
            target_port=parsed.get("target_port", 443 if option == '-ssl' else 80),
            server=parsed.get("server"),
            ssl_subject=parsed.get("ssl_subject"),
            ssl_issuer=parsed.get("ssl_issuer"),
            ssl_altnames=parsed.get("ssl_altnames"),
            ssl_cipher=parsed.get("ssl_cipher"),
            x_powered_by=parsed.get("x_powered_by"),
            x_frame_options=parsed.get("x_frame_options"),
            link_headers=parsed.get("link_headers"),
            via_header=parsed.get("via_header"),
            content_security_policy=parsed.get("content_security_policy"),
            strict_transport_security=parsed.get("strict_transport_security"),
            referrer_policy=parsed.get("referrer_policy"),
            content_type=parsed.get("content_type"),
            cache_control=parsed.get("cache_control"),
            expires=parsed.get("expires"),
            pragma=parsed.get("pragma"),
            set_cookie=parsed.get("set_cookie"),
            location_header=parsed.get("location_header"),
            parsed_vulnerabilities=parsed.get("vulnerabilities", "Aucune vulnérabilité"),
            scan_completed=scan_success,
            total_requests=len(all_vulns),
            percent_complete=100.0
        )

        # Envoi d'email
        subject = f"[EthicalPulse] Scan Nikto terminé pour {project.name}"
        message = (
            f"Le scan est terminé. Statut : {scan.status.upper()}.\n"
            f"Durée : {scan.duration:.2f} secondes.\n"
            f"Option utilisée : {option or 'Scan standard'}\n"
            f"Cible : {target}\n\n"
            f"Résumé des vulnérabilités :\n{chr(10).join(all_vulns[:5] or ['Aucune vulnérabilité détectée'])}"
        )
        send_scan_notification(scan, project, message, subject)

    except Exception as e:
        logger.exception(f"[!] Échec du scan Nikto : {e}")
        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        raise