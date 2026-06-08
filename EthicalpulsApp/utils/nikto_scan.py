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

from urllib.parse import urlparse

def clean_target_url(target):
    if not target:
        return None
    target = target.strip()
    for proto in ("http://", "https://"):
        while target.startswith(proto * 2):
            target = target[len(proto):]
    return target

from urllib.parse import urlparse

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
        "uri": None,
        "target_hostname": None,
        "target_port": 80,
    }

    # Remplissage port depuis target
    parsed_url = urlparse(target)
    parsed["target_port"] = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    parsed["target_hostname"] = parsed_url.hostname or target

    for line in output.splitlines():
        line = line.strip()
        lower_line = line.lower()

        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()

            if key == "server":
                parsed["server"] = val
            elif key == "x-powered-by":
                parsed["x_powered_by"] = val
            elif key == "x-frame-options":
                parsed["x_frame_options"] = val
            elif key == "link":
                parsed["link_headers"].append(line)
            elif key == "via":
                parsed["via_header"] = val
            elif key == "content-security-policy":
                parsed["content_security_policy"] = val
            elif key == "strict-transport-security":
                parsed["strict_transport_security"] = val
            elif key == "referrer-policy":
                parsed["referrer_policy"] = val
            elif key == "content-type":
                parsed["content_type"] = val
            elif key == "cache-control":
                parsed["cache_control"] = val
            elif key == "expires":
                parsed["expires"] = val
            elif key == "pragma":
                parsed["pragma"] = val
            elif key == "set-cookie":
                parsed["set_cookie"].append(line)
            elif key == "location":
                parsed["location_header"] = val
            elif key == "ssl subject":
                parsed["ssl_subject"] = val
            elif key == "ssl issuer":
                parsed["ssl_issuer"] = val
            elif key == "ssl altnames":
                parsed["ssl_altnames"] = val
            elif key == "ssl cipher":
                parsed["ssl_cipher"] = val
            elif key == "uri":
                parsed["uri"] = val
            elif key == "target host" or key == "host":
                parsed["target_hostname"] = val
            elif key == "target port" or key == "port":
                try:
                    parsed["target_port"] = int(val)
                except ValueError:
                    pass

        elif line.startswith("+") and not any(x in line.lower() for x in ["server", "nikto", "ssl"]):
            # Lignes vulnérabilités souvent avec +
            parsed["vulnerabilities"].append(line[1:].strip())

    # Si aucune vulnérabilité trouvée, message par défaut
    if not parsed["vulnerabilities"]:
        parsed["vulnerabilities"].append("Aucune vulnérabilité détectée")

    # Joindre les listes en chaînes
    for key in ["link_headers", "set_cookie", "vulnerabilities"]:
        parsed[key] = "\n".join(parsed[key]) if parsed[key] else "Non disponible"

    # Uri fallback
    if not parsed["uri"]:
        parsed["uri"] = f"http://{parsed['target_hostname']}:{parsed['target_port']}"

    return parsed

def send_scan_notification(scan, project, message, subject):
    if scan.created_by and scan.created_by.email:
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [scan.created_by.email],
                fail_silently=True,
            )
        except Exception as e:
            logger.error(f"Erreur envoi mail scan {scan.id} : {e}")



from urllib.parse import urlparse

from urllib.parse import urlparse


def build_nikto_command(target, option=None):
    parsed = urlparse(target)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme
    path = parsed.path if parsed.path else ""

    if not hostname:
        raise ValueError(f"Hostname non valide dans la cible : {target}")

    cmd = ["nikto", "-h", hostname, "-port", str(port)]

    if option == "-ssl" or port == 443:
        cmd.append("-ssl")
    elif option == "-nossl":
        cmd.append("-nossl")

    if option == "-Tuning 9":
        cmd.extend(["-Tuning", "9"])
    elif option == "-Tuning 4":
        cmd.extend(["-Tuning", "4"])
    elif option == "-Cgidirs all":
        cmd.extend(["-Cgidirs", "all"])

    cmd.extend(["-Display", "1234EP", "-nointeractive"])

    if path and path != "/":
        cmd.append(path)

    return cmd


NIKTO_TIMEOUT = getattr(settings, "NIKTO_TIMEOUT", 3600)  # 1 heure par défaut


logger = logging.getLogger(__name__)
NIKTO_TIMEOUT = getattr(settings, "NIKTO_TIMEOUT", 3600)  # 1h par défaut
from celery import shared_task
import subprocess
import logging
from django.utils import timezone
from urllib.parse import urlparse
from EthicalpulsApp.models import Scan, NiktoResult  # adapte selon tes imports

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def run_nikto_scan(self, scan_id, option):
    scan = None
    try:
        scan = Scan.objects.get(id=scan_id)
        project = scan.project
        raw_target = project.url or project.domain or str(project.ip_address)
        if not raw_target:
            raise ValueError("Aucune cible valide pour Nikto.")
        cleaned_target = clean_target_url(raw_target)

        cmd = build_nikto_command(cleaned_target, option)
        scan.status = "in_progress"
        scan.start_time = timezone.now()
        scan.save()

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=NIKTO_TIMEOUT,
            encoding="utf-8",
            errors="replace",
        )

        output = result.stdout + "\n" + result.stderr
        all_vulns = [
            line[1:].strip()
            for line in output.splitlines()
            if line.startswith("+") and not any(x in line.lower() for x in ["nikto", "server", "ssl"])
        ]

        scan_success = result.returncode == 0
        if not scan_success:
            # gérer erreurs et logs complémentaires
            pass

        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = "completed" if scan_success else "failed"
        scan.save()

        parsed = parse_nikto_output(output, cleaned_target)

        NiktoResult.objects.create(
            scan=scan,
            option=option or "",
            nikto_raw_output=output,
            vulnerability="\n".join(all_vulns or ["Aucune vulnérabilité détectée"]),
            description=output,
            uri=parsed.get("uri"),
            target_hostname=parsed.get("target_hostname"),
            target_port=parsed.get("target_port"),
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
            parsed_vulnerabilities=parsed.get("vulnerabilities"),
            scan_completed=scan_success,
            total_requests=len(all_vulns),
            percent_complete=100.0,
        )

        subject = f"[EthicalPulse] Scan Nikto terminé pour {project.name}"
        message = (
            f"Statut : {scan.status.upper()}.\n"
            f"Durée : {scan.duration:.2f} s.\n"
            f"Option : {option or 'Scan standard'}\n"
            f"Cible : {cleaned_target}\n\n"
            f"Résumé des vulnérabilités :\n{chr(10).join(all_vulns[:5] or ['Aucune détectée'])}"
        )
        send_scan_notification(scan, project, message, subject)
        return scan_success

    except subprocess.TimeoutExpired:
        if scan:
            scan.status = "failed"
            scan.end_time = timezone.now()
            scan.save()
        logger.error(f"Timeout Nikto pour scan {scan_id}")
        return False

    except Exception as e:
        logger.exception(f"Erreur Nikto pour scan {scan_id}: {e}")
        if scan:
            scan.status = "failed"
            scan.end_time = timezone.now()
            scan.save()
        return False