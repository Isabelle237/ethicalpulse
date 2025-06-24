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
        "target_port": 443 if "https" in target.lower() else 80,
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
                ("ssl_cipher", r"Cipher:\s*([^;]+)"),
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
        elif line.startswith("+") and not any(
            x in line.lower() for x in ["server", "nikto"]
        ):
            parsed["vulnerabilities"].append(line[1:].strip())
        elif line.lower().startswith("uri:"):
            parsed["uri"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("target host:") or line.lower().startswith(
            "host:"
        ):
            parsed["target_hostname"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("target port:") or line.lower().startswith(
            "port:"
        ):
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


def clean_target_url(target):
    """
    Nettoie la cible pour enlever les doublons de protocoles (http://, https://) et espaces.
    Retourne une URL ou un hostname propre.
    """
    if not target:
        return None
    target = target.strip()
    while any(target.startswith(proto * 2) for proto in ("http://", "https://")):
        for proto in ("http://", "https://"):
            double_proto = proto * 2
            if target.startswith(double_proto):
                target = target[len(proto) :]
    return target


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

        # Récupérer et nettoyer la cible
        raw_target = project.url or project.domain or str(project.ip_address)
        if not raw_target:
            raise ValueError("Aucune cible valide pour Nikto.")
        cleaned_target = clean_target_url(raw_target)

        # Construire la commande Nikto
        cmd = build_nikto_command(cleaned_target, option)

        scan.status = "in_progress"
        scan.start_time = timezone.now()
        scan.save()

        command_str = " ".join(cmd)
        logger.info(f"Commande Nikto : {command_str}")
        full_output = (
            f"--- Scan Nikto sur {cleaned_target} ---\nCommande : {command_str}\n"
        )

        try:
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
            full_output += output

            all_vulns = [
                line[1:].strip()
                for line in output.splitlines()
                if line.startswith("+")
                and not any(x in line.lower() for x in ["nikto", "server", "ssl"])
            ]

            scan_success = result.returncode == 0
            if not scan_success:
                full_output += f"\n[!] Code d'erreur Nikto : {result.returncode}\n"

        except subprocess.TimeoutExpired:
            scan_success = False
            full_output += f"\n[!] Timeout après {NIKTO_TIMEOUT} secondes."
            all_vulns = ["Timeout atteint"]

        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = "completed" if scan_success else "failed"
        scan.save()

        parsed = parse_nikto_output(full_output, cleaned_target)

        NiktoResult.objects.create(
            scan=scan,
            option=option or "",
            nikto_raw_output=full_output,
            vulnerability="\n".join(all_vulns or ["Aucune vulnérabilité détectée"]),
            description=full_output,
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

    except Exception as e:
        logger.exception(f"Erreur Nikto pour le scan {scan_id}: {e}")
        if scan:
            scan.status = "failed"
            scan.end_time = timezone.now()
            scan.save()
        raise
