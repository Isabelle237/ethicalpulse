import re
import subprocess
import logging
import shutil
import xml.etree.ElementTree as ET
import os
from datetime import datetime
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from EthicalpulsApp.models import NmapResult, Scan

logger = logging.getLogger(__name__)

NMAP_PATH = shutil.which("nmap")
NMAP_TIMEOUT = getattr(settings, "NMAP_TIMEOUT", 3600)


def is_root_user():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Pas de geteuid sur Windows ou certains environnements
        return False


def safe_get(elem, attr, default=""):
    if elem is not None and attr in elem.attrib:
        return elem.attrib[attr]
    return default


def parse_nmap_xml(xml_output, target):
    """Parse la sortie XML Nmap, retourne un dict complet et sécurisé."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.error(f"Erreur parsing XML Nmap : {e}")
        return None

    parsed_data = {
        "target": target,
        "os_detected": [],
        "os_accuracy": "0",
        "open_tcp_ports": [],
        "open_udp_ports": [],
        "service_details": [],
        "traceroute": [],
        "script_results": [],
    }

    # OS Detection
    for os_match in root.findall(".//os/osmatch"):
        name = safe_get(os_match, "name")
        accuracy = safe_get(os_match, "accuracy", "0")
        if name:
            parsed_data["os_detected"].append(f"{name} ({accuracy}%)")
            if int(accuracy) > int(parsed_data["os_accuracy"]):
                parsed_data["os_accuracy"] = accuracy

    # Ports
    for port in root.findall(".//port"):
        state_elem = port.find("state")
        if state_elem is None:
            continue
        state = safe_get(state_elem, "state")
        if state != "open":
            continue
        proto = safe_get(port, "protocol")
        portid = safe_get(port, "portid")
        service_elem = port.find("service")
        service_name = safe_get(service_elem, "name") if service_elem is not None else "unknown"
        version = safe_get(service_elem, "version") if service_elem is not None else ""
        service_str = f"{portid}/{proto} - {service_name}"
        if version:
            service_str += f" ({version})"

        if proto == "tcp":
            parsed_data["open_tcp_ports"].append(service_str)
        elif proto == "udp":
            parsed_data["open_udp_ports"].append(service_str)

        parsed_data["service_details"].append(service_str)

    # Script results
    for script in root.findall(".//script"):
        script_id = safe_get(script, "id")
        output = safe_get(script, "output")
        if script_id and output:
            parsed_data["script_results"].append(f"{script_id}: {output}")

    # Traceroute
    for hop in root.findall(".//trace/hop"):
        ttl = safe_get(hop, "ttl")
        ipaddr = safe_get(hop, "ipaddr")
        rtt = safe_get(hop, "rtt")
        if ttl and ipaddr and rtt:
            parsed_data["traceroute"].append(f"TTL {ttl}: {ipaddr} ({rtt}ms)")

    return parsed_data


def build_nmap_command(target, option=None):
    if not NMAP_PATH:
        raise EnvironmentError("Nmap n'est pas trouvé sur le système")

    cmd = []

    root_required_options = ["-sS", "-O", "--traceroute"]

    option_str = option or ""
    needs_root = any(opt in option_str for opt in root_required_options)

    if needs_root and not is_root_user():
        logger.warning(
            "Options Nmap nécessitent privilèges root, processus non root. Ajout de sudo."
        )
        cmd.append("sudo")  # sudoers doit permettre sans mdp

    cmd.append(NMAP_PATH)

    if option:
        # Gestion simple : découpe en arguments, attention options avec espaces ne sont pas supportées ici
        cmd.extend(option.split())
    else:
        cmd.extend(["-sS", "-sV", "-v"])

    cmd.extend(
        ["-oX", "-", "--max-retries", "2", "--max-scan-delay", "20ms", str(target)]
    )

    logger.info(f"Commande Nmap construite : {' '.join(cmd)}")
    return cmd


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(subprocess.TimeoutExpired,),
    retry_backoff=True,
    retry_jitter=True,
)
def run_nmap_scan(self, scan_id, option):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error(f"Scan Nmap avec id {scan_id} introuvable.")
        return False

    project = scan.project
    target = project.ip_address or project.domain
    if not target:
        logger.error(f"Scan #{scan_id} : Aucune cible valide (IP ou domaine)")
        scan.status = "failed"
        scan.error_log = "Aucune cible valide (IP ou domaine)"
        scan.save(update_fields=["status", "error_log"])
        return False

    option = option or "-sS -sV -v"
    cmd = build_nmap_command(target, option)
    command_str = " ".join(cmd)

    scan.status = "in_progress"
    scan.start_time = timezone.now()
    scan.progress = 0
    scan.error_log = ""
    scan.save(update_fields=["status", "start_time", "progress", "error_log"])

    logger.info(f"Début exécution Nmap : {command_str}")

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        output = ""
        stderr_output = ""
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                output += line
                # Extraction progression (exemple)
                match = re.search(r"(\d{1,3})\.\d+\% done", line)
                if match:
                    percent = int(match.group(1))
                    if percent > scan.progress:
                        scan.progress = min(percent, 95)
                        scan.save(update_fields=["progress"])

        # Récupération de stderr complet
        stderr_output = process.stderr.read()
        process.wait()

        parsed_results = parse_nmap_xml(output, target)

        if parsed_results is None:
            logger.warning(f"Scan #{scan_id} : Parsing XML a échoué.")
            scan.status = "failed"
            scan.error_log = "Parsing XML Nmap a échoué"
            scan.progress = 0
            scan.save(update_fields=["status", "error_log", "progress"])
            return False

        # Enregistrement du résultat en base, avec données JSON pour listes complexes
        NmapResult.objects.create(
            scan=scan,
            target=target,
            command_used=command_str,
            option=option,
            returncode=process.returncode,
            start_time=scan.start_time,
            end_time=timezone.now(),
            full_output=output,
            os_detected="\n".join(parsed_results["os_detected"]),
            os_accuracy=parsed_results.get("os_accuracy", "0"),
            traceroute="\n".join(parsed_results["traceroute"]),
            script_results="\n".join(parsed_results["script_results"]),
            open_tcp_ports="\n".join(parsed_results["open_tcp_ports"]),
            open_udp_ports="\n".join(parsed_results["open_udp_ports"]),
            service_details="\n".join(parsed_results["service_details"]),
            scan_status="finished" if process.returncode == 0 else "error",
            error_log=stderr_output if process.returncode != 0 else "",
        )

        scan.progress = 100
        scan.status = "completed" if process.returncode == 0 else "failed"
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.save(update_fields=["status", "end_time", "duration", "progress"])

        logger.info(
            f"Scan #{scan_id} terminé avec status {scan.status} en {scan.duration:.2f}s."
        )
        return scan.status == "completed"

    except subprocess.TimeoutExpired:
        logger.error(f"Scan #{scan_id} : Timeout dépassé ({NMAP_TIMEOUT}s)")
        scan.status = "failed"
        scan.error_log = f"Timeout dépassé ({NMAP_TIMEOUT}s)"
        scan.end_time = timezone.now()
        scan.save(update_fields=["status", "error_log", "end_time"])
        return False

    except Exception as e:
        logger.exception(f"Erreur inattendue durant scan #{scan_id} : {e}")
        scan.status = "failed"
        scan.error_log = str(e)
        scan.end_time = timezone.now()
        scan.save(update_fields=["status", "error_log", "end_time"])
        return False
