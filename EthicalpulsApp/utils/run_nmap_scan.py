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

NMAP_PATH = shutil.which('nmap')
NMAP_TIMEOUT = getattr(settings, 'NMAP_TIMEOUT', 3600)

def is_root_user():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Pas de geteuid sur Windows ou certains environnements
        return False

def parse_nmap_xml(xml_output, target):
    try:
        root = ET.fromstring(xml_output)
        parsed_data = {
            'target': target,
            'os_detected': [],
            'os_accuracy': "0",
            'open_tcp_ports': [],
            'open_udp_ports': [],
            'service_details': [],
            'traceroute': [],
            'script_results': []
        }

        for os_match in root.findall(".//os/osmatch"):
            name = os_match.get('name', '')
            accuracy = os_match.get('accuracy', '0')
            parsed_data['os_detected'].append(f"{name} ({accuracy}%)")
            if int(accuracy) > int(parsed_data['os_accuracy']):
                parsed_data['os_accuracy'] = accuracy

        for port in root.findall(".//port"):
            state_elem = port.find('state')
            if state_elem is None:
                continue
            state = state_elem.get('state')
            if state == 'open':
                proto = port.get('protocol')
                portid = port.get('portid')
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else 'unknown'
                version = service_elem.get('version') if service_elem is not None else ''

                service_str = f"{portid}/{proto} - {service}"
                if version:
                    service_str += f" ({version})"

                if proto == 'tcp':
                    parsed_data['open_tcp_ports'].append(service_str)
                elif proto == 'udp':
                    parsed_data['open_udp_ports'].append(service_str)

                parsed_data['service_details'].append(service_str)

        for script in root.findall(".//script"):
            script_id = script.get('id', '')
            output = script.get('output', '')
            parsed_data['script_results'].append(f"{script_id}: {output}")

        for hop in root.findall(".//trace/hop"):
            ttl = hop.get('ttl', '')
            ipaddr = hop.get('ipaddr', '')
            rtt = hop.get('rtt', '')
            parsed_data['traceroute'].append(f"TTL {ttl}: {ipaddr} ({rtt}ms)")

        return parsed_data

    except ET.ParseError as e:
        logger.error(f"Erreur parsing XML Nmap : {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur inattendue parsing XML Nmap : {e}")
        return None

def build_nmap_command(target, option=None):
    if not NMAP_PATH:
        raise EnvironmentError("Nmap n'est pas trouvé sur le système")

    cmd = []

    # Liste des options qui nécessitent les droits root
    root_required_options = ['-sS', '-O', '--traceroute']

    option_str = option or ''
    needs_root = any(opt in option_str for opt in root_required_options)

    if needs_root and not is_root_user():
        logger.warning("Options Nmap nécessitent les privilèges root, mais le processus n'est pas root. Tentative d'exécution via sudo.")
        cmd.append('sudo')  # nécessite config sudoers sans mot de passe pour celery_user

    cmd.append(NMAP_PATH)

    if option:
        cmd.extend(option.split())
    else:
        cmd.extend(['-sS', '-sV', '-v'])

    cmd.extend([
        '-oX', '-',
        '--max-retries', '2',
        '--max-scan-delay', '20ms',
        str(target)
    ])

    logger.info(f"Commande Nmap construite: {' '.join(cmd)}")
    return cmd

@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(subprocess.TimeoutExpired,),
    retry_backoff=True,
    retry_jitter=True
)
def run_nmap_scan(self, scan_id, option):
    scan = None
    target = None
    command_str = None

    try:
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        if project.ip_address:
            target = project.ip_address
        elif project.domain:
            target = project.domain
        else:
            raise ValueError("Aucune cible valide (IP ou domaine) pour Nmap")

        option = option or '-sS -sV -v'

        cmd = build_nmap_command(target, option)
        command_str = ' '.join(cmd)

        scan.status = 'in_progress'
        scan.start_time = timezone.now()
        scan.save()

        logger.info(f"Exécution de la commande Nmap : {command_str}")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=NMAP_TIMEOUT
        )

        parsed_results = parse_nmap_xml(result.stdout, target)
        scan_success = (result.returncode == 0 and parsed_results is not None)

        NmapResult.objects.create(
            scan=scan,
            target=target,
            command_used=command_str,
            option=option,
            returncode=result.returncode,
            start_time=scan.start_time,
            end_time=timezone.now(),
            os_detected='\n'.join(parsed_results['os_detected']) if parsed_results else "",
            os_accuracy=parsed_results['os_accuracy'] if parsed_results else "0",
            traceroute='\n'.join(parsed_results['traceroute']) if parsed_results else "",
            script_results='\n'.join(parsed_results['script_results']) if parsed_results else "",
            full_output=result.stdout + "\n" + result.stderr,
            open_tcp_ports='\n'.join(parsed_results['open_tcp_ports']) if parsed_results else "",
            open_udp_ports='\n'.join(parsed_results['open_udp_ports']) if parsed_results else "",
            service_details='\n'.join(parsed_results['service_details']) if parsed_results else "",
            scan_status='finished' if scan_success else 'error',
            error_log=result.stderr if result.returncode != 0 else ""
        )

        scan.status = 'completed' if scan_success else 'failed'
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.save()

        if scan.created_by and scan.created_by.email:
            subject = f"[EthicalPulse] Scan Nmap terminé pour {project.name}"
            site_url = getattr(settings, 'SITE_URL', 'http://localhost:8001')
            web_url = f"{site_url}/scans/{scan.id}/"

            message = f"""
Bonjour {scan.created_by.username},

Le scan Nmap demandé pour le projet "{project.name}" est terminé.

Cible analysée : {target}
Option utilisée : {option}
Durée du scan : {scan.duration:.2f} secondes
Statut final : {scan.status.upper()}

Résumé :
- OS détectés : {len(parsed_results['os_detected']) if parsed_results else 0}
- Ports TCP ouverts : {len(parsed_results['open_tcp_ports']) if parsed_results else 0}
- Ports UDP ouverts : {len(parsed_results['open_udp_ports']) if parsed_results else 0}
- Services détectés : {len(parsed_results['service_details']) if parsed_results else 0}
- Scripts exécutés : {len(parsed_results['script_results']) if parsed_results else 0}

Consultez les résultats complets ici :
{web_url}

Merci de votre confiance,
L'équipe EthicalPulse
"""
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [scan.created_by.email],
                fail_silently=True
            )

        return scan_success

    except subprocess.TimeoutExpired:
        error_msg = f"Le scan Nmap a dépassé le délai de {NMAP_TIMEOUT} secondes"
        logger.error(error_msg)

        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.error_log = error_msg
            scan.save()

            NmapResult.objects.create(
                scan=scan,
                target=target or "",
                command_used=command_str or "",
                option=option or "",
                returncode=None,
                scan_status='error',
                error_log=error_msg
            )
        raise self.retry(countdown=300)

    except Exception as e:
        logger.exception(f"Erreur critique du scan Nmap : {e}")

        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.error_log = str(e)
            scan.save()

        raise
