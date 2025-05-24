import os
import subprocess
import logging
import shutil
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from EthicalpulsApp.models import ReconngResult, Scan

logger = logging.getLogger(__name__)

# Configuration Recon-ng
RECONNG_PATH = shutil.which(getattr(settings, 'RECONNG_PATH', 'recon-ng'))
RECONNG_TIMEOUT = getattr(settings, 'RECONNG_TIMEOUT', 3600)  # 1 heure par défaut

# Options disponibles pour Recon-ng avec leurs commandes
RECONNG_OPTION_MAP = {
    'whois': ['recon/domains-contacts/whois_pocs'],
    'subdomains': ['recon/domains-hosts/bing_domain_web',
                  'recon/domains-hosts/google_site_web'],
    'dns': ['recon/domains-hosts/brute_hosts',
            'recon/domains-hosts/dns_brute'],
    'email': ['recon/contacts-credentials/hibp_breach'],
    'social': ['recon/profiles-contacts/linkedin_auth'],
    'vulns': ['recon/hosts-vulnerabilities/ssl_scan',
              'recon/hosts-vulnerabilities/web_vulns']
}

def parse_reconng_output(output, target):
    """Parse la sortie de Recon-ng"""
    parsed = {
        "target": target,
        "findings": [],
        "contacts": [],
        "hosts": [],
        "vulnerabilities": [],
        "errors": []
    }

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Parse les différents types de résultats
        if '[*]' in line:  # Information
            parsed["findings"].append(line)
        elif '[+]' in line:  # Succès
            if 'host' in line.lower():
                parsed["hosts"].append(line)
            elif 'contact' in line.lower():
                parsed["contacts"].append(line)
            elif any(vuln in line.lower() for vuln in ['vulnerability', 'vuln', 'cve']):
                parsed["vulnerabilities"].append(line)
        elif '[-]' in line:  # Erreur
            parsed["errors"].append(line)

    return parsed

@shared_task(bind=True)
def run_reconng_scan(self, scan_id, option):
    """Exécute un scan Recon-ng"""
    scan = None
    try:
        scan = Scan.objects.get(id=scan_id)
        project = scan.project

        if not RECONNG_PATH:
            raise FileNotFoundError("Recon-ng non trouvé dans le PATH")

        target = project.domain
        if not target:
            raise ValueError(f"Aucun domaine défini pour le projet '{project.name}'")

        # Création du workspace
        workspace_name = f"ethicalpulse_{scan_id}"
        
        # Configuration de la commande
        base_cmd = [RECONNG_PATH, '-w', workspace_name]
        modules = RECONNG_OPTION_MAP.get(option, [])
        if not modules:
            raise ValueError(f"Option invalide pour Recon-ng : {option}")

        scan.status = 'in_progress'
        scan.save()

        full_output = ""
        for module in modules:
            cmd = base_cmd + ['-m', module, '-o', f"TARGET={target}", '--no-analytics']
            
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=RECONNG_TIMEOUT
                )
                output = result.stdout + "\n" + result.stderr
                full_output += f"\n--- Module {module} ---\n{output}"

            except subprocess.TimeoutExpired:
                error_msg = f"Timeout pour le module {module} après {RECONNG_TIMEOUT} secondes"
                logger.error(error_msg)
                full_output += f"\n[ERROR] {error_msg}"
                continue

        # Analyse des résultats
        parsed = parse_reconng_output(full_output, target)
        scan_success = len(parsed["errors"]) == 0

        # Mise à jour du scan
        scan.end_time = timezone.now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.status = 'completed' if scan_success else 'failed'
        scan.save()

        # Création du résultat
        ReconngResult.objects.create(
            scan=scan,
            option=option,
            raw_output=full_output,
            target_domain=target,
            hosts_found="\n".join(parsed["hosts"]),
            contacts_found="\n".join(parsed["contacts"]),
            vulnerabilities_found="\n".join(parsed["vulnerabilities"]),
            errors="\n".join(parsed["errors"]),
            findings="\n".join(parsed["findings"]),
            total_hosts=len(parsed["hosts"]),
            total_contacts=len(parsed["contacts"]),
            total_vulnerabilities=len(parsed["vulnerabilities"]),
            scan_completed=scan_success
        )

        # Envoi d'email de notification
        if scan.created_by and scan.created_by.email:
            subject = f"[EthicalPulse] Scan Recon-ng terminé pour {project.name}"
            message = (
                f"Le scan est terminé. Statut : {scan.status.upper()}\n"
                f"Durée : {scan.duration:.2f} secondes\n"
                f"Domaine cible : {target}\n"
                f"Option utilisée : {option}\n\n"
                f"Résumé :\n"
                f"- Hôtes trouvés : {len(parsed['hosts'])}\n"
                f"- Contacts trouvés : {len(parsed['contacts'])}\n"
                f"- Vulnérabilités : {len(parsed['vulnerabilities'])}\n"
                f"- Erreurs : {len(parsed['errors'])}"
            )
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [scan.created_by.email])

    except Exception as e:
        logger.exception(f"Erreur lors du scan Recon-ng : {e}")
        if scan:
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        raise

    finally:
        # Nettoyage du workspace
        try:
            subprocess.run([RECONNG_PATH, '-w', workspace_name, '-C', 'workspaces remove'])
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage du workspace : {e}")