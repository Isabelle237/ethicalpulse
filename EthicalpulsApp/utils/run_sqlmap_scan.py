import subprocess
import logging
from celery import shared_task
from django.utils import timezone
from EthicalpulsApp.models import Scan, SqlmapResult, Vulnerability, UserNotification

logger = logging.getLogger(__name__)

def build_sqlmap_command(target_url, option=None):
    cmd = ['sqlmap', '-u', target_url]
    if option:
        cmd += option.strip().split()
    # Ajout d'une option de log pour garder la sortie dans un fichier si besoin
    # cmd += ['--output-dir=/tmp/sqlmap_logs']
    return cmd

def parse_sqlmap_output(output):
    """
    Parsing enrichi de la sortie SQLMap pour extraire :
    - vulnérabilités
    - paramètres vulnérables
    - DBMS
    - payloads
    - bases, tables, colonnes, dumps
    """
    import re
    parsed = {
        'is_vulnerable': False,
        'injection_type': None,
        'dbms': None,
        'payloads': [],
        'vulnerabilities': [],
        'options_used': '',
        'techniques_used': '',
        'dbs_found': [],
        'tables_found': {},
        'columns_found': {},
        'data_dumped': {},
        'parameters': [],
        'critical': False,
    }
    lines = output.splitlines()
    current_db = None
    current_table = None

    for line in lines:
        # Détection DBMS
        if "back-end DBMS" in line:
            parsed['dbms'] = line.split("is")[1].strip().strip('.')
        # Détection type d'injection
        if "Type: " in line:
            parsed['injection_type'] = line.split("Type:")[1].strip()
        # Payloads
        if "[PAYLOAD]" in line:
            parsed['payloads'].append(line.split("[PAYLOAD]")[1].strip())
        # Paramètres vulnérables
        if re.search(r"parameter '(\w+)' is vulnerable", line):
            param = re.findall(r"parameter '(\w+)' is vulnerable", line)[0]
            parsed['parameters'].append(param)
            parsed['is_vulnerable'] = True
            parsed['critical'] = True
            parsed['vulnerabilities'].append(line.strip())
        # Vulnérabilités critiques ou warnings
        if "[CRITICAL]" in line or "[WARNING]" in line:
            parsed['vulnerabilities'].append(line.strip())
            if "[CRITICAL]" in line:
                parsed['critical'] = True
        # Extraction des bases de données
        if "[INFO]" in line and "available databases" in line:
            dbs = []
            idx = lines.index(line) + 1
            while idx < len(lines) and lines[idx].strip() and not lines[idx].startswith("["):
                dbs.append(lines[idx].strip())
                idx += 1
            parsed['dbs_found'] = dbs
        # Extraction des tables
        if "[INFO]" in line and "tables found" in line:
            m = re.search(r"Database: (\w+)", line)
            if m:
                current_db = m.group(1)
                parsed['tables_found'][current_db] = []
            idx = lines.index(line) + 1
            while idx < len(lines) and lines[idx].strip() and not lines[idx].startswith("["):
                if current_db:
                    parsed['tables_found'][current_db].append(lines[idx].strip())
                idx += 1
        # Extraction des colonnes
        if "[INFO]" in line and "columns found" in line:
            m = re.search(r"Table: (\w+)", line)
            if m:
                current_table = m.group(1)
                parsed['columns_found'][current_table] = []
            idx = lines.index(line) + 1
            while idx < len(lines) and lines[idx].strip() and not lines[idx].startswith("["):
                if current_table:
                    parsed['columns_found'][current_table].append(lines[idx].strip())
                idx += 1
        # Extraction des dumps de données
        if "[INFO]" in line and "entries" in line and "dumped" in line:
            m = re.search(r"Table: (\w+)", line)
            if m:
                current_table = m.group(1)
                parsed['data_dumped'][current_table] = []
            idx = lines.index(line) + 1
            while idx < len(lines) and lines[idx].strip() and not lines[idx].startswith("["):
                if current_table:
                    parsed['data_dumped'][current_table].append(lines[idx].strip())
                idx += 1

    return parsed

def notify_user(scan, message):
    """Envoie une notification à l'utilisateur si vulnérabilité critique"""
    if scan.created_by:
        UserNotification.objects.create(
            user=scan.created_by,
            message=message
        )

@shared_task(bind=True)
def run_sqlmap_scan(self, scan_id, option):
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'in_progress'
        scan.start_time = timezone.now()
        scan.save()

        target_url = scan.project.url or scan.project.domain or scan.project.ip_address
        if not target_url:
            raise ValueError("Aucune cible valide pour SQLMap.")

        cmd = build_sqlmap_command(target_url, option)
        logger.info(f"[SQLMAP] Exécution : {' '.join(cmd)}")

        start_exec = timezone.now()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        end_exec = timezone.now()
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode

        if returncode != 0:
            scan.status = 'failed'
            scan.error_log = stderr
            scan.end_time = end_exec
            scan.save(update_fields=['status', 'error_log', 'end_time'])
            logger.error(f"[SQLMAP] Échec du scan #{scan.id} : {stderr}")
            # Fonctionnalité 1 : Relance automatique une fois si échec
            if not hasattr(scan, 'retried'):
                scan.retried = True
                logger.warning(f"[SQLMAP] Relance automatique du scan #{scan.id}")
                run_sqlmap_scan.apply_async((scan_id, option), countdown=10)
            return

        parsed = parse_sqlmap_output(stdout)

        # Enregistrement du résultat principal
        sqlmap_result = SqlmapResult.objects.create(
            scan=scan,
            project=scan.project,
            raw_output=stdout,
            is_vulnerable=parsed['is_vulnerable'],
            injection_type=parsed['injection_type'],
            dbms=parsed['dbms'],
            payloads='\n'.join(parsed['payloads']),
            dbs_found='\n'.join(parsed['dbs_found']),
            tables_found=parsed['tables_found'],
            columns_found=parsed['columns_found'],
            data_dumped=parsed['data_dumped'],
            options_used=' '.join(cmd),
            techniques_used=parsed['injection_type'],
        )

        # Fonctionnalité 2 : Enregistrement détaillé des vulnérabilités individuelles
        for vuln in parsed['vulnerabilities']:
            Vulnerability.objects.create(
                scan=scan,
                name="Injection SQL",
                description=vuln,
                severity='critical' if parsed['critical'] else ('high' if parsed['is_vulnerable'] else 'medium'),
                target_url=target_url,
                technique=parsed['injection_type'],
                dbms=parsed['dbms'],
                status='open',
            )

        # Fonctionnalité 3 : Notification utilisateur si vulnérabilité critique
        if parsed['critical']:
            notify_user(scan, f"⚠️ Vulnérabilité critique détectée sur {target_url} lors du scan SQLMap #{scan.id}")

        # Fonctionnalité 4 : Sauvegarde du temps d'exécution
        scan.duration = (end_exec - start_exec).total_seconds()
        scan.status = 'completed'
        scan.end_time = end_exec
        scan.save(update_fields=['status', 'end_time', 'duration'])
        logger.info(f"[SQLMAP] Scan #{scan.id} terminé avec succès en {scan.duration:.2f}s.")

    except subprocess.TimeoutExpired:
        msg = "Timeout : SQLMap a dépassé 900s."
        scan.status = 'failed'
        scan.error_log = msg
        scan.end_time = timezone.now()
        scan.save(update_fields=['status', 'error_log', 'end_time'])
        logger.error(f"[SQLMAP] Timeout du scan #{scan.id} : {msg}")

    except Exception as e:
        logger.exception(f"[SQLMAP] Erreur inconnue dans le scan #{scan.id}")
        if 'scan' in locals():
            scan.status = 'error'
            scan.error_log = str(e)
            scan.end_time = timezone.now()
            scan.save(update_fields=['status', 'error_log', 'end_time'])