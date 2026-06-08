import json
import subprocess
import logging
import re
import sys
from celery import shared_task
from django.utils import timezone
from EthicalpulsApp.models import Scan, SqlmapResult, UserNotification

logger = logging.getLogger(__name__)

VALID_SQLMAP_OPTIONS = {
    "--level", "--risk", "--batch", "--random-agent", "--flush-session",
    "--timeout", "--retries", "--fresh-queries", "--tamper", "--technique",
    "--dbs", "--tables", "--columns", "--dump"
}

def build_sqlmap_command(target_url, option=None):
    sqlmap_path = "/app/sqlmap/sqlmap.py"
    cmd = [sys.executable, sqlmap_path, "-u", target_url]

    forced_options = [
        "--level=5", "--risk=3", "--batch", "--random-agent", "--flush-session",
        "--timeout=30", "--retries=3", "--fresh-queries"
    ]

    option_list = option.strip().split() if option else []
    filtered_options = []
    for opt in option_list:
        base_opt = opt.split("=")[0]
        if base_opt == "--disable-redirects":
            continue
        if base_opt in VALID_SQLMAP_OPTIONS and opt not in forced_options:
            filtered_options.append(opt)

    tamper_present = any(opt.startswith("--tamper=") for opt in filtered_options)
    if not tamper_present and any(x in option for x in ["--dump", "--dbs", "--technique"]):
        filtered_options.append("--tamper=space2comment")

    return cmd + forced_options + filtered_options

def parse_sqlmap_output(output):
    parsed = {
        "is_vulnerable": False,
        "injection_type": None,
        "dbms": None,
        "payloads": [],
        "vulnerabilities": [],
        "options_used": "",
        "techniques_used": "",
        "dbs_found": [],
        "tables_found": {},
        "columns_found": {},
        "data_dumped": {},
        "parameters": [],
        "critical": False,
        "raw_output": output,  # texte brut complet
    }
    lines = output.splitlines()
    current_db = None
    current_table = None
    i = 0
    while i < len(lines):
        line = lines[i]

        if "back-end DBMS" in line:
            parsed["dbms"] = line.split("is")[-1].strip(" .")
        if "Type:" in line:
            parsed["injection_type"] = line.split("Type:")[-1].strip()
            parsed["techniques_used"] = parsed["injection_type"]
        if "[PAYLOAD]" in line:
            payload = line.split("[PAYLOAD]")[-1].strip()
            if payload not in parsed["payloads"]:
                parsed["payloads"].append(payload)
        match_param = re.search(r"parameter '(\w+)' is vulnerable", line)
        if match_param:
            parsed["parameters"].append(match_param.group(1))
            parsed["is_vulnerable"] = True
            parsed["critical"] = True
            parsed["vulnerabilities"].append(line.strip())
        if "[CRITICAL]" in line or "[WARNING]" in line:
            parsed["vulnerabilities"].append(line.strip())
            if "[CRITICAL]" in line:
                parsed["critical"] = True
        if "[INFO]" in line and "available databases" in line:
            dbs, j = [], i + 1
            while j < len(lines) and lines[j].strip() and not lines[j].startswith("["):
                dbs.append(lines[j].strip())
                j += 1
            parsed["dbs_found"] = dbs
            i = j - 1
        if "[INFO]" in line and "tables found" in line:
            db_match = re.search(r"Database: (\w+)", line)
            if db_match:
                current_db = db_match.group(1)
                parsed["tables_found"][current_db] = []
                j = i + 1
                while j < len(lines) and lines[j].strip() and not lines[j].startswith("["):
                    parsed["tables_found"][current_db].append(lines[j].strip())
                    j += 1
                i = j - 1
        if "[INFO]" in line and "columns found" in line:
            table_match = re.search(r"Table: (\w+)", line)
            if table_match:
                current_table = table_match.group(1)
                parsed["columns_found"][current_table] = []
                j = i + 1
                while j < len(lines) and lines[j].strip() and not lines[j].startswith("["):
                    parsed["columns_found"][current_table].append(lines[j].strip())
                    j += 1
                i = j - 1
        if "[INFO]" in line and "entries" in line and "dumped" in line:
            table_match = re.search(r"Table: (\w+)", line)
            if table_match:
                current_table = table_match.group(1)
                parsed["data_dumped"][current_table] = []
                j = i + 1
                while j < len(lines) and lines[j].strip() and not lines[j].startswith("["):
                    parsed["data_dumped"][current_table].append(lines[j].strip())
                    j += 1
                i = j - 1

        i += 1

    return parsed

def notify_user(scan, message, level="info"):
    if scan.created_by:
        UserNotification.objects.create(
            user=scan.created_by, message=message, severity=level
        )
@shared_task(bind=True)
def run_sqlmap_scan(self, scan_id, option):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error(f"[SQLMAP] Scan avec ID {scan_id} introuvable.")
        return

    try:
        scan.status = "in_progress"
        scan.start_time = timezone.now()
        scan.save(update_fields=["status", "start_time"])

        target_url = scan.project.url or scan.project.domain or scan.project.ip_address
        if not target_url:
            raise ValueError("Aucune cible valide pour SQLMap.")

        cmd = build_sqlmap_command(target_url, option)
        logger.info(f"[SQLMAP] Exécution : {' '.join(cmd)}")

        start_exec = timezone.now()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        end_exec = timezone.now()

        if result.returncode != 0:
            scan.status = "failed"
            scan.error_log = result.stderr or result.stdout
            scan.end_time = end_exec
            scan.save(update_fields=["status", "error_log", "end_time"])
            logger.error(f"[SQLMAP] Échec du scan #{scan.id} : {scan.error_log}")
            return

        parsed = parse_sqlmap_output(result.stdout)

        SqlmapResult.objects.create(
            scan=scan,
            project=scan.project,
            raw_output=parsed["raw_output"],
            is_vulnerable=parsed["is_vulnerable"],
            injection_type=parsed["injection_type"],
            dbms=parsed["dbms"],
            payloads="\n".join(parsed["payloads"]) if parsed["payloads"] else None,
            dbs_found="\n".join(parsed["dbs_found"]) if parsed["dbs_found"] else None,
            tables_found=parsed["tables_found"] if parsed["tables_found"] else {},
            columns_found=parsed["columns_found"] if parsed["columns_found"] else {},
            data_dumped=parsed["data_dumped"] if parsed["data_dumped"] else {},
            options_used=option,
            techniques_used=parsed["techniques_used"] or None,
        )

        if parsed["critical"]:
            notify_user(scan, f"⚠️ Vulnérabilité critique détectée sur {target_url} lors du scan SQLMap #{scan.id}", level="critical")

        scan.duration = (end_exec - start_exec).total_seconds()
        scan.status = "completed"
        scan.end_time = end_exec
        scan.error_log = ""
        scan.save(update_fields=["status", "end_time", "duration", "error_log"])

        logger.info(f"[SQLMAP] Scan #{scan.id} terminé avec succès en {scan.duration:.2f}s.")

    except subprocess.TimeoutExpired:
        scan.status = "failed"
        scan.error_log = "Timeout : SQLMap a dépassé 900s."
        scan.end_time = timezone.now()
        scan.save(update_fields=["status", "error_log", "end_time"])
        logger.error(f"[SQLMAP] Timeout du scan #{scan.id} : SQLMap trop long.")

    except Exception as e:
        logger.exception(f"[SQLMAP] Erreur inconnue dans le scan #{scan.id}: {e}")
        scan.status = "error"
        scan.error_log = str(e)
        scan.end_time = timezone.now()
        scan.save(update_fields=["status", "error_log", "end_time"])
        notify_user(scan, f"❗ Erreur lors du scan SQLMap #{scan.id} : {str(e)}", level="error")
