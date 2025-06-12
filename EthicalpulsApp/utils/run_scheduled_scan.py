from EthicalpulsApp.models import ScheduledScan
from celery import shared_task
from django.utils.timezone import now
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import subprocess
import time
import logging
from zapv2 import ZAPv2
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ScanExecutor:
    def __init__(self, scan, target_url: str):
        self.scan = scan
        self.target_url = target_url
        self.start_time = now()

    def execute_zap_scan(self) -> Dict[str, Any]:
        try:
            zap = ZAPv2(
                apikey=settings.ZAP_API_KEY,
                proxies={'http': settings.ZAP_PROXY, 'https': settings.ZAP_PROXY}
            )

            # Attente de la disponibilité de ZAP
            self._wait_for_zap(zap)
            
            # Lance le scan
            zap.urlopen(self.target_url)
            time.sleep(2)
            
            # Configuration du scan
            scan_id = zap.ascan.scan(
                self.target_url,
                recurse=True,
                in_scope_only=True
            )
            
            # Surveille la progression
            self._monitor_zap_progress(zap, scan_id)
            
            # Récupère et traite les résultats
            return self._process_zap_results(zap)

        except Exception as e:
            logger.error(f"Erreur ZAP: {str(e)}", exc_info=True)
            raise

    def execute_sqlmap_scan(self) -> Dict[str, Any]:
        try:
            command = [
                'sqlmap',
                '-u', self.target_url,
                '--batch',
                '--risk=3',
                '--level=5',
                '--threads=4',
                '--random-agent',
                '--output-dir=/tmp/sqlmap'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            return self._process_sqlmap_results(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("SQLMap timeout")
            raise
        except Exception as e:
            logger.error(f"Erreur SQLMap: {str(e)}", exc_info=True)
            raise

    def execute_nmap_scan(self) -> Dict[str, Any]:
        try:
            command = [
                'nmap',
                '-sV', '-sC', '-O',
                '-Pn', '-T4',
                '--script=vuln',
                self.scan.project.ip_address
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            return self._process_nmap_results(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Nmap timeout")
            raise
        except Exception as e:
            logger.error(f"Erreur Nmap: {str(e)}", exc_info=True)
            raise

    def _wait_for_zap(self, zap: ZAPv2, max_attempts: int = 30) -> None:
        for attempt in range(max_attempts):
            try:
                if zap.core.version:
                    return
            except:
                time.sleep(2)
        raise Exception("ZAP API non disponible après 60 secondes")

    def _monitor_zap_progress(self, zap: ZAPv2, scan_id: str) -> None:
        while int(zap.ascan.status(scan_id)) < 100:
            progress = int(zap.ascan.status(scan_id))
            self.scan.progress = progress
            self.scan.save(update_fields=['progress'])
            time.sleep(5)

    def _process_zap_results(self, zap: ZAPv2) -> Dict[str, Any]:
        from EthicalpulsApp.models import Vulnerability
        
        alerts = zap.core.alerts(baseurl=self.target_url)
        vulnerabilities = []

        for alert in alerts:
            vuln = Vulnerability.objects.create(
                scan=self.scan,
                name=alert.get('alert', 'Unknown'),
                description=alert.get('description', ''),
                severity=self._normalize_severity(alert.get('risk', 'Medium')),
                target_url=alert.get('url', self.target_url),
                remediation=alert.get('solution', ''),
                parameter=alert.get('param', ''),
                evidence=alert.get('evidence', ''),
                cve_id=alert.get('cweid', ''),
                status='open',
                discovered_at=now()
            )
            vulnerabilities.append(vuln)

        return {
            'count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

    def _normalize_severity(self, severity: str) -> str:
        severity_map = {
            'informational': 'Info',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Critical'
        }
        return severity_map.get(severity.lower(), 'Medium')

@shared_task(name='run_scheduled_scan')
def run_scheduled_scan(scheduled_scan_id: int) -> str:
    from EthicalpulsApp.models import ScheduledScan, Scan
    
    try:
        scheduled_scan = ScheduledScan.objects.select_related('target').get(id=scheduled_scan_id)
        
        if not scheduled_scan.is_active:
            logger.info(f"Scan {scheduled_scan_id} est désactivé")
            return "Scan désactivé"

        scan = Scan.objects.create(
            name=scheduled_scan.name,
            project=scheduled_scan.target,
            tool=scheduled_scan.tool.upper(),
            created_by=scheduled_scan.created_by,
            scheduled_scan=scheduled_scan,
            status='in_progress',
            start_time=now()
        )

        # Met à jour le scan planifié
        scheduled_scan.last_run = now()
        scheduled_scan.next_run_time = scheduled_scan.calculate_next_run()
        scheduled_scan.save(update_fields=['last_run', 'next_run_time'])

        # Planifie le prochain scan si nécessaire
        if scheduled_scan.is_active and scheduled_scan.next_run_time:
            run_scheduled_scan.apply_async(
                args=[scheduled_scan.id],
                eta=scheduled_scan.next_run_time
            )

        # Notification email
        if scheduled_scan.email_notification:
            _send_scan_notification(scheduled_scan, 'started')

        # Exécute le scan
        executor = ScanExecutor(scan, scheduled_scan.target.url)
        tool_method = getattr(executor, f'execute_{scheduled_scan.tool.lower()}_scan')
        results = tool_method()

        # Met à jour le scan
        scan.status = 'completed'
        scan.end_time = now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.save()

        # Notification de fin
        if scheduled_scan.email_notification:
            _send_scan_notification(scheduled_scan, 'completed', results)

        return f"Scan {scheduled_scan.tool} terminé avec {results['count']} vulnérabilités"

    except Exception as e:
        logger.error(f"Erreur lors du scan {scheduled_scan_id}: {str(e)}", exc_info=True)
        if 'scan' in locals():
            scan.status = 'failed'
            scan.error_log = str(e)
            scan.save()
            if scheduled_scan.email_notification:
                _send_scan_notification(scheduled_scan, 'failed', error=str(e))
        return f"Erreur: {str(e)}"

def _send_scan_notification(scan: 'ScheduledScan', status: str, results: Optional[Dict] = None, error: Optional[str] = None) -> None:
    subject = f'Scan planifié {scan.name} - {status.title()}'
    
    message = f"""
    Scan: {scan.name}
    Projet: {scan.target.name}
    Outil: {scan.get_tool_display()}
    Status: {status.title()}
    """

    if results:
        message += f"\nVulnérabilités trouvées: {results['count']}"
    
    if error:
        message += f"\nErreur: {error}"

    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [scan.created_by.email],
        fail_silently=True
    )