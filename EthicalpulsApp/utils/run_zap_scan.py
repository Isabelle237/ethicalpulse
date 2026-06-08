import json
import logging
import time
from celery import shared_task
from zapv2 import ZAPv2
from django.utils.timezone import now
from EthicalpulsApp.models import Scan, OwaspZapResult

logger = logging.getLogger(__name__)


def parse_zap_alert(alert):
    risk_map = {
        "high": "Critique",
        "medium": "Élevée",
        "low": "Moyenne",
        "informational": "Information",
        "info": "Information",
    }

    risk_raw = alert.get("risk", "").lower()
    risk = risk_map.get(risk_raw, "Information")

    return {
        "url": alert.get("url", ""),
        "risk": risk,
        "vulnerability": alert.get("alert", "Vulnérabilité détectée"),
        "description": alert.get("description", "").strip(),
        "evidence": alert.get("evidence", "").strip() or None,
        "recommendation": alert.get("solution", "").strip(),
    }


@shared_task
def run_zap_scan(scan_id, option=None):
    try:
        scan = Scan.objects.get(id=scan_id)
        target_url = scan.project.url
        if not target_url:
            raise ValueError("Le projet n'a pas d'URL définie.")

        zap = ZAPv2(
            apikey="620tjnb5od0ef8tep7n78usun",
            proxies={"http": "http://zap:8086", "https": "http://zap:8086"},
        )

        # Vérifie si ZAP est prêt
        for _ in range(30):
            try:
                if zap.core.version:
                    break
            except Exception:
                time.sleep(2)
        else:
            scan.status = "failed"
            scan.error_log = "L'API ZAP n'est pas disponible."
            scan.save()
            return

        logger.info(f"[ZAP] Début du scan avec option {option} sur {target_url}")
        zap.urlopen(target_url)
        time.sleep(2)

        # Exclusion fichiers lourds
        zap.spider.exclude_from_scan(".*\\.(mp4|zip|png|jpg|jpeg|gif|svg)$")
        zap.ascan.exclude_from_scan(".*\\.(mp4|zip|png|jpg|jpeg|gif|svg)$")

        # Paramétrage optionnel : taille max réponse
        zap.core.set_option_max_response_body_size(100000000)

        # Exécution des modules selon l'option choisie
        if option == "-ajax":
            zap.ajaxSpider.scan(target_url)
            while zap.ajaxSpider.status == 'running':
                time.sleep(5)

        elif option == "-quickurl":
            zap.spider.scan(target_url)
            time.sleep(3)
            while int(zap.spider.status) < 100:
                time.sleep(3)
            zap.ascan.scan(target_url)

        elif option == "-full":
            zap.spider.scan(target_url)
            while int(zap.spider.status) < 100:
                time.sleep(3)
            zap.ajaxSpider.scan(target_url)
            while zap.ajaxSpider.status == 'running':
                time.sleep(5)
            zap.ascan.scan(target_url)

        elif option in ["-xss", "-sqli"]:
            zap.spider.scan(target_url)
            while int(zap.spider.status) < 100:
                time.sleep(3)
            zap.ascan.scan(target_url)

        else:
            # fallback scan
            zap.spider.scan(target_url)
            while int(zap.spider.status) < 100:
                time.sleep(3)
            zap.ascan.scan(target_url)

        # Attendre la fin du Active Scan
        while int(zap.ascan.status) < 100:
            time.sleep(5)

        # Récupération des alertes
        alerts = zap.core.alerts(baseurl=target_url)
        scan.raw_output = json.dumps(alerts, ensure_ascii=False, indent=2)
        scan.save()

        # Nettoyage anciens résultats
        OwaspZapResult.objects.filter(scan=scan).delete()

        # Enregistrement des vulnérabilités filtrées
        for alert in alerts:
            alert_name = alert.get("alert", "").lower()

            if option == "-xss" and "xss" not in alert_name:
                continue
            if option == "-sqli" and "sql" not in alert_name:
                continue

            parsed = parse_zap_alert(alert)
            OwaspZapResult.objects.create(
                scan=scan,
                option=option or "-quickurl",
                **parsed
            )

        scan.status = "completed"
        scan.end_time = now()
        scan.duration = (scan.end_time - scan.start_time).total_seconds()
        scan.save()
        logger.info(f"[ZAP] Scan terminé pour {target_url}")

    except Exception as e:
        logger.error(f"Erreur dans run_zap_scan: {e}", exc_info=True)
        scan.status = "failed"
        scan.error_log = str(e)
        scan.save()
