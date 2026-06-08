from django.db.models import Count, Avg, F, Q, ExpressionWrapper, fields
from django.utils import timezone
from datetime import timedelta
from django.db.models.functions import TruncDate, Greatest
from ..models import (
    Scan,
    Project,
    NmapResult,
    NiktoResult,
    SqlmapResult,
    OwaspZapResult,
)


class AnalyticsService:
    @staticmethod
    def calculate_variations(current_metrics, previous_metrics):
        """Calcule les variations entre deux périodes"""
        return {
            "scan_count": (
                (
                    (
                        current_metrics["scan_metrics"]["total_count"]
                        - previous_metrics["scan_metrics"]["total_count"]
                    )
                    / previous_metrics["scan_metrics"]["total_count"]
                    * 100
                )
                if previous_metrics["scan_metrics"]["total_count"]
                else 0
            ),
            "finding_count": (
                (
                    (
                        current_metrics["finding_metrics"]["total_count"]
                        - previous_metrics["finding_metrics"]["total_count"]
                    )
                    / previous_metrics["finding_metrics"]["total_count"]
                    * 100
                )
                if previous_metrics["finding_metrics"]["total_count"]
                else 0
            ),
            "resolution_rate": (
                (
                    (
                        current_metrics["finding_metrics"].get("resolution_rate", 0)
                        - previous_metrics["finding_metrics"].get("resolution_rate", 0)
                    )
                )
                if previous_metrics["finding_metrics"].get("resolution_rate")
                else 0
            ),
            "avg_time_to_fix": (
                (
                    (
                        current_metrics["finding_metrics"].get("avg_time_to_fix", 0)
                        - previous_metrics["finding_metrics"].get("avg_time_to_fix", 0)
                    )
                    / previous_metrics["finding_metrics"].get("avg_time_to_fix", 1)
                    * 100
                )
                if previous_metrics["finding_metrics"].get("avg_time_to_fix")
                else 0
            ),
        }

    @staticmethod
    def get_analytics_data(start_date, end_date, project_id=None):
        """Récupère toutes les données analytiques (sans Vulnerability)"""
        base_filters = {"created_at__range": [start_date, end_date]}
        if project_id:
            base_filters["project_id"] = project_id

        scans = Scan.objects.filter(**base_filters)
        nmap_qs = NmapResult.objects.filter(
            scan__created_at__range=[start_date, end_date]
        )
        nikto_qs = NiktoResult.objects.filter(
            scan__created_at__range=[start_date, end_date]
        )
        sqlmap_qs = SqlmapResult.objects.filter(
            scan__created_at__range=[start_date, end_date]
        )
        zap_qs = OwaspZapResult.objects.filter(
            scan__created_at__range=[start_date, end_date]
        )
        if project_id:
            nmap_qs = nmap_qs.filter(scan__project_id=project_id)
            nikto_qs = nikto_qs.filter(scan__project_id=project_id)
            sqlmap_qs = sqlmap_qs.filter(project_id=project_id)
            zap_qs = zap_qs.filter(scan__project_id=project_id)

        # Métriques des scans
        scan_metrics = {
            "total_count": scans.count(),
            "trend_data": list(
                scans.annotate(date=TruncDate("created_at"))
                .values("date")
                .annotate(count=Count("id"))
                .order_by("date")
            ),
            "by_tool": list(
                scans.values("tool").annotate(count=Count("id")).order_by("-count")
            ),
            "success_rate": (
                (scans.filter(status="completed").count() / scans.count() * 100)
                if scans.exists()
                else 0
            ),
        }

        # Métriques findings (ZAP, Nikto, SQLMap)
        total_findings = (
            zap_qs.count()
            + nikto_qs.exclude(vulnerability__isnull=True).count()
            + sqlmap_qs.filter(is_vulnerable=True).count()
        )
        resolved = zap_qs.filter(
            status="resolved"
        ).count()  # à adapter selon ton modèle

        finding_metrics = {
            "total_count": total_findings,
            "resolution_rate": (
                (resolved / total_findings * 100) if total_findings else 0
            ),
            "avg_time_to_fix": None,  # À calculer si tu as les dates de résolution
            "by_severity": {
                "critical": zap_qs.filter(risk__iexact="Critical").count(),
                "high": zap_qs.filter(risk__iexact="High").count()
                + nikto_qs.filter(vulnerability__icontains="critique").count()
                + sqlmap_qs.filter(is_vulnerable=True).count(),
                "medium": zap_qs.filter(risk__iexact="Medium").count()
                + nikto_qs.filter(vulnerability__icontains="moyenne").count(),
                "low": zap_qs.filter(risk__iexact="Low").count()
                + nikto_qs.filter(vulnerability__icontains="faible").count(),
            },
            "by_status": {
                "open": zap_qs.filter(status="open").count(),
                "in_progress": zap_qs.filter(status="in_progress").count(),
                "resolved": zap_qs.filter(status="resolved").count(),
                "closed": zap_qs.filter(status="closed").count(),
            },
        }

        # Project metrics calculation
        project_metrics = {"labels": [], "data": [], "details": []}
        projects = Project.objects.filter(
            scans__created_at__range=[start_date, end_date]
        ).distinct()
        for project in projects:
            zap_count = OwaspZapResult.objects.filter(
                scan__project=project, scan__created_at__range=[start_date, end_date]
            ).count()
            nikto_count = (
                NiktoResult.objects.filter(
                    scan__project=project,
                    scan__created_at__range=[start_date, end_date],
                )
                .exclude(vulnerability__isnull=True)
                .count()
            )
            sqlmap_count = SqlmapResult.objects.filter(
                project=project,
                scan__created_at__range=[start_date, end_date],
                is_vulnerable=True,
            ).count()
            total = zap_count + nikto_count + sqlmap_count
            critical = OwaspZapResult.objects.filter(
                scan__project=project,
                risk="Critical",
                scan__created_at__range=[start_date, end_date],
            ).count()
            high = OwaspZapResult.objects.filter(
                scan__project=project,
                risk="High",
                scan__created_at__range=[start_date, end_date],
            ).count()
            project_metrics["labels"].append(project.name)
            project_metrics["data"].append(total)
            project_metrics["details"].append(
                {
                    "name": project.name,
                    "scan_count": project.scans.filter(
                        created_at__range=[start_date, end_date]
                    ).count(),
                    "finding_count": total,
                    "critical_count": critical,
                    "high_count": high,
                    "resolution_rate": 0,  # À calculer si tu as un champ de résolution
                }
            )

        return {
            "scan_metrics": scan_metrics,
            "finding_metrics": finding_metrics,
            "project_metrics": project_metrics,
        }

    @staticmethod
    def get_comparison_period(start_date, end_date):
        """Calcule la période précédente pour les comparaisons"""
        period_length = end_date - start_date
        previous_start = start_date - period_length
        previous_end = start_date - timedelta(days=1)
        return previous_start, previous_end
