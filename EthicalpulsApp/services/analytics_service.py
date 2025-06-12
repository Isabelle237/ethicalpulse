from django.db.models import Count, Avg, F, Q, ExpressionWrapper, fields
from django.utils import timezone
from datetime import timedelta
from django.db.models.functions import TruncDate, Greatest
from ..models import Scan, Vulnerability, Project

class AnalyticsService:
    @staticmethod
    def calculate_variations(current_metrics, previous_metrics):
        """Calcule les variations entre deux périodes"""
        return {
            'scan_count': ((current_metrics['scan_metrics']['total_count'] - 
                           previous_metrics['scan_metrics']['total_count']) / 
                          previous_metrics['scan_metrics']['total_count'] * 100) 
                          if previous_metrics['scan_metrics']['total_count'] else 0,
            
            'vuln_count': ((current_metrics['vuln_metrics']['total_count'] - 
                           previous_metrics['vuln_metrics']['total_count']) / 
                          previous_metrics['vuln_metrics']['total_count'] * 100)
                          if previous_metrics['vuln_metrics']['total_count'] else 0,
            
            'resolution_rate': ((current_metrics['vuln_metrics'].get('resolution_rate', 0) - 
                               previous_metrics['vuln_metrics'].get('resolution_rate', 0)))
                               if previous_metrics['vuln_metrics'].get('resolution_rate') else 0,
            
            'avg_time_to_fix': ((current_metrics['vuln_metrics'].get('avg_time_to_fix', 0) - 
                                previous_metrics['vuln_metrics'].get('avg_time_to_fix', 0)) / 
                               previous_metrics['vuln_metrics'].get('avg_time_to_fix', 1) * 100)
                               if previous_metrics['vuln_metrics'].get('avg_time_to_fix') else 0
        }

    @staticmethod
    def get_analytics_data(start_date, end_date, project_id=None):
        """Récupère toutes les données analytiques"""
        # Filtres de base
        base_filters = {'created_at__range': [start_date, end_date]}
        vuln_filters = {'discovered_at__range': [start_date, end_date]}
        
        if project_id:
            base_filters['project_id'] = project_id
            vuln_filters['scan__project_id'] = project_id

        # Récupération des données
        scans = Scan.objects.filter(**base_filters)
        vulnerabilities = Vulnerability.objects.filter(**vuln_filters)

        # Métriques des scans
        scan_metrics = {
            'total_count': scans.count(),
            'trend_data': list(
                scans.annotate(date=TruncDate('created_at'))
                .values('date')
                .annotate(count=Count('id'))
                .order_by('date')
            ),
            'by_tool': list(
                scans.values('tool')
                .annotate(count=Count('id'))
                .order_by('-count')
            ),
            'success_rate': (scans.filter(status='completed').count() / scans.count() * 100) 
                           if scans.exists() else 0
        }
        # Project metrics calculation
        project_metrics = {
            'labels': [],
            'data': [],
            'details': []
        }

        # Get projects with their metrics
        projects = Project.objects.filter(
            scans__created_at__range=[start_date, end_date]
        ).distinct().annotate(
            scan_count=Count('scans', filter=Q(scans__created_at__range=[start_date, end_date])),
            vuln_count=Count('scans__vulnerabilities', 
                            filter=Q(scans__created_at__range=[start_date, end_date])),
            critical_count=Count('scans__vulnerabilities',
                            filter=Q(scans__vulnerabilities__severity='critical',
                                    scans__created_at__range=[start_date, end_date])),
            high_count=Count('scans__vulnerabilities',
                            filter=Q(scans__vulnerabilities__severity='high',
                                scans__created_at__range=[start_date, end_date])),
            resolved_count=Count('scans__vulnerabilities',
                            filter=Q(scans__vulnerabilities__status__in=['resolved', 'closed'],
                                    scans__created_at__range=[start_date, end_date]))
        ).annotate(
            resolution_rate=ExpressionWrapper(
                (F('resolved_count') * 100.0) / Greatest(F('vuln_count'), 1),
                output_field=fields.FloatField()
            )
        ).order_by('-vuln_count')

        # Prepare project metrics data
        for project in projects:
            project_metrics['labels'].append(project.name)
            project_metrics['data'].append(project.vuln_count)
            project_metrics['details'].append({
                'name': project.name,
                'scan_count': project.scan_count,
                'vuln_count': project.vuln_count,
                'critical_count': project.critical_count,
                'high_count': project.high_count,
                'resolution_rate': project.resolution_rate
            })

        # Métriques des vulnérabilités
        vuln_metrics = {
            'total_count': vulnerabilities.count(),
            'resolution_rate': (vulnerabilities.filter(status__in=['resolved', 'closed']).count() / 
                              vulnerabilities.count() * 100) if vulnerabilities.exists() else 0,
            'avg_time_to_fix': vulnerabilities.filter(status='resolved')
                              .aggregate(avg_time=Avg('discovered_at'))['avg_time'],
            'by_severity': {
                'critical': vulnerabilities.filter(severity='critical').count(),
                'high': vulnerabilities.filter(severity='high').count(),
                'medium': vulnerabilities.filter(severity='medium').count(),
                'low': vulnerabilities.filter(severity='low').count()
            },
            'by_status': {
                'open': vulnerabilities.filter(status='open').count(),
                'in_progress': vulnerabilities.filter(status='in_progress').count(),
                'resolved': vulnerabilities.filter(status='resolved').count(),
                'closed': vulnerabilities.filter(status='closed').count()
            }
        }

        return {
            'scan_metrics': scan_metrics,
            'vuln_metrics': vuln_metrics,
            'project_metrics': project_metrics  # Added project metrics to returned data

        }
        

    @staticmethod
    def get_comparison_period(start_date, end_date):
        """Calcule la période précédente pour les comparaisons"""
        period_length = end_date - start_date
        previous_start = start_date - period_length
        previous_end = start_date - timedelta(days=1)
        return previous_start, previous_end