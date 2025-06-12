from django.urls import path
from . import vulnerability_views
urlpatterns = [
   path('scans/launch/', vulnerability_views.launch_scan, name='launch_scan'),  # Lancer un scan
    #relancer un scan
    path('scans/<int:scan_id>/delete/', vulnerability_views.delete_scan, name='delete_scan'),
    path('generate_scan_report/<int:scan_id>/', vulnerability_views.generate_scan_report, name='generate_scan_report'),
    path('vulnerabilities/filter/', vulnerability_views.vulnerabilities_filter, name='vulnerabilities_filter'),
    path('export_vulnerabilities/', vulnerability_views.export_vulnerabilities, name='export_vulnerabilities'),

    path('vulnerabilities/', vulnerability_views.vulnerabilities_view, name='vulnerabilities'),  # Liste des vulnérabilités
    path('scans/<int:scan_id>/relaunch/', vulnerability_views.relaunch_scan, name='relaunch_scan'),
    #path('scans/schedule/', views.ScheduledScan, name='ScheduledScan'),

  ]