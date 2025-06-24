from django.urls import path
from . import vulnerability_views

urlpatterns = [
    path(
        "scans/launch/", vulnerability_views.launch_scan, name="launch_scan"
    ),  # Lancer un scan
    # relancer un scan
    path(
        "scans/<int:scan_id>/delete/",
        vulnerability_views.delete_scan,
        name="delete_scan",
    ),
    path(
        "generate_scan_report/<int:scan_id>/",
        vulnerability_views.generate_scan_report,
        name="generate_scan_report",
    ),
    path(
        "export_project_report/",
        vulnerability_views.export_project_report,
        name="export_project_report",
    ),
    path(
        "export_vulnerabilities/",
        vulnerability_views.export_vulnerabilities,
        name="export_vulnerabilities",
    ),
    path(
        "export_project_report_csv/",
        vulnerability_views.export_project_report_csv,
        name="export_project_report_csv",
    ),
    path(
        "import_project_report/",
        vulnerability_views.import_project_report,
        name="import_project_report",
    ),
    path(
        "admin/vulnerabilities/",
        vulnerability_views.vulnerabilities_dashboard,
        name="vulnerabilities",
    ),
    path(
        "scans/<int:scan_id>/relaunch/",
        vulnerability_views.relaunch_scan,
        name="relaunch_scan",
    ),
    # path('scans/schedule/', views.ScheduledScan, name='ScheduledScan'),
]
