from django.urls import path
from . import sqlmap_views
urlpatterns = [    
  path('sqlmap/rapport/<int:scan_id>/pdf/', sqlmap_views.sqlmap_report_pdf, name='sqlmap_report_pdf'),
  path('scans/<int:scan_id>/rapport/sqlmap/', sqlmap_views.download_sqlmap_report, name='download_sqlmap_report'),

  ]