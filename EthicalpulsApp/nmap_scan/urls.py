from django.urls import path
from . import run_nmap_views

urlpatterns = [
       path('reports/nmap/<int:scan_id>/pdf/', run_nmap_views.nmap_report_pdf, name='nmap_report_pdf'),
]
