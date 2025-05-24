from django.urls import path
from . import run_nmap_views

urlpatterns = [
    path('report/<int:scan_id>/', run_nmap_views.download_nmap_report, name='download_nmap_report'),
]