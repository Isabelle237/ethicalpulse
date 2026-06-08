from django.urls import path
from . import zap_views

urlpatterns = [
        path('reports/zap/<int:scan_id>/pdf/', zap_views.zap_report_pdf, name='zap_report_pdf'),
]
