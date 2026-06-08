from django.urls import path
from . import sqlmap_views

urlpatterns = [

    path("rapports/sqlmap/<int:scan_id>/pdf/", sqlmap_views.sqlmap_report_pdf, name="sqlmap_report_pdf"),
]