from django.urls import path
from . import nikto_views

urlpatterns = [

       path('rapports/nikto/<int:scan_id>/pdf/', nikto_views.nikto_report_pdf, name='nikto_report_pdf'),
]
