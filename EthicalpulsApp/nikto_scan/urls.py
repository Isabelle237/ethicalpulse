from django.urls import path
from . import nikto_views

urlpatterns = [
 path('admin/scan/<int:scan_id>/', nikto_views.scan_result_detail, name='scan_result_detail'),
path('download-nikto-report/<int:scan_id>/', nikto_views.download_nikto_report, name='download_nikto_report'),
   
    ]