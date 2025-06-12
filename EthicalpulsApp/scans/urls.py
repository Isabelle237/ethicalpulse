from django.urls import path
from . import scans_view


urlpatterns = [
    path('scans/', scans_view.scan_list, name='scan_list'),
    path('scans/active/', scans_view.active_scans, name='active_scans'),
    path('scans/completed/', scans_view.completed_scans, name='completed_scans'),
    path('scans/scheduled/', scans_view.scheduled_scans, name='scheduled_scans'),
    path('scans/templates/', scans_view.scan_templates, name='scan_templates'),
    
    # Actions sur les scans
    path('scans/<int:scan_id>/stop/', scans_view.stop_scan, name='stop_scan'),
    path('scans/<int:scan_id>/delete/', scans_view.delete_scan, name='delete_scan'),
    path('scans/<int:scan_id>/restart/', scans_view.restart_scan, name='restart_scan'),
     path('scans/<int:scan_id>/report/', 
         scans_view.scan_report, 
         name='scan_report'),
    # Scans planifiés
    path('scans/scheduled/create/', scans_view.create_scheduled_scan, name='create_scheduled_scan'),
    path('scans/scheduled/<int:scan_id>/edit/', scans_view.edit_scheduled_scan, name='edit_scheduled_scan'),
    path('scans/scheduled/<int:scan_id>/delete/', scans_view.delete_scheduled_scan, name='delete_scheduled_scan'),
    path('scans/scheduled/<int:scan_id>/toggle/', scans_view.toggle_scheduled_scan, name='toggle_scheduled_scan'),
    path('scans/scheduled/<int:scan_id>/run-now/', scans_view.run_scheduled_scan_now, name='run_scheduled_scan_now'),
    path('scans/scheduled/<int:scan_id>/data/', scans_view.get_scheduled_scan_data, name='get_scheduled_scan_data'),
]