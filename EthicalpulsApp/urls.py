from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),

    # Utilisateurs
    path('users/', views.create_user_view, name='users'),
    path('users/edit/<int:user_id>/', views.edit_user_view, name='edit_user'),
    path('users/delete/<int:user_id>/', views.delete_user_view, name='delete_user'),
    path('users/delete-multiple/', views.delete_multiple_users_view, name='delete_multiple_users'),

    # Page principale pour afficher et gérer les projets,
    path('projects/', views.admin_projets, name='admin_projets'),
    path('projets/chart/type/', views.projects_chart_type, name='projects_chart_type'),
    path('projets/chart/trend/', views.projects_chart_trend, name='projects_chart_trend'),
    
    # Scans
    path('scans/launch/', views.launch_scan, name='launch_scan'),  # Lancer un scan
    #relancer un scan
    path('scans/<int:scan_id>/delete/', views.delete_scan, name='delete_scan'),
    path('generate_scan_report/<int:scan_id>/', views.generate_scan_report, name='generate_scan_report'),
    path('vulnerabilities/filter/', views.vulnerabilities_filter, name='vulnerabilities_filter'),

    path('vulnerabilities/', views.vulnerabilities_view, name='vulnerabilities'),  # Liste des vulnérabilités
    path('scans/<int:scan_id>/relaunch/', views.relaunch_scan, name='relaunch_scan'),
    path('scans/schedule/', views.schedule_scan, name='schedule_scan'),
    # Outils
    path('tools/', views.tools, name='tools'),
    path('tools_admin/', views.tools_admin, name='tools_admin'),
    path('tools/create/', views.tools_create, name='tools_create'),
    path('tools/<int:tool_id>/edit/', views.tools_edit, name='tools_edit'),
    path('tools/<int:tool_id>/delete/', views.tools_delete, name='tools_delete'),
    path('tools/<int:tool_id>/run/', views.tools_run, name='tools_run'),

    # Remédiations
    path('remediation/', views.remediations, name='remediations'),
    path('remediations_admin/', views.remediations_admin, name='remediations_admin'),
    path('remediation/create/', views.remediations_create, name='remediations_create'),
    path('remediation/<int:remediation_id>/', views.remediation_detail, name='remediation_detail'),
    path('remediation/<int:remediation_id>/edit/', views.remediations_edit, name='remediations_edit'),
    path('remediation/<int:remediation_id>/delete/', views.remediations_delete, name='remediations_delete'),
    path('remediation/<int:remediation_id>/execute/', views.remediations_execute, name='remediations_execute'),

    # Configuration
    path('settings_admin/', views.settings_admin, name='settings_admin'),
    path('settings/', views.settings_users, name='settings_users'),
    path('logs/', views.logs, name='logs'),

    # Divers
    path('error/', views.errorPage, name='error'),
    path('history/', views.history, name='history'),
    path('reports/', views.report, name='reports'),
    path('training/', views.training, name='training'),
    path('analytics/', views.analytics, name='analytics'),

    # Authentification
    path('login/', views.email_login, name='login'),
    path('verify-otp/', views.otp_verification, name='verify_otp'),  # ✅ Corrigé ici
    path('logout/', views.logout_view, name='logout'),
]
