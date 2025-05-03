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

    # Projets
    path('projects/', views.projects, name='projects'),
    path('projects/create/', views.projects_create, name='projects_create'),
    path('projects/<int:project_id>/', views.project_detail, name='project_detail'),
    path('projects/<int:project_id>/edit/', views.projects_edit, name='projects_edit'),
    path('projects/<int:project_id>/delete/', views.projects_delete, name='projects_delete'),

    # Scans
    path('scans/', views.scans, name='scans'),
    path('scans_admin/', views.scans_admin, name='scans_admin'),
    path('scans/create/', views.scans_create, name='scans_create'),
    path('scans/<int:scan_id>/edit/', views.scans_edit, name='scans_edit'),
    path('scans/<int:scan_id>/delete/', views.scans_delete, name='scans_delete'),
    path('scans/<int:scan_id>/start/', views.scans_start, name='scans_start'),
    path('scans/<int:scan_id>/cancel/', views.scans_cancel, name='scans_cancel'),

    # Vulnérabilités
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('vulnerabilities_admin/', views.vulnerabilities_admin, name='vulnerabilities_admin'),
    path('vulnerabilities/create/', views.vulnerabilities_create, name='vulnerabilities_create'),
    path('vulnerabilities/<int:vuln_id>/edit/', views.vulnerabilities_edit, name='vulnerabilities_edit'),
    path('vulnerabilities/<int:vuln_id>/delete/', views.vulnerabilities_delete, name='vulnerabilities_delete'),

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
