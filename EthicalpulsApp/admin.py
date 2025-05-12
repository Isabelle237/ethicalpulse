from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'username', 'role', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('role', 'is_active', 'is_staff')
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Informations personnelles', {'fields': ('role',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'role', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser')}
        ),
    )
    search_fields = ('email', 'username')
    ordering = ('email',)

admin.site.register(CustomUser, CustomUserAdmin)


class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'project_type', 'created_at', 'updated_at')
    search_fields = ('name', 'description', 'domain', 'ip_address', 'url')
    list_filter = ('project_type', 'created_at', 'updated_at')
    ordering = ('-created_at',)

from django.contrib import admin
from .models import Scan

# Définition d'un modèle d'administration pour Scan
class ScanAdmin(admin.ModelAdmin):
    list_display = ('name', 'project', 'status', 'start_time', 'end_time', 'tool', 'created_at')
    list_filter = ('status', 'tool', 'project')
    search_fields = ('name', 'project__name')  # Recherche par nom de scan et nom du projet
    date_hierarchy = 'start_time'  # Permet de filtrer par date
    ordering = ('-created_at',)  # Trie par date de création descendante

    # Personnalisation des champs dans l'édition
    fields = ('name', 'project', 'target_url', 'status', 'start_time', 'end_time', 'estimated_end_time', 'duration', 'findings_summary', 'next_scan', 'tool')
    readonly_fields = ('created_at',)  # Ne pas permettre la modification de created_at

    # Personnalisation des actions
    actions = ['mark_as_completed', 'mark_as_failed']

    def mark_as_completed(self, request, queryset):
        queryset.update(status='completed')
    mark_as_completed.short_description = "Marquer comme terminé"

    def mark_as_failed(self, request, queryset):
        queryset.update(status='failed')
    mark_as_failed.short_description = "Marquer comme échoué"

# Enregistrement du modèle et de l'administration
admin.site.register(Scan, ScanAdmin)




# Enregistrer les modèles dans l'admin
admin.site.register(Project, ProjectAdmin)
