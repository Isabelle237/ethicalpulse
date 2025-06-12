from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Project, Scan, Vulnerability

# Administration personnalisée pour CustomUser
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


# Administration personnalisée pour Project
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'project_type', 'created_at', 'updated_at')
    search_fields = ('name', 'description', 'domain', 'ip_address', 'url')
    list_filter = ('project_type', 'created_at', 'updated_at')
    ordering = ('-created_at',)

admin.site.register(Project, ProjectAdmin)


# Administration personnalisée pour Scan
class ScanAdmin(admin.ModelAdmin):
    list_display = ('name', 'project', 'tool', 'status', 'start_time', 'end_time', 'created_at')
    list_filter = ('status', 'tool', 'project')
    search_fields = ('name', 'project__name')  # Recherche par nom de scan et nom du projet
    date_hierarchy = 'start_time'  # Permet de filtrer par date
    ordering = ('-created_at',)  # Trie par date de création descendante

    # Personnalisation des champs dans l'édition
    fields = ('name', 'project', 'tool', 'status', 'start_time', 'end_time', 'duration')
    readonly_fields = ('created_at', 'duration')  # Ne pas permettre la modification de certains champs

    # Actions personnalisées
    actions = ['mark_as_completed', 'mark_as_failed']

    def mark_as_completed(self, request, queryset):
        queryset.update(status='completed')
        self.message_user(request, "Les scans sélectionnés ont été marqués comme terminés.")
    mark_as_completed.short_description = "Marquer comme terminé"

    def mark_as_failed(self, request, queryset):
        queryset.update(status='failed')
        self.message_user(request, "Les scans sélectionnés ont été marqués comme échoués.")
    mark_as_failed.short_description = "Marquer comme échoué"

admin.site.register(Scan, ScanAdmin)


# Administration personnalisée pour Vulnerability
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('name', 'scan', 'severity', 'status', 'discovered_at')
    list_filter = ('severity', 'status', 'scan__tool')
    search_fields = ('name', 'description', 'scan__name', 'target_url')
    date_hierarchy = 'discovered_at'  # Permet de filtrer par date
    ordering = ('-discovered_at',)  # Trie par date de découverte descendante

    # Personnalisation des champs dans l'édition
    fields = ('name', 'scan', 'severity', 'status', 'description', 'target_url', 'remediation', 'cve_id', 'discovered_at')
    readonly_fields = ('discovered_at',)  # Ne pas permettre la modification de la date de découverte

admin.site.register(Vulnerability, VulnerabilityAdmin)