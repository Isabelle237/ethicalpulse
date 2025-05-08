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

class ScanAdmin(admin.ModelAdmin):
    list_display = ('name', 'scan_type', 'status', 'project', 'start_time', 'end_time', 'created_at')
    search_fields = ('name', 'project__name', 'status')
    list_filter = ('status', 'scan_type', 'created_at')
    ordering = ('-created_at',)
    list_editable = ('status',)

# Enregistrer les modèles dans l'admin
admin.site.register(Project, ProjectAdmin)
admin.site.register(Scan, ScanAdmin)
