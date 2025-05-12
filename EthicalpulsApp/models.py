from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
import pyotp
from .validators import validate_ip, validate_mac, validate_url  # Correction de l'importation
ROLES = [
    ('ADMIN', 'Administrateur'),
    ('PROJECT_MANAGER', 'Chef de projet'),
    ('DEVELOPER', 'Développeur'),
    ('SECURITY_ANALYST', 'Analyste sécurité'),
]

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("L'adresse e-mail est requise")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.otp_secret = pyotp.random_base32()  # Générer un secret OTP pour l'utilisateur
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150)
    role = models.CharField(max_length=30, choices=ROLES)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)

    # Ajout des champs nécessaires pour l'OTP
    otp_code = models.CharField(max_length=6, null=True, blank=True)  # Code OTP
    otp_created_at = models.DateTimeField(null=True, blank=True)  # Date de création de l'OTP
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32)  # Secret OTP pour générer les codes

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'role']

    def __str__(self):
        return self.email




# Choix du type de projet
PROJECT_TYPES = [
    ('web', 'Application Web'),
    ('api', 'API'),
    ('mobile', 'Application Mobile'),
    ('infra', 'Infrastructure Réseau'),
    ('desktop', 'Application Desktop'),
    ('autre', 'Autre'),
]

class Project(models.Model):
    name = models.CharField(max_length=100, verbose_name="Nom du projet")
    description = models.TextField(blank=True, verbose_name="Description")
    project_type = models.CharField(max_length=20, choices=PROJECT_TYPES, verbose_name="Type de projet")
    domain = models.CharField(max_length=255, blank=True, null=True, verbose_name="Nom de domaine")
    ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="Adresse IP", validators=[validate_ip])
    url = models.URLField(blank=True, null=True, verbose_name="URL", validators=[validate_url])
    scope = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de création")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name


   

class Scan(models.Model):
    
    STATUS_CHOICES = (
        ('scheduled', 'Planifié'),
        ('in_progress', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    )
    
    TOOL_CHOICES = (
        ('ZAP', 'OWASP ZAP'),
        ('NMAP', 'Nmap'),
        ('SQLMAP', 'SQLMap'),
        ('APISEC', 'API Security Scanner'),
    )
    report_file = models.FileField( upload_to='scan_reports/',  null=True, blank=True,  default='',verbose_name="Rapport du Scan")
    name = models.CharField(max_length=255)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    duration = models.FloatField(blank=True, null=True)
    findings_summary = models.JSONField(blank=True, null=True, default=dict)
    next_scan = models.DateTimeField(blank=True, null=True)
    tool = models.CharField(max_length=20, choices=TOOL_CHOICES, default='ZAP')
    created_at = models.DateTimeField(auto_now_add=True)
    target_url = models.URLField(blank=True, null=True, verbose_name="URL cible", validators=[validate_url])
    nmap_results = models.JSONField(null=True, blank=True)
    zap_results = models.JSONField(null=True, blank=True)
    sqlmap_results = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.get_scan_type_display()})"
    def get_vulnerabilities(self):
        """Retourne les vulnérabilités associées à ce scan."""
        return self.vulnerabilities.all()

class Vulnerability(models.Model):
    SEVERITY_CHOICES = (
        ('critical', 'Critique'),
        ('high', 'Élevée'),
        ('medium', 'Moyenne'),
        ('low', 'Faible'),
        ('info', 'Information'),
    )

    STATUS_CHOICES = (
        ('open', 'Ouverte'),
        ('in_progress', 'En cours'),
        ('resolved', 'Résolue'),
        ('closed', 'Fermée'),
        ('false_positive', 'Faux positif'),
    )

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="vulnerabilities")
    cve_id = models.CharField(max_length=20, blank=True, null=True, verbose_name="CVE ID")
    name = models.CharField(max_length=255, verbose_name="Nom de la vulnérabilité")
    description = models.TextField(blank=True, verbose_name="Description")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, verbose_name="Sévérité")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', verbose_name="Statut")
    target_url = models.URLField(blank=True, null=True, verbose_name="URL cible")
    steps_to_reproduce = models.TextField(blank=True, null=True, verbose_name="Étapes de reproduction")
    remediation = models.TextField(blank=True, null=True, verbose_name="Recommandations")
    discovered_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de découverte")
    is_scheduled = models.BooleanField(default=False)  # Nouveau champ pour différencier les scans planifiés

    class Meta:
        ordering = ['-discovered_at']

    def __str__(self):
        return f"{self.name} ({self.get_severity_display()})"

from django.db import models

class ScheduledScan(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    tool = models.CharField(max_length=50)
    scheduled_time = models.DateTimeField()
    frequency = models.CharField(max_length=20, choices=[
        ('once', 'Une seule fois'),
        ('daily', 'Tous les jours'),
        ('weekly', 'Toutes les semaines'),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan planifié pour {self.project.name} à {self.scheduled_time}"