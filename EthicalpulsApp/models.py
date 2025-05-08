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
    ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="Adresse IP",validators=[validate_ip])
    url = models.URLField(blank=True, null=True, verbose_name="URL",validators=[validate_url])
    scope = models.TextField(blank=True, null=True)
    mac_address = models.CharField(max_length=50, blank=True, null=True, verbose_name="Adresse MAC",validators=[validate_mac])
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de création")
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return self.name



class Scan(models.Model):
    STATUS_CHOICES = [
        ('in_progress', 'En cours'),
        ('scheduled', 'Planifié'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ]
    
    SCAN_TYPE_CHOICES = [
        ('FULL', 'Scan complet'),
        ('TARGETED', 'Scan ciblé'),
        ('API', 'Scan API'),
        ('INFRA', 'Scan d\'infrastructure'),
    ]
    
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    target_url = models.URLField(blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    next_scan = models.DateTimeField(null=True, blank=True)
    findings_summary = models.JSONField(null=True, blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='scans')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.get_status_display()})"

    @property
    def duration(self):
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return int(delta.total_seconds() / 60)  # Duration in minutes
        return None
    