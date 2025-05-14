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

from django.db import models
from django.utils.timezone import now
from .validators import validate_ip, validate_url

# Choix de gravité pour les vulnérabilités
SEVERITY_CHOICES = (
    ('critical', 'Critique'),
    ('high', 'Élevée'),
    ('medium', 'Moyenne'),
    ('low', 'Faible'),
    ('info', 'Information'),
)

# Choix de statut pour les vulnérabilités
STATUS_CHOICES = (
    ('open', 'Ouverte'),
    ('in_progress', 'En cours'),
    ('resolved', 'Résolue'),
    ('closed', 'Fermée'),
    ('false_positive', 'Faux positif'),
)

# Choix du type de projet
PROJECT_TYPES = [
    ('web', 'Application Web'),
    ('api', 'API'),
    ('mobile', 'Application Mobile'),
    ('infra', 'Infrastructure Réseau'),
    ('desktop', 'Application Desktop'),
    ('autre', 'Autre'),
]

# Choix des outils de scan
TOOL_CHOICES = (
    ('ZAP', 'OWASP ZAP'),
    ('NMAP', 'Nmap'),
    ('SQLMAP', 'SQLMap'),
    ('APISEC', 'API Security Scanner'),
)

class Project(models.Model):
    name = models.CharField(max_length=100, verbose_name="Nom du projet")
    description = models.TextField(blank=True, verbose_name="Description")
    project_type = models.CharField(max_length=20, choices=PROJECT_TYPES, verbose_name="Type de projet")
    domain = models.CharField(max_length=255, blank=True, null=True, verbose_name="Nom de domaine")
    ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="Adresse IP", validators=[validate_ip])
    url = models.URLField(blank=True, null=True, verbose_name="URL", validators=[validate_url])
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de création")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class Scan(models.Model):
    name = models.CharField(max_length=255, verbose_name="Nom du scan")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="scans")
    tool = models.CharField(max_length=20, choices=TOOL_CHOICES, default='ZAP', verbose_name="Outil utilisé")
    status = models.CharField(max_length=20, choices=[
        ('scheduled', 'Planifié'),
        ('in_progress', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ], default='scheduled', verbose_name="Statut")
    start_time = models.DateTimeField(blank=True, null=True, verbose_name="Heure de début")
    end_time = models.DateTimeField(blank=True, null=True, verbose_name="Heure de fin")
    duration = models.FloatField(blank=True, null=True, verbose_name="Durée (en secondes)")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de création")

    def __str__(self):
        return f"{self.name} ({self.tool})"


class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255, verbose_name="Nom de la vulnérabilité")
    description = models.TextField(blank=True, null=True, verbose_name="Description")
    severity = models.CharField(max_length=50, choices=SEVERITY_CHOICES, verbose_name="Gravité")
    target_url = models.URLField(blank=True, null=True, verbose_name="URL cible")
    remediation = models.TextField(blank=True, null=True, verbose_name="Remédiation")
    cve_id = models.CharField(max_length=50, blank=True, null=True, verbose_name="CVE ID")
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='open', verbose_name="Statut")
    discovered_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de découverte")

    # Champs spécifiques à OWASP ZAP
    alert = models.CharField(max_length=255, blank=True, null=True, verbose_name="Alerte")
    risk = models.CharField(max_length=50, blank=True, null=True, verbose_name="Risque")
    confidence = models.CharField(max_length=50, blank=True, null=True, verbose_name="Confiance")
    evidence = models.TextField(blank=True, null=True, verbose_name="Preuve")
    reference = models.TextField(blank=True, null=True, verbose_name="Références")

    # Champs spécifiques à SQLMap
    parameter = models.CharField(max_length=255, blank=True, null=True, verbose_name="Paramètre vulnérable")
    technique = models.CharField(max_length=255, blank=True, null=True, verbose_name="Technique utilisée")

    # Champs spécifiques à Nmap
    port = models.IntegerField(blank=True, null=True, verbose_name="Port")
    protocol = models.CharField(max_length=50, blank=True, null=True, verbose_name="Protocole")
    state = models.CharField(max_length=50, blank=True, null=True, verbose_name="État")
    service = models.CharField(max_length=255, blank=True, null=True, verbose_name="Service")

    def __str__(self):
        return self.name

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