from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
import pyotp

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
    ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="Adresse IP")
    url = models.URLField(blank=True, null=True, verbose_name="URL")
    scope = models.TextField(blank=True, null=True)
    mac_address = models.CharField(max_length=50, blank=True, null=True, verbose_name="Adresse MAC")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de création")

    def __str__(self):
        return self.name
