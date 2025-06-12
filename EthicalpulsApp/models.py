from datetime import timedelta
from dateutil.relativedelta import relativedelta
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
import pyotp
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
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
    ('AIRCRACK', 'Aircrack-ng'),
    ('BEEF', 'BeEF'),
    ('METASPLOIT', 'Metasploit'),
    ('HASHCAT', 'Hashcat'),
    ('JOHN', 'John The Ripper'),
    ('RECONNG', 'Recon-ng'),
    ('WIRESHARK', 'Wireshark'),
    ('WIFITE', 'Wifite'),
    ('GHIDRA', 'Ghidra'),
    ('SNORT', 'Snort'),
    ('NETCAT', 'Netcat'),
    ('NIKTO', 'Nikto'),
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
    tool = models.CharField(max_length=20, choices=TOOL_CHOICES, verbose_name="Outil utilisé")
    status = models.CharField(max_length=20, choices=[
        ('scheduled', 'Planifié'),
        ('in_progress', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ], default='scheduled')
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    progress = models.IntegerField(default=0)
    duration = models.FloatField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    notified = models.BooleanField(default=False)
    created_by = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True, blank=True)
    error_log = models.TextField(null=True, blank=True)
    scheduled_scan = models.ForeignKey('ScheduledScan', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.tool})"

class ScheduledScan(models.Model):
    FREQUENCY_CHOICES = [
        ('once', 'Une seule fois'),
        ('daily', 'Quotidien'),
        ('weekly', 'Hebdomadaire'),
        ('monthly', 'Mensuel'),
    ]

    TOOL_CHOICES = [
        ('ZAP', 'OWASP ZAP'),
        ('NMAP', 'Nmap'),
        ('SQLMAP', 'SQLMap'),
        ('NIKTO', 'Nikto'),
    ]

    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
        ('cancelled', 'Annulé')
    ]

    name = models.CharField(max_length=255, verbose_name="Nom",blank=True, null=True,)
    description = models.TextField(blank=True, null=True, verbose_name="Description")
    tool = models.CharField(max_length=20, choices=TOOL_CHOICES, verbose_name="Outil")
    target = models.ForeignKey('Project', on_delete=models.CASCADE, related_name="scheduled_scans", verbose_name="Projet cible")
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES, verbose_name="Fréquence")
    next_run_time = models.DateTimeField(verbose_name="Prochaine exécution")
    last_run = models.DateTimeField(null=True, blank=True, verbose_name="Dernière exécution")
    created_by = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, verbose_name="Créé par",blank=True, null=True,)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_log = models.TextField(null=True, blank=True)
    configuration = models.JSONField(null=True, blank=True)
    email_notification = models.BooleanField(default=True, verbose_name="Notifications par email")
    
    class Meta:
        ordering = ['next_run_time']
        verbose_name = "Scan planifié"
        verbose_name_plural = "Scans planifiés"

    def __str__(self):
        return f"{self.name} ({self.get_frequency_display()})"

    def calculate_next_run(self):
        """Calcule la prochaine date d'exécution"""
        if not self.next_run_time:
            return None

        now = timezone.now()
        next_run = self.next_run_time

        if self.frequency == 'once':
            if next_run <= now:
                self.is_active = False
                self.save()
                return None
        elif self.frequency == 'daily':
            while next_run <= now:
                next_run += timedelta(days=1)
        elif self.frequency == 'weekly':
            while next_run <= now:
                next_run += timedelta(weeks=1)
        elif self.frequency == 'monthly':
            while next_run <= now:
                next_run += relativedelta(months=1)

        return next_run

    def get_remaining_time(self):
        """Retourne le temps restant avant le prochain scan"""
        if not self.next_run_time:
            return None
        
        now = timezone.now()
        if self.next_run_time <= now:
            return "En retard"
            
        diff = self.next_run_time - now
        days = diff.days
        hours = diff.seconds // 3600
        minutes = (diff.seconds % 3600) // 60
        
        if days > 0:
            return f"{days}j {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

class ScanTemplate(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    configuration = models.JSONField()
    created_by = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['name']

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
    resolved_at = models.DateTimeField(null=True, blank=True)  # Ajout

    # Champs spécifiques à OWASP ZAP
    alert = models.CharField(max_length=255, blank=True, null=True, verbose_name="Alerte")
    risk = models.CharField(max_length=50, blank=True, null=True, verbose_name="Risque")
    confidence = models.CharField(max_length=50, blank=True, null=True, verbose_name="Confiance")
    evidence = models.TextField(blank=True, null=True, verbose_name="Preuve")
    reference = models.TextField(blank=True, null=True, verbose_name="Références")

    # Champs spécifiques à SQLMap
    parameter = models.CharField(max_length=255, blank=True, null=True, verbose_name="Paramètre vulnérable")
    technique = models.CharField(max_length=255, blank=True, null=True, verbose_name="Technique utilisée")
    dbms = models.CharField(max_length=255, blank=True, null=True, verbose_name="SGBD détecté")
    request_type = models.CharField(max_length=50, blank=True, null=True, verbose_name="Type de requête")

    # Champs spécifiques à Nmap
    port = models.IntegerField(blank=True, null=True, verbose_name="Port")
    protocol = models.CharField(max_length=50, blank=True, null=True, verbose_name="Protocole")
    state = models.CharField(max_length=50, blank=True, null=True, verbose_name="État")
    service = models.CharField(max_length=255, blank=True, null=True, verbose_name="Service")
    version = models.CharField(max_length=255, blank=True, null=True, verbose_name="Version du service")

    def __str__(self):
        return self.name
    
from django.db import models
from django.conf import settings

class UserNotification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.email}"

from django.db import models

# Options pour chaque outil
NMAP_OPTIONS = (
    ('-sS', 'Scan SYN - Scan furtif TCP'),
    ('-sT', 'Scan TCP - Établit connexions complètes'),
    ('-sU', 'Scan UDP - Détecte services UDP'),
    ('-sV', 'Détection Version - Identifie services/versions'),
    ('-O', "OS Detection - Identifie systèmes d'exploitation"),
    ('-A', 'Scan Agressif - OS, version, scripts, traceroute'),
    ('-p-', 'Tous Ports - Scanne tous les ports TCP'),
    ('-F', 'Scan rapide - Scan SYN des ports les plus courants'),
)


NETCAT_OPTIONS = (
    ('-lvp', 'Listener (-lvp) - Écoute sur un port'),
    ('-v', 'Connexion (-v) - Connecter à un port'),
    ('-z', 'Scanner Port (-z) - Scanner ports sans envoi de données'),
    ('-e', 'Exécution (-e) - Exécuter programme après connexion'),
    ('-u', 'UDP (-u) - Utiliser UDP au lieu de TCP'),
)

ZAP_OPTIONS = (
    ('-quickurl', 'Scan rapide - Analyse de base'),
    ('-ajax', 'Scan Ajax - Analyse des applications Ajax'),
    ('-full', 'Scan complet - Analyse approfondie'),
    ('-xss', 'XSS - Test des vulnérabilités XSS uniquement'),
    ('-sqli', 'SQL Injection - Test des vulnérabilités SQLi uniquement'),
)


AIRCRACK_OPTIONS = (
    ('airmon-ng start', 'Active le mode moniteur'),
    ('airodump-ng', 'Capture les paquets WiFi'),
    ('aireplay-ng -0', 'Effectue une attaque de désauthentification'),
    ('aircrack-ng -w', 'Cracker une clé WPA avec une wordlist'),
    ('aircrack-ng -K', 'Attaque PTW (WEP)'),
)

BEEF_OPTIONS = (
    ('-x', 'Active les consoles XSS'),
    ('--host', "Spécifie l'hôte d'écoute"),
    ('--port', "Spécifie le port d'écoute"),
    ('--password', 'Définit un mot de passe'),
    ('--hook-url', "URL du hook pour exploiter les navigateurs"),
)


METASPLOIT_OPTIONS = (
    ('use exploit/multi/handler', 'Configure un handler'),
    ('use auxiliary/scanner/smb/smb_version', 'Scanner SMB'),
    ('use auxiliary/scanner/http/dir_scanner', 'Scanner les répertoires HTTP'),
    ('use exploit/windows/smb/ms17_010_eternalblue', 'Exploit MS17-010 (EternalBlue)'),
    ('use exploit/multi/http/wp_admin_shell_upload', 'Upload de shell admin WordPress'),
)

HASHCAT_OPTIONS = (
    ('-a 0', 'Attaque par dictionnaire'),
    ('-a 1', 'Attaque par combinaison'),
    ('-a 3', 'Attaque par brute-force'),
    ('-a 6', 'Attaque hybride (dictionnaire + masque)'),
    ('-a 7', 'Attaque hybride (masque + dictionnaire)'),
    ('-m 0', 'Hash MD5'),
)

JOHN_OPTIONS = (
    ('--wordlist', 'Attaque par dictionnaire'),
    ('--rules', 'Utilise des règles de mutation'),
    ('--incremental', 'Mode brute-force'),
    ('--format=md5', 'Hash MD5'),
    ('--format=sha1', 'Hash SHA1'),
    ('--show', 'Affiche les mots de passe craqués'),
)

RECONNG_OPTIONS = (
    ('modules load recon/domains-hosts/brute_hosts', 'Brute force DNS'),
    ('modules load recon/hosts-hosts/resolve', 'Résolution DNS'),
    ('modules load recon/domains-contacts/whois_pocs', 'Contacts WHOIS'),
    ('modules load recon/domains-vulnerabilities/xssed', 'Archives XSSed'),
    ('modules load recon/domains-hosts/google_site_web', 'Recherche Google Site Web'),
)

WIRESHARK_OPTIONS = (
    ('-i', 'Capture sur une interface'),
    ('-r', 'Ouvre un fichier de capture'),
    ('-f', 'Applique un filtre BPF'),
    ('-Y', "Applique un filtre d'affichage"),
    ('-w', 'Écrit dans un fichier'),
)

WIFITE_OPTIONS = (
    ('-all', 'Attaque tous les réseaux'),
    ('-wpa', 'Cible uniquement WPA/WPA2'),
    ('-wep', 'Cible uniquement WEP'),
    ('-wps', 'Cible uniquement WPS'),
    ('-dict', 'Spécifie un dictionnaire'),
)

GHIDRA_OPTIONS = (
    ('analyzeHeadless', 'Analyse en ligne de commande'),
    ('launch', "Lance l'interface graphique"),
    ('analyzeHeadless -import', 'Importe un fichier binaire'),
    ('analyzeHeadless -process', 'Traite un fichier binaire'),
    ('analyzeHeadless -export', 'Exporte les résultats'),
)

SNORT_OPTIONS = (
    ('-T', 'Teste la configuration'),
    ('-c', 'Spécifie un fichier de configuration'),
    ('-i', 'Spécifie une interface'),
    ('-A', "Mode d'alerte"),
    ('-l', 'Dossier de logs'),
)



class NmapResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='nmap_results', null=True, blank=True)
    target = models.CharField(max_length=255, blank=True, null=True)  # IP ou domaine
    command_used = models.TextField(null=True, blank=True)            # Commande exacte exécutée
    option = models.CharField(max_length=255, choices=NMAP_OPTIONS)  # Ex: -sS -sV -O
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    returncode = models.IntegerField(null=True, blank=True)
    # Résumé global
    os_detected = models.CharField(max_length=255, null=True, blank=True)
    os_accuracy = models.CharField(max_length=100, null=True, blank=True)
    traceroute = models.TextField(null=True, blank=True)
    script_results = models.TextField(null=True, blank=True)  # Résultats des scripts NSE

    # Résultats complets bruts (parse possible plus tard)
    full_output = models.TextField(null=True, blank=True)  # Toute la sortie Nmap texte ou XML

    # Liste de ports détectés (TCP/UDP)
    open_tcp_ports = models.TextField(null=True, blank=True)  # Format: "80/http, 443/https"
    open_udp_ports = models.TextField(null=True, blank=True)

    # Services détectés
    service_details = models.TextField(null=True, blank=True)  # nom, version, etc.
    # Statut & logs
    scan_status = models.CharField(max_length=50, default='pending', null=True, blank=True)  # pending, running, finished, error
    error_log = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Scan Nmap - {self.target} ({self.start_time.date()})"


class OwaspZapResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=10, choices=ZAP_OPTIONS)
    url = models.URLField()
    risk = models.CharField(max_length=50)
    vulnerability = models.CharField(max_length=255)
    description = models.TextField()
    evidence = models.TextField(null=True, blank=True)
    recommendation = models.TextField()



SQLMAP_OPTIONS = (
    ("--batch", "Scan simple (automatique)"),
    ("--level=3 --risk=2 --batch", "Scan approfondi"),
    ("--technique=BE --batch", "Scan booléen + erreur"),
    ("--dbs --batch", "Lister les bases (si vulnérable)"),
    ("--dump --batch", "Extraire les données (si vulnérable)"),
    ("--batch --random-agent", "Scan + contournement User-Agent"),
)
class SqlmapResult(models.Model):
    scan = models.ForeignKey(Scan,related_name='w', on_delete=models.CASCADE, blank=True,null = True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True,blank=True)
    raw_output = models.TextField(blank=True, null=True)
    is_vulnerable = models.BooleanField(default=False)
    injection_type = models.CharField(max_length=255, blank=True, null=True)
    dbms = models.CharField(max_length=255, blank=True, null=True)
    payloads = models.TextField(blank=True, null=True)
    dbs_found = models.TextField(blank=True, null=True)
    tables_found = models.JSONField(default=dict, blank=True)
    columns_found = models.JSONField(default=dict, blank=True)
    data_dumped = models.JSONField(default=dict, blank=True)
    options_used = models.TextField(blank=True, null=True)
    techniques_used = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)



class AircrackngResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=20, choices=AIRCRACK_OPTIONS)
    ssid = models.CharField(max_length=100)
    mac_address = models.CharField(max_length=17)
    channel = models.IntegerField()
    signal_strength = models.IntegerField()
    encryption = models.CharField(max_length=20)
    key = models.CharField(max_length=100, null=True, blank=True)


class BeefResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=15, choices=BEEF_OPTIONS)
    victim_ip = models.GenericIPAddressField()
    browser = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    hook_time = models.DateTimeField()
    executed_modules = models.TextField()

from django.db import models
from EthicalpulsApp.models import Scan

# Options disponibles pour les scans Nikto
NIKTO_OPTIONS = (
    ('-h', "Scan standard d'un hôte"),
    ('-Tuning 9', "Tests d'injection SQL"),
    ('-Tuning 4', 'Tests XSS'),
    ('-ssl', "Force l'utilisation de SSL/HTTPS"),
    ('-nossl', "Force l'utilisation de HTTP"),
    ('-Cgidirs all', 'Teste tous les dossiers CGI'),
)

class NiktoResult(models.Model):
    scan = models.ForeignKey(Scan, related_name='niktoresults',on_delete=models.CASCADE, null=True, blank=True)
    option = models.CharField(max_length=44, choices=NIKTO_OPTIONS)
    nikto_raw_output = models.TextField(blank=True, null=True)
    vulnerability = models.TextField(blank=True, null=True)
    description = models.TextField()
    uri = models.CharField(max_length=255, null=True, blank=True)
    target_hostname = models.CharField(max_length=255, null=True, blank=True)
    target_port = models.IntegerField()

    # Informations du serveur / SSL
    server = models.CharField(max_length=255, blank=True, null=True)
    ssl_subject = models.CharField(max_length=255, blank=True, null=True)
    ssl_issuer = models.CharField(max_length=255, blank=True, null=True)
    ssl_altnames = models.CharField(max_length=255, blank=True, null=True)
    ssl_cipher = models.CharField(max_length=255, blank=True, null=True)

    # En-têtes HTTP
    x_powered_by = models.CharField(max_length=255, blank=True, null=True)
    x_frame_options = models.CharField(max_length=255, blank=True, null=True)
    link_headers = models.TextField(blank=True, null=True)
    via_header = models.CharField(max_length=255, blank=True, null=True)
    content_security_policy = models.TextField(blank=True, null=True)
    strict_transport_security = models.CharField(max_length=255, blank=True, null=True)
    referrer_policy = models.CharField(max_length=255, blank=True, null=True)
    content_type = models.CharField(max_length=255, blank=True, null=True)
    cache_control = models.CharField(max_length=255, blank=True, null=True)
    expires = models.CharField(max_length=255, blank=True, null=True)
    pragma = models.CharField(max_length=255, blank=True, null=True)
    set_cookie = models.TextField(blank=True, null=True)
    location_header = models.CharField(max_length=255, blank=True, null=True)

    # Résultats et état du scan
    parsed_vulnerabilities = models.TextField(blank=True)
    scan_completed = models.BooleanField(default=False)
    total_requests = models.IntegerField(default=0)
    percent_complete = models.FloatField(default=0.0)

    def __str__(self):
        return f"Nikto Result for {self.target_hostname}:{self.target_port} - {self.get_option_display()}"

class MetasploitResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=44, choices=METASPLOIT_OPTIONS)
    vulnerability = models.CharField(max_length=255)
    exploited = models.BooleanField(default=False)
    payload = models.CharField(max_length=255, null=True, blank=True)
    session_info = models.TextField(null=True, blank=True)


class HashcatResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=10, choices=HASHCAT_OPTIONS)
    hash_type = models.CharField(max_length=100)
    original_hash = models.TextField()
    cracked_password = models.CharField(max_length=255, null=True, blank=True)
    time_taken = models.FloatField()


class JohntheripperResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=20, choices=JOHN_OPTIONS)
    hash = models.TextField()
    cracked_password = models.CharField(max_length=255)
    method_used = models.CharField(max_length=100)


class ReconngResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=50, choices=RECONNG_OPTIONS)
    subdomain = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    email_found = models.EmailField(null=True, blank=True)
    whois_info = models.TextField(null=True, blank=True)

class WiresharkResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=5, choices=WIRESHARK_OPTIONS)
    protocol = models.CharField(max_length=50)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    length = models.IntegerField()
    info = models.TextField()

class WifiteResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=10, choices=WIFITE_OPTIONS)
    target_ssid = models.CharField(max_length=100)
    mac_address = models.CharField(max_length=17)
    encryption_type = models.CharField(max_length=20)
    attack_status = models.CharField(max_length=50)

class GhidraResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=24, choices=GHIDRA_OPTIONS)
    binary_name = models.CharField(max_length=255)
    analysis_report = models.TextField()

class SnortResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=5, choices=SNORT_OPTIONS)
    alert_message = models.TextField()
    packet_info = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
class NetcatResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=4, choices=NETCAT_OPTIONS)
    port = models.IntegerField()
    state = models.CharField(max_length=20)
    protocol = models.CharField(max_length=10, default="TCP")
    banner = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    
    from django.db import models
from django.contrib.auth import get_user_model
import json

User = get_user_model()

class SystemLog(models.Model):
    TYPE_CHOICES = [
        ('auth', 'Authentification'),
        ('scan', 'Scans'),
        ('vuln', 'Vulnérabilités'),
        ('system', 'Système'),
    ]
    
    LEVEL_CHOICES = [
        ('info', 'Information'),
        ('warning', 'Avertissement'),
        ('error', 'Erreur'),
        ('critical', 'Critique'),
    ]
    
    timestamp = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    message = models.TextField()
    url = models.URLField(max_length=500, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    data = models.JSONField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"{self.get_type_display()} - {self.timestamp}"
        
    @property
    def data_json(self):
        if self.data:
            return json.dumps(self.data, indent=2)
        return "{}"
