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
    created_by = models.ForeignKey(
        'CustomUser',  # Utilise le modèle CustomUser
        on_delete=models.SET_NULL,  # Si l'utilisateur est supprimé, garde le scan
        null=True,
        blank=True,
        verbose_name="Créé par",
        related_name="scans_created"
    )
    error_log = models.TextField(null=True, blank=True)
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
    
    # Fichier regroupant toutes les options disponibles pour chaque outil de scan

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

SQLMAP_OPTIONS = (
    ('-u', 'URL cible'),
    ('--dbs', 'Liste les bases de données disponibles'),
    ('--tables', 'Liste les tables dans une base de données'),
    ('--columns', 'Liste les colonnes dans une table'),
    ('--dump', "Extrait les données d'une table"),
    ('--level', "Niveau d'agressivité du scan (1 à 5)"),
    ('--risk', "Niveau de risque du scan (1 à 3)"),
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


class SqlmapResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE,null=True,blank=True)
    option = models.CharField(max_length=10, choices=SQLMAP_OPTIONS)
    dbms = models.CharField(max_length=100)
    db_name = models.CharField(max_length=100)
    table_name = models.CharField(max_length=100)
    column_name = models.CharField(max_length=100)
    dumped_data = models.TextField(null=True, blank=True)


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
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, null=True, blank=True)
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