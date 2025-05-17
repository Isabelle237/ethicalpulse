# =================== Imports Standard ===================
import random
import time
import json
import os
from datetime import timedelta, datetime
from zapv2 import ZAPv2
import subprocess
import logging
import pyotp
import nmap
from reportlab.lib import colors
# =================== Imports Django ===================
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django.urls import reverse
from django.middleware.csrf import get_token
from django.utils.timezone import make_aware, now
from django.core.paginator import Paginator

# =================== Imports pour la génération de PDF ===================
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
#from reportlab.lib.colors import HexColor, black, white, colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# =================== Imports Spécifiques au Projet ===================
from EthicalpulsApp.models import *
from .forms import *
from .models import *

# =================== Imports de Bibliothèques Externes ===================
from celery import shared_task

# =================== Imports pour les Scans et Vulnérabilités ===================
from .models import Project, Scan, Vulnerability, ScheduledScan
from .forms import ScanForm



def index(request):
    return render(request, 'dashboard/index.html')

def dashboard(request):
    return render(request, 'admin/dashboard.html')

# =================== Utilisateurs ===================

@csrf_protect
def create_user_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            if not user.otp_secret:
                user.otp_secret = pyotp.random_base32()
            user.save()

            html_message = render_to_string('emails/account_confirmation.html', {
                'username': user.username,
            })
            plain_message = strip_tags(html_message)

            send_mail(
                subject="Confirmation de création de compte",
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )

            messages.success(request, "L'utilisateur a été créé avec succès.")
            return redirect('users')
        else:
            messages.error(request, "Une erreur est survenue lors de la création de l'utilisateur.")
    else:
        form = CustomUserCreationForm()

    users_list = CustomUser.objects.all()
    return render(request, 'admin/users.html', {
        'form': form,
        'users_list': users_list
    })
    
@csrf_protect
def edit_user_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, "L'utilisateur a été mis à jour.")
            return redirect('users')
        else:
            messages.error(request, "Erreur lors de la mise à jour de l'utilisateur.")
    else:
        form = CustomUserCreationForm(instance=user)

    return render(request, 'admin/edit_user_modal.html', {'form': form, 'user': user})

@require_POST
def delete_user_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    messages.success(request, "L'utilisateur a été supprimé.")
    return redirect('users')

@require_POST
def delete_multiple_users_view(request):
    ids = request.POST.getlist('user_ids[]')
    if ids:
        CustomUser.objects.filter(id__in=ids).delete()
        messages.success(request, f"{len(ids)} utilisateur(s) supprimé(s).")
    else:
        messages.warning(request, "Aucun utilisateur sélectionné.")
    return redirect('users')


def admin_projets(request):
    """
    View to handle project listing, creation, editing, and deletion.
    """
    # Handle POST requests for add/edit/delete
    if request.method == 'POST':
        if 'add_project' in request.POST:
            form = ProjectForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Nouveau projet ajouté.")
                return redirect('admin_projets')
            else:
                messages.error(request, "Erreur lors de l’ajout du projet.")
        elif 'edit_project' in request.POST:
            project_id = request.POST.get('project_id')
            if not project_id or not project_id.isdigit():
                messages.error(request, "ID de projet invalide.")
                return redirect('admin_projets')
            project = get_object_or_404(Project, id=project_id)
            form = ProjectForm(request.POST, instance=project)
            if form.is_valid():
                form.save()
                messages.success(request, "Projet modifié avec succès.")
                return redirect('admin_projets')
            else:
                messages.error(request, "Erreur lors de la modification du projet.")
        elif 'delete_project' in request.POST:
            project_id = request.POST.get('project_id')
            if not project_id or not project_id.isdigit():
                messages.error(request, "ID de projet invalide.")
                return redirect('admin_projets')
            project = get_object_or_404(Project, id=project_id)
            project.delete()
            messages.success(request, f"Le projet « {project.name} » a été supprimé.")
            return redirect('admin_projets')
    else:
        form = ProjectForm()

    # Handle search query
    search_query = request.GET.get('search', '')
    projects = Project.objects.all()
    if search_query:
        projects = projects.filter(
            Q(name__icontains=search_query) |
            Q(domain__icontains=search_query) |
            Q(ip_address__icontains=search_query) |
            Q(url__icontains=search_query) |
            Q(mac_address__icontains=search_query)
        )

    # Sorting (optional, as template handles client-side sorting)
    sort_by = request.GET.get('sort', 'created_at')
    order = request.GET.get('order', 'desc')
    if sort_by in ['name', 'project_type', 'domain', 'created_at']:
        if order == 'desc':
            projects = projects.order_by(f'-{sort_by}')
        else:
            projects = projects.order_by(sort_by)

    context = {
        'projects': projects,
        'form': form,
        'search_query': search_query,
    }
    return render(request, 'admin/projects.html', context)

def projects_chart_type(request):
    """
    API view to provide data for the project type doughnut chart.
    """
    data = (
        Project.objects.values('project_type')
        .annotate(count=Count('id'))
        .order_by('project_type')
    )
    chart_data = [
        {
            'project_type': dict(PROJECT_TYPES).get(item['project_type'], item['project_type']),
            'count': item['count']
        }
        for item in data
    ]
    return JsonResponse({'data': chart_data})


def projects_chart_trend(request):
    """
    API view to provide data for the project trend line chart (projects created per month).
    """
    end_date = timezone.now()
    start_date = end_date - datetime.timedelta(days=365)  # Last 12 months
    data = []
    current_date = start_date
    while current_date <= end_date:
        next_date = current_date + datetime.timedelta(days=30)  # Approx 1 month
        count = Project.objects.filter(
            created_at__gte=current_date,
            created_at__lt=next_date
        ).count()
        data.append({
            'month': current_date.strftime('%Y-%m'),
            'count': count
        })
        current_date = next_date
    return JsonResponse({'data': data})

@csrf_protect
def email_login(request):
    if request.method == "POST":
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            user = authenticate(request, email=email, password=password)
            if user:
                otp_code = str(random.randint(100000, 999999))  # Nouveau code à chaque connexion

                user.otp_code = otp_code  # Stocke le code OTP dans l'utilisateur
                user.otp_created_at = timezone.now()  # Stocke la date de création
                user.save()

                # Envoi du code OTP par email
                send_otp_email(user.email, otp_code, user)

                # Enregistre l'ID utilisateur dans la session pour la vérification ultérieure
                request.session['otp_user_id'] = user.id
                return redirect('verify_otp')
            else:
                messages.error(request, "Identifiants invalides.")
    else:
        form = EmailLoginForm()

    return render(request, 'registration/login.html', {'form': form})


@csrf_protect
def otp_verification(request):
    if request.method == "POST":
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data["otp_code"]
            user_id = request.session.get("otp_user_id")  # Récupère l'ID utilisateur depuis la session
            
            if user_id:  # Vérifie que l'ID utilisateur existe dans la session
                try:
                    user = CustomUser.objects.get(id=user_id)
                    
                    # Vérification de l'OTP et de la validité dans le temps
                    if user.otp_code == otp_code and user.otp_created_at and timezone.now() - user.otp_created_at <= timedelta(minutes=10):
                        auth_login(request, user)  # Connecte l'utilisateur
                        user.otp_code = None  # Supprime le code OTP après la validation
                        user.otp_created_at = None
                        user.save()  # Sauvegarde les modifications dans la base de données
                        
                        # Redirige en fonction du rôle de l'utilisateur
                        if user.is_staff:  # Si l'utilisateur est un admin
                            return redirect("dashboard")
                        else:  # Sinon, redirige vers les utilisateurs
                            return redirect("index")
                    else:
                        messages.error(request, "Code OTP invalide ou expiré.")  # Message d'erreur
                except CustomUser.DoesNotExist:
                    messages.error(request, "Utilisateur introuvable.")  # Si l'utilisateur n'existe pas
            else:
                messages.error(request, "Session expirée. Veuillez recommencer.")  # Si l'ID utilisateur n'est pas dans la session
    else:
        form = OTPVerificationForm()

    return render(request, 'registration/otp_verification.html', {'form': form})

def send_otp_email(email, otp_code, user):
    context = {
        'otp_code': otp_code,
        'user': user,
        'current_year': datetime.now().year,
    }
    subject = "Votre code OTP - Ethical Pulse Shield"
    message = render_to_string('emails/otp_confirmation.html', context)
    send_mail(subject, '', settings.DEFAULT_FROM_EMAIL, [email], html_message=message)

def logout_view(request):
    logout(request)
    request.session.flush()
    messages.success(request, "Vous avez été déconnecté avec succès.")
    return redirect('login')



    from django.shortcuts import render, redirect, get_object_or_404


@login_required
def get_project_details(request, project_id):
    """
    API endpoint to fetch project details for scan form.
    """
    project = get_object_or_404(Project, id=project_id)
    data = {
        'name': project.name,
        'url': project.url,
        'ip_address': project.ip_address,
        'domain': project.domain,
    }
    return JsonResponse(data)

from collections import Counter

from collections import Counter
from django.shortcuts import render, get_object_or_404
from .models import Project, Scan, Vulnerability
from .forms import ScanForm

from collections import Counter
from django.shortcuts import render
from .models import Project, Scan, Vulnerability
from .forms import ScanForm

def vulnerabilities_view(request):
    projects = Project.objects.all()
    scans = Scan.objects.prefetch_related('vulnerabilities').select_related('project').all()
    vulnerabilities = Vulnerability.objects.select_related('scan', 'scan__project').all()
    form = ScanForm()

    # Filtres GET
    project_filter = request.GET.get('project')
    severity_filter = request.GET.get('severity')
    status_filter = request.GET.get('status')

    if project_filter:
        vulnerabilities = vulnerabilities.filter(scan__project_id=project_filter)
    if severity_filter:
        vulnerabilities = vulnerabilities.filter(severity__iexact=severity_filter)
    if status_filter:
        vulnerabilities = vulnerabilities.filter(status__iexact=status_filter)

    # Sévérités valides
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']

    # Ajouter les sévérités et durées à chaque scan
    for scan in scans:
        vuln_qs = scan.vulnerabilities.all()
        try:
            scan.severities = dict(Counter(
                v.severity for v in vuln_qs if v.severity in valid_severities
            ))
        except Exception as e:
            scan.severities = {}
            print(f"[Erreur] Scan ID {scan.id} – problème lors du comptage des sévérités : {e}")

        if scan.start_time and scan.end_time:
            scan.duration = scan.end_time - scan.start_time
        else:
            scan.duration = None

    # Statistiques dynamiques globales
    critical_vulns = vulnerabilities.filter(severity='critical').count()
    high_vulns = vulnerabilities.filter(severity='high').count()
    medium_vulns = vulnerabilities.filter(severity='medium').count()
    low_vulns = vulnerabilities.filter(severity='low').count()
    total_vulns = critical_vulns + high_vulns + medium_vulns + low_vulns

    def percent(count):
        return (count / total_vulns) * 100 if total_vulns > 0 else 0

    context = {
        'projects': projects,
        'vulnerabilities': vulnerabilities.distinct(),
        'form': form,
        'scans': scans,
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'medium_vulns': medium_vulns,
        'low_vulns': low_vulns,
        'critical_percentage': percent(critical_vulns),
        'high_percentage': percent(high_vulns),
        'medium_percentage': percent(medium_vulns),
        'low_percentage': percent(low_vulns),
    }

    return render(request, 'admin/vulnerabilities.html', context)

def vulnerabilities_filter(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        project = data.get('project')
        severity = data.get('severity')
        status = data.get('status')

        # Filtrer les vulnérabilités
        vulnerabilities = Vulnerability.objects.select_related('scan', 'scan__project').all()

        if project:
            vulnerabilities = vulnerabilities.filter(scan__project_id=project)
        if severity:
            vulnerabilities = vulnerabilities.filter(severity__iexact=severity)
        if status:
            vulnerabilities = vulnerabilities.filter(scan__status__iexact=status)

        # Préparer les données pour la réponse JSON
        results = []
        for vuln in vulnerabilities:
            results.append({
                'id': vuln.id,
                'name': vuln.name,
                'project': vuln.scan.project.name,
                'severity': vuln.severity,
                'severity_class': get_severity_class(vuln.severity),
                'status': vuln.scan.status,
                'status_class': get_status_class(vuln.scan.status),
                'target_url': vuln.target_url,
                'discovered_at': vuln.discovered_at.strftime('%d/%m/%Y'),
            })

        return JsonResponse({'vulnerabilities': results})



def vuln_view(request):
    # Récupérer les scans avec les filtres
    scans = Scan.objects.all()  # Ajoute ici tes filtres si nécessaire

    # Pagination : 15 éléments par page
    paginator = Paginator(scans, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'vuln_view.html', {'scans': page_obj})


def get_severity_class(severity):
    if severity == 'critical':
        return 'danger'
    elif severity == 'high':
        return 'warning text-dark'
    elif severity == 'medium':
        return 'primary'
    elif severity == 'low':
        return 'success'
    else:
        return 'secondary'

def get_status_class(status):
    if status == 'scheduled':
        return 'warning text-dark'
    elif status == 'in_progress':
        return 'primary'
    elif status == 'completed':
        return 'success'
    elif status == 'failed':
        return 'danger'
    else:
        return 'secondary'

def classify_scan_findings(scan_results):
    severity_map = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }

    def get_nmap_severity(service, port):
        critical_services = ['msrpc', 'rdp', 'telnet', 'vnc']
        high_services = ['ftp', 'smb', 'smtp']
        medium_services = ['http', 'ssh', 'mysql']
        low_services = ['https', 'dns']
        service = service.lower()
        if service in critical_services or port in [3389, 23, 5900]:
            return 'critical'
        elif service in high_services or port in [21, 445, 25]:
            return 'high'
        elif service in medium_services or port in [80, 22, 3306]:
            return 'medium'
        elif service in low_services or port in [443, 53]:
            return 'low'
        else:
            return 'info'

    def get_sqlmap_severity(vulnerability):
        """
        Détermine la sévérité en fonction des vulnérabilités SQLMap.
        """
        if "boolean-based blind" in vulnerability.lower():
            return 'high'
        elif "time-based blind" in vulnerability.lower():
            return 'medium'
        elif "error-based" in vulnerability.lower():
            return 'critical'
        else:
            return 'info'

    def get_zap_severity(risk):
        """
        Récupère directement la sévérité à partir des résultats ZAP.
        """
        risk = risk.lower()
        if risk == 'high':
            return 'critical'
        elif risk == 'medium':
            return 'high'
        elif risk == 'low':
            return 'medium'
        else:
            return 'info'

    # Parcourir les résultats des différents outils
    for tool, results in scan_results.items():
        for result in results:
            if tool == "nmap":
                severity = get_nmap_severity(result.get('service', ''), result.get('port', 0))
            elif tool == "sqlmap":
                severity = get_sqlmap_severity(result.get('description', ''))
            elif tool == "zap":
                severity = get_zap_severity(result.get('risk', ''))
            else:
                severity = 'info'

            if severity not in severity_map:
                severity_map[severity] = []  # Initialiser une liste si elle n'existe pas
            severity_map[severity].append({
                "tool": tool,
                "description": result.get('description', 'Aucune description disponible'),
                "state": result.get('state', 'N/A'),
                "service": result.get('service', 'N/A'),
                "port": result.get('port', 'N/A'),
                "url": result.get('url', 'N/A'),
                "evidence": result.get('evidence', 'N/A'),
                "remediation": result.get('remediation', 'N/A'),
                "cve_id": result.get('cve_id', None)
            })

    # Vérifiez que toutes les entrées de severity_map sont des listes
    for key, value in severity_map.items():
        if not isinstance(value, list):
            severity_map[key] = []

    return severity_map

def parse_scan_results(output, tool):
    results = {
        "nmap": [],
        "zap": [],
        "sqlmap": [],
        "apisec": []
    }

    if tool == 'NMAP':
        lines = output.splitlines()
        protocols = []
        for line in lines:
            if "open" in line and "/" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_protocol = parts[0].split('/')
                    port = int(port_protocol[0])
                    protocol = port_protocol[1]
                    state = parts[1]
                    service = parts[2]
                    protocols.append({
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service
                    })
        if protocols:
            results["nmap"].append({"protocols": protocols})

    elif tool == 'SQLMAP':
        if "vulnerable" in output.lower():
            vulnerabilities = output.split("vulnerable")[1:]
            for vuln in vulnerabilities:
                results["sqlmap"].append({
                    "risk": "high",
                    "description": vuln.strip(),
                    "parameter": "non précisé",
                    "evidence": "Payload détecté dans la requête",
                    "remediation": "Utilisez des requêtes préparées et échappez les entrées utilisateur."
                })

    elif tool == 'ZAP':
        lines = output.lower().splitlines()
        for line in lines:
            if "alert" in line or "xss" in line:
                results["zap"].append({
                    "risk": "high",
                    "alert": "XSS détectée",
                    "url": "inconnue",
                    "evidence": "Payload détecté dans la réponse",
                    "remediation": "Validez et échappez les entrées utilisateur."
                })

    # Vérifiez que chaque clé contient une liste
    for key, value in results.items():
        if not isinstance(value, list):
            results[key] = []

    return results


def launch_scan(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            scan = form.save(commit=False)
            scan.status = 'in_progress'
            scan.start_time = now()
            scan.save()

            tool = scan.tool
            project = scan.project
            target_url = project.url

            if not target_url:
                messages.error(request, "Le projet sélectionné n'a pas d'URL définie.")
                return redirect('vulnerabilities')

            try:
                if tool == 'ZAP':
                    zap = ZAPv2(
                        apikey='620tjnb5od0ef8tep7n78usun',
                        proxies={'http': 'http://zap:8086', 'https': 'http://zap:8086'}
                    )

                    # Vérifier la disponibilité de l'API ZAP
                    for i in range(30):
                        try:
                            if zap.core.version:
                                break
                        except:
                            time.sleep(2)
                    else:
                        raise Exception("L'API ZAP n'est pas disponible.")

                    # Lancer le scan ZAP
                    zap.urlopen(target_url)
                    time.sleep(2)
                    scan_id = zap.ascan.scan(target_url)
                    while int(zap.ascan.status(scan_id)) < 100:
                        time.sleep(5)

                    # Récupérer les alertes ZAP
                    alerts = zap.core.alerts(baseurl=target_url)
                    for alert in alerts:
                        name = alert.get('alert', 'Vulnérabilité détectée')
                        description = alert.get('description', 'Aucune description disponible.')
                        severity = alert.get('risk', 'Medium')
                        remediation = alert.get('solution', 'Aucune solution disponible.')
                        parameter = alert.get('param', 'Non spécifié')
                        evidence = alert.get('evidence', 'Aucune preuve disponible.')

                        Vulnerability.objects.create(
                            scan=scan,
                            name=name,
                            description=description,
                            severity=severity,
                            target_url=alert.get('url', target_url),
                            remediation=remediation,
                            parameter=parameter,
                            evidence=evidence,
                            cve_id=alert.get('cweid', ''),
                            status='open',
                            discovered_at=now()
                        )

                elif tool == 'SQLMAP':
                    # Lancer SQLMap
                    command = ['sqlmap', '-u', target_url, '--batch', '--output-dir=/tmp', '--flush-session']
                    result = subprocess.run(command, capture_output=True, text=True)
                    output = result.stdout.lower()

                    # Analyser les résultats SQLMap
                    if "is vulnerable" in output:
                        parameter = None
                        technique = None
                        dbms = None
                        request_type = None

                        if "parameter:" in output:
                            parameter = output.split("parameter:")[1].split("\n")[0].strip()
                        if "technique:" in output:
                            technique = output.split("technique:")[1].split("\n")[0].strip()
                        if "dbms:" in output:
                            dbms = output.split("dbms:")[1].split("\n")[0].strip()
                        if "type:" in output:
                            request_type = output.split("type:")[1].split("\n")[0].strip()

                        name = "SQL Injection"
                        description = f"SQL Injection détectée sur le paramètre '{parameter}' en utilisant la technique '{technique}'. SGBD détecté : {dbms}."
                        remediation = "Utilisez des requêtes préparées et échappez les entrées utilisateur."

                        Vulnerability.objects.create(
                            scan=scan,
                            name=name,
                            description=description,
                            severity="High",
                            target_url=target_url,
                            parameter=parameter,
                            remediation=remediation,
                            evidence=f"Technique: {technique}, SGBD: {dbms}, Type de requête: {request_type}",
                            cve_id=None,
                            status='open',
                            discovered_at=now()
                        )

                elif tool == 'NMAP':
                    # Lancer Nmap
                    command = ['nmap', '-sV', '-O', '-Pn', '-T4', project.ip_address]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=400)
                    output = result.stdout
                    lines = output.splitlines()

                    # Analyser les résultats Nmap
                    for line in lines:
                        if "open" in line and "/" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                port_protocol = parts[0].split('/')
                                port = int(port_protocol[0])
                                protocol = port_protocol[1]
                                state = parts[1]
                                service = parts[2]
                                version = " ".join(parts[3:]) if len(parts) > 3 else None

                                name = f"Port {port} - {service}"
                                description = f"Port {port} ({service}) est {state}."
                                remediation = "Vérifiez la configuration du service."

                                Vulnerability.objects.create(
                                    scan=scan,
                                    name=name,
                                    description=description,
                                    severity="Medium",
                                    target_url=project.url,
                                    parameter=None,
                                    remediation=remediation,
                                    evidence=f"Protocole: {protocol}, État: {state}, Service: {service}, Version: {version}",
                                    cve_id=None,
                                    status='open',
                                    discovered_at=now()
                                )

                # Mettre à jour le statut du scan
                scan.status = 'completed'
                scan.end_time = now()
                scan.duration = (scan.end_time - scan.start_time).total_seconds()
                scan.save()
                messages.success(request, f"Scan {tool} terminé avec succès.")

            except Exception as e:
                # Gestion des erreurs
                scan.status = 'failed'
                scan.save()
                messages.error(request, f"Erreur lors de l'exécution du scan {tool} : {str(e)}")
        else:
            messages.error(request, "Le formulaire est invalide.")
    return redirect('vulnerabilities')

def export_vulnerabilities(request):
    format = request.GET.get('format', 'json')
    vulnerabilities = Vulnerability.objects.select_related('scan', 'scan__project').all()

    if format == 'json':
        data = list(vulnerabilities.values())
        return JsonResponse(data, safe=False)

    elif format == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="vulnerabilities.csv"'
        writer = csv.writer(response)
        writer.writerow(['ID', 'Nom', 'Projet', 'Sévérité', 'Statut', 'URL cible', 'Découvert le'])
        for vuln in vulnerabilities:
            writer.writerow([
                vuln.id, vuln.name, vuln.scan.project.name, vuln.severity,
                vuln.status, vuln.target_url, vuln.discovered_at
            ])
        return response

    else:
        return JsonResponse({'error': 'Format non pris en charge'}, status=400)


from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from django.utils.timezone import now

def generate_scan_report(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    project = scan.project
    vulnerabilities = scan.vulnerabilities.all()

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="rapport_scan_{scan.id}.pdf"'

    doc = SimpleDocTemplate(response, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=72, bottomMargin=36)
    elements = []
    styles = getSampleStyleSheet()

    # Style personnalisé pour le titre
    title_style = ParagraphStyle(name='TitleStyle', fontSize=24, leading=28, alignment=1, textColor=colors.HexColor("#FFFFFF"), spaceAfter=20)
    subtitle_style = ParagraphStyle(name='SubtitleStyle', fontSize=14, leading=18, alignment=0, textColor=colors.HexColor("#003366"), spaceAfter=10)
    body_style = ParagraphStyle(name='BodyText', parent=styles['Normal'], fontSize=10, leading=14)
    footer_style = ParagraphStyle(name='FooterStyle', fontSize=9, alignment=1, textColor=colors.HexColor("#FFFFFF"), backColor=colors.HexColor("#003366"), spaceBefore=10)

    # Fond bleu
    elements.append(Spacer(1, 12))

    # Informations du scan
    scan_info = f"""
    <b>Nom du Scan :</b> {scan.name}<br/>
    <b>Projet :</b> {project.name}<br/>
    <b>Outil utilisé :</b> {scan.tool}<br/>
    <b>Statut :</b> {scan.status}<br/>
    <b>Durée :</b> {f"{scan.duration:.2f} secondes" if scan.duration else "N/A"}<br/>
    """
    elements.append(Paragraph(scan_info, body_style))
    elements.append(Spacer(1, 12))

    # Titre principal centré et souligné
    title = Paragraph("<u>Rapport de Scan</u>", title_style)
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Résultats du Scan en fonction de l'outil
    if scan.tool == 'NMAP':
        elements.append(Paragraph("Résultats du Scan NMAP", subtitle_style))
        nmap_details = f"""
        <b>Adresse IP cible :</b> {project.ip_address}<br/>
        <b>Ports ouverts :</b> Liste des ports ouverts et services sur {project.ip_address}.<br/>
        """
        elements.append(Paragraph(nmap_details, body_style))

        # Ajouter les vulnérabilités de Nmap
        for vuln in vulnerabilities:
            if vuln.port:
                nmap_vuln_details = f"""
                <b>Port :</b> {vuln.port}<br/>
                <b>Protocole :</b> {vuln.protocol}<br/>
                <b>Service :</b> {vuln.service}<br/>
                <b>Version :</b> {vuln.version}<br/>
                <b>Gravité :</b> {vuln.severity}<br/>
                """
                elements.append(Paragraph(nmap_vuln_details, body_style))

    elif scan.tool == 'SQLMAP':
        elements.append(Paragraph("Résultats du Scan SQLMAP", subtitle_style))
        sqlmap_details = f"""
        <b>Paramètre vulnérable :</b> {', '.join([vuln.parameter for vuln in vulnerabilities if vuln.parameter])}<br/>
        <b>DBMS détecté :</b> {', '.join([vuln.dbms for vuln in vulnerabilities if vuln.dbms])}<br/>
        <b>Technique utilisée :</b> {', '.join([vuln.technique for vuln in vulnerabilities if vuln.technique])}<br/>
        """
        elements.append(Paragraph(sqlmap_details, body_style))

        # Ajouter les vulnérabilités spécifiques à SQLMap
        for vuln in vulnerabilities:
            sqlmap_vuln_details = f"""
            <b>Paramètre :</b> {vuln.parameter or 'Non spécifié'}<br/>
            <b>Technique :</b> {vuln.technique or 'Non spécifiée'}<br/>
            <b>SGBD détecté :</b> {vuln.dbms or 'Non spécifié'}<br/>
            """
            elements.append(Paragraph(sqlmap_vuln_details, body_style))

    elif scan.tool == 'ZAP':
        elements.append(Paragraph("Résultats du Scan ZAP", subtitle_style))
        zap_details = f"""
        <b>Alertes :</b><br/>
        <i>Liste des vulnérabilités détectées par ZAP.</i><br/>
        """
        elements.append(Paragraph(zap_details, body_style))

        # Ajouter les vulnérabilités de ZAP
        for vuln in vulnerabilities:
            zap_vuln_details = f"""
            <b>Alerte :</b> {vuln.alert or 'Non spécifiée'}<br/>
            <b>Risque :</b> {vuln.risk or 'Non spécifié'}<br/>
            <b>Confiance :</b> {vuln.confidence or 'Non spécifiée'}<br/>
            <b>Preuve :</b> {vuln.evidence or 'Non spécifiée'}<br/>
            """
            elements.append(Paragraph(zap_vuln_details, body_style))

    else:
        elements.append(Paragraph("Aucun outil de scan spécifié.", body_style))

    # Pied de page
    elements.append(PageBreak())
    footer = f"""
    <b>EthicalPulse</b> - Rapport généré automatiquement<br/>
    <b>Date :</b> {now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    """
    elements.append(Paragraph(footer, footer_style))

    # Générer le PDF
    doc.build(elements)
    return response


def delete_scan(request, scan_id):
    """
    Supprime un scan spécifique.
    """
    scan = get_object_or_404(Scan, id=scan_id)
    scan.delete()
    messages.success(request, f"Le scan #{scan_id} a été supprimé avec succès.")
    return redirect('vulnerabilities')


def relaunch_scan(request, scan_id):
    # Récupérer le scan existant
    original_scan = get_object_or_404(Scan, id=scan_id)
    try:
        # Créer un nouveau scan basé sur l'original
        new_scan = Scan.objects.create(
            name=f"{original_scan.name} (Relancé)",
            project=original_scan.project,
            tool=original_scan.tool,
            status='in_progress',
            start_time=now(),
        )

        # Relancer le scan en appelant la logique d'exécution
        if new_scan.tool == 'NMAP':
            command = ['nmap', '-sT', '-Pn', '-T4', '-F', new_scan.project.ip_address]
            result = subprocess.run(command, capture_output=True, text=True, timeout=400)
            output = result.stdout
            scan_results = parse_scan_results(output, 'NMAP')
        elif new_scan.tool == 'SQLMAP':
            command = ['sqlmap', '-u', new_scan.project.url, '--batch', '--output-dir=/tmp']
            result = subprocess.run(command, capture_output=True, text=True, timeout=400)
            output = result.stdout
            scan_results = parse_scan_results(output, 'SQLMAP')
        elif new_scan.tool == 'ZAP':
            zap = ZAPv2(apikey='620tjnb5od0ef8tep7n78usun', proxies={'http': 'http://localhost:8086'})
            zap.urlopen(new_scan.project.url)
            zap.spider.scan(new_scan.project.url)
            while int(zap.spider.status()) < 100:
                time.sleep(2)
            zap.ascan.scan(new_scan.project.url)
            while int(zap.ascan.status()) < 100:
                time.sleep(5)
            alerts = zap.core.alerts(baseurl=new_scan.project.url)
            scan_results = {"zap": alerts}
        else:
            messages.error(request, "Outil de scan non pris en charge.")
            return redirect('vulnerabilities')

        # Traiter les résultats et mettre à jour le nouveau scan
        severity_map = classify_scan_findings(scan_results)
        for severity, vulns in severity_map.items():
            for vuln_data in vulns:
                Vulnerability.objects.create(
                    scan=new_scan,
                    name=vuln_data.get('description', 'Vulnérabilité détectée'),
                    description=vuln_data.get('description', ''),
                    severity=severity,
                    target_url=new_scan.project.url,
                    remediation=vuln_data.get('remediation', ''),
                    cve_id=vuln_data.get('cve_id', None),
                    status='open',
                    discovered_at=now()
                )
        new_scan.status = 'completed'
        new_scan.end_time = now()
        new_scan.duration = (new_scan.end_time - new_scan.start_time).total_seconds()
        new_scan.save()
        messages.success(request, f"Le scan {new_scan.name} a été relancé avec succès.")
    except Exception as e:
        new_scan.status = 'failed'
        new_scan.save()
        messages.error(request, f"Erreur lors de la relance du scan : {str(e)}")
    return redirect('vulnerabilities')


@shared_task
def execute_scheduled_scans():
    # Récupérer les scans planifiés dont l'heure est arrivée
    scheduled_scans = Scan.objects.filter(status='scheduled', start_time__lte=now())
    for scan in scheduled_scans:
        try:
            # Mettre à jour le statut à "En cours"
            scan.status = 'in_progress'
            scan.save()

            # Logique pour exécuter le scan (exemple avec ZAP)
            if scan.tool == 'ZAP':
                zap = ZAPv2(apikey='620tjnb5od0ef8tep7n78usun', proxies={'http': 'http://localhost:8086'})
                zap.urlopen(scan.project.url)
                zap.spider.scan(scan.project.url)
                while int(zap.spider.status()) < 100:
                    time.sleep(2)
                zap.ascan.scan(scan.project.url)
                while int(zap.ascan.status()) < 100:
                    time.sleep(5)
                alerts = zap.core.alerts(baseurl=scan.project.url)
                scan_results = {"zap": alerts}

                # Traiter les résultats et mettre à jour le scan
                severity_map = classify_scan_findings(scan_results)
                for severity, vulns in severity_map.items():
                    for vuln_data in vulns:
                        Vulnerability.objects.create(
                            scan=scan,
                            name=vuln_data.get('description', 'Vulnérabilité détectée'),
                            description=vuln_data.get('description', ''),
                            severity=severity,
                            target_url=scan.project.url,
                            remediation=vuln_data.get('remediation', ''),
                            cve_id=vuln_data.get('cve_id', None),
                            status='open',
                            discovered_at=now()
                        )

            # Mettre à jour le statut à "Complet"
            scan.status = 'completed'
            scan.end_time = now()
            scan.duration = (scan.end_time - scan.start_time).total_seconds()
            scan.save()
        except Exception as e:
            # En cas d'erreur, mettre à jour le statut à "Échoué"
            scan.status = 'failed'
            scan.save()



def tools_admin(request):
    return render(request, 'admin/tools.html')

def tools(request):
    return render(request, 'tools/index.html')

def tools_create(request):
    return redirect('tools')

def tools_edit(request, tool_id):
    return redirect('tools')

def tools_delete(request, tool_id):
    return redirect('tools')

def tools_run(request, tool_id):
    return redirect('tools')

def remediations(request):
    return render(request, 'remediation.html')

def remediations_admin(request):
    return render(request, 'admin/remediation.html')

def remediation_detail(request, remediation_id):
    return render(request, 'admin/remediation_detail.html')

def remediations_create(request):
    return redirect('remediations')

def remediations_edit(request, remediation_id):
    return redirect('remediations')

def remediations_delete(request, remediation_id):
    return redirect('remediations')

def remediations_execute(request, remediation_id):
    return redirect('remediations')

def settings_admin(request):
    return render(request, 'admin/settings.html')

def settings_users(request):
    return render(request, 'settings.html')

def logs(request):
    return render(request, 'admin/logs.html')

def errorPage(request):
    return render(request, 'dashboard/404.html')

def history(request):
    return render(request, 'history.html')

def report(request):
    return render(request, 'reports.html')

def training(request):
    return render(request, 'training.html')

def analytics(request):
    return render(request, 'analytics.html')



