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

@login_required
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

@login_required
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


def vulnerabilities_view(request):
    projects = Project.objects.all()
    scans = Scan.objects.prefetch_related('vulnerabilities').all()
    vulnerabilities = Vulnerability.objects.select_related('scan', 'scan__project').all()
    form = ScanForm()

    project_filter = request.GET.get('project')
    severity_filter = request.GET.get('severity')
    status_filter = request.GET.get('status')

    if project_filter:
        vulnerabilities = vulnerabilities.filter(scan__project_id=project_filter)
    if severity_filter:
        vulnerabilities = vulnerabilities.filter(severity__iexact=severity_filter)
    if status_filter:
        vulnerabilities = vulnerabilities.filter(status__iexact=status_filter)

    # Ajouter les sévérités pour chaque scan
    for scan in scans:
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in scan.vulnerabilities.all():
            severity_key = vuln.severity.lower()  # Convertir en minuscules
            if severity_key in severities:
                severities[severity_key] += 1
            else:
                severities["info"] += 1  # Ajouter à "info" si la sévérité est inconnue

        # Ajouter la durée du scan
        if scan.start_time and scan.end_time:
            scan.duration = scan.end_time - scan.start_time
        else:
            scan.duration = None
        
        
   # Statistiques dynamiques
    critical_vulns = Vulnerability.objects.filter(severity='critical').count()
    high_vulns = Vulnerability.objects.filter(severity='high').count()
    medium_vulns = Vulnerability.objects.filter(severity='medium').count()
    low_vulns = Vulnerability.objects.filter(severity='low').count()

    total_vulns = critical_vulns + high_vulns + medium_vulns + low_vulns
     # Pourcentage
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

    for result in scan_results.get("nmap", []):
        for port_info in result.get("protocols", []):
            severity = get_nmap_severity(port_info['service'], port_info['port'])
            severity_map[severity].append({
                "tool": "Nmap",
                "description": f"{port_info['port']}/{port_info['protocol']} - {port_info['service']}",
                "state": port_info['state']
            })

    for alert in scan_results.get("zap", []):
        zap_sev = alert.get("risk", "Informational").lower()
        severity = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info"
        }.get(zap_sev, "info")
        severity_map[severity].append({
            "tool": "ZAP",
            "description": alert.get("alert", "Unknown issue"),
            "url": alert.get("url", "")
        })

    for vuln in scan_results.get("sqlmap", []):
        sql_sev = vuln.get("risk", "info").lower()
        if "high" in sql_sev:
            severity = "high"
        elif "medium" in sql_sev:
            severity = "medium"
        elif "low" in sql_sev:
            severity = "low"
        else:
            severity = "info"
        severity_map[severity].append({
            "tool": "SQLMap",
            "description": vuln.get("description", "Injection détectée"),
            "parameter": vuln.get("parameter", "")
        })

    for issue in scan_results.get("apisec", []):
        risk = issue.get("risk", "info").lower()
        if "critical" in risk:
            severity = "critical"
        elif "high" in risk:
            severity = "high"
        elif "medium" in risk:
            severity = "medium"
        elif "low" in risk:
            severity = "low"
        else:
            severity = "info"
        severity_map[severity].append({
            "tool": "API Security Scanner",
            "description": issue.get("issue", "API issue"),
            "endpoint": issue.get("endpoint", "")
        })

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
            results["sqlmap"].append({
                "risk": "high",
                "description": "Injection SQL détectée.",
                "parameter": "non précisé"
            })

    elif tool == 'ZAP':
        lines = output.lower().splitlines()
        for line in lines:
            if "alert" in line or "xss" in line:
                results["zap"].append({
                    "risk": "high",
                    "alert": "XSS détectée",
                    "url": "inconnue"
                })

    return results



def launch_scan(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            # Créer un scan avec le statut "in_progress"
            scan = form.save(commit=False)
            scan.status = 'in_progress'
            scan.start_time = now()
            scan.save()

            tool = scan.tool
            project = scan.project
            target_url = project.url

            if not target_url:
                messages.error(request, "Le projet sélectionné n'a pas d'URL définie.")
                return JsonResponse({'error': "Le projet sélectionné n'a pas d'URL définie."}, status=400)

            try:
                # Lancer le scan en fonction de l'outil
                if tool == 'ZAP':
                    zap = ZAPv2(apikey='620tjnb5od0ef8tep7n78usun', proxies={'http': 'http://zap:8086'})
                    zap.urlopen(target_url)
                    zap.spider.scan(target_url)
                    while int(zap.spider.status()) < 100:
                        time.sleep(2)
                    zap.ascan.scan(target_url)
                    while int(zap.ascan.status()) < 100:
                        time.sleep(5)
                    alerts = zap.core.alerts(baseurl=target_url)
                    for alert in alerts:
                        Vulnerability.objects.create(
                            scan=scan,
                            name=alert.get('alert', 'Vulnérabilité détectée'),
                            description=alert.get('description', ''),
                            severity=alert.get('risk', 'Medium'),
                            target_url=alert.get('url', target_url),
                            remediation=alert.get('solution', ''),
                            cve_id=alert.get('cweid', None),
                            alert=alert.get('alert', ''),
                            risk=alert.get('risk', ''),
                            confidence=alert.get('confidence', ''),
                            parameter=alert.get('param', ''),
                            evidence=alert.get('evidence', ''),
                            reference=alert.get('reference', ''),
                            status='open',
                            discovered_at=now()
                        )

                elif tool == 'SQLMAP':
                    command = ['sqlmap', '-u', target_url, '--batch', '--output-dir=/tmp', '--flush-session']
                    result = subprocess.run(command, capture_output=True, text=True)
                    output = result.stdout.lower()
                    if "is vulnerable" in output:
                        parameter = None
                        technique = None
                        if "parameter:" in output:
                            parameter_start = output.find("parameter:") + len("parameter:")
                            parameter_end = output.find("\n", parameter_start)
                            parameter = output[parameter_start:parameter_end].strip()
                        if "technique:" in output:
                            technique_start = output.find("technique:") + len("technique:")
                            technique_end = output.find("\n", technique_start)
                            technique = output[technique_start:technique_end].strip()
                        Vulnerability.objects.create(
                            scan=scan,
                            name="SQL Injection",
                            description="SQLMap a détecté une injection SQL.",
                            severity="High",
                            target_url=target_url,
                            remediation="Utiliser des requêtes préparées et échapper les entrées.",
                            parameter=parameter,
                            technique=technique,
                            status='open',
                            discovered_at=now()
                        )

                elif tool == 'NMAP':
                    command = ['nmap', '-sT', '-Pn', '-T4', '-F', target_url]
                    result = subprocess.run(command, capture_output=True, text=True)
                    output = result.stdout
                    lines = output.splitlines()
                    for line in lines:
                        if "open" in line and "/" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                port_protocol = parts[0].split('/')
                                port = int(port_protocol[0])
                                protocol = port_protocol[1]
                                state = parts[1]
                                service = parts[2]
                                Vulnerability.objects.create(
                                    scan=scan,
                                    name=f"{port}/{protocol} - {service}",
                                    description=f"Port {port} ({service}) est ouvert.",
                                    severity="Medium",
                                    port=port,
                                    protocol=protocol,
                                    state=state,
                                    service=service,
                                    status='open',
                                    discovered_at=now()
                                )

                # Mettre à jour le statut du scan
                scan.status = 'completed'
                scan.end_time = now()
                scan.duration = (scan.end_time - scan.start_time).total_seconds()
                scan.save()
                return JsonResponse({'message': 'Scan terminé avec succès.', 'scan_id': scan.id})
            except Exception as e:
                scan.status = 'failed'
                scan.save()
                return JsonResponse({'error': f"Erreur lors de l'exécution du scan : {str(e)}"}, status=500)
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



def generate_scan_report(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="rapport_scan_{scan.id}.pdf"'

    doc = SimpleDocTemplate(response, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Styles personnalisés
    title_style = ParagraphStyle(
        name='TitleStyle',
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#003366"),
        spaceAfter=20
    )
    subtitle_style = ParagraphStyle(
        name='SubtitleStyle',
        fontSize=14,
        leading=18,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#003366"),
        spaceAfter=10
    )
    footer_style = ParagraphStyle(
        name='FooterStyle',
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#FFFFFF"),
        backColor=colors.HexColor("#003366"),
        spaceBefore=10
    )

    # Logo
    logo_path = os.path.join('static', 'logo.png')
    if os.path.exists(logo_path):
        elements.append(Image(logo_path, width=1.5 * inch, height=1.5 * inch))

    # Titre principal
    elements.append(Paragraph(f"Rapport de Scan #{scan.id}", title_style))
    elements.append(Spacer(1, 12))

    # Détails du scan
    elements.append(Paragraph("Détails du Scan", subtitle_style))
    details = [
        ["Nom du Scan", scan.name],
        ["Projet", scan.project.name],
        ["Adresse IP", scan.project.ip_address or 'N/A'],
        ["URL", scan.project.url or 'N/A'],
        ["Outil utilisé", scan.tool],
        ["Durée", f"{scan.duration} secondes" if scan.duration else "N/A"],
        ["Statut", scan.status]
    ]
    table_details = Table(details, hAlign='LEFT', colWidths=[2.5 * inch, 4 * inch])
    table_details.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#D3D3D3')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    elements.append(table_details)
    elements.append(Spacer(1, 24))

    # Résultats des vulnérabilités
    elements.append(Paragraph("<b>Vulnérabilités détectées :</b>", styles['Heading2']))

    # Générer le tableau des vulnérabilités en fonction de l'outil
    data = []
    if scan.tool.lower() == "nmap":
        data = [["Port", "Protocole", "État", "Service", "Description"]]
        for vuln in scan.vulnerabilities.all():
            data.append([
                vuln.port or "-",
                vuln.protocol or "-",
                vuln.state or "-",
                vuln.service or "-",
                vuln.description or "-"
            ])

    elif scan.tool.lower() == "zap":
        data = [["Nom", "Risque", "Confiance", "Paramètre", "Preuve", "CWE", "Autres Infos"]]
        for vuln in scan.vulnerabilities.all():
            data.append([
                vuln.name or "-",
                vuln.risk or "-",
                vuln.confidence or "-",
                vuln.parameter or "-",
                vuln.evidence or "-",
                vuln.cve_id or "-",  # CWE ID
                vuln.description or "-"
            ])

    elif scan.tool.lower() == "sqlmap":
        data = [["Nom", "Paramètre", "Technique", "Description", "Remédiation"]]
        for vuln in scan.vulnerabilities.all():
            data.append([
                vuln.name or "-",
                vuln.parameter or "-",
                vuln.technique or "-",
                vuln.description or "-",
                vuln.remediation or "-"
            ])

    # Vérifier si des données sont disponibles
    if len(data) > 1:  # Si le tableau contient des données (en plus de l'en-tête)
        table_vulns = Table(data, hAlign='LEFT', repeatRows=1, colWidths=[1.5 * inch] * len(data[0]))
        table_vulns.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#003366")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F5F5F5')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(table_vulns)
    else:
        elements.append(Paragraph("Aucune vulnérabilité détectée.", styles['Normal']))

    elements.append(Spacer(1, 24))

    # Pied de page
    footer = Paragraph("EthicalPulse &copy; 2025 - Rapport généré par EthicalPulseShield.", footer_style)
    elements.append(Spacer(1, 24))
    elements.append(footer)

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



