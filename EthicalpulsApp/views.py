from datetime import timedelta, datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model,login
import pyotp
import random
from EthicalpulsApp.models import *
from .forms import *
from django.http import JsonResponse
from django.db.models import Count
from django.contrib import messages
from django.urls import reverse
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.db.models import Count


# =================== Pages Générales ===================

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



# def liste_projets(request):
#     projects = Project.objects.all().order_by('-created_at')

#     if request.method == 'POST':
#         form = ProjectForm(request.POST)
#         if form.is_valid():
#             form.save()
#             return redirect('liste_projets')
#     else:
#         form = ProjectForm()

#     return render(request, 'admin/projects.html', {'form': form, 'projects': projects})

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Project
from .forms import ProjectForm
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import JsonResponse
from django.utils import timezone
from django.contrib import messages
from django.db.models import Q
from .models import Project, PROJECT_TYPES
from .forms import ProjectForm
#import datetime

@login_required
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


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
import nmap
import subprocess
import json
from zapv2 import ZAPv2
from .models import Scan, Project
from .forms import ScanForm
import logging

logger = logging.getLogger(__name__)

@login_required
def admin_scans(request):
    """
    View to handle scan listing, creation, and actions (start, stop, etc.).
    """
    if request.method == 'POST':
        if 'add_scan' in request.POST:
            form = ScanForm(request.POST)
            if form.is_valid():
                scan = form.save(commit=False)
                scan.status = 'scheduled'
                scan.save()
                messages.success(request, "Nouveau scan planifié.")
                return redirect('admin_scans')
            else:
                messages.error(request, "Erreur lors de la création du scan.")
        elif 'start_scan' in request.POST:
            scan_id = request.POST.get('scan_id')
            if not scan_id or not scan_id.isdigit():
                messages.error(request, "ID de scan invalide.")
                return redirect('admin_scans')
            scan = get_object_or_404(Scan, id=scan_id)
            if scan.status == 'scheduled':
                scan.status = 'in_progress'
                scan.start_time = timezone.now()
                scan.save()
                # Use project's url or ip_address as target
                target = scan.project.url or scan.project.ip_address or scan.project.domain
                if not target:
                    scan.status = 'failed'
                    scan.end_time = timezone.now()
                    scan.save()
                    messages.error(request, "Le projet n'a pas d'URL ou d'IP valide.")
                    return redirect('admin_scans')
                try:
                    if scan.scan_type in ['INFRA', 'TARGETED']:
                        results = run_nmap_scan(target)
                    elif scan.scan_type in ['API', 'FULL']:
                        results = run_zap_scan(target)
                    else:
                        results = run_openvas_scan(target)
                    scan.findings_summary = results
                    scan.status = 'completed'
                    scan.end_time = timezone.now()
                    scan.save()
                    messages.success(request, f"Le scan « {scan.name} » est terminé.")
                except Exception as e:
                    logger.error(f"Erreur lors du scan {scan.id}: {str(e)}")
                    scan.status = 'failed'
                    scan.end_time = timezone.now()
                    scan.save()
                    messages.error(request, "Erreur lors du lancement du scan.")
            else:
                messages.error(request, "Le scan ne peut pas être démarré.")
            return redirect('admin_scans')
        elif 'stop_scan' in request.POST:
            scan_id = request.POST.get('scan_id')
            if not scan_id or not scan_id.isdigit():
                messages.error(request, "ID de scan invalide.")
                return redirect('admin_scans')
            scan = get_object_or_404(Scan, id=scan_id)
            if scan.status == 'in_progress':
                scan.status = 'failed'
                scan.end_time = timezone.now()
                scan.findings_summary = {"critical": 0, "high": 0, "medium": 0}
                scan.save()
                messages.success(request, f"Le scan « {scan.name} » a été arrêté.")
            else:
                messages.error(request, "Le scan ne peut pas être arrêté.")
            return redirect('admin_scans')
        elif 'edit_scan' in request.POST:
            scan_id = request.POST.get('scan_id')
            if not scan_id or not scan_id.isdigit():
                messages.error(request, "ID de scan invalide.")
                return redirect('admin_scans')
            scan = get_object_or_404(Scan, id=scan_id)
            form = ScanForm(request.POST, instance=scan)
            if form.is_valid():
                form.save()
                messages.success(request, f"Le scan « {scan.name} » a été modifié.")
            else:
                messages.error(request, "Erreur lors de la modification du scan.")
            return redirect('admin_scans')
    else:
        form = ScanForm()

    scans = Scan.objects.select_related('project').all()
    scan_templates = [
        {
            'id': 1,
            'name': 'Scan complet',
            'description': 'Analyse complète incluant toutes les méthodes de test',
            'tools': 'OWASP ZAP, Nmap, OpenVAS',
            'estimated_duration': '45-60 minutes par application'
        },
        {
            'id': 2,
            'name': 'Scan API rapide',
            'description': 'Scan léger pour les API et services REST',
            'tools': 'OWASP ZAP, API Security Scanner',
            'estimated_duration': '15-20 minutes par API'
        },
        {
            'id': 3,
            'name': 'Scan d\'infrastructure',
            'description': 'Analyse des serveurs et de l\'infrastructure réseau',
            'tools': 'Nmap, OpenVAS',
            'estimated_duration': '30-40 minutes par segment réseau'
        }
    ]
    context = {
        'scans': scans,
        'form': form,
        'scan_templates': scan_templates,
    }
    return render(request, 'admin/scans.html', context)

def run_nmap_scan(target):
    """
    Execute Nmap scan for INFRA or TARGETED scans.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-sV -O -p1-1000')
        findings = {"critical": 0, "high": 0, "medium": 0}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        findings['medium'] += 1
        return findings
    except Exception as e:
        logger.error(f"Nmap scan error: {str(e)}")
        return {"critical": 0, "high": 0, "medium": 0}

def run_zap_scan(target):
    """
    Execute OWASP ZAP scan for API or FULL scans.
    """
    zap = ZAPv2(apikey='your-zap-api-key', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
    try:
        zap.urlopen(target)
        zap.spider.scan(target)
        zap.ascan.scan(target)
        alerts = zap.core.alerts(baseurl=target)
        findings = {"critical": 0, "high": 0, "medium": 0}
        for alert in alerts:
            risk = alert.get('risk')
            if risk == 'High':
                findings['high'] += 1
            elif risk == 'Medium':
                findings['medium'] += 1
            elif risk == 'Low':
                findings['medium'] += 1
        return findings
    except Exception as e:
        logger.error(f"ZAP scan error: {str(e)}")
        return {"critical": 0, "high": 0, "medium": 0}

def run_openvas_scan(target):
    """
    Execute OpenVAS scan for FULL scans.
    """
    try:
        cmd = f"gvm-cli socket --gmp-username admin --gmp-password admin --xml '<create_task><name>Scan {target}</name><target>{target}</target></create_task>'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        findings = {"critical": 0, "high": 0, "medium": 0}
        return findings
    except Exception as e:
        logger.error(f"OpenVAS scan error: {str(e)}")
        return {"critical": 0, "high": 0, "medium": 0}

@login_required
def get_scan_progress(request, scan_id):
    """
    API endpoint to fetch scan progress (simulated for now).
    """
    scan = get_object_or_404(Scan, id=scan_id)
    if scan.status == 'in_progress':
        return JsonResponse({'status': scan.status, 'progress': 50})
    return JsonResponse({'status': scan.status, 'progress': 100})

@login_required
def get_scan_details(request, scan_id):
    """
    API endpoint to fetch scan details for editing.
    """
    scan = get_object_or_404(Scan, id=scan_id)
    data = {
        'name': scan.name,
        'scan_type': scan.scan_type,
        'target_url': scan.target_url,
        'next_scan': scan.next_scan.isoformat() if scan.next_scan else '',
        'project': scan.project.id,
    }
    return JsonResponse(data)

def scans_start(request, scan_id):
    return redirect('scans')

def scans_cancel(request, scan_id):
    return redirect('scans')

def vulnerabilities(request):
    return render(request, 'vulnerabilities.html')

def vulnerabilities_admin(request):
    return render(request, 'admin/vulnerabilities.html')

def vulnerabilities_create(request):
    return redirect('vulnerabilities')

def vulnerabilities_edit(request, vuln_id):
    return redirect('vulnerabilities')

def vulnerabilities_delete(request, vuln_id):
    return redirect('vulnerabilities')

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

def scans_admin(request):
    return render(request, 'admin/scans.html')
