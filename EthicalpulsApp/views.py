# =================== Imports Standard ===================
from optparse import Option
import random
import re
import tempfile
import time
import json
import os
from datetime import timedelta, datetime
from EthicalpulsApp.aircrack_scan.aircrack_views import handle_aircrack_scan
from EthicalpulsApp.beef_scan.beef_views import handle_beef_scan
from EthicalpulsApp.ghidra_scan.ghidra_views import handle_ghidra_scan
from EthicalpulsApp.hashcat_scan.hashcat_views import handle_hashcat_scan
from EthicalpulsApp.john_scan.john_views import handle_john_scan
from EthicalpulsApp.metasploit_scan.metasploit_views import handle_metasploit_scan
from EthicalpulsApp.netcat_scan.netcat_views import handle_netcat_scan
from EthicalpulsApp.nikto_scan.nikto_views import handle_nikto_scan
from EthicalpulsApp.nmap_scan.run_nmap_views import handle_nmap_scan
from EthicalpulsApp.reconng_scan.reconng_views import handle_reconng_scan
from EthicalpulsApp.snort_scan.snort_views import handle_snort_scan
from EthicalpulsApp.sqlmap_scan.sqlmap_views import handle_sqlmap_scan
from EthicalpulsApp.utils import run_nmap_scan
from EthicalpulsApp.utils import run_aircrack_scan, run_beef_scan, run_ghidra_analysis, run_hashcat_scan, run_john_scan, run_metasploit_scan, run_reconng_scan, run_snort_scan, run_sqlmap_scan, run_wifite_scan, run_wireshark_capture, run_zap_scan
from EthicalpulsApp.utils.netcat_scan import run_netcat_scan
from EthicalpulsApp.utils.nikto_scan import run_nikto_scan
from EthicalpulsApp.wifite_scan.wifite_views import handle_wifite_scan
from EthicalpulsApp.wireshark_scan.wireshark_views import handle_wireshark_scan
from EthicalpulsApp.zap_scan.zap_views import handle_zap_scan
from zapv2 import ZAPv2
import subprocess
import logging
import pyotp


# Configure logger
logger = logging.getLogger(__name__)
from django.db import transaction
import nmap
from reportlab.lib import colors
# =================== Imports Django ===================
from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, JsonResponse, HttpResponse
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

from django.core.paginator import Paginator

from django.core.paginator import Paginator

def users(request):
    user_list = User.objects.all()
    paginator = Paginator(user_list, 12)  # 12 utilisateurs par page
    page_number = request.GET.get('page')
    users_page = paginator.get_page(page_number)

    return render(request, 'admin/users.html', {
        'users_list': users_page
    })

def log(request):
    """
    View to handle the log page.
    """
    # Here you can implement logic to fetch logs if needed
    return render(request, 'admin/logs.html')   

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


def get_base_context(request):
    return {
        'projects': Project.objects.all(),
        'current_project': request.session.get('current_project'),
    }



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


logger = logging.getLogger(__name__)

@login_required
@require_http_methods(["GET", "POST"])
def tools_admin(request):
    if request.method == "POST":
        tool_name = request.POST.get("tool", "").strip().upper()
        project_id = request.POST.get("project_id", "").strip()
        option = request.POST.get("option", "").strip()
        target_port = request.POST.get("target_port", "").strip()

        if not project_id.isdigit():
            messages.error(request, "ID de projet invalide.")
            return redirect('tools_admin')

        project = get_object_or_404(Project, id=int(project_id))

        tool_handlers = {
            'NETCAT': lambda: handle_netcat_scan(project, option, target_port, request),
            'NIKTO': lambda: handle_nikto_scan(project, option, request),
            'NMAP': lambda: handle_nmap_scan(project, option, request),
            'ZAP': lambda: handle_zap_scan(project, option, request),
            'SQLMAP': lambda: handle_sqlmap_scan(request),  # retourne une redirection, pas un tuple
            'AIRCRACK': lambda: handle_aircrack_scan(project, option, request),
            'BEEF': lambda: handle_beef_scan(project, option, request),
            'METASPLOIT': lambda: handle_metasploit_scan(project, option, request),
            'HASHCAT': lambda: handle_hashcat_scan(project, option, request),
            'JOHN': lambda: handle_john_scan(project, option, request),
            'RECONNG': lambda: handle_reconng_scan(project, option, request),
            'WIRESHARK': lambda: handle_wireshark_scan(project, option, request),
            'WIFITE': lambda: handle_wifite_scan(project, option, request),
            'GHIDRA': lambda: handle_ghidra_scan(project, option, request),
            'SNORT': lambda: handle_snort_scan(project, option, request),
        }

        handler = tool_handlers.get(tool_name)

        if handler:
            # ✅ SQLMAP retourne directement une réponse, on ne décompose pas
            if tool_name == "SQLMAP":
                return handler()  # retourne HttpResponseRedirect

            # ✅ Autres outils : on suppose qu'ils retournent (success, message)
            success, message = handler()
            if success:
                messages.success(request, message)
            else:
                messages.error(request, message)
        else:
            messages.error(request, f"Outil '{tool_name}' non pris en charge.")

        return redirect('tools_admin')

    # GET
    context = prepare_tools_context()
    return render(request, 'admin/tools.html', context)

def prepare_tools_context():
    """Prépare le contexte pour la vue tools_admin"""
    def get_options(model):
        try:
            return model._meta.get_field('option').choices
        except Exception as e:
            logger.error(f"Erreur options pour {model.__name__}: {e}")
            return []

    options = {
        "nmap_options": get_options(NmapResult),
        "zap_options": get_options(OwaspZapResult),
        "sqlmap_options": SQLMAP_OPTIONS,
        "aircrack_options": get_options(AircrackngResult),
        "beef_options": get_options(BeefResult),
        "metasploit_options": get_options(MetasploitResult),
        "hashcat_options": get_options(HashcatResult),
        "john_options": get_options(JohntheripperResult),
        "reconng_options": get_options(ReconngResult),
        "wireshark_options": get_options(WiresharkResult),
        "ghidra_options": get_options(GhidraResult),
        "snort_options": get_options(SnortResult),
        "wifite_options": get_options(WifiteResult),
        "netcat_options": get_options(NetcatResult),
        "nikto_options": get_options(NiktoResult),
    }

    nikto_results = NiktoResult.objects.select_related('scan').order_by('-scan__start_time')[:10]

    return {
        "projects": Project.objects.all(),
        'scans_history': Scan.objects.select_related('project')
            .prefetch_related(
                'nmap_results',
                'niktoresults',
                'sqlmapresults',
                # Ajoute ici les related_name de tous tes outils si besoin
            ).order_by('-start_time')[:100],  # Mets une valeur assez grande pour voir tous les scans
        "nikto_results": nikto_results,
        **options,
    }




def tools(request):
    return render(request, 'tools/index.html')

def tools_create(request):
    return redirect('tools')

def afficher_sortie_scan(scan):
    try:
        if scan.tool == 'NMAP':
            result = scan.nmap_results.last()
            if result:
                print("\n--- Sortie brute Nmap ---")
                print(result.full_output)
                print("--- Fin de sortie Nmap ---\n")
            else:
                print("Aucun résultat Nmap disponible pour ce scan.")
        elif scan.tool == 'NIKTO':
            result = scan.nikto_results.last()
            if result:
                print("\n--- Sortie brute Nikto ---")
                print(result.full_output)
                print("--- Fin de sortie Nikto ---\n")
            else:
                print("Aucun résultat Nikto disponible pour ce scan.")
        # ➕ Ajoute les autres outils si nécessaire
        else:
            print(f"Affichage non implémenté pour l'outil {scan.tool}")
    except Exception as e:
        print(f"Erreur lors de l'affichage de la sortie brute : {e}")

from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.contrib import messages
from datetime import datetime
import csv
import json
import xml.etree.ElementTree as ET
from .models import SystemLog
from .decorators import admin_required

@login_required
@admin_required
def logs_view(request):
    # Filtres
    log_type = request.GET.get('type')
    log_level = request.GET.get('level')
    
    # Query de base
    logs = SystemLog.objects.all()
    
    # Application des filtres
    if log_type:
        logs = logs.filter(type=log_type)
    if log_level:
        logs = logs.filter(level=log_level)
    
    # Pagination
    paginator = Paginator(logs, 25)  # 25 logs par page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'logs': page_obj,
        'current_type': log_type,
        'current_level': log_level,
    }
    
    return render(request, 'admin/logs.html', context)


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
import csv
import json
from datetime import datetime

@login_required
def export_logs(request):
    if request.method != 'POST':
        messages.error(request, 'Méthode non autorisée')
        return redirect('logs')
        
    # Get export parameters
    export_format = request.POST.get('format', 'csv')
    date_from = request.POST.get('date_from')
    date_to = request.POST.get('date_to')
    
    # Build query
    logs = SystemLog.objects.all()
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
        
    # Handle different export formats
    if export_format == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="logs.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Date', 'Type', 'Niveau', 'Utilisateur', 'IP', 'Message'])
        
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.get_type_display(),
                log.get_level_display(),
                str(log.user) if log.user else 'Système',
                log.ip_address or '-',
                log.message
            ])
            
        return response
        
    elif export_format == 'json':
        data = [{
            'date': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'type': log.get_type_display(),
            'level': log.get_level_display(),
            'user': str(log.user) if log.user else 'Système',
            'ip': log.ip_address or '-',
            'message': log.message,
            'data': log.data
        } for log in logs]
        
        response = HttpResponse(
            json.dumps(data, indent=2),
            content_type='application/json'
        )
        response['Content-Disposition'] = 'attachment; filename="logs.json"'
        return response
        
    else:  # xml format
        # Add XML export handling if needed
        messages.error(request, 'Format XML non supporté pour le moment')
        return redirect('logs')



from django.contrib import messages
from EthicalpulsApp.models import Scan

def dashboard_view(request):
    if request.user.is_authenticated:
        recent_scans = Scan.objects.filter(
            scheduled_scan__created_by=request.user,
            status='completed',
            notified=False
        )
        for scan in recent_scans:
            messages.info(request, f"Le scan '{scan.name}' s’est terminé avec succès à {scan.end_time.strftime('%d/%m/%Y %H:%M')}.")
            scan.notified = True
            scan.save()
    
    # Reste du code

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
import json
from .services.analytics_service import AnalyticsService
from .utils.json_encoder import CustomJSONEncoder

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
import json
from django.db.models import Count, Avg, F, Q, ExpressionWrapper, fields
from django.db.models.functions import TruncDate, Greatest
from .models import Scan, Vulnerability, Project
from .utils.json_encoder import CustomJSONEncoder

@login_required
def analytics_dashboard(request):
    # Get period parameters
    period = request.GET.get('period', '30d')
    project_id = request.GET.get('project')
    end_date = timezone.now()
    
    # Calculate start date based on period
    if period == '7d':
        start_date = end_date - timedelta(days=7)
    elif period == '90d':
        start_date = end_date - timedelta(days=90)
    elif period == '1y':
        start_date = end_date - timedelta(days=365)
    elif period == 'custom':
        try:
            start_date = timezone.datetime.strptime(request.GET.get('start_date'), '%Y-%m-%d')
            end_date = timezone.datetime.strptime(request.GET.get('end_date'), '%Y-%m-%d')
        except (TypeError, ValueError):
            start_date = end_date - timedelta(days=30)
    else:  # default 30d
        start_date = end_date - timedelta(days=30)

    # Base filters
    scan_filters = {'created_at__range': [start_date, end_date]}
    vuln_filters = {'discovered_at__range': [start_date, end_date]}
    
    if project_id:
        scan_filters['project_id'] = project_id
        vuln_filters['scan__project_id'] = project_id

    # Get data for scan metrics
    scans = Scan.objects.filter(**scan_filters)
    scan_metrics = {
        'total_count': scans.count(),
        'trend_data': list(
            scans.annotate(date=TruncDate('created_at'))
            .values('date')
            .annotate(count=Count('id'))
            .order_by('date')
            .values_list('count', flat=True)
        ),
        'trend_labels': list(
            scans.annotate(date=TruncDate('created_at'))
            .values('date')
            .annotate(count=Count('id'))
            .order_by('date')
            .values_list('date', flat=True)
        )
    }

    # Get data for vulnerability metrics
    vulnerabilities = Vulnerability.objects.filter(**vuln_filters)
    total_vulns = vulnerabilities.count()
    vuln_metrics = {
        'total_count': total_vulns,
        'by_severity': {
            'critical': vulnerabilities.filter(severity='critical').count(),
            'high': vulnerabilities.filter(severity='high').count(),
            'medium': vulnerabilities.filter(severity='medium').count(),
            'low': vulnerabilities.filter(severity='low').count()
        },
        'by_status': {
            'open': vulnerabilities.filter(status='open').count(),
            'in_progress': vulnerabilities.filter(status='in_progress').count(),
            'resolved': vulnerabilities.filter(status='resolved').count(),
            'closed': vulnerabilities.filter(status='closed').count()
        },
        'resolution_rate': (vulnerabilities.filter(status__in=['resolved', 'closed']).count() / total_vulns * 100) if total_vulns > 0 else 0
    }

    # Get data for tool metrics
    tool_metrics = {
        'labels': [],
        'data': [],
        'detection_rate': [],
        'success_rate': []
    }
    
    tools_data = scans.values('tool').annotate(
        count=Count('id'),
        success_count=Count('id', filter=Q(status='completed')),
        vuln_count=Count('vulnerabilities')
    ).order_by('-count')
    
    for tool in tools_data:
        tool_metrics['labels'].append(tool['tool'])
        tool_metrics['data'].append(tool['count'])
        tool_metrics['success_rate'].append(
            (tool['success_count'] / tool['count'] * 100) if tool['count'] > 0 else 0
        )
        tool_metrics['detection_rate'].append(
            (tool['vuln_count'] / tool['success_count']) if tool['success_count'] > 0 else 0
        )

    # Get data for project metrics
    project_metrics = {
        'labels': [],
        'data': [],
        'details': []
    }

    projects = Project.objects.filter(
        scans__created_at__range=[start_date, end_date]
    ).distinct().annotate(
        scan_count=Count('scans', filter=Q(scans__created_at__range=[start_date, end_date])),
        vuln_count=Count('scans__vulnerabilities', filter=Q(scans__created_at__range=[start_date, end_date])),
        critical_count=Count('scans__vulnerabilities', 
                           filter=Q(scans__vulnerabilities__severity='critical',
                                  scans__created_at__range=[start_date, end_date])),
        high_count=Count('scans__vulnerabilities',
                        filter=Q(scans__vulnerabilities__severity='high',
                               scans__created_at__range=[start_date, end_date])),
        resolved_count=Count('scans__vulnerabilities',
                           filter=Q(scans__vulnerabilities__status__in=['resolved', 'closed'],
                                  scans__created_at__range=[start_date, end_date]))
    ).annotate(
        resolution_rate=ExpressionWrapper(
            F('resolved_count') * 100.0 / Greatest(F('vuln_count'), 1),
            output_field=fields.FloatField()
        )
    ).order_by('-vuln_count')

    for project in projects:
        project_metrics['labels'].append(project.name)
        project_metrics['data'].append(project.vuln_count)
        project_metrics['details'].append({
            'name': project.name,
            'scan_count': project.scan_count,
            'vuln_count': project.vuln_count,
            'critical_count': project.critical_count,
            'high_count': project.high_count,
            'resolution_rate': project.resolution_rate
        })

    # Calculate variations with previous period
    previous_start = start_date - (end_date - start_date)
    previous_end = start_date - timedelta(days=1)
    
    previous_scans = Scan.objects.filter(created_at__range=[previous_start, previous_end])
    previous_vulns = Vulnerability.objects.filter(discovered_at__range=[previous_start, previous_end])
    
    variations = {
        'scan_count': ((scan_metrics['total_count'] - previous_scans.count()) / 
                      previous_scans.count() * 100) if previous_scans.count() > 0 else 0,
        'vuln_count': ((vuln_metrics['total_count'] - previous_vulns.count()) / 
                      previous_vulns.count() * 100) if previous_vulns.count() > 0 else 0,
        'resolution_rate': vuln_metrics['resolution_rate'] - (
            (previous_vulns.filter(status__in=['resolved', 'closed']).count() / 
             previous_vulns.count() * 100) if previous_vulns.count() > 0 else 0
        ),
    }

    context = {
        'period': period,
        'start_date': start_date,
        'end_date': end_date,
        'projects': Project.objects.all(),
        'selected_project': project_id,
        'variations': variations,
        # JSON data for charts
        'scan_metrics_json': json.dumps(scan_metrics, cls=CustomJSONEncoder),
        'vuln_metrics_json': json.dumps(vuln_metrics, cls=CustomJSONEncoder),
        'tool_metrics_json': json.dumps(tool_metrics, cls=CustomJSONEncoder),
        'project_metrics_json': json.dumps(project_metrics, cls=CustomJSONEncoder),
        # Raw data for template
        'scan_metrics': scan_metrics,
        'vuln_metrics': vuln_metrics,
        'tool_metrics': tool_metrics,
        'project_metrics': project_metrics
    }

    return render(request, 'analytics.html', context)


# views.py
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages

@require_POST
@login_required
def relaunch_scan(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    # Crée un nouveau scan avec les mêmes paramètres
    new_scan = Scan.objects.create(
        name=f"{scan.name} (Relancé {timezone.now():%Y-%m-%d %H:%M:%S})",
        project=scan.project,
        tool=scan.tool,
        status='scheduled',
        start_time=timezone.now(),
        created_by=request.user
    )
    # Relance la tâche selon l'outil
    if scan.tool == 'NMAP':
        from EthicalpulsApp.utils.run_nmap_scan import run_nmap_scan
        transaction.on_commit(lambda: run_nmap_scan.delay(new_scan.id, scan.nmap_results.first.option if scan.nmap_results.exists() else None))
    elif scan.tool == 'NIKTO':
        from EthicalpulsApp.utils.nikto_scan import run_nikto_scan
        transaction.on_commit(lambda: run_nikto_scan.delay(new_scan.id, scan.nikto_results.first.option if scan.nikto_results.exists() else None))
    elif scan.tool == 'SQLMAP':
        from EthicalpulsApp.utils.run_sqlmap_scan import run_sqlmap_scan
        options = scan.sqlmap_results.first.options_used.split() if scan.sqlmap_results.exists() else []
        transaction.on_commit(lambda: run_sqlmap_scan.delay(new_scan.id, options))
    # ... autres outils ...
    messages.success(request, "Scan relancé avec succès.")
    return redirect('scans')

from django.http import JsonResponse, Http404

def completed_scan_details(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    # Prépare un dict avec toutes les infos utiles
    data = {
        "id": scan.id,
        "name": scan.name,
        "tool": scan.tool,
        "status": scan.status,
        "start_time": scan.start_time.strftime("%d/%m/%Y %H:%M"),
        "end_time": scan.end_time.strftime("%d/%m/%Y %H:%M") if scan.end_time else "",
        "project": scan.project.name if scan.project else "",
        "target": scan.target_ip or (scan.project.url if scan.project else ""),
        "created_by": scan.created_by.get_full_name() if scan.created_by else "",
        "vulnerability_count": scan.vulnerability_count,
        # Ajoute ici les champs spécifiques à chaque outil si besoin
    }
    # Ajoute les résultats spécifiques selon l’outil
    if scan.tool.upper() == "NMAP" and hasattr(scan, "nmap_results"):
        result = scan.nmap_results.first()
        if result:
            data["result"] = {
                "command": result.command_used,
                "option": result.option,
                "os_detected": result.os_detected,
                "open_tcp_ports": result.open_tcp_ports,
                "service_details": result.service_details,
                "full_output": result.full_output[:2000],
            }
    elif scan.tool.upper() == "NIKTO" and hasattr(scan, "nikto_results"):
        result = scan.nikto_results.first()
        if result:
            data["result"] = {
                "uri": result.uri,
                "vulnerability": result.vulnerability,
                "server": result.server,
                "ssl_subject": result.ssl_subject,
                "ssl_issuer": result.ssl_issuer,
                "nikto_raw_output": result.nikto_raw_output[:2000],
            }
    elif scan.tool.upper() == "SQLMAP" and hasattr(scan, "sqlmap_results"):
        result = scan.sqlmap_results.first()
        if result:
            data["result"] = {
                "target_url": result.target_url,
                "options_used": result.options_used,
                "is_vulnerable": result.is_vulnerable,
                "injection_type": result.injection_type,
                "dbms": result.dbms,
                "payloads": result.payloads,
                "raw_output": result.raw_output[:2000],
            }
    return JsonResponse(data)