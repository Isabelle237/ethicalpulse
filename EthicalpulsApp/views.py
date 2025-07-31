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
from EthicalpulsApp.utils import (
    run_aircrack_scan,
    run_beef_scan,
    run_ghidra_analysis,
    run_hashcat_scan,
    run_john_scan,
    run_metasploit_scan,
    run_reconng_scan,
    run_snort_scan,
    run_sqlmap_scan,
    run_wifite_scan,
    run_wireshark_capture,
    run_zap_scan,
)
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

# from reportlab.lib.colors import HexColor, black, white, colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# =================== Imports Spécifiques au Projet ===================
from EthicalpulsApp.models import *
from .forms import *
from .models import *

# =================== Imports de Bibliothèques Externes ===================
from celery import shared_task

# =================== Imports pour les Scans et Vulnérabilités ===================
from .models import Project, Scan, ScheduledScan
from .forms import ScanForm

from django.core.paginator import Paginator

from django.core.paginator import Paginator


def users(request):
    user_list = User.objects.all()
    paginator = Paginator(user_list, 12)  # 12 utilisateurs par page
    page_number = request.GET.get("page")
    users_page = paginator.get_page(page_number)

    return render(request, "admin/users.html", {"users_list": users_page})


@login_required
def log(request):
    """
    View to read and display application logs.
    """
    log_file_path = os.path.join(settings.BASE_DIR, "logs/app.log")
    logs = []

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as file:
            logs = file.readlines()[-200:]  # Affiche les 200 dernières lignes

    return render(request, "admin/logs.html", {"logs": logs})


def index(request):
    return render(request, "dashboard/index.html")


from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import Project, Scan, SystemLog


from django.db.models import Count
from datetime import timedelta
from django.utils import timezone
from .models import (
    Project,
    Scan,
    SystemLog,
    NmapResult,
    NiktoResult,
    SqlmapResult,
    OwaspZapResult,
)


@login_required
def dashboard(request):
    # Filtres dynamiques
    project_id = request.GET.get("project")
    severity = request.GET.get("severity")
    vuln_type = request.GET.get("type")

    scan_qs = Scan.objects.all()
    project_qs = Project.objects.all()

    # Filtrage des résultats par projet
    nmap_qs = NmapResult.objects.all()
    nikto_qs = NiktoResult.objects.all()
    sqlmap_qs = SqlmapResult.objects.all()
    zap_qs = OwaspZapResult.objects.all()

    if project_id:
        scan_qs = scan_qs.filter(project_id=project_id)
        nmap_qs = nmap_qs.filter(scan__project_id=project_id)
        nikto_qs = nikto_qs.filter(scan__project_id=project_id)
        sqlmap_qs = sqlmap_qs.filter(project_id=project_id)
        zap_qs = zap_qs.filter(scan__project_id=project_id)

    # Pour la "gravité", on utilise les risques ZAP et les vulnérabilités Nikto/SQLMap
    # On considère "risk" de ZAP et "is_vulnerable" de SQLMap, et la présence de vulnérabilité dans Nikto

    # Score global (exemple simple : 100 - % de vulnérabilités élevées)
    total_findings = (
        zap_qs.count()
        + nikto_qs.exclude(vulnerability__isnull=True).count()
        + sqlmap_qs.filter(is_vulnerable=True).count()
    )
    high_crit = (
        zap_qs.filter(risk__in=["High", "Critical"]).count()
        + nikto_qs.filter(vulnerability__icontains="critique").count()
        + sqlmap_qs.filter(is_vulnerable=True).count()
    )
    core_score = (
        max(0, 100 - int((high_crit / total_findings) * 100)) if total_findings else 100
    )

    # Vulnérabilités par gravité (on utilise risk pour ZAP, et on mappe les autres)
    vuln_by_severity = {
        "critical": zap_qs.filter(risk__iexact="Critical").count(),
        "high": zap_qs.filter(risk__iexact="High").count(),
        "medium": zap_qs.filter(risk__iexact="Medium").count(),
        "low": zap_qs.filter(risk__iexact="Low").count(),
        "info": zap_qs.filter(risk__iexact="Informational").count(),
    }
    # Ajout Nikto/SQLMap si besoin
    vuln_by_severity["high"] += nikto_qs.filter(
        vulnerability__icontains="critique"
    ).count()
    vuln_by_severity["medium"] += nikto_qs.filter(
        vulnerability__icontains="moyenne"
    ).count()
    vuln_by_severity["low"] += nikto_qs.filter(
        vulnerability__icontains="faible"
    ).count()
    vuln_by_severity["high"] += sqlmap_qs.filter(is_vulnerable=True).count()

    # Evolution dans le temps (30 derniers jours)
    today = timezone.now().date()
    vuln_over_time = []
    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        count = (
            zap_qs.filter(scan__start_time__date=day).count()
            + nikto_qs.filter(scan__start_time__date=day).count()
            + sqlmap_qs.filter(scan__start_time__date=day, is_vulnerable=True).count()
        )
        vuln_over_time.append({"date": day.strftime("%d/%m"), "count": count})

    # Top findings ZAP (par vulnérabilité)
    top_vulns = (
        zap_qs.values("vulnerability")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )

    # Projets à risque (score = % de findings critiques/hautes)
    projects_risk = []
    for p in project_qs:
        zap_count = OwaspZapResult.objects.filter(scan__project=p).count()
        nikto_count = (
            NiktoResult.objects.filter(scan__project=p)
            .exclude(vulnerability__isnull=True)
            .count()
        )
        sqlmap_count = SqlmapResult.objects.filter(
            project=p, is_vulnerable=True
        ).count()
        total = zap_count + nikto_count + sqlmap_count
        high = (
            OwaspZapResult.objects.filter(
                scan__project=p, risk__in=["High", "Critical"]
            ).count()
            + NiktoResult.objects.filter(
                scan__project=p, vulnerability__icontains="critique"
            ).count()
            + SqlmapResult.objects.filter(project=p, is_vulnerable=True).count()
        )
        score = max(0, 100 - int((high / total) * 100)) if total else 100
        projects_risk.append({"name": p.name, "score": score})
    projects_risk = sorted(projects_risk, key=lambda x: x["score"])

    # Actions recommandées (exemple simple)
    recommendations = []
    if vuln_by_severity["critical"] > 0:
        recommendations.append(
            "Corrigez immédiatement les vulnérabilités critiques détectées (ZAP/Nikto/SQLMap)."
        )
    if vuln_by_severity["high"] > 0:
        recommendations.append("Priorisez la correction des vulnérabilités élevées.")
    if not recommendations:
        recommendations.append("Aucune action urgente recommandée.")

    # Alertes & notifications (logs récents)
    alerts = SystemLog.objects.order_by("-timestamp")[:10]

    # Filtres dynamiques
    severities = ["critical", "high", "medium", "low", "info"]
    types = list(zap_qs.values_list("vulnerability", flat=True).distinct())
    projects = project_qs

    context = {
        "core_score": core_score,
        "vuln_by_severity": vuln_by_severity,
        "vuln_over_time": vuln_over_time,
        "top_vulns": top_vulns,
        "projects_risk": projects_risk,
        "recommendations": recommendations,
        "alerts": alerts,
        "projects": projects,
        "severities": severities,
        "types": types,
    }
    return render(request, "admin/dashboard.html", context)


# =================== Utilisateurs ===================


from django.utils.crypto import get_random_string

from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.core.mail import send_mail
from django.conf import settings
from django.utils.html import strip_tags
from django.contrib import messages
from django.template.loader import render_to_string
import pyotp

@csrf_protect
@login_required
def create_user_view(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            try:
                # Génération du mot de passe temporaire
                generated_password = get_random_string(length=10)

                user = form.save(commit=False)
                user.set_password(generated_password)  # encodage
                user.is_active = True

                if not user.otp_secret:
                    user.otp_secret = pyotp.random_base32()

                user.save()

                # Préparer l'email de confirmation
                html_message = render_to_string(
                    "emails/account_confirmation.html",
                    {
                        "username": user.username,
                        "email": user.email,
                        "password": generated_password,
                    },
                )
                plain_message = strip_tags(html_message)

                send_mail(
                    subject="Votre compte a été créé avec succès",
                    message=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )

                messages.success(request, "L'utilisateur a été créé et le mot de passe a été envoyé.")
                return redirect("users")  # PRG Pattern

            except Exception as e:
                messages.error(request, f"Erreur lors de la création : {str(e)}")
                return redirect("users")

        else:
            messages.error(request, "Le formulaire est invalide.")
            return redirect("users")  # Évite de rester sur POST même en cas d'erreur

    else:
        form = CustomUserCreationForm()

    users_list = CustomUser.objects.all()
    return render(request, "admin/users.html", {"form": form, "users_list": users_list})


def edit_user_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        role = request.POST.get("role")
        is_active_str = request.POST.get("is_active")
        is_active = True if is_active_str == "True" else False

        # Validation simple
        if not username or not email or not role:
            messages.error(request, "Tous les champs sont requis.")
            return redirect("users")

        user.username = username
        user.email = email
        user.role = role  # Assure-toi que ton modèle a bien ce champ
        user.is_active = is_active

        user.save()
        messages.success(request, "Utilisateur mis à jour avec succès.")
        return redirect("users")

    # En GET, redirection simple
    return redirect("users")


@require_POST
def delete_user_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    messages.success(request, "L'utilisateur a été supprimé.")
    return redirect("users")


@require_POST
def delete_multiple_users_view(request):
    ids = request.POST.getlist("user_ids[]")
    if ids:
        CustomUser.objects.filter(id__in=ids).delete()
        messages.success(request, f"{len(ids)} utilisateur(s) supprimé(s).")
    else:
        messages.warning(request, "Aucun utilisateur sélectionné.")
    return redirect("users")


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from .models import Project, CustomUser
from .forms import ProjectForm
import json


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from .models import Project, CustomUser
from .forms import ProjectForm
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from .models import Project, CustomUser
from .forms import ProjectForm
import json
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.contrib.auth.decorators import login_required


@require_GET
@login_required
def get_project_json(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    data = {
        "id": project.id,
        "name": project.name,
        "domain": project.domain,
        "url": project.url,
        "ip_address": project.ip_address,
        "description": project.description,
        "project_type": getattr(project, "project_type", ""),
        "is_active": project.is_active,
        "allowed_users": [u.id for u in project.allowed_users.all()],
    }
    return JsonResponse(data)


@login_required
@csrf_protect
def admin_projets(request):
    projects = Project.objects.prefetch_related("allowed_users").all()
    users = CustomUser.objects.all()
    project_types = Project.objects.values_list("project_type", flat=True).distinct()
    form = ProjectForm()

    if request.method == "POST":
        # Ajout d'un projet
        if "add_project" in request.POST:
            form = ProjectForm(request.POST)
            if form.is_valid():
                url = form.cleaned_data["url"]
                ip = form.cleaned_data["ip_address"]
                domain = form.cleaned_data["domain"]
                # Vérification unicité
                if (
                    Project.objects.filter(url=url).exists()
                    or Project.objects.filter(ip_address=ip).exists()
                    or Project.objects.filter(domain=domain).exists()
                ):
                    messages.error(
                        request, "Un projet existe déjà avec cette URL, IP ou domaine."
                    )
                else:
                    project = form.save(commit=False)
                    if "is_active" in form.cleaned_data:
                        project.is_active = form.cleaned_data["is_active"]
                    project.save()
                    form.save_m2m()
                    messages.success(request, "Nouveau projet ajouté.")
                return redirect("admin_projets")
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
                return redirect("admin_projets")

        # Edition d'un projet
        elif "edit_project" in request.POST:
            project_id = request.POST.get("project_id")
            project = get_object_or_404(Project, id=project_id)
            form = ProjectForm(request.POST, instance=project)

            if form.is_valid():
                url = form.cleaned_data["url"]
                ip = form.cleaned_data["ip_address"]
                domain = form.cleaned_data["domain"]

                if (
                    Project.objects.exclude(id=project.id).filter(url=url).exists()
                    or Project.objects.exclude(id=project.id)
                    .filter(ip_address=ip)
                    .exists()
                    or Project.objects.exclude(id=project.id)
                    .filter(domain=domain)
                    .exists()
                ):
                    messages.error(
                        request, "Un projet existe déjà avec cette URL, IP ou domaine."
                    )
                else:
                    form.save()
                    messages.success(request, "Projet modifié avec succès.")
                return redirect("admin_projets")
            else:
                messages.error(request, "Erreur lors de la modification du projet.")
                return redirect("admin_projets")

        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            return redirect("admin_projets")

        # Suppression d'un projet
    elif "delete_project" in request.POST:
        project_id = request.POST.get("project_id")
        project = get_object_or_404(Project, id=project_id)
        project.delete()
        messages.success(request, f"Le projet « {project.name} » a été supprimé.")
        return redirect("admin_projets")

    # Préparation des données pour le JS
    projects_json = [
        {
            "id": p.id,
            "name": p.name,
            "domain": p.domain,
            "url": p.url,
            "ip_address": p.ip_address,
            "description": p.description,
            "project_type": getattr(p, "project_type", ""),
            "is_active": getattr(p, "is_active", True),
            "allowed_users": [u.id for u in p.allowed_users.all()],
        }
        for p in projects
    ]
    users_json = [{"id": u.id, "username": u.username, "email": u.email} for u in users]
    status_chart = {
        "labels": ["Actif", "Inactif"],
        "data": [
            (
                projects.filter(is_active=True).count()
                if hasattr(Project, "is_active")
                else projects.count()
            ),
            (
                projects.filter(is_active=False).count()
                if hasattr(Project, "is_active")
                else 0
            ),
        ],
    }
    user_chart = {
        "labels": [u.username for u in users],
        "data": [
            u.allowed_projects.count() for u in users
        ],  # adapte le related_name si besoin
    }

    context = {
        "projects": projects,
        "form": form,
        "users": users,
        "project_types": project_types,
        "projects_json": json.dumps(projects_json),
        "users_json": json.dumps(users_json),
        "status_chart": json.dumps(status_chart),
        "user_chart": json.dumps(user_chart),
    }
    return render(request, "admin/projects.html", context)


@require_POST
@login_required
def delete_project(request):
    project_id = request.POST.get("project_id")
    project = get_object_or_404(Project, id=project_id)
    project.delete()
    messages.success(request, f"Le projet « {project.name} » a été supprimé.")
    return redirect("admin_projets")

def projects_chart_type(request):
    """
    API view to provide data for the project type doughnut chart.
    """
    data = (
        Project.objects.values("project_type")
        .annotate(count=Count("id"))
        .order_by("project_type")
    )
    chart_data = [
        {
            "project_type": dict(PROJECT_TYPES).get(
                item["project_type"], item["project_type"]
            ),
            "count": item["count"],
        }
        for item in data
    ]
    return JsonResponse({"data": chart_data})


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
            created_at__gte=current_date, created_at__lt=next_date
        ).count()
        data.append({"month": current_date.strftime("%Y-%m"), "count": count})
        current_date = next_date
    return JsonResponse({"data": data})


@csrf_protect
def email_login(request):
    if request.method == "POST":
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            user = authenticate(request, email=email, password=password)
            if user:
                otp_code = str(
                    random.randint(100000, 999999)
                )  # Nouveau code à chaque connexion

                user.otp_code = otp_code  # Stocke le code OTP dans l'utilisateur
                user.otp_created_at = timezone.now()  # Stocke la date de création
                user.save()

                # Envoi du code OTP par email
                send_otp_email(user.email, otp_code, user)

                # Enregistre l'ID utilisateur dans la session pour la vérification ultérieure
                request.session["otp_user_id"] = user.id
                return redirect("verify_otp")
            else:
                messages.error(request, "Identifiants invalides.")
    else:
        form = EmailLoginForm()

    return render(request, "registration/login.html", {"form": form})


@csrf_protect
def otp_verification(request):
    if request.method == "POST":
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data["otp_code"]
            user_id = request.session.get(
                "otp_user_id"
            )  # Récupère l'ID utilisateur depuis la session

            if user_id:  # Vérifie que l'ID utilisateur existe dans la session
                try:
                    user = CustomUser.objects.get(id=user_id)

                    # Vérification de l'OTP et de la validité dans le temps
                    if (
                        user.otp_code == otp_code
                        and user.otp_created_at
                        and timezone.now() - user.otp_created_at
                        <= timedelta(minutes=10)
                    ):
                        auth_login(request, user)  # Connecte l'utilisateur
                        user.otp_code = None  # Supprime le code OTP après la validation
                        user.otp_created_at = None
                        user.save()  # Sauvegarde les modifications dans la base de données

                        # Redirige en fonction du rôle de l'utilisateur
                        if user.is_staff:  # Si l'utilisateur est un admin
                            return redirect("analytics_dashboard")
                        else:  # Sinon, redirige vers les utilisateurs
                            return redirect("analytics_dashboard")
                    else:
                        messages.error(
                            request, "Code OTP invalide ou expiré."
                        )  # Message d'erreur
                except CustomUser.DoesNotExist:
                    messages.error(
                        request, "Utilisateur introuvable."
                    )  # Si l'utilisateur n'existe pas
            else:
                messages.error(
                    request, "Session expirée. Veuillez recommencer."
                )  # Si l'ID utilisateur n'est pas dans la session
    else:
        form = OTPVerificationForm()

    return render(request, "registration/otp_verification.html", {"form": form})


def send_otp_email(email, otp_code, user):
    context = {
        "otp_code": otp_code,
        "user": user,
        "current_year": datetime.now().year,
    }
    subject = "Votre code OTP - Ethical Pulse Shield"
    message = render_to_string("emails/otp_confirmation.html", context)
    send_mail(subject, "", settings.DEFAULT_FROM_EMAIL, [email], html_message=message)


def logout_view(request):
    if request.user.is_authenticated:
        messages.success(request, "Vous avez été déconnecté avec succès.")
    logout(request)  # Déconnecte l'utilisateur
    request.session.flush()  # Nettoie complètement la session
    return redirect("login")


@login_required
def get_project_details(request, project_id):
    """
    API endpoint to fetch project details for scan form.
    """
    project = get_object_or_404(Project, id=project_id)
    data = {
        "name": project.name,
        "url": project.url,
        "ip_address": project.ip_address,
        "domain": project.domain,
    }
    return JsonResponse(data)


from collections import Counter

from collections import Counter
from django.shortcuts import render, get_object_or_404
from .models import Project, Scan
from .forms import ScanForm

from collections import Counter
from django.shortcuts import render
from .models import Project, Scan
from .forms import ScanForm


def get_base_context(request):
    return {
        "projects": Project.objects.all(),
        "current_project": request.session.get("current_project"),
    }


def tools_edit(request, tool_id):
    return redirect("tools")


def tools_delete(request, tool_id):
    return redirect("tools")


def tools_run(request, tool_id):
    return redirect("tools")


def remediations(request):
    return render(request, "remediation.html")


def remediations_admin(request):
    return render(request, "admin/remediation.html")


def remediation_detail(request, remediation_id):
    return render(request, "admin/remediation_detail.html")


def remediations_create(request):
    return redirect("remediations")


def remediations_edit(request, remediation_id):
    return redirect("remediations")


def remediations_delete(request, remediation_id):
    return redirect("remediations")


def remediations_execute(request, remediation_id):
    return redirect("remediations")


def vulnerabilities_user(request):
    return render(request, "vulnerabilities.html")


def admin_required(user):
    return user.is_superuser or user.is_staff


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from EthicalpulsApp.settings_app import get_app_config, set_app_config


def admin_required(user):
    return user.is_superuser or user.is_staff


@login_required
def settings_admin(request):
    settings = SystemSettings.objects.first()
    logs = SystemLog.objects.order_by("-timestamp")[:50]  # 50 derniers logs
    return render(
        request,
        "admin/settings.html",
        {
            "config": settings,
            "logs": logs,
        },
    )


def settings_users(request):
    return render(request, "settings.html")


def logs(request):
    return render(request, "admin/logs.html")


def errorPage(request):
    return render(request, "dashboard/404.html")


def history(request):
    return render(request, "history.html")


def report(request):
    return render(request, "reports.html")


def training(request):
    return render(request, "training.html")


def analytics(request):
    return render(request, "analytics.html")


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
            return redirect("tools_admin")

        project = get_object_or_404(Project, id=int(project_id))

        tool_handlers = {
            "NETCAT": lambda: handle_netcat_scan(project, option, target_port, request),
            "NIKTO": lambda: handle_nikto_scan(project, option, request),
            "NMAP": lambda: handle_nmap_scan(project, option, request),
            "ZAP": lambda: handle_zap_scan(project, option, request),
            "SQLMAP": lambda: handle_sqlmap_scan(
                request
            ),  # retourne une redirection, pas un tuple
            "AIRCRACK": lambda: handle_aircrack_scan(project, option, request),
            "BEEF": lambda: handle_beef_scan(project, option, request),
            "METASPLOIT": lambda: handle_metasploit_scan(project, option, request),
            "HASHCAT": lambda: handle_hashcat_scan(project, option, request),
            "JOHN": lambda: handle_john_scan(project, option, request),
            "RECONNG": lambda: handle_reconng_scan(project, option, request),
            "WIRESHARK": lambda: handle_wireshark_scan(project, option, request),
            "WIFITE": lambda: handle_wifite_scan(project, option, request),
            "GHIDRA": lambda: handle_ghidra_scan(project, option, request),
            "SNORT": lambda: handle_snort_scan(project, option, request),
        }

        handler = tool_handlers.get(tool_name)

        if handler:
            if tool_name == "SQLMAP":
                return handler()  # retourne HttpResponseRedirect
            success, message = handler()
            if success:
                messages.success(request, message)
            else:
                messages.error(request, message)
        else:
            messages.error(request, f"Outil '{tool_name}' non pris en charge.")

        return redirect("tools_admin")

    # GET : Prépare le contexte pour le tableau et le terminal
    scans = Scan.objects.select_related("project").order_by("-start_time")
    structured_results = []
    for scan in scans:
        structured_results.append(
            {
                "id": scan.id,
                "tool": scan.tool,
                "target_hostname": getattr(scan, "target_hostname", ""),
                "target_port": getattr(scan, "target_port", ""),
                "start_time": scan.start_time,
                "status": scan.status,
                "vulnerability": getattr(scan, "main_vuln", ""),
            }
        )

    # Résultat brut du dernier scan lancé (terminal)
    last_scan = scans.first() if scans else None
    last_raw_output = None
    if last_scan:
        tool = last_scan.tool.upper()
        # NMAP
        if tool == "NMAP" and hasattr(last_scan, "nmap_results"):
            result = last_scan.nmap_results.last()
            if result and getattr(result, "full_output", None):
                last_raw_output = result.full_output
        # NIKTO
        elif tool == "NIKTO" and hasattr(last_scan, "nikto_results"):
            result = last_scan.nikto_results.last()
            if result and getattr(result, "nikto_raw_output", None):
                last_raw_output = result.nikto_raw_output
        # SQLMAP
        elif tool == "SQLMAP" and hasattr(last_scan, "sqlmap_results"):
            result = last_scan.sqlmap_results.last()
            if result and getattr(result, "raw_output", None):
                last_raw_output = result.raw_output
        elif tool == "ZAP" and hasattr(last_scan, "OwaspZapResult"):
            result = last_scan.sqlmap_results.last()
            if result and getattr(result, "raw_output", None):
                last_raw_output = result.raw_output

        # ➕ Ajoute ici les autres outils si besoin (exemple pour Metasploit, etc.)
        # elif tool == "METASPLOIT" and hasattr(last_scan, "metasploit_results"):
        #     result = last_scan.metasploit_results.last()
        #     if result and getattr(result, "raw_output", None):
        #         last_raw_output = result.raw_output

    context = prepare_tools_context()
    context.update(
        {
            "structured_results": structured_results,
            "last_raw_output": last_raw_output,
        }
    )
    return render(request, "admin/tools.html", context)


def prepare_tools_context():
    """Prépare le contexte pour la vue tools_admin"""

    def get_options(model):
        try:
            return model._meta.get_field("option").choices
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

    nikto_results = NiktoResult.objects.select_related("scan").order_by(
        "-scan__start_time"
    )[:10]

    return {
        "projects": Project.objects.all(),
        "scans_history": Scan.objects.select_related("project")
        .prefetch_related(
            "nmap_results",
            "nikto_results",
            "sqlmap_results",
            "OwaspZapResult",
            # Ajoute ici les related_name de tous tes outils si besoin
        )
        .order_by("-start_time")[:100],
        "nikto_results": nikto_results,
        **options,
    }


# Action : supprimer un scan
@require_POST
@login_required
def delete_scan(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    scan.delete()
    messages.success(request, "Scan supprimé avec succès.")
    return redirect("tools_admin")


def tools(request):
    return render(request, "tools/index.html")


def tools_create(request):
    return redirect("tools")


def afficher_sortie_scan(scan):
    try:
        if scan.tool == "NMAP":
            result = scan.nmap_results.last()
            if result:
                print("\n--- Sortie brute Nmap ---")
                print(result.full_output)
                print("--- Fin de sortie Nmap ---\n")
            else:
                print("Aucun résultat Nmap disponible pour ce scan.")
        elif scan.tool == "NIKTO":
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
    log_type = request.GET.get("type")
    log_level = request.GET.get("level")

    # Query de base
    logs = SystemLog.objects.all()

    # Application des filtres
    if log_type:
        logs = logs.filter(type=log_type)
    if log_level:
        logs = logs.filter(level=log_level)

    # Pagination
    paginator = Paginator(logs, 25)  # 25 logs par page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    context = {
        "logs": page_obj,
        "current_type": log_type,
        "current_level": log_level,
    }

    return render(request, "admin/logs.html", context)


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
import csv
import json
from datetime import datetime


@login_required
def export_logs(request):
    if request.method != "POST":
        messages.error(request, "Méthode non autorisée")
        return redirect("logs")

    # Get export parameters
    export_format = request.POST.get("format", "csv")
    date_from = request.POST.get("date_from")
    date_to = request.POST.get("date_to")

    # Build query
    logs = SystemLog.objects.all()
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)

    # Handle different export formats
    if export_format == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="logs.csv"'

        writer = csv.writer(response)
        writer.writerow(["Date", "Type", "Niveau", "Utilisateur", "IP", "Message"])

        for log in logs:
            writer.writerow(
                [
                    log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    log.get_type_display(),
                    log.get_level_display(),
                    str(log.user) if log.user else "Système",
                    log.ip_address or "-",
                    log.message,
                ]
            )

        return response

    elif export_format == "json":
        data = [
            {
                "date": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "type": log.get_type_display(),
                "level": log.get_level_display(),
                "user": str(log.user) if log.user else "Système",
                "ip": log.ip_address or "-",
                "message": log.message,
                "data": log.data,
            }
            for log in logs
        ]

        response = HttpResponse(
            json.dumps(data, indent=2), content_type="application/json"
        )
        response["Content-Disposition"] = 'attachment; filename="logs.json"'
        return response

    else:  # xml format
        # Add XML export handling if needed
        messages.error(request, "Format XML non supporté pour le moment")
        return redirect("logs")


from django.contrib import messages
from EthicalpulsApp.models import Scan


def dashboard_view(request):
    if request.user.is_authenticated:
        recent_scans = Scan.objects.filter(
            scheduled_scan__created_by=request.user, status="completed", notified=False
        )
        for scan in recent_scans:
            messages.info(
                request,
                f"Le scan '{scan.name}' s’est terminé avec succès à {scan.end_time.strftime('%d/%m/%Y %H:%M')}.",
            )
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
from .models import Scan, Project
from .utils.json_encoder import CustomJSONEncoder


from django.db.models import Count, Q
from datetime import timedelta
from django.utils import timezone
import json
from .models import (
    Project,
    Scan,
    SystemLog,
    NmapResult,
    NiktoResult,
    SqlmapResult,
    OwaspZapResult,
)

from collections import Counter
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import json
from .models import (
    Project,
    Scan,
    SystemLog,
    NmapResult,
    NiktoResult,
    SqlmapResult,
    OwaspZapResult,
)
from django.contrib.auth.decorators import login_required

from collections import Counter
from datetime import timedelta
from django.db.models import Count, Q
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def analytics_dashboard(request):
    selected_project = request.GET.get("project")
    period = request.GET.get("period", "30d")
    search = request.GET.get("search", "")
    end_date = timezone.now()
    if period == "7d":
        start_date = end_date - timedelta(days=7)
    elif period == "30d":
        start_date = end_date - timedelta(days=30)
    elif period == "90d":
        start_date = end_date - timedelta(days=90)
    elif period == "1y":
        start_date = end_date - timedelta(days=365)
    elif period == "custom":
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
    else:
        start_date = end_date - timedelta(days=30)

    projects = Project.objects.all()
    scans = Scan.objects.filter(created_at__range=[start_date, end_date])
    nmap_qs = NmapResult.objects.filter(scan__created_at__range=[start_date, end_date])
    nikto_qs = NiktoResult.objects.filter(
        scan__created_at__range=[start_date, end_date]
    )
    sqlmap_qs = SqlmapResult.objects.filter(
        scan__created_at__range=[start_date, end_date]
    )
    zap_qs = OwaspZapResult.objects.filter(
        scan__created_at__range=[start_date, end_date]
    )

    if selected_project:
        scans = scans.filter(project_id=selected_project)
        nmap_qs = nmap_qs.filter(scan__project_id=selected_project)
        nikto_qs = nikto_qs.filter(scan__project_id=selected_project)
        sqlmap_qs = sqlmap_qs.filter(project_id=selected_project)
        zap_qs = zap_qs.filter(scan__project_id=selected_project)

    if search:
        scans = scans.filter(name__icontains=search)
        nmap_qs = nmap_qs.filter(target__icontains=search)
        nikto_qs = nikto_qs.filter(target_hostname__icontains=search)
        sqlmap_qs = sqlmap_qs.filter(injection_type__icontains=search)
        zap_qs = zap_qs.filter(vulnerability__icontains=search)

    # KPIs scans
    scan_metrics = {
        "total_count": scans.count(),
        "last_scan": (
            scans.order_by("-created_at").first().created_at if scans.exists() else None
        ),
        "last_scan_project": (
            scans.order_by("-created_at").first().project.name
            if scans.exists()
            else "-"
        ),
        "trends": {
            "labels": json.dumps(
                [s.created_at.strftime("%d/%m") for s in scans.order_by("created_at")]
            ),
            "data": json.dumps([1 for _ in scans]),
        },
        "success_data": json.dumps(
            [
                scans.filter(status="completed").count(),
                scans.filter(status="failed").count(),
            ]
        ),
    }

    # KPIs findings (tous outils)
    total_findings = (
        nmap_qs.count() + nikto_qs.count() + sqlmap_qs.count() + zap_qs.count()
    )
    resolved = 0  # À adapter si tu ajoutes un champ de résolution
    vuln_metrics = {
        "total_count": total_findings,
        "resolution_rate": (resolved / total_findings * 100) if total_findings else 0,
        "severity": {
            "labels": json.dumps(["Critique", "Élevée", "Moyenne", "Faible", "Info"]),
            "data": json.dumps(
                [
                    zap_qs.filter(risk__iexact="Critical").count(),
                    zap_qs.filter(risk__iexact="High").count()
                    + nikto_qs.filter(vulnerability__icontains="critique").count()
                    + sqlmap_qs.filter(is_vulnerable=True).count(),
                    zap_qs.filter(risk__iexact="Medium").count()
                    + nikto_qs.filter(vulnerability__icontains="moyenne").count(),
                    zap_qs.filter(risk__iexact="Low").count()
                    + nikto_qs.filter(vulnerability__icontains="faible").count(),
                    zap_qs.filter(risk__iexact="Informational").count(),
                ]
            ),
        },
    }

    # Top 5 découvertes récurrentes (tous outils) - version corrigée
    findings = []
    # ZAP : 1 vuln par ligne
    findings += [
        v for v in zap_qs.values_list("vulnerability", flat=True) if v and v != "-"
    ]
    # Nikto : split multi-lignes
    for n in nikto_qs:
        findings += [
            v.strip()
            for v in (n.vulnerability or "").split("\n")
            if v.strip() and v.strip() != "-"
        ]
    # SQLMap : 1 type par ligne
    findings += [
        v for v in sqlmap_qs.values_list("injection_type", flat=True) if v and v != "-"
    ]
    # Nmap : 1 OS détecté par ligne
    findings += [
        v for v in nmap_qs.values_list("os_detected", flat=True) if v and v != "-"
    ]

    # Nettoyage des doublons et vides
    findings = [f for f in findings if f]
    top5_findings = Counter(findings).most_common(5)
    vuln_metrics["top5"] = [
        {"name": name, "count": count} for name, count in top5_findings
    ]

    # Types de découvertes (barres groupées)
    types_counter = Counter(findings)
    types_labels = [name for name, _ in types_counter.most_common(5)]
    types_data = [count for _, count in types_counter.most_common(5)]

    # Projets les plus exposés (courbe pointillée)
    project_exposed = []
    for p in projects:
        count = (
            NmapResult.objects.filter(
                scan__project=p, scan__created_at__range=[start_date, end_date]
            ).count()
            + NiktoResult.objects.filter(
                scan__project=p, scan__created_at__range=[start_date, end_date]
            ).count()
            + SqlmapResult.objects.filter(
                project=p, scan__created_at__range=[start_date, end_date]
            ).count()
            + OwaspZapResult.objects.filter(
                scan__project=p, scan__created_at__range=[start_date, end_date]
            ).count()
        )
        project_exposed.append({"name": p.name, "count": count})
    project_exposed = sorted(project_exposed, key=lambda x: x["count"], reverse=True)[
        :5
    ]
    project_labels = [p["name"] for p in project_exposed]
    project_data = [p["count"] for p in project_exposed]

    # Analyse détaillée par projet
    project_metrics = {
        "vulnerable": {
            "labels": json.dumps(project_labels),
            "data": json.dumps(project_data),
        },
        "most_secure": {
            "name": (
                projects.annotate(
                    crit=Count(
                        "scans__zap_results",
                        filter=Q(scans__zap_results__risk="Critical"),
                    )
                )
                .order_by("crit")
                .first()
                .name
                if projects.exists()
                else "-"
            ),
            "critical_rate": 0,
        },
        "details": [
            {
                "name": p.name,
                "scan_count": p.scans.filter(
                    created_at__range=[start_date, end_date]
                ).count(),
                "finding_count": (
                    NmapResult.objects.filter(
                        scan__project=p, scan__created_at__range=[start_date, end_date]
                    ).count()
                    + NiktoResult.objects.filter(
                        scan__project=p, scan__created_at__range=[start_date, end_date]
                    ).count()
                    + SqlmapResult.objects.filter(
                        project=p, scan__created_at__range=[start_date, end_date]
                    ).count()
                    + OwaspZapResult.objects.filter(
                        scan__project=p, scan__created_at__range=[start_date, end_date]
                    ).count()
                ),
                "critical_count": OwaspZapResult.objects.filter(
                    scan__project=p,
                    risk="Critical",
                    scan__created_at__range=[start_date, end_date],
                ).count(),
                "resolution_rate": 0,
                "avg_resolution_time": "-",
            }
            for p in projects
        ],
    }

    context = {
        "projects": projects,
        "selected_project": selected_project,
        "period": period,
        "start_date": start_date,
        "end_date": end_date,
        "search": search,
        "scan_metrics": scan_metrics,
        "vuln_metrics": vuln_metrics,
        "project_metrics": project_metrics,
        "types_labels": json.dumps(types_labels),
        "types_data": json.dumps(types_data),
        "top5_findings": vuln_metrics["top5"],
        "project_exposed_labels": json.dumps(project_labels),
        "project_exposed_data": json.dumps(project_data),
    }
    return render(request, "analytics.html", context)


from django.http import HttpResponse
import csv
import json

import csv
import json
from django.http import HttpResponse
from django.utils import timezone
from datetime import timedelta
from .models import Project, Scan, NmapResult, NiktoResult, SqlmapResult, OwaspZapResult


@login_required
def export_analytics(request):
    period = request.GET.get("period", "30d")
    project_id = request.GET.get("project")
    export_format = request.GET.get("format", "csv")
    end_date = timezone.now()
    if period == "7d":
        start_date = end_date - timedelta(days=7)
    elif period == "30d":
        start_date = end_date - timedelta(days=30)
    elif period == "90d":
        start_date = end_date - timedelta(days=90)
    elif period == "1y":
        start_date = end_date - timedelta(days=365)
    elif period == "custom":
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
    else:
        start_date = end_date - timedelta(days=30)

    # Récupère les résultats filtrés
    nmap_qs = NmapResult.objects.filter(scan__created_at__range=[start_date, end_date])
    nikto_qs = NiktoResult.objects.filter(
        scan__created_at__range=[start_date, end_date]
    )
    sqlmap_qs = SqlmapResult.objects.filter(
        scan__created_at__range=[start_date, end_date]
    )
    zap_qs = OwaspZapResult.objects.filter(
        scan__created_at__range=[start_date, end_date]
    )

    if project_id:
        nmap_qs = nmap_qs.filter(scan__project_id=project_id)
        nikto_qs = nikto_qs.filter(scan__project_id=project_id)
        sqlmap_qs = sqlmap_qs.filter(project_id=project_id)
        zap_qs = zap_qs.filter(scan__project_id=project_id)

    # Prépare les données à exporter
    data = []
    for obj in nmap_qs:
        d = {f.name: getattr(obj, f.name) for f in obj._meta.fields}
        d["tool"] = "Nmap"
        data.append(d)
    for obj in nikto_qs:
        d = {f.name: getattr(obj, f.name) for f in obj._meta.fields}
        d["tool"] = "Nikto"
        data.append(d)
    for obj in sqlmap_qs:
        d = {f.name: getattr(obj, f.name) for f in obj._meta.fields}
        d["tool"] = "SQLMap"
        data.append(d)
    for obj in zap_qs:
        d = {f.name: getattr(obj, f.name) for f in obj._meta.fields}
        d["tool"] = "OWASP ZAP"
        data.append(d)

    if export_format == "json":
        response = HttpResponse(
            json.dumps(data, indent=2, default=str), content_type="application/json"
        )
        response["Content-Disposition"] = "attachment; filename=analytics.json"
        return response
    else:  # CSV par défaut
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=analytics.csv"
        if data:
            fieldnames = list(data[0].keys())
            writer = csv.DictWriter(response, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        else:
            response.write("Aucune donnée à exporter.")
        return response


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
        status="scheduled",
        start_time=timezone.now(),
        created_by=request.user,
    )
    # Relance la tâche selon l'outil
    if scan.tool == "NMAP":
        from EthicalpulsApp.utils.run_nmap_scan import run_nmap_scan

        transaction.on_commit(
            lambda: run_nmap_scan.delay(
                new_scan.id,
                scan.nmap_results.first.option if scan.nmap_results.exists() else None,
            )
        )
    elif scan.tool == "NIKTO":
        from EthicalpulsApp.utils.nikto_scan import run_nikto_scan

        transaction.on_commit(
            lambda: run_nikto_scan.delay(
                new_scan.id,
                (
                    scan.nikto_results.first.option
                    if scan.nikto_results.exists()
                    else None
                ),
            )
        )
    elif scan.tool == "SQLMAP":
        from EthicalpulsApp.utils.run_sqlmap_scan import run_sqlmap_scan

        options = (
            scan.sqlmap_results.first.options_used.split()
            if scan.sqlmap_results.exists()
            else []
        )
        transaction.on_commit(lambda: run_sqlmap_scan.delay(new_scan.id, options))
    # ... autres outils ...
    messages.success(request, "Scan relancé avec succès.")
    return redirect("scans")


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


from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.shortcuts import render
from .models import AuditLog


from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import render

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def history(request):
    logs = AuditLog.objects.select_related('user').all()

    # Filtres GET
    action = request.GET.get("action", "").strip()
    user_id = request.GET.get("user", "").strip()
    status = request.GET.get("status", "").strip()
    search = request.GET.get("search", "").strip()

    if action:
        logs = logs.filter(action_type=action)
    if user_id.isdigit():
        logs = logs.filter(user__id=user_id)
    if status in ("success", "error"):
        logs = logs.filter(status=status)
    if search:
        logs = logs.filter(
            Q(message__icontains=search) |
            Q(object_repr__icontains=search) |
            Q(object_type__icontains=search)
        )

    logs = logs.order_by("-timestamp")

    paginator = Paginator(logs, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    # Utilisateurs uniques dans les logs pour filtre
    users = (
        AuditLog.objects
        .filter(user__isnull=False)
        .values_list("user__id", "user__username")
        .distinct()
        .order_by("user__username")
    )

    context = {
        "logs": page_obj,
        "users": users,
        "actions": AuditLog.ACTION_TYPES,
        "current_action": action,
        "current_user": user_id,
        "current_status": status,
        "search": search,
    }
    return render(request, "history.html", context)
