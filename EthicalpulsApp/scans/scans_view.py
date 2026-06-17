from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse
from django.contrib import messages
from django.utils.timezone import now, make_aware, is_naive
from datetime import timedelta, datetime
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from ..models import Scan, ScheduledScan, ScanTemplate
from ..forms import ScanForm
from ..utils.run_scheduled_scan import run_scheduled_scan
from django.core.paginator import Paginator

from EthicalpulsApp.forms import ScheduledScanForm
from EthicalpulsApp.models import Scan, ScheduledScan, UserNotification

# Tâche Celery
from EthicalpulsApp.utils.run_scheduled_scan import run_scheduled_scan


##############################
# Gestion des scans planifiés
##############################



@login_required
def scan_list(request):
    """
    Vue principale qui gère tous les onglets : active, completed, failed, scheduled, templates.
    Affiche les modals dans scans.html.
    """
    user = request.user
    section = request.GET.get("tab", "active")

    # --- SCANS ACTIFS (in_progress, scheduled)
    if user.is_superuser or user.is_staff:
        active_query = Scan.objects.filter(
            status__in=["in_progress", "scheduled"]
        ).order_by("-created_at")
    else:
        active_query = Scan.objects.filter(
            status__in=["in_progress", "scheduled"], created_by=user
        ).order_by("-created_at")

    active_paginator = Paginator(active_query, 8)
    active_page = request.GET.get("active_page")
    active_scans = active_paginator.get_page(active_page)

    # --- SCANS TERMINÉS
    if user.is_superuser or user.is_staff:
        completed_query = Scan.objects.filter(status="completed").order_by("-end_time")
    else:
        completed_query = Scan.objects.filter(
            status="completed", created_by=user
        ).order_by("-end_time")

    completed_paginator = Paginator(completed_query, 10)
    completed_page = request.GET.get("completed_page")
    completed_scans = completed_paginator.get_page(completed_page)

    # --- SCANS ÉCHOUÉS (optional)
    if user.is_superuser or user.is_staff:
        failed_query = Scan.objects.filter(status__in=["failed", "error"]).order_by(
            "-end_time"
        )
    else:
        failed_query = Scan.objects.filter(
            status__in=["failed", "error"], created_by=user
        ).order_by("-end_time")

    failed_paginator = Paginator(failed_query, 10)
    failed_page = request.GET.get("failed_page")
    failed_scans = failed_paginator.get_page(failed_page)

    # --- SCANS PLANIFIÉS
    scheduled_scans = ScheduledScan.objects.filter(created_by=user).order_by(
        "next_run_time"
    )

    # --- TEMPLATES DE SCAN
    scan_templates = ScanTemplate.objects.all().order_by("name")

    # --- CONTEXTE FINAL
    context = {
        "section": section,
        "active_scans": active_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "scheduled_scans": scheduled_scans,
        "scan_templates": scan_templates,
        "form": ScheduledScanForm(),
    }

    return render(request, "scans.html", context)



@login_required
def active_scans(request):
    """Récupère les scans actifs pour affichage dans le modal"""
    active_scans = Scan.objects.filter(
        status__in=["in_progress", "scheduled"]
    ).order_by("-created_at")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        data = [
            {
                "id": scan.id,
                "name": scan.name,
                "status": scan.status,
                "progress": scan.progress,
                "created_at": scan.created_at.isoformat(),
                "tool": scan.tool.name,
                "target": str(scan.target),
            }
            for scan in active_scans
        ]
        return JsonResponse({"scans": data})

    # Si ce n'est pas une requête AJAX, on redirige vers la vue principale
    return redirect("scan_list")


from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required

from EthicalpulsApp.models import (
    Scan,
    NmapResult,
    NiktoResult,
    SqlmapResult,
    OwaspZapResult,
)


@login_required
def completed_scans(request):
    """Récupère les scans terminés pour affichage dans le modal avec pagination"""
    completed_scans = Scan.objects.filter(status="completed").order_by("-end_time")

    paginator = Paginator(completed_scans, 10)
    page = request.GET.get("page")
    scans = paginator.get_page(page)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        data = {
            "scans": [
                {
                    "id": scan.id,
                    "name": scan.name,
                    "end_time": scan.end_time.isoformat() if scan.end_time else None,
                    "duration": (
                        scan.get_duration() if hasattr(scan, "get_duration") else None
                    ),
                    "vulnerability_count": (
                        NmapResult.objects.filter(scan=scan).count()
                        + NiktoResult.objects.filter(scan=scan).count()
                        + SqlmapResult.objects.filter(scan=scan).count()
                        + OwaspZapResult.objects.filter(scan=scan).count()
                        # Ajoute ici d'autres modèles de résultats si besoin
                    ),
                    "tool": scan.tool if hasattr(scan, "tool") else "-",
                    "target": str(scan.target) if hasattr(scan, "target") else "-",
                }
                for scan in scans
            ],
            "has_next": scans.has_next(),
            "has_previous": scans.has_previous(),
            "page": scans.number,
            "total_pages": scans.paginator.num_pages,
        }
        return JsonResponse(data)

    return redirect("scan_list")



@login_required
def scan_templates(request):
    """Récupère les templates pour affichage dans le modal"""
    templates = ScanTemplate.objects.all().order_by("name")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        data = [
            {
                "id": template.id,
                "name": template.name,
                "description": template.description,
                "tool": template.tool.name if template.tool else None,
                "target_type": template.target_type,
                "created_by": template.created_by.username,
                "created_at": template.created_at.isoformat(),
            }
            for template in templates
        ]
        return JsonResponse({"templates": data})

    return redirect("scan_list")


@login_required
def stop_scan(request, scan_id):
    """Arrête un scan en cours."""
    if request.method == "POST":
        scan = get_object_or_404(Scan, id=scan_id, status="in_progress")
        try:
            scan.stop_scan()
            messages.success(request, "Scan arrêté avec succès")
        except Exception as e:
            messages.error(request, f"Erreur lors de l'arrêt du scan: {str(e)}")
        return redirect("scan_list")
    return JsonResponse({"error": "Méthode non autorisée"}, status=405)


@login_required
def delete_scan(request, scan_id):
    """Supprime un scan."""
    if request.method == "POST":
        scan = get_object_or_404(Scan, id=scan_id)
        try:
            scan.delete()
            messages.success(request, "Scan supprimé avec succès")
        except Exception as e:
            messages.error(request, f"Erreur lors de la suppression: {str(e)}")
        return redirect("scan_list")
    return JsonResponse({"error": "Méthode non autorisée"}, status=405)



from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.http import JsonResponse, Http404
from django.contrib import messages
from EthicalpulsApp.models import ScheduledScan, Scan
from EthicalpulsApp.forms import ScheduledScanForm

@login_required
def restart_scan(request, scan_id):
    if request.method != "POST":
        return JsonResponse({"error": "Méthode non autorisée"}, status=405)

    original_scan = get_object_or_404(Scan, id=scan_id)
    try:
        new_scan = Scan.objects.create(
            name=f"Relancé: {original_scan.name}",
            project=original_scan.project,
            tool=original_scan.tool,
            created_by=request.user,
            target_ip=original_scan.target_ip,
            target_url=original_scan.target_url,
            status="pending",
        )
        run_scheduled_scan.delay(new_scan.id)
        messages.success(request, "Scan relancé avec succès")
    except Exception as e:
        messages.error(request, f"Erreur lors du redémarrage: {str(e)}")
    return redirect("scan_list")


@login_required
def delete_scheduled_scan(request, scan_id):
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    scan.delete()
    messages.success(request, "Scan planifié supprimé avec succès")
    return redirect("scan_list")


@login_required
def scheduled_scans(request):
    scans = ScheduledScan.objects.filter(created_by=request.user).order_by("next_run_time")
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        data = [
            {
                "id": scan.id,
                "name": scan.name,
                "next_run_time": scan.next_run_time.isoformat() if scan.next_run_time else None,
                "frequency": scan.frequency,
                "is_active": scan.is_active,
                "tool": scan.tool.name,
                "target": str(scan.target),
                "remaining_time": scan.get_remaining_time(),
            }
            for scan in scans
        ]
        return JsonResponse({"scans": data})
    return redirect("scan_list")


@login_required
def create_scheduled_scan(request):
    if request.method == "POST":
        form = ScheduledScanForm(request.POST)
        if form.is_valid():
            scan = form.save(commit=False)
            scan.created_by = request.user

            if not scan.next_run_time:
                scan.next_run_time = scan.calculate_next_run()

            scan.save()

            if scan.is_active:
                run_scheduled_scan.apply_async(args=[scan.id], eta=scan.next_run_time)

            messages.success(request, "Scan planifié créé avec succès")
            return redirect("scan_list")
        else:
            # Affiche les erreurs dans les messages
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field} : {error}")
            messages.error(request, "Erreur lors de la création du scan planifié")
            return redirect("scan_list")
    return JsonResponse({"error": "Méthode non autorisée"}, status=405)



@login_required
def edit_scheduled_scan(request, scan_id):
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    if request.method == "POST":
        form = ScheduledScanForm(request.POST, instance=scan)
        if form.is_valid():
            form.save()
            messages.success(request, "Scan planifié mis à jour avec succès")
            return JsonResponse({"success": True})
        return JsonResponse({"success": False, "errors": form.errors})
    return JsonResponse({"success": False, "error": "Méthode non autorisée"})


@login_required
def toggle_scheduled_scan(request, scan_id):
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    scan.is_active = not scan.is_active
    scan.save()
    status = "activé" if scan.is_active else "désactivé"
    messages.success(request, f"Scan planifié {status}")
    return redirect("scan_list")


@login_required
def run_scheduled_scan_now(request, scan_id):
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Méthode non autorisée"})

    scan = get_object_or_404(ScheduledScan, id=scan_id)
    try:
        new_scan = Scan.objects.create(
            name=scan.name,
            project=scan.target,
            tool=scan.tool,
            created_by=request.user,
            scheduled_scan=scan,
            status="pending",
        )
        run_scheduled_scan.delay(new_scan.id)
        return JsonResponse({"success": True})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})


@login_required
def manage_scheduled_scan(request, scan_id=None):
    scan = get_object_or_404(ScheduledScan, id=scan_id) if scan_id else None

    if request.method == "POST":
        form = ScheduledScanForm(request.POST, instance=scan)
        if "delete" in request.POST:
            scan.delete()
            messages.success(request, "Scan planifié supprimé avec succès")
            return redirect("scan_list")
        elif "toggle_active" in request.POST:
            scan.is_active = not scan.is_active
            scan.save()
            status = "activé" if scan.is_active else "désactivé"
            messages.success(request, f"Scan planifié {status}")
            return redirect("scan_list")

        if form.is_valid():
            scan = form.save(commit=False)
            scan.created_by = request.user
            scan.next_run_time = scan.calculate_next_run()
            scan.save()
            if scan.is_active:
                run_scheduled_scan.apply_async(args=[scan.id], eta=scan.next_run_time)
            messages.success(request, "Scan planifié mis à jour avec succès")
            return redirect("scan_list")
        else:
            messages.error(request, "Erreur lors de la soumission du formulaire")

    else:
        form = ScheduledScanForm(instance=scan)

    context = {"form": form, "scan": scan}
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"errors": form.errors})
    return render(request, "scans.html", context)


@login_required
@login_required
def get_scheduled_scan_data(request, scan_id):
    print(f"Utilisateur connecté: {request.user} (email: {request.user.email if request.user else 'N/A'})")
    try:
        scan = ScheduledScan.objects.get(pk=scan_id, created_by=request.user)
    except ScheduledScan.DoesNotExist:
        print("Scan non trouvé ou accès refusé")
        return JsonResponse({"error": "Scan planifié non trouvé."}, status=404)

    data = {
        "id": scan.id,
        "name": scan.name,
        "description": scan.description,
        "tool": scan.tool,
        "target": scan.target.id if scan.target else None,
        "frequency": scan.frequency,
        "next_run_time": scan.next_run_time.isoformat() if scan.next_run_time else "",
        "is_active": scan.is_active,
        "remaining_time": scan.get_remaining_time(),
    }
    return JsonResponse(data)

