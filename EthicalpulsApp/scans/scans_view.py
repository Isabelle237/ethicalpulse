from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.utils.timezone import now, make_aware, is_naive
from datetime import timedelta, datetime
from django.core.paginator import Paginator

from EthicalpulsApp.forms import ScheduledScanForm
from EthicalpulsApp.models import Scan, ScheduledScan, Vulnerability, UserNotification

# Tâche Celery
from EthicalpulsApp.utils.run_scheduled_scan import run_scheduled_scan


##############################
# Gestion des scans planifiés
##############################

@login_required
def manage_scheduled_scan(request, scan_id=None):
    """
    Crée ou met à jour un scan planifié.
    Si scan_id est fourni, un scan existant sera mis à jour,
    sinon un nouveau sera créé.
    """
    if scan_id:
        scan = get_object_or_404(ScheduledScan, id=scan_id)
        if request.method == 'POST':
            if 'delete' in request.POST:
                scan.delete()
                messages.success(request, "Scan planifié supprimé avec succès")
                return redirect('scan_list')
            elif 'toggle_active' in request.POST:
                scan.is_active = not scan.is_active
                scan.save()
                status = "activé" if scan.is_active else "désactivé"
                messages.success(request, f"Scan planifié {status}")
                return redirect('scan_list')
            
            form = ScheduledScanForm(request.POST, instance=scan)
            if form.is_valid():
                scan = form.save(commit=False)
                scan.next_run_time = scan.calculate_next_run()
                scan.save()
                if scan.is_active:
                    run_scheduled_scan.apply_async(args=[scan.id], eta=scan.next_run_time)
                messages.success(request, "Scan planifié mis à jour avec succès")
                return redirect('scan_list')
            else:
                messages.error(request, "Erreur lors de la mise à jour du scan planifié")
        else:
            form = ScheduledScanForm(instance=scan)
    else:
        if request.method == 'POST':
            form = ScheduledScanForm(request.POST)
            if form.is_valid():
                scan = form.save(commit=False)
                scan.created_by = request.user
                scan.save()
                if scan.is_active:
                    run_scheduled_scan.apply_async(args=[scan.id], eta=scan.next_run_time)
                messages.success(request, "Nouveau scan planifié créé avec succès")
                return redirect('scan_list')
            else:
                messages.error(request, "Erreur lors de la création du scan planifié")
        else:
            form = ScheduledScanForm()

    context = {
        'form': form,
        'scan': scan if scan_id else None,
    }
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Pour les requêtes AJAX, on peut renvoyer les erreurs de formulaire.
        return JsonResponse({'errors': form.errors})
    return render(request, 'scans.html', context)


@login_required
def get_scheduled_scan_data(request, scan_id):
    """Retourne les données d'un scan planifié en JSON pour alimenter les modals."""
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    data = {
        'id': scan.id,
        'name': scan.name,
        'description': scan.description,
        'tool': scan.tool,
        'target': scan.target.id if scan.target else None,
        'frequency': scan.frequency,
        'next_run_time': scan.next_run_time.isoformat() if scan.next_run_time else '',
        'email_notification': scan.email_notification,
        'is_active': scan.is_active,
        'remaining_time': scan.get_remaining_time(),
    }
    return JsonResponse(data)

@login_required
def scan_list(request):
    """
    Vue principale qui gère tous les onglets (active, completed, scheduled, templates)
    et qui affiche les modals dans scans.html.
    """
    context = {
        'active_scans': Scan.objects.filter(
            status__in=['in_progress', 'scheduled']
        ).order_by('-created_at'),
        
        'scheduled_scans': ScheduledScan.objects.filter(
            created_by=request.user
        ).order_by('next_run_time'),
        
        'scan_templates': ScanTemplate.objects.all().order_by('name'),
        'section': request.GET.get('tab', 'active'),
        'form': ScheduledScanForm(),
    }
    
    completed_query = Scan.objects.filter(status='completed').order_by('-end_time')
    paginator = Paginator(completed_query, 10)
    page = request.GET.get('page')
    context['completed_scans'] = paginator.get_page(page)
    
    return render(request, 'scans.html', context)


@login_required
def create_scheduled_scan(request):
    if request.method == 'POST':
        form = ScheduledScanForm(request.POST)
        if form.is_valid():
            scan = form.save(commit=False)
            scan.created_by = request.user
            scan.save()
            messages.success(request, "Scan planifié créé avec succès")
            return redirect('scan_list')
        else:
            messages.error(request, "Erreur lors de la création du scan planifié")
    return redirect('scan_list')

@login_required
def edit_scheduled_scan(request, scan_id):
    """Modifie un scan planifié via AJAX."""
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    if request.method == 'POST':
        form = ScheduledScanForm(request.POST, instance=scan)
        if form.is_valid():
            scan = form.save()
            messages.success(request, "Scan planifié mis à jour avec succès")
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'errors': form.errors})
    return JsonResponse({'success': False, 'error': 'Méthode non autorisée'})

@login_required
def toggle_scheduled_scan(request, scan_id):
    """Inverse l'état actif d'un scan planifié."""
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    scan.is_active = not scan.is_active
    scan.save()
    status = "activé" if scan.is_active else "désactivé"
    messages.success(request, f"Scan planifié {status}")
    return redirect('scan_list')




@login_required
def run_scheduled_scan_now(request, scan_id):
    """Lance immédiatement un scan planifié via une requête POST (AJAX)."""
    if request.method == 'POST':
        scan = get_object_or_404(ScheduledScan, id=scan_id)
        try:
            new_scan = Scan.objects.create(
                name=scan.name,
                target=scan.target,
                tool=scan.tool,
                created_by=request.user,
                scheduled_scan=scan,
                status='pending'
            )
            run_scheduled_scan.delay(new_scan.id)
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Méthode non autorisée'})
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from ..models import Scan, ScheduledScan, ScanTemplate
from ..forms import ScanForm
from ..utils.run_scheduled_scan import run_scheduled_scan
from django.core.paginator import Paginator

@login_required
def active_scans(request):
    """Récupère les scans actifs pour affichage dans le modal"""
    active_scans = Scan.objects.filter(
        status__in=['in_progress', 'scheduled']
    ).order_by('-created_at')
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        data = [{
            'id': scan.id,
            'name': scan.name,
            'status': scan.status,
            'progress': scan.progress,
            'created_at': scan.created_at.isoformat(),
            'tool': scan.tool.name,
            'target': str(scan.target),
        } for scan in active_scans]
        return JsonResponse({'scans': data})
        
    # Si ce n'est pas une requête AJAX, on redirige vers la vue principale
    return redirect('scan_list')

@login_required
def completed_scans(request):
    """Récupère les scans terminés pour affichage dans le modal avec pagination"""
    completed_scans = Scan.objects.filter(
        status='completed'
    ).order_by('-end_time')
    
    paginator = Paginator(completed_scans, 10)
    page = request.GET.get('page')
    scans = paginator.get_page(page)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        data = {
            'scans': [{
                'id': scan.id,
                'name': scan.name,
                'end_time': scan.end_time.isoformat(),
                'duration': scan.get_duration(),
                'vulnerability_count': scan.vulnerability_set.count(),
                'tool': scan.tool.name,
                'target': str(scan.target),
            } for scan in scans],
            'has_next': scans.has_next(),
            'has_previous': scans.has_previous(),
            'page': scans.number,
            'total_pages': scans.paginator.num_pages,
        }
        return JsonResponse(data)
        
    return redirect('scan_list')

@login_required
def scheduled_scans(request):
    """Récupère les scans planifiés pour affichage dans le modal"""
    scheduled_scans = ScheduledScan.objects.filter(
        created_by=request.user
    ).order_by('next_run_time')
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        data = [{
            'id': scan.id,
            'name': scan.name,
            'next_run_time': scan.next_run_time.isoformat() if scan.next_run_time else None,
            'frequency': scan.frequency,
            'is_active': scan.is_active,
            'tool': scan.tool.name,
            'target': str(scan.target),
            'remaining_time': scan.get_remaining_time(),
        } for scan in scheduled_scans]
        return JsonResponse({'scans': data})
        
    return redirect('scan_list')

@login_required
def scan_templates(request):
    """Récupère les templates pour affichage dans le modal"""
    templates = ScanTemplate.objects.all().order_by('name')
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        data = [{
            'id': template.id,
            'name': template.name,
            'description': template.description,
            'tool': template.tool.name if template.tool else None,
            'target_type': template.target_type,
            'created_by': template.created_by.username,
            'created_at': template.created_at.isoformat(),
        } for template in templates]
        return JsonResponse({'templates': data})
        
    return redirect('scan_list')

@login_required
def stop_scan(request, scan_id):
    """Arrête un scan en cours."""
    if request.method == 'POST':
        scan = get_object_or_404(Scan, id=scan_id, status='in_progress')
        try:
            scan.stop_scan()
            messages.success(request, 'Scan arrêté avec succès')
        except Exception as e:
            messages.error(request, f"Erreur lors de l'arrêt du scan: {str(e)}")
        return redirect('scan_list')
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

@login_required
def delete_scheduled_scan(request, scan_id):
    """Supprime un scan planifié."""
    scan = get_object_or_404(ScheduledScan, id=scan_id)
    scan.delete()
    messages.success(request, "Scan planifié supprimé avec succès")
    return redirect('scan_list')


@login_required
def delete_scan(request, scan_id):
    """Supprime un scan."""
    if request.method == 'POST':
        scan = get_object_or_404(Scan, id=scan_id)
        try:
            scan.delete()
            messages.success(request, 'Scan supprimé avec succès')
        except Exception as e:
            messages.error(request, f'Erreur lors de la suppression: {str(e)}')
        return redirect('scan_list')
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)



@login_required
def restart_scan(request, scan_id):
    """Redémarre un scan terminé ou échoué."""
    if request.method == 'POST':
        original_scan = get_object_or_404(Scan, id=scan_id)
        try:
            new_scan = Scan.objects.create(
                name=f"Restart: {original_scan.name}",
                project=original_scan.project,
                tool=original_scan.tool,
                created_by=request.user,
                target_ip=original_scan.target_ip,
                target_url=original_scan.target_url,
                status='scheduled'
            )
            run_scheduled_scan.delay(new_scan.id)
            messages.success(request, 'Scan relancé avec succès')
            return redirect('scan_list')
        except Exception as e:
            messages.error(request, f'Erreur lors du redémarrage: {str(e)}')
            return redirect('scan_list')
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

@login_required
def scan_report(request, scan_id):
    """Affiche le rapport détaillé d'un scan"""
    scan = get_object_or_404(Scan, id=scan_id)
    
    context = {
        'scan': scan,
        'vulnerabilities': scan.vulnerability_set.all().order_by('-severity'),
        'scan_details': {
            'duration': scan.get_duration(),
            'start_time': scan.start_time,
            'end_time': scan.end_time,
            'status': scan.status,
            'tool': scan.tool,
            'target': scan.target,
        }
    }
    
    return render(request, 'scans/report.html', context)