import logging
import os
from pyexpat.errors import messages
import tempfile

from django.http import FileResponse
from django.shortcuts import redirect
from django.db import transaction

from EthicalpulsApp.utils.run_nmap_scan import run_nmap_scan

logger = logging.getLogger(__name__)

from django.utils import timezone

from gettext import translation
import threading
import time
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak # type: ignore
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle # type: ignore
from reportlab.lib import colors # type: ignore
from reportlab.lib.pagesizes import letter # type: ignore

from EthicalpulsApp.models import NmapResult, Scan
from EthicalpulsApp.views import afficher_sortie_scan

def handle_nmap_scan(project, option, request):
    """Gère le lancement d'un scan Nmap"""
    try:
        valid_options = [opt[0] for opt in NmapResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Nmap : '{option}'")

        if not project.ip_address:
            raise ValueError(f"Aucune adresse IP définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool='NMAP',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        transaction.on_commit(lambda: run_nmap_scan.delay(scan_instance.id, option))

        # 🔎 Afficher dans la console la sortie brute (après un court délai)
        def afficher_apres_scan():
            time.sleep(4)  # Attendre un peu que le résultat soit enregistré
            scan = Scan.objects.get(id=scan_instance.id)
            afficher_sortie_scan(scan)

        threading.Thread(target=afficher_apres_scan).start()

        return True, f"Scan Nmap lancé pour le projet '{project.name}'"

    except ValueError as e:
        return False, str(e)
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan Nmap : {e}")
        return False, f"Erreur inattendue : {str(e)}"



def generate_nmap_report(scan_data, filename):
    """Génère un rapport PDF détaillé pour un scan Nmap"""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,
        textColor=colors.HexColor('#003366')
    )
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#2E5090')
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14
    )

    # Logo et titre
    elements.append(Paragraph("Rapport de Scan Nmap", title_style))
    elements.append(Spacer(1, 20))

    # Informations de base
    elements.append(Paragraph("Informations Générales", header_style))
    scan_info = f"""
    <para>
    <b>Cible :</b> {scan_data['target']}<br/>
    <b>Commande utilisée :</b> {scan_data['command_used']}<br/>
    <b>Options de scan :</b> {scan_data['option']}<br/>
    <b>Date de début :</b> {scan_data['start_time'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
    <b>Date de fin :</b> {scan_data['end_time'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
    </para>
    """
    elements.append(Paragraph(scan_info, body_style))
    elements.append(Spacer(1, 12))

    # Détection de l'OS
    if scan_data['os_detected']:
        elements.append(Paragraph("Détection du Système d'Exploitation", header_style))
        os_info = f"""
        <para>
        <b>OS détecté :</b> {scan_data['os_detected']}<br/>
        <b>Précision :</b> {scan_data['os_accuracy']}%<br/>
        </para>
        """
        elements.append(Paragraph(os_info, body_style))
        elements.append(Spacer(1, 12))

    # Ports TCP ouverts
    if scan_data['open_tcp_ports']:
        elements.append(Paragraph("Ports TCP Ouverts", header_style))
        elements.append(Paragraph(scan_data['open_tcp_ports'].replace('\n', '<br/>'), body_style))
        elements.append(Spacer(1, 12))

    # Ports UDP ouverts
    if scan_data['open_udp_ports']:
        elements.append(Paragraph("Ports UDP Ouverts", header_style))
        elements.append(Paragraph(scan_data['open_udp_ports'].replace('\n', '<br/>'), body_style))
        elements.append(Spacer(1, 12))

    # Services détectés
    if scan_data['service_details']:
        elements.append(Paragraph("Services Détectés", header_style))
        services = scan_data['service_details'].split('\n')
        for service in services:
            if service.strip():
                elements.append(Paragraph(f"• {service}", body_style))
        elements.append(Spacer(1, 12))

    # Résultats des scripts NSE
    if scan_data['script_results']:
        elements.append(Paragraph("Résultats des Scripts NSE", header_style))
        scripts = scan_data['script_results'].split('\n')
        for script in scripts:
            if script.strip():
                elements.append(Paragraph(f"• {script}", body_style))
        elements.append(Spacer(1, 12))

    # Traceroute
    if scan_data['traceroute']:
        elements.append(Paragraph("Traceroute", header_style))
        elements.append(Paragraph(scan_data['traceroute'].replace('\n', '<br/>'), body_style))
        elements.append(Spacer(1, 12))

    # Statut du scan et erreurs
    elements.append(Paragraph("Statut du Scan", header_style))
    status_info = f"""
    <para>
    <b>Statut final :</b> {scan_data['scan_status']}<br/>
    """
    if scan_data['error_log']:
        status_info += f"<b>Erreurs rencontrées :</b><br/>{scan_data['error_log']}"
    status_info += "</para>"
    elements.append(Paragraph(status_info, body_style))

    # Pied de page
    elements.append(PageBreak())
    footer = f"""
    <para alignment="center">
    <b>EthicalPulse Security Assessment</b><br/>
    Rapport généré le : {timezone.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    </para>
    """
    elements.append(Paragraph(footer, body_style))

    # Génération du PDF
    doc.build(elements)

    """Génère un rapport PDF détaillé pour un scan Nmap"""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,
        textColor=colors.HexColor('#003366')
    )
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#2E5090')
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14
    )

    # Logo et titre
    elements.append(Paragraph("Rapport de Scan Nmap", title_style))
    elements.append(Spacer(1, 20))

    # Informations de base
    elements.append(Paragraph("Informations Générales", header_style))
    scan_info = f"""
    <para>
    <b>Cible :</b> {scan_data['target']}<br/>
    <b>Commande utilisée :</b> {scan_data['command_used']}<br/>
    <b>Options de scan :</b> {scan_data['option']}<br/>
    <b>Date de début :</b> {scan_data['start_time'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
    <b>Date de fin :</b> {scan_data['end_time'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
    </para>
    """
    elements.append(Paragraph(scan_info, body_style))
    elements.append(Spacer(1, 12))

    # Détection de l'OS
    if scan_data['os_detected']:
        elements.append(Paragraph("Détection du Système d'Exploitation", header_style))
        os_info = f"""
        <para>
        <b>OS détecté :</b> {scan_data['os_detected']}<br/>
        <b>Précision :</b> {scan_data['os_accuracy']}%<br/>
        </para>
        """
        elements.append(Paragraph(os_info, body_style))
        elements.append(Spacer(1, 12))

    # Ports TCP ouverts
    if scan_data['open_tcp_ports']:
        elements.append(Paragraph("Ports TCP Ouverts", header_style))
        elements.append(Paragraph(scan_data['open_tcp_ports'].replace('\n', '<br/>'), body_style))
        elements.append(Spacer(1, 12))

    # Ports UDP ouverts
    if scan_data['open_udp_ports']:
        elements.append(Paragraph("Ports UDP Ouverts", header_style))
        elements.append(Paragraph(scan_data['open_udp_ports'].replace('\n', '<br/>'), body_style))
        elements.append(Spacer(1, 12))

    # Services détectés
    if scan_data['service_details']:
        elements.append(Paragraph("Services Détectés", header_style))
        services = scan_data['service_details'].split('\n')
        for service in services:
            if service.strip():
                elements.append(Paragraph(f"• {service}", body_style))
        elements.append(Spacer(1, 12))

    # Résultats des scripts NSE
    if scan_data['script_results']:
        elements.append(Paragraph("Résultats des Scripts NSE", header_style))
        scripts = scan_data['script_results'].split('\n')
        for script in scripts:
            if script.strip():
                elements.append(Paragraph(f"• {script}", body_style))
        elements.append(Spacer(1, 12))

    # Traceroute
    if scan_data['traceroute']:
        elements.append(Paragraph("Traceroute", header_style))
        elements.append(Paragraph(scan_data['traceroute'].replace('\n', '<br/>'), body_style))
        elements.append(Spacer(1, 12))

    # Statut du scan et erreurs
    elements.append(Paragraph("Statut du Scan", header_style))
    status_info = f"""
    <para>
    <b>Statut final :</b> {scan_data['scan_status']}<br/>
    """
    if scan_data['error_log']:
        status_info += f"<b>Erreurs rencontrées :</b><br/>{scan_data['error_log']}"
    status_info += "</para>"
    elements.append(Paragraph(status_info, body_style))

    # Pied de page
    elements.append(PageBreak())
    footer = f"""
    <para alignment="center">
    <b>EthicalPulse Security Assessment</b><br/>
    Rapport généré le : {timezone.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    </para>
    """
    elements.append(Paragraph(footer, body_style))

    # Génération du PDF
    doc.build(elements)
  
  

def download_nmap_report(request, scan_id):
    try:
        # Récupération du résultat Nmap
        nmap_result = NmapResult.objects.get(scan__id=scan_id)
        
        # Préparation des données pour le rapport
        scan_data = {
            'target': nmap_result.target,
            'command_used': nmap_result.command_used,
            'option': nmap_result.option,
            'start_time': nmap_result.start_time,
            'end_time': nmap_result.end_time or timezone.now(),
            'os_detected': nmap_result.os_detected,
            'os_accuracy': nmap_result.os_accuracy,
            'traceroute': nmap_result.traceroute,
            'script_results': nmap_result.script_results,
            'open_tcp_ports': nmap_result.open_tcp_ports,
            'open_udp_ports': nmap_result.open_udp_ports,
            'service_details': nmap_result.service_details,
            'scan_status': nmap_result.scan_status,
            'error_log': nmap_result.error_log,
            'full_output': nmap_result.full_output
        }

        # Création d'un fichier temporaire pour le PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmpfile:
            try:
                # Génération du rapport PDF
                generate_nmap_report(scan_data, tmpfile.name)
                
                # Préparation de la réponse HTTP
                response = FileResponse(
                    open(tmpfile.name, 'rb'),
                    content_type='application/pdf',
                    filename=f'nmap_scan_report_{scan_id}.pdf'
                )
                
                # Nettoyage du fichier temporaire
                os.unlink(tmpfile.name)
                
                return response
                
            except Exception as e:
                # En cas d'erreur, on s'assure de nettoyer le fichier temporaire
                if os.path.exists(tmpfile.name):
                    os.unlink(tmpfile.name)
                raise e

    except NmapResult.DoesNotExist:
        messages.error(request, "Résultat du scan Nmap non trouvé.")
        return redirect('tools_admin')
    except Exception as e:
        messages.error(request, f"Erreur lors de la génération du rapport : {str(e)}")
        return redirect('tools_admin')