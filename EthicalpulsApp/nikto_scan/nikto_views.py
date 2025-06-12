import logging
import os
from pyexpat.errors import messages
import tempfile

from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.db import transaction

from EthicalpulsApp.utils.nikto_scan import run_nikto_scan

logger = logging.getLogger(__name__)

from django.utils import timezone

import time
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak # type: ignore
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle # type: ignore
from reportlab.lib import colors # type: ignore
from reportlab.lib.pagesizes import letter # type: ignore

from EthicalpulsApp.models import NiktoResult, NmapResult, Scan


def scan_result_detail(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    result = NiktoResult.objects.filter(scan=scan).first()
    return render(request, 'admin/scan_detail.html', {
        'scan': scan,
        'result': result
    })


def generate_nikto_report(scan_data, filename):
    """Génère un rapport PDF pour un scan Nikto"""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1
    )
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#2E5090')
    )

    # Titre
    elements.append(Paragraph("Rapport de Scan Nikto", title_style))
    elements.append(Spacer(1, 12))

    # Informations de base
    elements.append(Paragraph("Informations de la Cible", header_style))
    target_info = f"""
    <para>
    <b>URI :</b> {scan_data['url']}<br/>
    <b>Hostname :</b> {scan_data['host']}<br/>
    <b>Port :</b> {scan_data['port']}<br/>
    <b>Option utilisée :</b> {scan_data['option_used']}<br/>
    </para>
    """
    elements.append(Paragraph(target_info, styles['Normal']))
    elements.append(Spacer(1, 12))

    # Informations serveur
    elements.append(Paragraph("Informations Serveur", header_style))
    server_info = f"""
    <para>
    <b>Serveur :</b> {scan_data['server_info']['server']}<br/>
    <b>SSL Subject :</b> {scan_data['server_info']['ssl_info']['subject']}<br/>
    <b>SSL Issuer :</b> {scan_data['server_info']['ssl_info']['issuer']}<br/>
    <b>SSL Cipher :</b> {scan_data['server_info']['ssl_info']['cipher']}<br/>
    </para>
    """
    elements.append(Paragraph(server_info, styles['Normal']))
    elements.append(Spacer(1, 12))

    # En-têtes de sécurité
    elements.append(Paragraph("En-têtes de Sécurité", header_style))
    security_headers = f"""
    <para>
    <b>X-Powered-By :</b> {scan_data['server_info']['headers']['x_powered_by']}<br/>
    <b>X-Frame-Options :</b> {scan_data['server_info']['headers']['x_frame_options']}<br/>
    <b>Content-Security-Policy :</b> {scan_data['server_info']['headers']['content_security']}<br/>
    <b>Strict-Transport-Security :</b> {scan_data['server_info']['headers']['transport_security']}<br/>
    </para>
    """
    elements.append(Paragraph(security_headers, styles['Normal']))
    elements.append(Spacer(1, 12))

    # Vulnérabilités
    elements.append(Paragraph("Vulnérabilités Détectées", header_style))
    if scan_data['vulnerabilities']:
        for vuln in scan_data['vulnerabilities'].split('\n'):
            if vuln.strip():
                elements.append(Paragraph(f"• {vuln}", styles['Normal']))
    else:
        elements.append(Paragraph("Aucune vulnérabilité détectée", styles['Normal']))

    # Description détaillée
    elements.append(Paragraph("Description Détaillée", header_style))
    elements.append(Paragraph(scan_data['description'], styles['Normal']))

    # Sortie brute
    elements.append(Paragraph("Sortie Brute", header_style))
    elements.append(Paragraph(scan_data['output'], styles['Code']))

    # Pied de page
    elements.append(Spacer(1, 20))
    footer = f"""
    <para alignment="center">
    <b>Rapport généré le :</b> {timezone.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    EthicalPulse Security Assessment
    </para>
    """
    elements.append(Paragraph(footer, styles['Normal']))

    # Génération du PDF
    doc.build(elements)

def download_nikto_report(request, scan_id):
    nikto_result = NiktoResult.objects.get(scan__id=scan_id)

    scan_data = {
        'url': nikto_result.uri,  # Utilise uri au lieu de target_url
        'host': nikto_result.target_hostname,  # Utilise target_hostname au lieu de host
        'port': nikto_result.target_port,  # Utilise target_port au lieu de port
        'server_info': {
            'server': nikto_result.server,
            'ssl_info': {
                'subject': nikto_result.ssl_subject,
                'issuer': nikto_result.ssl_issuer,
                'cipher': nikto_result.ssl_cipher
            },
            'headers': {
                'x_powered_by': nikto_result.x_powered_by,
                'x_frame_options': nikto_result.x_frame_options,
                'content_security': nikto_result.content_security_policy,
                'transport_security': nikto_result.strict_transport_security
            }
        },
        'vulnerabilities': nikto_result.vulnerability,
        'output': nikto_result.nikto_raw_output,
        'description': nikto_result.description,
        'option_used': nikto_result.option
    }

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmpfile:
        generate_nikto_report(scan_data, tmpfile.name)
        tmpfile.seek(0)
        response = FileResponse(
            open(tmpfile.name, 'rb'),
            content_type='application/pdf',
            filename=f'nikto_report_{scan_id}.pdf'
        )
        
        # Nettoyage du fichier temporaire après l'envoi
        os.unlink(tmpfile.name)
        return response


def handle_nikto_scan(project, option, request):
    """Gère le lancement d'un scan Nikto"""
    try:
        # Validation de l'URL du projet
        if not project.url:
            raise ValueError(f"Aucune URL définie pour le projet '{project.name}'")

        # Validation des options
        valid_options = [opt[0] for opt in NiktoResult._meta.get_field('option').choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Nikto : '{option}'")

        # Création du scan
        scan_instance = Scan.objects.create(
            project=project,
            tool='NIKTO',
            status='in_progress',
            start_time=timezone.now(),
            created_by=request.user
        )

        # Lancement du scan en arrière-plan
        transaction.on_commit(lambda: run_nikto_scan.delay(scan_instance.id, option))

        return True, f"Scan Nikto lancé pour le projet '{project.name}' avec l'option '{option}'"
    except ValueError as e:
        return False, str(e)
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan Nikto : {e}")
        return False, f"Erreur inattendue : {str(e)}"

