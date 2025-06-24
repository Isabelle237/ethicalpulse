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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak  # type: ignore
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore
from reportlab.lib import colors  # type: ignore
from reportlab.lib.pagesizes import letter  # type: ignore

from EthicalpulsApp.models import NmapResult, Scan


def handle_nmap_scan(project, option, request):
    from EthicalpulsApp.views import afficher_sortie_scan

    """Gère le lancement d'un scan Nmap"""
    try:
        valid_options = [opt[0] for opt in NmapResult._meta.get_field("option").choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Nmap : '{option}'")

        if not project.ip_address:
            raise ValueError(
                f"Aucune adresse IP définie pour le projet '{project.name}'"
            )

        scan_instance = Scan.objects.create(
            project=project,
            tool="NMAP",
            status="in_progress",
            start_time=timezone.now(),
            created_by=request.user,
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
    """Génère un rapport PDF synthétique pour un scan Nmap"""
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter

    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Styles personnalisés
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=22,
        spaceAfter=20,
        alignment=1,
        textColor=colors.HexColor("#0d6efd"),
    )
    header_style = ParagraphStyle(
        "CustomHeader",
        parent=styles["Heading2"],
        fontSize=13,
        spaceAfter=10,
        textColor=colors.HexColor("#212529"),
    )
    body_style = ParagraphStyle(
        "CustomBody", parent=styles["Normal"], fontSize=10, leading=14
    )

    # Titre
    elements.append(Paragraph("📊 Résumé du Scan Nmap", title_style))
    elements.append(Spacer(1, 16))

    # Carte résumé
    elements.append(Paragraph("Informations Générales", header_style))
    infos = f"""
    <b>Cible :</b> {scan_data['target']}<br/>
    <b>Date du scan :</b> {scan_data['start_time'].strftime('%d %B %Y')}<br/>
    <b>Durée du scan :</b> {str(scan_data.get('duration', 'N/A'))}<br/>
    <b>Outil utilisé :</b> Nmap<br/>
    <b>Commande :</b> {scan_data['command_used']}<br/>
    <b>Options :</b> {scan_data['option']}<br/>
    """
    elements.append(Paragraph(infos, body_style))
    elements.append(Spacer(1, 12))

    # Tableau synthétique des vulnérabilités (adapte les valeurs selon ta collecte)
    vuln_counts = scan_data.get(
        "vuln_counts", {"low": 0, "medium": 0, "high": 0, "critical": 0}
    )
    table_data = [
        [
            Paragraph("<b>Faible</b>", body_style),
            Paragraph("<b>Moyenne</b>", body_style),
            Paragraph("<b>Élevée</b>", body_style),
            Paragraph("<b>Critique</b>", body_style),
        ],
        [
            Paragraph(
                f"<font color='white'>{vuln_counts.get('low',0)}</font>", body_style
            ),
            Paragraph(
                f"<font color='black'>{vuln_counts.get('medium',0)}</font>", body_style
            ),
            Paragraph(
                f"<font color='white'>{vuln_counts.get('high',0)}</font>", body_style
            ),
            Paragraph(
                f"<font color='white'>{vuln_counts.get('critical',0)}</font>",
                body_style,
            ),
        ],
    ]
    table = Table(table_data, colWidths=[70] * 4, rowHeights=[18, 28])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 1), (0, 1), colors.green),
                ("BACKGROUND", (1, 1), (1, 1), colors.yellow),
                ("BACKGROUND", (2, 1), (2, 1), colors.red),
                ("BACKGROUND", (3, 1), (3, 1), colors.HexColor("#222")),
                ("TEXTCOLOR", (1, 1), (1, 1), colors.black),
                ("TEXTCOLOR", (0, 1), (0, 1), colors.white),
                ("TEXTCOLOR", (2, 1), (2, 1), colors.white),
                ("TEXTCOLOR", (3, 1), (3, 1), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(table)
    elements.append(Spacer(1, 18))

    # Statut du scan
    elements.append(Paragraph("Statut du Scan", header_style))
    status_info = f"""
    <b>Statut final :</b> {scan_data['scan_status']}<br/>
    """
    if scan_data["error_log"]:
        status_info += f"<b>Erreurs rencontrées :</b><br/>{scan_data['error_log']}"
    elements.append(Paragraph(status_info, body_style))
    elements.append(Spacer(1, 12))

    # Pied de page
    from django.utils import timezone

    footer = f"""
    <para alignment="center">
    <b>EthicalPulse Security Assessment</b><br/>
    Rapport généré le : {timezone.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    </para>
    """
    elements.append(Spacer(1, 24))
    elements.append(Paragraph(footer, body_style))

    # Génération du PDF
    doc.build(elements)


def download_nmap_report(request, scan_id):
    try:
        # Récupération du résultat Nmap
        nmap_result = NmapResult.objects.get(scan__id=scan_id)

        # Préparation des données pour le rapport
        scan_data = {
            "target": nmap_result.target,
            "command_used": nmap_result.command_used,
            "option": nmap_result.option,
            "start_time": nmap_result.start_time,
            "end_time": nmap_result.end_time or timezone.now(),
            "os_detected": nmap_result.os_detected,
            "os_accuracy": nmap_result.os_accuracy,
            "traceroute": nmap_result.traceroute,
            "script_results": nmap_result.script_results,
            "open_tcp_ports": nmap_result.open_tcp_ports,
            "open_udp_ports": nmap_result.open_udp_ports,
            "service_details": nmap_result.service_details,
            "scan_status": nmap_result.scan_status,
            "error_log": nmap_result.error_log,
            "full_output": nmap_result.full_output,
        }

        # Création d'un fichier temporaire pour le PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmpfile:
            try:
                # Génération du rapport PDF
                generate_nmap_report(scan_data, tmpfile.name)

                # Préparation de la réponse HTTP
                response = FileResponse(
                    open(tmpfile.name, "rb"),
                    content_type="application/pdf",
                    filename=f"nmap_scan_report_{scan_id}.pdf",
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
        return redirect("tools_admin")
    except Exception as e:
        messages.error(request, f"Erreur lors de la génération du rapport : {str(e)}")
        return redirect("tools_admin")
