import logging
import os
import tempfile

from django.http import FileResponse
from django.shortcuts import redirect
from django.db import transaction

from EthicalpulsApp.utils.run_nmap_scan import run_nmap_scan
from django.contrib import messages

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


# views.py
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from EthicalpulsApp.models import Scan, NmapResult

import qrcode
import base64
from io import BytesIO
from django.urls import reverse

@login_required
def nmap_report_pdf(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, tool__iexact="nmap")
    result = NmapResult.objects.filter(scan=scan).first()
    if not result:
        messages.error(request, "Aucun résultat Nmap trouvé pour ce scan.")
        return redirect("tools_admin")

    # Générer un QR code vers la page du scan (exemple URL publique)
    scan_url = request.build_absolute_uri(
        reverse("nmap_report_pdf", args=[scan.id])
    )
    qr = qrcode.make(scan_url)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

    context = {
        "scan": scan,
        "result": result,
        "qr_code_base64": qr_code_base64,
        "ai_analysis": scan.ai_analysis or "Aucune analyse IA disponible.",
    }

    html_string = render_to_string("rapports/nmap_report_pdf.html", context)
    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="nmap_report_scan_{scan.id}.pdf"'
    return response
