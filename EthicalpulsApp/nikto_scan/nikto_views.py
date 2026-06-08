import logging
import os
import tempfile

from django.http import FileResponse
from django.shortcuts import get_object_or_404, render
from django.db import transaction
from django.utils import timezone
from django.utils.html import strip_tags

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from EthicalpulsApp.models import NiktoResult, Scan
from EthicalpulsApp.utils.nikto_scan import run_nikto_scan

logger = logging.getLogger(__name__)

from django.db import transaction
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

def handle_nikto_scan(project, option, request):
    """Gère le lancement d'un scan Nikto"""
    try:
        # Validation de la cible : URL, domain ou IP
        raw_target = project.url or project.domain or str(project.ip_address)
        if not raw_target:
            raise ValueError(f"Aucune cible définie (URL, domaine ou IP) pour le projet '{project.name}'")

        # Validation des options Nikto selon choix du modèle
        valid_options = [opt[0] for opt in NiktoResult._meta.get_field("option").choices]
        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour Nikto : '{option}'")

        # Création du scan
        scan_instance = Scan.objects.create(
            project=project,
            tool="NIKTO",
            status="in_progress",
            start_time=timezone.now(),
            created_by=request.user,
        )

        # Lancement asynchrone après commit transaction
        transaction.on_commit(lambda: run_nikto_scan.delay(scan_instance.id, option))

        return True, f"Scan Nikto lancé pour le projet '{project.name}' avec l'option '{option or 'standard'}'."

    except ValueError as e:
        logger.warning(f"Validation échouée lors du lancement Nikto : {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan Nikto : {e}", exc_info=True)
        return False, f"Erreur inattendue : {str(e)}"


from django.template.loader import render_to_string

from django.template.loader import render_to_string
import qrcode
import base64
from io import BytesIO

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse
from django.urls import reverse
from django.template.loader import render_to_string
from django.contrib import messages
import qrcode
import base64
from io import BytesIO
from weasyprint import HTML
from EthicalpulsApp.models import Scan, NiktoResult

@login_required
def nikto_report_pdf(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, tool__iexact="nikto")
    result = NiktoResult.objects.filter(scan=scan).first()
    if not result:
        messages.error(request, "Aucun résultat Nikto trouvé pour ce scan.")
        return redirect("active_scans")

    # Générer un QR code vers la page du scan (URL publique)
    scan_url = request.build_absolute_uri(
        reverse("nikto_report_pdf", args=[scan.id])
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

    html_string = render_to_string("rapports/nikto_report.html", context)
    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="nikto_report_scan_{scan.id}.pdf"'
    return response
