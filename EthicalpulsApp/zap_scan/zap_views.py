import logging
import base64
from io import BytesIO

from django.utils import timezone
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.contrib import messages

from weasyprint import HTML
import qrcode

from EthicalpulsApp.models import Scan, OwaspZapResult
from EthicalpulsApp.utils.run_zap_scan import run_zap_scan

logger = logging.getLogger(__name__)


def handle_zap_scan(project, option, request):
    """Gère le lancement d'un scan OWASP ZAP"""
    try:
        valid_options = [opt[0] for opt in OwaspZapResult._meta.get_field("option").choices]

        if option and option not in valid_options:
            raise ValueError(f"Option invalide pour ZAP : '{option}'")

        if not project.url:
            raise ValueError(f"Aucune URL définie pour le projet '{project.name}'")

        scan_instance = Scan.objects.create(
            project=project,
            tool="ZAP",
            status="in_progress",
            start_time=timezone.now(),
            created_by=request.user,
        )

        # Lancer le scan en tâche asynchrone après commit
        transaction.on_commit(lambda: run_zap_scan.delay(scan_instance.id, option))
        return True, f"Scan ZAP lancé pour le projet '{project.name}'"

    except ValueError as e:
        return False, str(e)

    except Exception as e:
        logger.error(f"Erreur lors du lancement du scan ZAP : {e}", exc_info=True)
        return False, f"Erreur inattendue : {str(e)}"


@login_required
def zap_report_pdf(request, scan_id):
    """Génère un rapport PDF pour un scan ZAP avec QR code et analyse IA"""
    scan = get_object_or_404(Scan, id=scan_id, tool__iexact="zap")
    results = OwaspZapResult.objects.filter(scan=scan)

    if not results.exists():
        messages.error(request, "Aucun résultat ZAP trouvé pour ce scan.")
        return redirect("tools_admin")

    # Génération du QR code (URL locale ou publique)
    scan_url = request.build_absolute_uri(reverse("zap_report_pdf", args=[scan.id]))
    qr_img = qrcode.make(scan_url)
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

    context = {
        "scan": scan,
        "results": results,
        "qr_code_base64": qr_code_base64,
        "ai_analysis": scan.ai_analysis or "Aucune analyse IA disponible.",
    }

    # Chargement du template HTML
    html_string = render_to_string("rapports/zap_report_pdf.html", context)

    # Conversion en PDF avec WeasyPrint
    pdf_file = HTML(string=html_string, base_url=request.build_absolute_uri("/")).write_pdf()

    # Réponse HTTP avec fichier attaché
    response = HttpResponse(pdf_file, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="zap_report_scan_{scan.id}.pdf"'
    return response
