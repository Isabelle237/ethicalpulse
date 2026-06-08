from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.db import transaction
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from EthicalpulsApp.models import Project, Scan
from EthicalpulsApp.utils.run_sqlmap_scan import run_sqlmap_scan

import logging

logger = logging.getLogger(__name__)


SQLMAP_OPTIONS = (
    ("--batch", "Scan simple (automatique)"),
    ("--level=5 --risk=3 --batch", "Scan approfondi"),
    ("--technique=BE --batch", "Scan booléen + erreur"),
    ("--dbs --batch", "Lister les bases (si vulnérable)"),
    ("--dump --batch", "Extraire les données (si vulnérable)"),
    ("--batch --random-agent", "Scan + contournement User-Agent"),
)


@login_required
@require_POST
def handle_sqlmap_scan(request):
    project_id = request.POST.get("project_id")
    sqlmap_option = request.POST.get("sqlmap_option", "--batch")

    if not project_id:
        messages.error(request, "Projet non défini.")
        return redirect("tools_admin")

    project = get_object_or_404(Project, id=project_id)

    if not project.url:
        messages.error(
            request, f"Aucune URL définie pour le projet « {project.name} »."
        )
        return redirect("tools_admin")

    allowed_options = {opt for opt, label in SQLMAP_OPTIONS}
    if sqlmap_option not in allowed_options:
        messages.error(request, "Option SQLMap non autorisée.")
        return redirect("tools_admin")

    scan = Scan.objects.create(
        name=f"SQLMap Scan - {project.name} - {timezone.now():%Y-%m-%d %H:%M:%S}",
        project=project,
        tool="SQLMAP",
        status="scheduled",
        start_time=timezone.now(),
        created_by=request.user,
    )

    try:
        transaction.on_commit(lambda: run_sqlmap_scan.delay(scan.id, sqlmap_option))
        logger.info(
            f"[SQLMAP] Scan #{scan.id} lancé pour {project.url} avec options : {sqlmap_option}"
        )
        messages.success(request, f"Scan SQLMap lancé pour « {project.name} ».")
    except Exception as e:
        scan.status = "error"
        scan.error_log = str(e)
        scan.save(update_fields=["status", "error_log"])
        logger.error(
            f"[SQLMAP] Échec lancement du scan #{scan.id} : {e}", exc_info=True
        )
        messages.error(request, "Échec du lancement du scan SQLMap.")

    return redirect("active_scans")


from django.http import HttpResponse
from django.template.loader import render_to_string

from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpResponse
from weasyprint import HTML
from io import BytesIO
import base64
import qrcode

@login_required
def sqlmap_report_pdf(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, tool__iexact="sqlmap")
    result = scan.sqlmapresults.first()
    if not result:
        return HttpResponse("Aucun résultat SQLMap.", status=404)

    # Génération QR Code facultatif
    qr_code_base64 = None
    try:
        url = request.build_absolute_uri(f"/scans/{scan.id}/details/")
        qr = qrcode.make(url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    except Exception:
        qr_code_base64 = None

    html_string = render_to_string(
        "rapports/sqlmap_report_pdf.html",
        {"scan": scan, "result": result, "qr_code_base64": qr_code_base64}
    )
    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="sqlmap_report_{scan.id}.pdf"'
    return response
