# views/sqlmap_views.py

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

def parse_sqlmap_output(output):
    """
    Analyse la sortie SQLMap pour extraire les infos utiles.
    """
    import re
    result = {
        'is_vulnerable': False,
        'injection_type': None,
        'dbms': None,
        'payloads': [],
        'dbs_found': [],
        'tables_found': {},
        'columns_found': {},
        'data_dumped': {},
    }

    dbms_match = re.search(r"the back-end DBMS is '(.*?)'", output)
    if dbms_match:
        result['is_vulnerable'] = True
        result['dbms'] = dbms_match.group(1)

    inj_type_match = re.search(r"type: '(.*?)'", output)
    if inj_type_match:
        result['injection_type'] = inj_type_match.group(1)
    elif "SQL injection" in output:
        result['injection_type'] = "SQL Injection"

    payloads = re.findall(r"payload: (.*?)\n", output)
    result['payloads'] = [p.strip() for p in payloads]

    dbs_section = re.search(r"available databases\s*:\s*\n(-+\n)?((?:\[\*\].*\n)+)", output)
    if dbs_section:
        dbs = re.findall(r"\[\*\]\s*(.+)", dbs_section.group(2))
        result['dbs_found'] = [db.strip() for db in dbs]

    tables_found = {}
    tables_sections = re.finditer(r"Database: (.*?)\n.*?table\(s\) found.*?\n(-+\n)?((?:\[\*\].*\n)+)", output, re.DOTALL)
    for match in tables_sections:
        db = match.group(1).strip()
        tables = re.findall(r"\[\*\]\s*(.+)", match.group(3))
        tables_found[db] = [t.strip() for t in tables]
    result['tables_found'] = tables_found

    columns_found = {}
    columns_sections = re.finditer(r"Table: (.*?)\n.*?column\(s\) found.*?\n(-+\n)?((?:\[\*\].*\n)+)", output, re.DOTALL)
    for match in columns_sections:
        table = match.group(1).strip()
        columns = re.findall(r"\[\*\]\s*(.+)", match.group(3))
        columns_found[table] = [c.strip() for c in columns]
    result['columns_found'] = columns_found

    data_dumped = {}
    dump_sections = re.finditer(r"Table: (.*?)\n.*?Dumping data for table.*?\n(-+\n)?((?:\|.*\n)+)", output, re.DOTALL)
    for match in dump_sections:
        table = match.group(1).strip()
        rows = []
        lines = match.group(3).splitlines()
        headers = []
        for l in lines:
            if l.startswith("|") and not headers:
                headers = [h.strip() for h in l.strip("|").split("|")]
            elif l.startswith("|"):
                values = [v.strip() for v in l.strip("|").split("|")]
                if len(values) == len(headers):
                    rows.append(dict(zip(headers, values)))
        if rows:
            data_dumped[table] = rows
    result['data_dumped'] = data_dumped

    return result
SQLMAP_OPTIONS = (
    ("--batch", "Scan simple (automatique)"),
    ("--level=3 --risk=2 --batch", "Scan approfondi"),
    ("--technique=BE --batch", "Scan booléen + erreur"),
    ("--dbs --batch", "Lister les bases (si vulnérable)"),
    ("--dump --batch", "Extraire les données (si vulnérable)"),
    ("--batch --random-agent", "Scan + contournement User-Agent"),
)

@login_required
@require_POST
def handle_sqlmap_scan(request):
    project_id = request.POST.get('project_id')
    sqlmap_option = request.POST.get('sqlmap_option', '--batch')

    if not project_id:
        messages.error(request, "Projet non défini.")
        return redirect('tools_admin')

    project = get_object_or_404(Project, id=project_id)

    if not project.url:
        messages.error(request, f"Aucune URL définie pour le projet « {project.name} ».")
        return redirect('tools_admin')

    # Vérification si l’option est autorisée
    allowed_options = {opt for opt, label in SQLMAP_OPTIONS}
    if sqlmap_option not in allowed_options:
        messages.error(request, "Option SQLMap non autorisée.")
        return redirect('tools_admin')

    options_list = ['-u', project.url] + sqlmap_option.strip().split()

    # Création d’un enregistrement Scan
    scan = Scan.objects.create(
        name=f"SQLMap Scan - {project.name} - {timezone.now():%Y-%m-%d %H:%M:%S}",
        project=project,
        tool='SQLMAP',
        status='scheduled',
        start_time=timezone.now(),
        created_by=request.user
    )

    try:
        sqlmap_option = request.POST.get('sqlmap_option', '--batch')
        transaction.on_commit(lambda: run_sqlmap_scan.delay(scan.id, sqlmap_option))
        logger.info(f"[SQLMAP] Scan #{scan.id} lancé pour {project.url} avec options : {options_list}")
        messages.success(request, f"Scan SQLMap lancé pour « {project.name} ».")
    except Exception as e:
        scan.status = 'error'
        scan.error_log = f"Erreur lors du lancement du scan : {str(e)}"
        scan.save(update_fields=['status', 'error_log'])
        logger.error(f"[SQLMAP] Échec lancement du scan #{scan.id} : {str(e)}", exc_info=True)
        messages.error(request, f"Échec du lancement du scan SQLMap.")

    return redirect('tools_admin')

from django.http import HttpResponse
from django.template.loader import render_to_string

@login_required
def sqlmap_report_pdf(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    result = getattr(scan, 'sqlmap_result', None)
    if hasattr(result, 'all'):
        result = result.all().first()
    if not result:
        messages.error(request, "Aucun résultat SQLMap trouvé pour ce scan.")
        return redirect('tools_admin')

    context = {
        'scan': scan,
        'result': result,
    }
    html_string = render_to_string('rapports/sqlmap_report_pdf.html', context)
    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="sqlmap_report_scan_{scan.id}.pdf"'

    return response

@login_required
def download_sqlmap_report(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, tool__iexact='sqlmap')
    result = scan.sqlmapresults.first()
    if not result:
        raise Http404("Aucun résultat SQLMap trouvé.")

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 770, f"Rapport SQLMap - Scan #{scan.id}")
    p.setFont("Helvetica", 12)
    cible = scan.project.url or scan.project.domain or scan.project.ip_address or ""
    p.drawString(50, 750, f"Cible : {cible}")
    p.drawString(50, 735, f"Commande : {result.options_used}")
    p.drawString(50, 720, f"Vulnérable : {'Oui' if result.is_vulnerable else 'Non'}")
    p.drawString(50, 705, f"Type d'injection : {result.injection_type}")
    p.drawString(50, 690, f"DBMS : {result.dbms}")

    # Tableau des vulnérabilités
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, 670, "Vulnérabilités détectées :")
    p.setFont("Helvetica", 10)
    y = 655
    vulns = scan.vulnerabilities.all()
    if vulns:
        p.drawString(55, y, "Nom")
        p.drawString(200, y, "Technique")
        p.drawString(320, y, "DBMS")
        p.drawString(400, y, "Gravité")
        y -= 15
        for vuln in vulns:
            if y < 100:
                p.showPage()
                y = 770
            p.drawString(55, y, vuln.name[:25])
            p.drawString(200, y, (vuln.technique or "")[:15])
            p.drawString(320, y, (vuln.dbms or "")[:15])
            p.drawString(400, y, vuln.severity)
            y -= 15
    else:
        p.drawString(55, y, "Aucune vulnérabilité détectée.")
        y -= 15

    # Sortie brute
    p.setFont("Helvetica-Bold", 12)
    y -= 20
    p.drawString(50, y, "Sortie brute :")
    y -= 15
    p.setFont("Helvetica", 8)
    text = p.beginText(50, y)
    for line in (result.raw_output or '')[:4000].splitlines():
        if y < 50:
            p.drawText(text)
            p.showPage()
            y = 770
            text = p.beginText(50, y)
        text.textLine(line)
        y -= 10
    p.drawText(text)
    p.save()
    buffer.seek(0)
    return FileResponse(buffer, as_attachment=True, filename=f"rapport_sqlmap_{scan.id}.pdf")
    scan = get_object_or_404(Scan, id=scan_id, tool__iexact='sqlmap')
    result = scan.sqlmapresults.first()
    if not result:
        raise Http404("Aucun résultat SQLMap trouvé.")
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 770, f"Rapport SQLMap - Scan #{scan.id}")
    p.setFont("Helvetica", 12)
    p.drawString(50, 750, f"Cible : {result.project.url if result.project else ''}")
    p.drawString(50, 735, f"Commande : {result.options_used}")
    p.drawString(50, 720, f"Vulnérable : {'Oui' if result.is_vulnerable else 'Non'}")
    p.drawString(50, 705, f"Type d'injection : {result.injection_type}")
    p.drawString(50, 690, f"DBMS : {result.dbms}")
    p.drawString(50, 675, "Payloads :")
    text = p.beginText(70, 660)
    for line in (result.payloads or '').splitlines():
        text.textLine(line)
    p.drawText(text)
    p.showPage()
    p.setFont("Helvetica", 10)
    p.drawString(50, 800, "Sortie brute :")
    text = p.beginText(50, 780)
    for line in (result.raw_output or '')[:4000].splitlines():
        text.textLine(line)
    p.drawText(text)
    p.save()
    buffer.seek(0)
    return FileResponse(buffer, as_attachment=True, filename=f"rapport_sqlmap_{scan.id}.pdf")