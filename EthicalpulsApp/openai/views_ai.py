import os
import traceback
import requests
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from EthicalpulsApp.models import Scan

def split_text(text, max_len=3500):
    """
    Découpe un texte en morceaux de taille max_len sans couper au milieu des mots.
    """
    parts = []
    start = 0
    while start < len(text):
        if start + max_len >= len(text):
            parts.append(text[start:])
            break
        split_pos = text.rfind('\n', start, start + max_len)
        if split_pos == -1 or split_pos <= start:
            split_pos = text.rfind(' ', start, start + max_len)
        if split_pos == -1 or split_pos <= start:
            split_pos = start + max_len
        parts.append(text[start:split_pos].strip())
        start = split_pos
    return parts
@csrf_exempt
@login_required
@require_GET
def ai_scan_analysis(request, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return JsonResponse({"error": "Scan introuvable."}, status=404)

    tool_result_map = {
        "NMAP": ("nmap_results", "full_output"),
        "NIKTO": ("niktoresults", "vulnerability"),
        "SQLMAP": ("sqlmapresults", "raw_output"),
        "ZAP": ("owaspzapresult_set", "vulnerability"),
    }

    tool = scan.tool.upper()
    if tool not in tool_result_map:
        return JsonResponse({"error": f"Outil '{tool}' non supporté."}, status=400)

    related_name, attr = tool_result_map[tool]
    try:
        result_qs = getattr(scan, related_name).all()
    except AttributeError:
        return JsonResponse({"error": f"Relation '{related_name}' introuvable."}, status=500)

    result = result_qs.first() if result_qs else None
    if not result:
        return JsonResponse({"error": "Aucun résultat de scan trouvé."}, status=404)

    findings = getattr(result, attr, "").strip()
    if not findings:
        return JsonResponse({"error": "Le rapport de scan est vide."}, status=400)

    api_key = os.getenv("TOGETHER_API_KEY")
    if not api_key:
        return JsonResponse({"error": "Clé API Together.ai non configurée dans .env"}, status=500)

    # Choix du prompt selon l'outil pour une analyse adaptée et pédagogique
    if tool == "NMAP":
        user_base_prompt = (
            "Tu es un expert en cybersécurité et vulgarisateur.\n"
            "Tu analyses un résultat brut d’un scan réseau Nmap (format nmaprun XML).\n"
            "Explique ce que c’est, détaille les vulnérabilités détectées par gravité, "
            "Cite et explique chaque vulnérabilité (ports/services concernés, risques, contexte d’exploitation), "
            "donne des remédiations claires, et termine par des bonnes pratiques de sécurité.\n"
            "Sois très pédagogique pour qu'un débutant puisse comprendre."
        )
    elif tool == "NIKTO":
        user_base_prompt = (
            "Tu es un expert en sécurité web et vulgarisateur.\n"
            "Tu analyses un rapport brut d’un scan de vulnérabilités web Nikto.\n"
            "Cite et explique les vulnérabilités détectées, leur gravité, les risques associés, "
            "comment les exploiter et comment s’en protéger.\n"
            "Donne des remédiations précises et des bonnes pratiques.\n"
            "Sois clair et pédagogique pour qu'un débutant puisse comprendre."
        )
    elif tool == "SQLMAP":
        user_base_prompt = (
            "Tu es un expert en sécurité des bases de données et vulgarisateur.\n"
            "Tu analyses un rapport brut d’un scan d’injections SQL SQLMap.\n"
            "Cite et explique les vulnérabilités SQL détectées, leur gravité, risques d’exploitation, "
            "les méthodes d’attaque possibles, les remédiations, et bonnes pratiques pour éviter ces failles.\n"
            "Sois clair et pédagogique pour qu'un débutant puisse comprendre."
        )
    elif tool == "ZAP":
        user_base_prompt = (
            "Tu es un expert en sécurité applicative et vulgarisateur.\n"
            "Tu analyses un rapport brut d’un scan OWASP ZAP.\n"
            "Cite et explique les vulnérabilités détectées (XSS, CSRF, etc), leurs risques, contexte d’exploitation, "
            "les remédiations techniques et organisationnelles, et les bonnes pratiques à adopter.\n"
            "Sois clair, structuré et pédagogique."
        )
    else:
        user_base_prompt = (
            "Tu es un expert en cybersécurité et vulgarisateur.\n"
            "Analyse ce rapport brut de scan.\n"
            "Explique clairement, détaille les vulnérabilités, risques, remédiations et bonnes pratiques."
        )

    chunks = split_text(findings, max_len=3500)

    system_msg = "Tu es un assistant expert en cybersécurité, clair et pédagogique."

    full_response = ""

    for i, chunk in enumerate(chunks):
        prompt = f"{user_base_prompt}\n\nVoici la partie {i+1} du rapport de scan :\n{chunk}\n\nAnalyse complète et pédagogique :"
        try:
            response = requests.post(
                "https://api.together.xyz/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "mistralai/Mistral-7B-Instruct-v0.1",
                    "messages": [
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 1024
                },
                timeout=90
            )
            if response.status_code != 200:
                return JsonResponse({"error": f"Erreur HTTP {response.status_code} sur partie {i+1}", "contenu": response.text}, status=500)

            data = response.json()
            chunk_response = data["choices"][0]["message"]["content"]
            full_response += f"\n\n--- Partie {i+1} ---\n\n{chunk_response}"

        except Exception as e:
            return JsonResponse({"error": f"Erreur API partie {i+1}: {str(e)}", "traceback": traceback.format_exc()}, status=500)

    # Stockage dans la base
    scan.ai_analysis = full_response.strip()
    scan.save()

    return JsonResponse({"analyse_ia": full_response.strip()})
