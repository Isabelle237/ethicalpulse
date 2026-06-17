"""Context processors globaux (disponibles dans tous les templates)."""

from django.urls import reverse, NoReverseMatch

from .models import AuditLog, UserNotification


def _safe_url(name, default="#"):
    try:
        return reverse(name)
    except NoReverseMatch:
        return default


# Verbe lisible selon le type d'action de l'AuditLog
_ACTION_VERB = {
    "create": "créé",
    "update": "modifié",
    "delete": "supprimé",
    "scan": "lancé",
    "export": "exporté",
    "import": "importé",
    "report": "généré",
    "remediation": "appliquée",
}


def _classify_audit(audit):
    """Retourne (libellé, url, icône, couleur) pour une entrée d'AuditLog."""
    ot = (audit.object_type or "").lower()
    if "project" in ot or "projet" in ot:
        base, url, icon, color = "Projet", _safe_url("admin_projets"), "bi-folder-fill", "accent"
    elif "vuln" in ot:
        base, url, icon, color = "Vulnérabilité", _safe_url("vulnerabilities"), "bi-bug-fill", "danger"
    elif "scan" in ot:
        base, url, icon, color = "Scan", _safe_url("scan_list"), "bi-search", "info"
    elif "remediation" in ot:
        base, url, icon, color = "Remédiation", _safe_url("remediations_admin"), "bi-clipboard-check", "success"
    elif "user" in ot:
        base, url, icon, color = "Utilisateur", _safe_url("users"), "bi-person-fill", "accent"
    elif audit.action_type == "export" or "report" in ot or "rapport" in ot:
        base, url, icon, color = "Rapport", _safe_url("reports"), "bi-file-earmark-text-fill", "accent"
    else:
        base, url, icon, color = "Activité", "#", "bi-activity", "secondary"
    verb = _ACTION_VERB.get(audit.action_type, "")
    text = f"{base} {verb}".strip()
    return text, url, icon, color


def notifications(request):
    """Notifications agrégées (UserNotification + AuditLog) pour le navbar."""
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {}

    items = []

    # Notifications personnelles (ex : vulnérabilité détectée par un scan)
    for n in UserNotification.objects.filter(user=request.user).order_by("-created_at")[:10]:
        items.append({
            "icon": "bi-shield-exclamation",
            "color": "danger",
            "text": n.message,
            "url": _safe_url("vulnerabilities_user"),
            "time": n.created_at,
            "is_read": n.is_read,
        })

    # Activité système utile (on écarte connexions/déconnexions et bruit)
    audits = (
        AuditLog.objects
        .exclude(action_type__in=["login", "logout", "other"])
        .order_by("-timestamp")[:12]
    )
    for a in audits:
        text, url, icon, color = _classify_audit(a)
        items.append({
            "icon": icon,
            "color": color,
            "text": text,
            "url": url,
            "time": a.timestamp,
            "is_read": True,
        })

    # Fusion triée par date, limitée
    items.sort(key=lambda x: x["time"], reverse=True)

    unread = UserNotification.objects.filter(user=request.user, is_read=False).count()

    return {
        "nav_notifications": items[:8],
        "nav_notif_unread": unread,
    }
