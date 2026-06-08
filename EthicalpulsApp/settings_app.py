APP_CONFIG = {
    "site_name": "Ethical Pulse Shield",
    "site_description": "Plateforme de gestion de la sécurité et des vulnérabilités",
    "timezone": "Europe/Paris",
    "date_format": "dd/mm/yyyy",
    "dark_mode": True,
    "animations": True,
    "results_per_page": 25,
    "default_language": "fr",
    "password_complexity": True,
    "password_history": True,
    "password_expiration": 90,
    "session_timeout": 30,
    "max_login_attempts": 5,
    "enable_2fa": True,
    "require_2fa_admins": True,
    "csrf_protection": True,
    "smtp_server": "smtp.entreprise.com",
    "smtp_port": 587,
    "smtp_security": "TLS",
    "smtp_username": "clara@entreprise.com",
    "smtp_password": "password",
    "default_sender": "security-alerts@entreprise.com",
    "default_reply_to": "no-reply@entreprise.com",
    "enable_api": False,
    "api_rate_limit": 120,
    "api_key_expiry": "90 jours",
    "enable_api_logs": False,
    "public_api_docs": False,
    "notif_email": False,
    "notif_sms": False,
    "notif_webhook": False,
    "notif_slack": False,
    "notif_browser": False,
    "notif_critical": False,
    "notif_high": False,
    "notif_medium": False,
    "notif_low": False,
    "notif_info": False,
    "notif_grouping": "Par type de vulnérabilité",
    "notif_quiet_hours": False,
    "notif_quiet_start": "22:00",
    "notif_quiet_end": "07:00",
    "notif_critical_override": False,
    "enable_backup": False,
    "backup_frequency": "Quotidienne",
    "backup_time": "02:00",
    "backup_location": "AWS S3",
    "s3_bucket": "ethicalpulse-backups",
    "s3_region": "eu-west-3",
    "retention_policy": "30 jours",
    "encrypt_backups": False,
    "log_level": "Info",
    "log_retention": "90 jours",
    "log_rotation": "Quotidienne",
    "enable_audit_logs": False,
    "forward_syslog": False,
    "syslog_server": "logs.entreprise.com",
    "syslog_port": 514,
    "syslog_protocol": "TCP",
    "license_type": "Enterprise",
    "license_company": "Ethical Security Inc.",
    "license_contact": "Jean Dupont",
    "license_email": "jean.dupont@ethicalsecurity.com",
    "license_issue_date": "2025-01-15",
    "license_expiry_date": "2026-01-15",
    "license_hardware_id": "EP-7890-1234-5678-9012",
    "license_alerts": False,
    "license_alert_days": 30,
    "license_notification_contact": "admin@ethicalsecurity.com",
}
import importlib
import os

SETTINGS_PATH = os.path.abspath(__file__)


def get_app_config():
    import EthicalpulsApp.settings_app as settings_app

    importlib.reload(settings_app)
    return settings_app.APP_CONFIG.copy()


def set_app_config(new_config):
    lines = ["APP_CONFIG = {\n"]
    for k, v in new_config.items():
        if isinstance(v, str):
            lines.append(f'    "{k}": "{v}",\n')
        elif isinstance(v, bool):
            lines.append(f'    "{k}": {str(v)},\n')
        else:
            lines.append(f'    "{k}": {v},\n')
    lines.append("}\n")
    with open(SETTINGS_PATH, "w") as f:
        f.writelines(lines)
