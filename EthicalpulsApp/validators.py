# validators.py

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def validate_ip(value):
    # Vérifie si l'adresse IP est valide
    ip_regex = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if not re.match(ip_regex, value):
        raise ValidationError(_('Adresse IP invalide.'))

def validate_mac(value):
    # Vérifie si l'adresse MAC est valide
    mac_regex = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    if not re.match(mac_regex, value):
        raise ValidationError(_('Adresse MAC invalide.'))

def validate_url(value):
    # Vérifie si l'URL est valide
    url_regex = r'^(http|https)://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9./?&=]*)?$'
    if not re.match(url_regex, value):
        raise ValidationError(_('URL invalide.'))
