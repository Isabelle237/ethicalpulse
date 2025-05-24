# ethicalpulsApp/templatetags/scan_filters.py

from django import template

register = template.Library()

@register.filter
def scan_status_color(value):
    """Retourne une couleur de badge en fonction du statut du scan."""
    if value == 'in_progress':
        return 'warning'  # Jaune pour les scans en cours
    elif value == 'completed':
        return 'success'  # Vert pour les scans terminés avec succès
    elif value == 'failed':
        return 'danger'  # Rouge pour les scans échoués
    else:
        return 'secondary'  # Gris pour les statuts inconnus
# ethicalpulsApp/templatetags/custom_filters.py

from django import template

register = template.Library()

@register.filter
def status_color(value):
    """
    Retourne une couleur en fonction du statut du scan.
    """
    if value == 'scheduled':
        return 'gray'  # Gris pour "Planifié"
    elif value == 'in_progress':
        return 'blue'  # Bleu pour "En cours"
    elif value == 'completed':
        return 'green'  # Vert pour "Terminé"
    elif value == 'failed':
        return 'red'  # Rouge pour "Échoué"
    return 'black'  # Par défaut, noir
from django import template

register = template.Library()

@register.filter
def dict_key(value, key):
    """
    Retourne la valeur associée à une clé dans un dictionnaire.
    """
    try:
        return value.get(key, {})
    except AttributeError:
        return {}

register = template.Library()

@register.filter
def get_port(value):
    """Retourne le numéro de port depuis une chaîne 'port/service'"""
    if value and '/' in value:
        return value.split('/')[0]
    return value

@register.filter
def get_service(value):
    """Retourne le service depuis une chaîne 'port/service'"""
    if value and '/' in value:
        return value.split('/')[1]
    return value
    
    from django import template

register = template.Library()

@register.filter(name='split')
def split_filter(value, arg=None):
    """
    Divise une chaîne selon un séparateur
    Usage: {{ value|split:"/" }}
    """
    if arg:
        return value.split(arg)
    return value.split()

@register.filter(name='get_port')
def get_port(port_string):
    """
    Extrait le numéro de port de la chaîne
    Usage: {{ "80/http"|get_port }} -> 80
    """
    return port_string.split('/')[0] if port_string else ''

@register.filter(name='get_service')
def get_service(port_string):
    """
    Extrait le nom du service de la chaîne
    Usage: {{ "80/http"|get_service }} -> http
    """
    parts = port_string.split('/')
    return parts[1] if len(parts) > 1 else ''