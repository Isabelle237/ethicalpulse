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
    
    