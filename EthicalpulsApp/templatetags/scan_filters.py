# ethicalpulsApp/templatetags/custom_filters.py

import builtins
import json
from django import template
from django.core.serializers.json import DjangoJSONEncoder

register = template.Library()

# Adds a CSS class to a form field
@register.filter(name='addclass')
def addclass(field, css_class):
    return field.as_widget(attrs={"class": css_class})

# Status color mapping
@register.filter(name='status_color')
def status_color(value):
    if value == 'scheduled':
        return 'gray'
    elif value == 'in_progress':
        return 'blue'
    elif value == 'completed':
        return 'green'
    elif value == 'failed':
        return 'red'
    return 'black'

# Get item from a dictionary
@register.filter(name='dict_key')
@register.filter(name='get_item')
def get_item(dictionary, key):
    try:
        return dictionary.get(key, '')
    except AttributeError:
        return ''

# Get item from a list by index
@register.filter(name='list_index')
def list_index(lst, index):
    try:
        return lst[int(index)]
    except (IndexError, ValueError, TypeError):
        return ''

# Extract port from 'port/service'
@register.filter(name='get_port')
def get_port(port_string):
    return port_string.split('/')[0] if port_string and '/' in port_string else port_string

# Extract service from 'port/service'
@register.filter(name='get_service')
def get_service(port_string):
    parts = port_string.split('/')
    return parts[1] if len(parts) > 1 else ''

# Split a string by a delimiter
@register.filter(name='split')
def split(value, delimiter='/'):
    try:
        return value.split(delimiter)
    except AttributeError:
        return []

# Convert to JavaScript-safe string
@register.filter(name='to_js')
def to_js(value):
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(str(v) for v in value) + ']'
    return str(value)

# Convert to JSON string
@register.filter(name='json')
def jsonify(data):
    return json.dumps(data, cls=DjangoJSONEncoder)

# Absolute value (renamed to avoid conflict)
@register.filter(name='abs_val')
def abs_val(value):
    try:
        return builtins.abs(float(value))
    except (ValueError, TypeError):
        return value

# Format duration
@register.filter(name='format_duration')
def format_duration(value):
    try:
        hours = value.total_seconds() // 3600
        minutes = (value.total_seconds() % 3600) // 60
        return f"{int(hours)}h {int(minutes)}m"
    except (AttributeError, TypeError):
        return value
