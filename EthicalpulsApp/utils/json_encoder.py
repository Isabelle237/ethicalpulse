from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import QuerySet
from django.db.models.fields.files import FieldFile
from datetime import datetime, date, timedelta

class CustomJSONEncoder(DjangoJSONEncoder):
    """Custom JSON encoder that handles Django model instances and QuerySets"""
    
    def default(self, obj):
        # Handle QuerySets
        if isinstance(obj, QuerySet):
            return list(obj)
        
        # Handle dates and times
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
            
        # Handle timedelta
        if isinstance(obj, timedelta):
            total_seconds = int(obj.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
            
        # Handle file fields
        if isinstance(obj, FieldFile):
            return obj.url if obj else None
            
        # Let the base class handle anything else
        return super().default(obj)