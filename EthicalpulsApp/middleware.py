from .models import AuditLog
from django.utils.deprecation import MiddlewareMixin

class AuditLogMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.user.is_authenticated and request.method in ["POST", "PUT", "DELETE"]:
            action_type = "other"
            if "delete" in view_func.__name__:
                action_type = "delete"
            elif "create" in view_func.__name__:
                action_type = "create"
            elif "update" in view_func.__name__ or "edit" in view_func.__name__:
                action_type = "update"
            elif "scan" in view_func.__name__:
                action_type = "scan"
            elif "login" in view_func.__name__:
                action_type = "login"
            elif "logout" in view_func.__name__:
                action_type = "logout"
            elif "export" in view_func.__name__:
                action_type = "export"
            elif "import" in view_func.__name__:
                action_type = "import"
            # ...ajoute d'autres patterns si besoin

            AuditLog.objects.create(
                action_type=action_type,
                object_type=view_func.__name__,
                object_id=str(view_kwargs.get("pk") or view_kwargs.get("id") or ""),
                object_repr=str(view_func),
                user=request.user,
                ip_address=request.META.get("REMOTE_ADDR"),
                details={"POST": dict(request.POST)},
                status="success"
            )