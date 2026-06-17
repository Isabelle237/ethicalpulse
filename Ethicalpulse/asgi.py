"""
ASGI config for Ethicalpulse project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Ethicalpulse.settings")

# Initialize Django ASGI application early to ensure the app registry is
# populated before importing code that may import models / consumers.
django_asgi_app = get_asgi_application()

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path

from .consumers import ScanProgressConsumer

websocket_urlpatterns = [
    re_path(r"^ws/scan/(?P<scan_id>[^/]+)/$", ScanProgressConsumer.as_asgi()),
]

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
