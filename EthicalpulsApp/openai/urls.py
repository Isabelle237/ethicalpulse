from django.urls import path
from EthicalpulsApp.openai import views_ai

urlpatterns = [
    path("ai/analyse/<int:scan_id>/", views_ai.ai_scan_analysis, name="ai_scan_analysis"),    ]