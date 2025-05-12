from django.apps import AppConfig


class EthicalpulsappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'EthicalpulsApp'
    def ready(self):
        import EthicalpulsApp.signals