import subprocess
from django.db.backends.signals import connection_created
from django.db import connections
from django.apps import AppConfig

# Fonction pour démarrer ZAP en mode daemon
def start_zap(sender, connection, **kwargs):
    try:
        # Vérifie si ZAP est déjà en cours d'exécution avant de lancer un nouveau processus
        subprocess.Popen(['/opt/zap/zap.sh', '-daemon', '-host', '127.0.0.1', '-port', '8090', '-config', 'api.disablekey=true'])
        print("ZAP démarré en mode daemon sur http://127.0.0.1:8090")
    except Exception as e:
        print(f"Erreur lors du démarrage de ZAP : {str(e)}")

# Configuration de l'application pour enregistrer le signal
class MyAppConfig(AppConfig):
    name = 'mon_app'

    def ready(self):
        # Connecter la fonction de démarrage de ZAP au signal de connexion à la base de données
        connection_created.connect(start_zap)
