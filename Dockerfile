# Utiliser l'image de base Python
FROM python:3.10

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système requises
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier le fichier requirements.txt dans le conteneur
COPY requirements.txt /app/

# Installer les dépendances Python (en créant un environnement virtuel)
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le code du projet dans le conteneur
COPY . /app/

# Exposer le port 8000 pour l'application Django
EXPOSE 8000

# Définir le point d'entrée et exécuter le serveur de développement Django
CMD ["sh", "-c", "until nc -z -v -w30 db 3306; do echo 'Waiting for MySQL...'; sleep 5; done; python manage.py runserver 0.0.0.0:8000"]
