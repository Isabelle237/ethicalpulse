# Utiliser l'image Python slim
FROM python:3.10-slim

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    build-essential \
    libmariadb-dev \
    pkg-config \
    nmap \
    openjdk-17-jre \
    wget \
    netcat-openbsd \
    git \
    redis-server \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Installer Nikto
RUN git clone https://github.com/sullo/Nikto /opt/nikto \
 && chmod +x /opt/nikto/program/nikto.pl \
 && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Installer gvm-tools et zapcli
RUN pip install --no-cache-dir gvm-tools zapcli

# Télécharger et installer ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2_16_1_unix.sh \
 && sh ZAP_2_16_1_unix.sh -q \
 && ln -s /root/ZAP_2.16.1/zap.sh /usr/local/bin/zap \
 && rm ZAP_2_16_1_unix.sh

# Copier sqlmap localement dans l'image
COPY sqlmap /opt/sqlmap

# Rendre sqlmap exécutable
RUN ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py

# Copier les fichiers de dépendances Python
COPY requirements.txt .
COPY dev-requirements.txt .

# Installer les dépendances de production
RUN pip install --no-cache-dir -r requirements.txt

# Installer les outils de développement (black, flake8...)
RUN pip install --no-cache-dir -r dev-requirements.txt

# Copier tout le code source
COPY . .

# Créer les dossiers nécessaires pour les fichiers statiques et médias
RUN mkdir -p /app/static /app/staticfiles /app/media

# Copier les fichiers statiques
COPY static/ /app/static/

# Copier le reste du code de l'application
COPY . .

# Définir les permissions
RUN chmod -R 755 /app/static /app/staticfiles /app/media \
    && chown -R www-data:www-data /app/static /app/staticfiles /app/media

# Collecter les fichiers statiques
RUN python manage.py collectstatic --noinput

# Commande de démarrage
CMD ["sh", "-c", "\
    service redis-server start && \
    zap.sh -daemon -host 0.0.0.0 -port 8086 -config api.key=620tjnb5od0ef8tep7n78usun & \
    echo 'Attente que ZAP soit prêt...' && \
    while ! nc -z localhost 8086; do echo 'ZAP n\\'est pas encore prêt...'; sleep 1; done && \
    echo 'ZAP est prêt.' && \
    until nc -z -v -w30 db 3306; do echo 'Waiting for MySQL...'; sleep 5; done && \
    python manage.py migrate && \
    celery -A Ethicalpulse worker --loglevel=info & \
    python manage.py runserver 0.0.0.0:8000"]
