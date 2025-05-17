FROM python:3.10-slim

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
    sqlmap \
    netcat-openbsd \ 
    && apt-get clean

# Installer gvm-tools via pip (car ce n'est pas un paquet apt)
RUN pip install --no-cache-dir gvm-tools zapcli

# Télécharger et installer OWASP ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2_16_1_unix.sh && \
    sh ZAP_2_16_1_unix.sh -q && \
    ln -s /root/ZAP_2.16.1/zap.sh /usr/local/bin/zap && \
    rm ZAP_2_16_1_unix.sh

# Copier les fichiers de dépendances avant le code source
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du code
COPY . .

#CMD ["sh", "-c", "zap.sh -daemon -host 0.0.0.0 -port 8080 &&until nc -z -v -w30 db 3306; do echo 'Waiting for MySQL...'; sleep 5; done; python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
CMD ["sh", "-c", "service redis-server start && ./zap.sh -daemon -host 0.0.0.0 -port 8086 -config api.key=620tjnb5od0ef8tep7n78usun && \
    echo 'Attente que ZAP soit prêt...' && \
    while ! nc -z localhost 8086; do echo 'ZAP n\'est pas encore prêt...'; sleep 1; done && \
    echo 'ZAP est prêt.' && \
    until nc -z -v -w30 db 3306; do echo 'Waiting for MySQL...'; sleep 5; done && \
    python manage.py migrate && \
    python manage.py runserver 0.0.0.0:8000"]