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
    && apt-get clean

# Installer gvm-tools via pip (car ce n'est pas un paquet apt)
RUN pip install --no-cache-dir gvm-tools

# Installer OWASP ZAP version 2.16.1
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2_16_1_unix.sh && \
    sh ZAP_2_16_1_unix.sh -q && \
    ln -s /root/ZAP_2.16.1/zap.sh /usr/local/bin/zap && \
    rm ZAP_2_16_1_unix.sh

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "until nc -z -v -w30 db 3306; do echo 'Waiting for MySQL...'; sleep 5; done; python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
