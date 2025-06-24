
# EthicalPulse

Plateforme de sécurité informatique EthicalPulse pour la gestion de projets, analyses de vulnérabilités et automatisation de scans.

---

## Table des matières

* [Présentation](#présentation)
* [Prérequis](#prérequis)
* [Installation avec Docker](#installation-avec-docker)
* [Lancer le projet avec Makefile](#lancer-le-projet-avec-makefile)
* [Configuration de la base de données](#configuration-de-la-base-de-données)
* [Gestion des fichiers statiques](#gestion-des-fichiers-statiques)
* [Utilisation de Celery](#utilisation-de-celery)
* [Dépannage](#dépannage)
* [Support](#support)

---

## Présentation

EthicalPulse est une application backend Django conçue pour faciliter la gestion sécurisée de projets et automatiser les analyses de vulnérabilités via des outils comme Nikto, sqlmap, Zap, nmap, et plus. Le projet s’appuie sur Docker pour simplifier le déploiement, avec une architecture incluant Redis et PostgreSQL.

---

## Prérequis

* Docker (version 20.10+)
* Docker Compose (version 2+)
* Make (pour utiliser le Makefile)
* Git
* Minimum 4 Go RAM, 20 Go espace disque

---

## Installation avec Docker

1. **Cloner le dépôt**

```bash
git clone https://github.com/Isabelle237/ethicalpulse.git
cd ethicalpulse
```

2. **Copier et configurer le fichier d'environnement**

```bash
cp .env.example .env
# Modifier .env selon vos paramètres (DB, secrets, etc.)
```

3. **Construire et lancer les conteneurs**

```bash
docker-compose up --build -d
```

4. **Appliquer les migrations Django**

```bash
docker-compose exec web python manage.py migrate
```

5. **Créer un superutilisateur**

```bash
docker-compose exec web python manage.py createsuperuser
```

6. **Accéder à l’application**

* Backend Django : [http://localhost:8000](http://localhost:8000)
* Interface d’administration Django : [http://localhost:8000/admin/](http://localhost:8000/admin/)

---

## Lancer le projet avec Makefile

Pour simplifier la gestion, utilisez les commandes Make définies :

| Commande               | Description                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| `make build`           | Construire l’image et lancer les conteneurs (`docker-compose up --build -d`)                                 |
| `make up`              | Démarrer les conteneurs existants (`docker-compose up -d`)                                                   |
| `make down`            | Arrêter et supprimer les conteneurs (`docker-compose down`)                                                  |
| `make migrate`         | Appliquer les migrations Django (`docker-compose exec web python manage.py migrate`)                         |
| `make createsuperuser` | Créer un superutilisateur (`docker-compose exec web python manage.py createsuperuser`)                       |
| `make collectstatic`   | Collecter les fichiers statiques Django (`docker-compose exec web python manage.py collectstatic --noinput`) |
| `make logs`            | Afficher les logs en temps réel (`docker-compose logs -f`)                                                   |
| `make celery`          | Lancer le worker Celery (`docker-compose exec web celery -A Ethicalpulse worker --loglevel=info`)            |

**Exemple d’utilisation :**

```bash
make build
make migrate
make createsuperuser
make logs
```

---

## Configuration de la base de données

Le projet utilise PostgreSQL. Par défaut, la connexion est configurée via variables d’environnement dans `.env`. Exemple :

```
DB_NAME=ethicalpulse
DB_USER=ethicalpulse
DB_PASSWORD=motdepasse
DB_HOST=db
DB_PORT=5432
```

Pour créer la base et l’utilisateur, vous pouvez accéder au container PostgreSQL et exécuter :

```bash
docker-compose exec db psql -U postgres
CREATE DATABASE ethicalpulse;
CREATE USER ethicalpulse WITH ENCRYPTED PASSWORD 'motdepasse';
GRANT ALL PRIVILEGES ON DATABASE ethicalpulse TO ethicalpulse;
\q
```

---

## Gestion des fichiers statiques

Les fichiers statiques sont collectés automatiquement lors du build Docker grâce à la commande :

```bash
python manage.py collectstatic --noinput
```

Si besoin, vous pouvez relancer cette commande via :

```bash
make collectstatic
```

Les fichiers statiques seront servis depuis `/staticfiles` en production.

---

## Utilisation de Celery

Celery est utilisé pour gérer les tâches asynchrones (ex : scans automatisés).

Pour lancer un worker Celery dans le container Docker :

```bash
make celery
```

---

## Dépannage

* **Module manquant (ex: celery, channels, etc.)**
  Vérifiez que vos dépendances sont bien installées dans `requirements.txt` et que vous avez bien rebuild l’image Docker :

  ```bash
  make build
  ```

* **Erreur de connexion à la base de données**
  Vérifiez que le container PostgreSQL tourne, et que les variables d’environnement sont correctes.

* **Problèmes avec les fichiers statiques**
  Relancez la collecte statique :

  ```bash
  make collectstatic
  ```

* **Celery ne démarre pas**
  Vérifiez les logs :

  ```bash
  docker-compose logs -f web
  ```

---

## Support

Pour toute question ou problème, merci de consulter :

* La documentation officielle (lien à insérer)
* La page issues du dépôt GitHub : [https://github.com/Isabelle237/ethicalpulse/issues](https://github.com/Isabelle237/ethicalpulse/issues)
* Contacter l’équipe support : [support@ethicalpulse.example.com](mailto:support@ethicalpulse.example.com)

