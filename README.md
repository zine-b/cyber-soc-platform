# Cyber SOC Platform

Mini plateforme SOC/SIEM développée avec **FastAPI**, **React**, **Docker**, **Traefik** et déployée sur **Google Cloud Platform (GCP)**.

Ce projet a été réalisé dans un objectif d’apprentissage full-stack et DevOps. Il simule une plateforme de supervision sécurité capable de recevoir des logs, détecter une attaque brute force SSH, générer des alertes, gérer des incidents et afficher les données dans un dashboard web.

---

## 1. Présentation du projet

Cyber SOC Platform est une application full-stack inspirée des concepts de SIEM, SOC dashboard et incident management.

L’application permet de :

* collecter des logs de sécurité ;
* parser des logs SSH Linux ;
* détecter une tentative de brute force SSH ;
* générer automatiquement des alertes ;
* créer et suivre des incidents ;
* assigner un incident à un analyste ;
* lier une alerte à un incident ;
* afficher logs, alertes et incidents dans un dashboard React ;
* paginer les logs côté backend ;
* déployer l’application avec Docker Compose ;
* exposer l’application en HTTPS via Traefik et Let’s Encrypt.

---

## 2. Architecture

Architecture générale :

```text
Internet
   ↓
Traefik Reverse Proxy :80 / :443
   ↓
Frontend React servi par Nginx
   ↓
Backend FastAPI
   ↓
SQLite via volume Docker
```

Architecture des routes :

```text
https://cyber-soc.duckdns.org          → Frontend React
https://cyber-soc.duckdns.org/api      → Backend FastAPI
https://cyber-soc.duckdns.org/docs     → Swagger UI
https://cyber-soc.duckdns.org/openapi.json → OpenAPI schema
```

Le backend n’est pas exposé directement sur Internet. Il est accessible uniquement à travers Traefik via le réseau Docker interne.

---

## 3. Technologies utilisées

### Backend

* Python
* FastAPI
* Uvicorn
* SQLAlchemy
* Pydantic
* SQLite
* python-dotenv

### Frontend

* React
* Vite
* JavaScript
* Axios
* CSS
* Nginx

### DevOps / Déploiement

* Docker
* Docker Compose
* Traefik
* Let’s Encrypt
* DuckDNS
* Google Cloud Platform
* Compute Engine VM
* Linux Ubuntu

---

## 4. Fonctionnalités

### Logs

* Ingestion de logs via API REST.
* Parsing de logs SSH Linux.
* Extraction automatique de :

  * username ;
  * IP source ;
  * action ;
  * sévérité ;
  * catégorie.

Exemple de log supporté :

```text
Failed password for root from 185.10.20.30 port 52344 ssh2
```

Résultat après parsing :

```json
{
  "category": "authentication",
  "action": "login_failed",
  "username": "root",
  "source_ip": "185.10.20.30",
  "severity": "medium"
}
```

### Détection

Règle de détection implémentée :

```text
Si une même IP fait 5 échecs SSH dans les 10 dernières minutes,
alors une alerte SSH_BRUTE_FORCE est créée.
```

### Alertes

L’application permet de :

* consulter les alertes ;
* consulter le détail d’une alerte ;
* changer le statut d’une alerte ;
* lier une alerte à un incident.

Statuts disponibles :

```text
open
investigating
resolved
false_positive
```

### Incidents

L’application permet de :

* créer un incident ;
* consulter les incidents ;
* consulter le détail d’un incident ;
* assigner un incident à un analyste ;
* changer le statut d’un incident ;
* afficher les alertes liées à un incident.

### Dashboard

Le frontend affiche :

* total des logs ;
* total des alertes ;
* alertes ouvertes ;
* alertes high ;
* total des incidents ;
* incidents ouverts ;
* tableau des logs ;
* tableau des alertes ;
* tableau des incidents.

---

## 5. Structure du projet

```text
cyber-soc-platform/
  backend/
    app/
      __init__.py
      main.py
      database.py
      models.py
      schemas.py
      parsers.py
      detection.py
    Dockerfile
    requirements.txt
    .dockerignore

  frontend/
    src/
      api/
        client.js
      App.jsx
      main.jsx
      index.css
    nginx.conf
    Dockerfile
    package.json
    .dockerignore

  traefik/
    traefik_dynamic.yml
    acme.json

  docker-compose.yml
  README.md
  .gitignore
```

---

## 6. Backend

Le backend est organisé en plusieurs modules :

```text
database.py  → configuration SQLAlchemy et connexion SQLite
models.py    → modèles de base de données
schemas.py   → schémas Pydantic pour les requêtes et réponses
parsers.py   → parsing des logs SSH
detection.py → règles de détection
main.py      → routes API FastAPI
```

Principaux endpoints :

```http
GET /                         → vérifier que l’API fonctionne
POST /ingest/log              → envoyer un log
GET /logs                     → récupérer les logs avec pagination
GET /alerts                   → récupérer les alertes
GET /alerts/{alert_id}        → récupérer une alerte
PATCH /alerts/{alert_id}/status  
PATCH /alerts/{alert_id}/assign-incident

POST /incidents
GET /incidents
GET /incidents/{incident_id}
PATCH /incidents/{incident_id}/status
PATCH /incidents/{incident_id}/assign
```

Pagination des logs :

```http
GET /logs?page=1&limit=10
```

Exemple de réponse :

```json
{
  "count": 10,
  "total": 25,
  "page": 1,
  "limit": 10,
  "total_pages": 3,
  "logs": []
}
```

---

## 7. Frontend

Le frontend est développé avec React et Vite.

Il utilise Axios pour communiquer avec le backend :

```javascript
import axios from "axios";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
});

export default apiClient;
```

En production, le frontend utilise une URL relative :

```text
/api
```

Cela permet de fonctionner correctement derrière Traefik, sans mettre l’IP ou le domaine en dur dans le code.

---

## 8. Installation locale sans Docker

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend disponible sur :

```text
http://127.0.0.1:8000
```

Swagger :

```text
http://127.0.0.1:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend disponible sur :

```text
http://localhost:5173
```

---

## 9. Lancement avec Docker Compose

Depuis la racine du projet :

```bash
docker compose up -d --build
```

Voir les conteneurs :

```bash
docker ps
```

Voir les logs :

```bash
docker logs -f cyber-soc-backend
docker logs -f cyber-soc-frontend
docker logs -f cyber-soc-traefik
```

Arrêter les services :

```bash
docker compose down
```

Supprimer aussi les volumes :

```bash
docker compose down -v
```

---

## 10. Reverse proxy avec Traefik

Traefik est utilisé comme reverse proxy dédié.

Il écoute sur :

```text
80  → HTTP
443 → HTTPS
```

Il route les requêtes de cette manière :

```text
/             → frontend
/api          → backend
/docs         → backend Swagger
/openapi.json → backend OpenAPI schema
```

La configuration dynamique Traefik est dans :

```text
traefik/traefik_dynamic.yml
```

Exemple de service backend dans Traefik :

```yaml
backend-service:
  loadBalancer:
    servers:
      - url: "http://backend:8000"
```

Exemple de service frontend :

```yaml
frontend-service:
  loadBalancer:
    servers:
      - url: "http://frontend:80"
```

---

## 11. HTTPS avec DuckDNS et Let’s Encrypt

Le domaine utilisé :

```text
cyber-soc.duckdns.org
```

DuckDNS pointe vers l’adresse IP publique de la VM GCP.

Traefik utilise Let’s Encrypt avec le challenge HTTP pour générer automatiquement le certificat SSL.

URLs finales :

```text
https://cyber-soc.duckdns.org
https://cyber-soc.duckdns.org/api
https://cyber-soc.duckdns.org/docs
```

Vérification de la redirection HTTP vers HTTPS :

```bash
curl -I http://cyber-soc.duckdns.org
```

Résultat attendu :

```text
HTTP/1.1 308 Permanent Redirect
Location: https://cyber-soc.duckdns.org/
```

Vérification HTTPS :

```bash
curl -I https://cyber-soc.duckdns.org
```

Résultat attendu :

```text
HTTP/2 200
```

---

## 12. Déploiement sur Google Cloud Platform

Le projet est déployé sur une VM Compute Engine.

Étapes réalisées :

1. Création d’une VM Ubuntu sur GCP.
2. Installation de Docker et Docker Compose.
3. Configuration des règles firewall :

   * port 22 pour SSH ;
   * port 80 pour HTTP ;
   * port 443 pour HTTPS.
4. Configuration DuckDNS vers l’IP publique de la VM.
5. Clonage du projet depuis GitHub.
6. Lancement avec Docker Compose.
7. Configuration HTTPS avec Traefik et Let’s Encrypt.

Commandes principales sur la VM :

```bash
git clone <repository-url>
cd cyber-soc-platform
docker compose up -d --build
```

---

## 13. Tests fonctionnels

### Tester l’API

```bash
curl https://cyber-soc.duckdns.org/api
```

Résultat attendu :

```json
{
  "message": "Cyber SOC Platform API is running"
}
```

### Tester les logs

```bash
curl "https://cyber-soc.duckdns.org/api/logs?page=1&limit=10"
```

### Tester Swagger

```text
https://cyber-soc.duckdns.org/docs
```

### Tester le frontend

```text
https://cyber-soc.duckdns.org
```

---

## 14. Exemple de données de test

Envoyer 5 logs SSH avec la même IP pour déclencher une alerte :

```json
{
  "source": "linux-server-01",
  "log_type": "linux_auth",
  "message": "Failed password for root from 185.10.20.30 port 52344 ssh2"
}
```

```json
{
  "source": "linux-server-01",
  "log_type": "linux_auth",
  "message": "Failed password for admin from 185.10.20.30 port 52345 ssh2"
}
```

```json
{
  "source": "linux-server-01",
  "log_type": "linux_auth",
  "message": "Failed password for test from 185.10.20.30 port 52346 ssh2"
}
```

```json
{
  "source": "linux-server-01",
  "log_type": "linux_auth",
  "message": "Failed password for ubuntu from 185.10.20.30 port 52347 ssh2"
}
```

```json
{
  "source": "linux-server-01",
  "log_type": "linux_auth",
  "message": "Failed password for postgres from 185.10.20.30 port 52348 ssh2"
}
```

Après ces 5 logs, une alerte `SSH_BRUTE_FORCE` doit être créée.

---

## 15. Commandes Docker utiles

Voir les conteneurs :

```bash
docker ps
```

Voir les logs Traefik :

```bash
docker logs -f cyber-soc-traefik
```

Voir les logs backend :

```bash
docker logs -f cyber-soc-backend
```

Voir les logs frontend :

```bash
docker logs -f cyber-soc-frontend
```

Entrer dans un conteneur :

```bash
docker exec -it cyber-soc-backend sh
```

Redémarrer tout :

```bash
docker compose down
docker compose up -d --build
```

---

## 16. Problèmes rencontrés et solutions

### Problème : conflit Anaconda / Pydantic

Une erreur est apparue avec Anaconda car un package exigeait `pydantic<2.0`.

Solution :

* créer un environnement virtuel Python dédié ;
* ne pas installer les dépendances dans l’environnement Anaconda global.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Problème : frontend ne communique pas avec le backend

Cause :

* mauvaise URL API ;
* variable Vite non rebuildée ;
* reverse proxy mal configuré.

Solution :

* utiliser une URL relative `/api` ;
* rebuild le frontend ;
* router `/api` vers le backend avec Traefik.

### Problème : Traefik Docker provider et erreur Docker API

Erreur rencontrée :

```text
client version 1.24 is too old. Minimum supported API version is 1.40
```

Solution :

* ne plus utiliser le Docker provider ;
* utiliser le file provider de Traefik ;
* définir les routes dans `traefik/traefik_dynamic.yml`.

---

## 17. Compétences démontrées

Ce projet démontre des compétences en :

### Développement backend

* API REST ;
* FastAPI ;
* SQLAlchemy ;
* Pydantic ;
* logique de détection ;
* pagination backend.

### Développement frontend

* React ;
* Axios ;
* dashboard ;
* gestion d’état ;
* interaction avec API ;
* pagination.

### DevOps

* Docker ;
* Docker Compose ;
* Nginx ;
* Traefik ;
* HTTPS ;
* Let’s Encrypt ;
* DuckDNS ;
* déploiement sur GCP ;
* reverse proxy ;
* volumes Docker ;
* logs et debug.

### Cybersécurité

* logique SOC ;
* logs SSH ;
* brute force detection ;
* alert management ;
* incident management.

---

## 18. Prochaines améliorations

Les prochaines étapes possibles :

1. Ajouter un endpoint `/health`.
2. Ajouter des healthchecks Docker.
3. Ajouter une authentification JWT.
4. Ajouter des rôles : admin, analyst, readonly.
5. Remplacer SQLite par PostgreSQL.
6. Ajouter Alembic pour les migrations.
7. Ajouter GitHub Actions pour CI/CD.
8. Ajouter des tests unitaires.
9. Ajouter un système de commentaires sur les incidents.
10. Ajouter Prometheus/Grafana pour le monitoring.
11. Ajouter des logs structurés.
12. Ajouter un vrai système de multi-tenant.
13. Ajouter d’autres règles de détection.
14. Ajouter une threat intelligence simple.

---

## 19. Statut actuel

Statut du projet :

```text
MVP fonctionnel
Déploiement cloud fonctionnel
HTTPS fonctionnel
Reverse proxy fonctionnel
Backend non exposé directement
Dashboard accessible publiquement
```

URL de production :

```text
https://cyber-soc.duckdns.org
```
