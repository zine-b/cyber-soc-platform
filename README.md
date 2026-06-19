# Cyber SOC Platform

Mini plateforme SOC/SIEM développée avec **Go**, **React**, **PostgreSQL**, **Docker** et **Traefik**.

Elle collecte des logs, parse les événements SSH Linux, détecte les tentatives de brute force, génère des alertes et permet de gérer des incidents depuis un dashboard web.

## Architecture

```text
Internet
   ↓
Traefik :80 / :443
   ├── /api, /docs, /openapi.json → API Go :8000
   └── /                         → React + Nginx :80
                                      ↓
                                PostgreSQL :5432
```

Le backend utilise PostgreSQL avec Docker Compose et peut utiliser SQLite pour le développement local.

## Technologies

- Backend : Go 1.25, `net/http`, GORM, pgx, SQLite
- Migrations : `golang-migrate` avec migrations SQL versionnées et embarquées
- Frontend : React, Vite, Axios, CSS, Nginx
- Données : PostgreSQL 16 en production, SQLite en local
- Déploiement : Docker Compose, Traefik, Let’s Encrypt, DuckDNS, GCP

## Fonctionnalités

- ingestion et pagination des logs ;
- parsing de plusieurs formats d’échecs SSH ;
- détection de 5 échecs depuis une même IP en 10 minutes ;
- génération d’alertes `SSH_BRUTE_FORCE` sans doublon ouvert ;
- consultation et changement de statut des alertes ;
- création, assignation et changement de statut des incidents ;
- liaison d’une alerte à un incident ;
- documentation OpenAPI et Swagger UI ;
- migrations de schéma automatiques au démarrage ;
- arrêt gracieux et endpoint de santé connecté à la base.

## Structure

```text
cyber-soc-platform/
  backend/
    cmd/api/main.go
    internal/
      api/api.go
      config/config.go
      domain/models.go
      security/parser.go
      store/store.go
      migrations/
        migrations.go
        postgres/*.sql
        sqlite/*.sql
    Dockerfile
    go.mod
  frontend/
    src/
    Dockerfile
    nginx.conf
  traefik/
    traefik_dynamic.yml
  docker-compose.yml
```

## API

```http
GET   /health
POST  /ingest/log
GET   /logs?page=1&limit=10

GET   /alerts
GET   /alerts/{alert_id}
PATCH /alerts/{alert_id}/status
PATCH /alerts/{alert_id}/assign-incident

POST  /incidents
GET   /incidents
GET   /incidents/{incident_id}
PATCH /incidents/{incident_id}/status
PATCH /incidents/{incident_id}/assign
```

Documentation locale :

```text
http://localhost:8000/docs
http://localhost:8000/openapi.json
```

## Configuration du backend

Copier les variables d’environnement :

```bash
cp backend/.env.example backend/.env
```

Variables disponibles :

```dotenv
DATABASE_URL=sqlite:///./cyber_soc.db
APP_NAME=Cyber SOC Platform API
APP_VERSION=0.1.0
FRONTEND_URL=http://localhost:5173
PORT=8000
```

Exemple PostgreSQL :

```dotenv
DATABASE_URL=postgresql://cyber_user:cyber_password@localhost:5432/cyber_soc
```

## Lancement local

Prérequis : Go 1.25+, Node.js et npm.

Backend :

```bash
cd backend
go mod tidy
set -a
source .env
set +a
go run ./cmd/api
```

Frontend, dans un second terminal :

```bash
cd frontend
npm install
VITE_API_BASE_URL=http://localhost:8000 npm run dev
```

## Lancement avec Docker Compose

```bash
docker compose up -d --build
```

Pour tester sur une machine locale sans domaine public ni certificat
Let’s Encrypt :

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build postgres backend frontend
```

Ouvrir ensuite :

```text
http://localhost:5173
http://localhost:8000/health
http://localhost:8000/docs
```

Commandes utiles :

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f traefik
docker compose down
```

Le backend attend que PostgreSQL soit sain avant de démarrer. Au démarrage,
`golang-migrate` applique les migrations SQL manquantes, puis GORM prend en
charge les lectures et écritures. La version courante du schéma est stockée
dans `schema_migrations`.

Pour ajouter une migration, créer la même version pour les deux dialectes :

```text
backend/internal/migrations/postgres/000002_description.up.sql
backend/internal/migrations/postgres/000002_description.down.sql
backend/internal/migrations/sqlite/000002_description.up.sql
backend/internal/migrations/sqlite/000002_description.down.sql
```

Les fichiers sont embarqués dans le binaire et appliqués automatiquement au
prochain démarrage.

## Test fonctionnel

Envoyer cinq logs avec la même IP :

```bash
for user in root admin test ubuntu postgres; do
  curl -X POST http://localhost:8000/ingest/log \
    -H 'Content-Type: application/json' \
    -d "{\"source\":\"linux-server-01\",\"log_type\":\"linux_auth\",\"message\":\"Failed password for $user from 185.10.20.30 port 52344 ssh2\"}"
done
```

Puis vérifier l’alerte :

```bash
curl http://localhost:8000/alerts
```

Une alerte ouverte `SSH_BRUTE_FORCE` de sévérité `high` doit être présente.

## Déploiement

Traefik route le domaine `cyber-soc.duckdns.org` :

```text
/                     → frontend
/api                  → backend, avec suppression du préfixe /api
/docs                 → Swagger UI
/openapi.json         → schéma OpenAPI
```

Le backend n’est pas publié directement sur Internet ; il est joignable par Traefik sur le réseau Docker interne.

Pour déployer :

```bash
git clone <repository-url>
cd cyber-soc-platform
docker compose up -d --build
```

## Tests Go

```bash
cd backend
go test ./...
```
