# rac-auth-service

Microservicio de autenticación que actúa como **fachada de Keycloak**, centralizando login, refresh, logout y userinfo.

## Endpoints

| Método | Ruta | Descripción |
|--------|------|--------------|
| POST | `/api/auth/login` | Login contra Keycloak y genera JWT interno opcional |
| POST | `/api/auth/refresh` | Refresca token |
| POST | `/api/auth/logout` | Cierra sesión en Keycloak |
| GET  | `/api/auth/userinfo` | Retorna datos del usuario autenticado |
| GET  | `/health` | Health check |

## Variables de entorno

Ver `.env.example`

## Ejecución local

```bash
go run cmd/server/main.go
