# API — Phase 1

Base: `http://localhost:8080`. All `/api/v1` except register/login need
`Authorization: Bearer <jwt>`.

## Auth

```http
POST /api/v1/auth/register  {"username":"alice","password":"...","role":"viewer"}
→ 201 {"id","username","role"}   # first user forced admin

POST /api/v1/auth/login  {"username":"alice","password":"..."}
→ 200 {"token","role"}
```

## Projects

```http
POST /api/v1/projects  {"name":"acme","description":"lab"}
→ 201 Project   # operator+

GET /api/v1/projects → 200 [Project]
GET /api/v1/projects/{id} → 200 Project | 404
```

## Scope

```http
POST /api/v1/projects/{id}/scope  {"value":"10.10.10.0/24"}
→ 201 ScopeEntry | 400 invalid   # operator+

GET /api/v1/projects/{id}/scope → 200 [ScopeEntry]
```

Values: CIDR (`10.10.0.0/16`), IP (`10.0.0.5`), domain (`web01.lab`).

## Targets (scope-enforced)

```http
POST /api/v1/projects/{id}/targets  {"value":"10.10.10.10"}
→ 201 Target | 403 scope denied | 400 invalid   # operator+

GET /api/v1/projects/{id}/targets → 200 [Target]
GET /api/v1/projects/{id}/timeline → 200 [TimelineEvent]
GET /healthz → 200 {"status":"ok"}
```

## Errors

```json
{"error":"scope denied for \"8.8.8.8\": IP 8.8.8.8 is outside authorized scope"}
```

- 400 malformed JSON / bad field / invalid scope syntax
- 401 missing/expired token, bad credentials
- 403 valid auth but forbidden (out-of-scope, viewer write)
- 404 unknown project
- 409 duplicate (username, project name, scope/target value)
