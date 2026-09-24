# Certificate Radar API

HTTP API для управления TLS targets и запуска/просмотра результатов сканирования.

## Base URL

```text
http://localhost:8080
```

Все API endpoints используют JSON.

---

# 1. Health

## GET `/health`

Проверка доступности API.

### Response `200 OK`

```json
{
  "status": "ok"
}
```

### Example

```bash
curl http://localhost:8080/health
```

---

# 2. Targets

Target — TLS endpoint, который Certificate Radar должен мониторить.

Target состоит из:

- `id` — уникальный идентификатор
- `address` — адрес TCP connection
- `port` — TLS port
- `server_name` — SNI / hostname для TLS verification
- `enabled` — участвует ли target в scanning
- `owner` — владелец сервиса
- `criticality` — бизнес-критичность

Поддерживаются:

```text
example.com
example.com:8443
10.0.0.10
10.0.0.10:8443
https://example.com
https://example.com:8443
```

---

## POST `/api/targets`

Создать target.

### Request

```json
{
  "target": "https://example.com",
  "owner": "platform",
  "criticality": "HIGH"
}
```

### Fields

| Field         | Type   | Required | Description                         |
| ------------- | ------ | -------: | ----------------------------------- |
| `target`      | string |      yes | Hostname, IP, URL или host:port     |
| `owner`       | string |       no | Владелец сервиса                    |
| `criticality` | string |       no | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

Если `criticality` не указан, используется `LOW`.

### Response `201 Created`

```json
{
  "id": "8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b",
  "address": "example.com",
  "port": 443,
  "server_name": "example.com",
  "enabled": true,
  "owner": "platform",
  "criticality": "HIGH"
}
```

### Example

```bash
curl -X POST http://localhost:8080/api/targets \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "owner": "platform",
    "criticality": "HIGH"
  }'
```

### Errors

`400 Bad Request`

```json
{
  "error": "..."
}
```

---

# 3. List Targets

## GET `/api/targets`

Получить список targets.

### Response `200 OK`

```json
[
  {
    "id": "8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b",
    "address": "example.com",
    "port": 443,
    "server_name": "example.com",
    "enabled": true,
    "owner": "platform",
    "criticality": "HIGH"
  }
]
```

### Example

```bash
curl http://localhost:8080/api/targets
```

---

# 4. Get Target

## GET `/api/targets/:id`

Получить target по ID.

### Example

```bash
curl http://localhost:8080/api/targets/8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b
```

### Response `200 OK`

```json
{
  "id": "8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b",
  "address": "example.com",
  "port": 443,
  "server_name": "example.com",
  "enabled": true,
  "owner": "platform",
  "criticality": "HIGH"
}
```

### Errors

`404 Not Found`

```json
{
  "error": "target not found"
}
```

---

# 5. Update Target

## PUT `/api/targets/:id`

Изменяет metadata target.

В текущем MVP через этот endpoint нельзя менять:

- `address`
- `port`
- `server_name`
- `id`

Для изменения самого endpoint рекомендуется создать новый target.

### Request

Все поля optional.

```json
{
  "owner": "security",
  "criticality": "CRITICAL",
  "enabled": false
}
```

### Fields

| Field         | Type    | Description                         |
| ------------- | ------- | ----------------------------------- |
| `owner`       | string  | Владелец сервиса                    |
| `criticality` | string  | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `enabled`     | boolean | Включить/выключить scanning         |

### Example

```bash
curl -X PUT \
  http://localhost:8080/api/targets/8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "security",
    "criticality": "CRITICAL",
    "enabled": true
  }'
```

### Response `200 OK`

```json
{
  "id": "8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b",
  "address": "example.com",
  "port": 443,
  "server_name": "example.com",
  "enabled": true,
  "owner": "security",
  "criticality": "CRITICAL"
}
```

---

# 6. Scan Target

## POST `/api/scans/:targetID`

Немедленно выполнить TLS scan для target.

Pipeline:

```text
Target
  ↓
TCP connection
  ↓
TLS handshake
  ↓
Certificate collection
  ↓
Certificate analysis
  ↓
Chain validation
  ↓
Hostname validation
  ↓
Crypto analysis
  ↓
Risk calculation
  ↓
Database
```

### Example

```bash
curl -X POST \
  http://localhost:8080/api/scans/8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b
```

### Response `200 OK`

```json
{
  "target_id": "8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b",
  "scanned_at": "2026-09-24T17:00:00Z",
  "days_left": 73,
  "status": "OK",

  "hostname": {
    "status": "MATCH",
    "error": ""
  },

  "chain": {
    "status": "VALID",
    "error": ""
  },

  "self_signed": false,

  "tls_version": 772,
  "cipher_suite": 4865,

  "owner": "platform",
  "criticality": "HIGH",

  "certificate": {
    "fingerprint_sha256": "abc123...",
    "serial_number": "123456789",
    "subject": "CN=example.com",
    "common_name": "example.com",
    "dns_names": ["example.com", "www.example.com"],
    "ip_addresses": [],
    "issuer": "CN=Example CA",
    "valid_from": "2026-07-01T00:00:00Z",
    "valid_to": "2026-12-06T00:00:00Z",
    "signature_algorithm": "SHA256-RSA",
    "public_key_algorithm": "RSA",
    "public_key_size": 2048
  },

  "findings": [],

  "risk": {
    "score": 0,
    "level": "LOW"
  }
}
```

### Errors

`404 Not Found`

Target does not exist.

`502 Bad Gateway`

TLS connection, handshake, scanner или analysis failure.

---

# 7. Get Latest Scan

## GET `/api/scans/targets/:targetID/latest`

Получить последний сохранённый scan target.

### Example

```bash
curl \
  http://localhost:8080/api/scans/targets/8b7d7c1e5f3c4a8e9d1b2c3d4e5f6a7b/latest
```

### Response

Формат идентичен `POST /api/scans/:targetID`.

### Errors

`404 Not Found`

Если target или scan отсутствует.

```json
{
  "error": "scan not found"
}
```

---

# 8. Recent Scans

## GET `/api/scans/recent`

Получить историю scans с pagination, filtering и sorting.

По умолчанию:

```text
limit=50
offset=0
sort=scanned_at
order=desc
```

---

## Pagination

### `limit`

Количество результатов.

Диапазон:

```text
1..100
```

Default:

```text
50
```

Example:

```text
GET /api/scans/recent?limit=20
```

### `offset`

Количество пропущенных результатов.

Default:

```text
0
```

Example:

```text
GET /api/scans/recent?limit=20&offset=20
```

### Response

```json
{
  "items": [],
  "limit": 20,
  "offset": 20,
  "has_more": true
}
```

`has_more=true` означает, что после текущей страницы существуют ещё результаты.

---

# 9. Scan Filters

## Status

```text
status=OK
status=INFORMATION
status=WARNING
status=CRITICAL
status=EXPIRED
```

Example:

```text
GET /api/scans/recent?status=CRITICAL
```

---

## Risk Level

```text
risk_level=LOW
risk_level=MEDIUM
risk_level=HIGH
risk_level=CRITICAL
```

Example:

```text
GET /api/scans/recent?risk_level=HIGH
```

---

## Owner

Фильтрация по owner.

```text
GET /api/scans/recent?owner=platform
```

---

## Criticality

```text
criticality=LOW
criticality=MEDIUM
criticality=HIGH
criticality=CRITICAL
```

Example:

```text
GET /api/scans/recent?criticality=CRITICAL
```

---

## Issuer

Фильтрация по Certificate Issuer.

Example:

```text
GET /api/scans/recent?issuer=Let's%20Encrypt
```

Фильтр применяется к issuer сертификата scan.

---

## Days Left

### Minimum

```text
days_left_min=7
```

Показывает сертификаты, у которых осталось минимум 7 дней.

### Maximum

```text
days_left_max=30
```

Показывает сертификаты, у которых осталось максимум 30 дней.

### Range

```text
GET /api/scans/recent?days_left_min=0&days_left_max=30
```

Получить сертификаты, истекающие в ближайшие 30 дней.

Если:

```text
days_left_min > days_left_max
```

API возвращает `400 Bad Request`.

---

# 10. Scan Sorting

Параметр:

```text
sort
```

Поддерживаемые значения:

```text
scanned_at
days_left
status
risk_score
owner
criticality
```

Направление:

```text
order=asc
order=desc
```

### Nearest expiration

```text
GET /api/scans/recent?sort=days_left&order=asc
```

### Highest risk

```text
GET /api/scans/recent?sort=risk_score&order=desc
```

### Owner

```text
GET /api/scans/recent?sort=owner&order=asc
```

### Invalid sort

```text
GET /api/scans/recent?sort=unknown
```

Response:

```json
{
  "error": "invalid sort \"unknown\""
}
```

---

# 11. Combined Query

Фильтры можно комбинировать.

Например:

```text
GET /api/scans/recent
    ?limit=20
    &offset=0
    &status=CRITICAL
    &risk_level=HIGH
    &owner=platform
    &criticality=HIGH
    &issuer=Let's%20Encrypt
    &days_left_max=14
    &sort=days_left
    &order=asc
```

В curl:

```bash
curl --get http://localhost:8080/api/scans/recent \
  --data-urlencode "limit=20" \
  --data-urlencode "offset=0" \
  --data-urlencode "status=CRITICAL" \
  --data-urlencode "risk_level=HIGH" \
  --data-urlencode "owner=platform" \
  --data-urlencode "criticality=HIGH" \
  --data-urlencode "issuer=Let's Encrypt" \
  --data-urlencode "days_left_max=14" \
  --data-urlencode "sort=days_left" \
  --data-urlencode "order=asc"
```

---

# 12. Scan Response Model

Основной объект scan:

```json
{
  "target_id": "string",
  "scanned_at": "RFC3339 timestamp",
  "days_left": 73,
  "status": "OK",

  "hostname": {
    "status": "MATCH",
    "error": ""
  },

  "chain": {
    "status": "VALID",
    "error": ""
  },

  "self_signed": false,

  "tls_version": 772,
  "cipher_suite": 4865,

  "owner": "platform",
  "criticality": "HIGH",

  "certificate": {},
  "findings": [],
  "risk": {}
}
```

---

# 13. Certificate

```json
{
  "fingerprint_sha256": "string",
  "serial_number": "string",
  "subject": "string",
  "common_name": "string",
  "dns_names": ["example.com"],
  "ip_addresses": [],
  "issuer": "string",
  "valid_from": "RFC3339 timestamp",
  "valid_to": "RFC3339 timestamp",
  "signature_algorithm": "SHA256-RSA",
  "public_key_algorithm": "RSA",
  "public_key_size": 2048
}
```

`fingerprint_sha256` — SHA-256 fingerprint DER certificate.

---

# 14. Certificate Status

Статус рассчитывается по `days_left`.

| Days Left | Status        |
| --------: | ------------- |
|    `> 60` | `OK`          |
|   `31–60` | `INFORMATION` |
|   `15–30` | `WARNING`     |
|    `0–14` | `CRITICAL`    |
|     `< 0` | `EXPIRED`     |

---

# 15. Hostname Validation

```json
{
  "status": "MATCH",
  "error": ""
}
```

Possible values:

```text
MATCH
MISMATCH
UNKNOWN
```

При mismatch:

```json
{
  "status": "MISMATCH",
  "error": "..."
}
```

---

# 16. Chain Validation

```json
{
  "status": "VALID",
  "error": ""
}
```

Possible values:

```text
VALID
INVALID
UNKNOWN
```

При ошибке validation:

```json
{
  "status": "INVALID",
  "error": "..."
}
```

---

# 17. Findings

Finding описывает техническую проблему сертификата/TLS endpoint.

Example:

```json
{
  "type": "WEAK_KEY",
  "severity": "WARNING",
  "message": "RSA key size is less than 2048 bits"
}
```

Поддерживаемые types:

```text
SELF_SIGNED
CHAIN_INVALID
HOSTNAME_MISMATCH
EXPIRED
WEAK_KEY
WEAK_SIGNATURE
```

Severity:

```text
INFO
WARNING
CRITICAL
```

---

# 18. Risk

```json
{
  "score": 85,
  "level": "CRITICAL"
}
```

Risk levels:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Текущий score учитывает:

- certificate expiration
- chain errors
- hostname mismatch
- self-signed certificate
- weak public key
- weak signature
- service criticality

Точная формула является внутренней реализацией Risk Engine и не является частью API contract.

---

# 19. TLS Information

`tls_version` и `cipher_suite` представлены числовыми IANA/Go TLS identifiers.

Например:

```json
{
  "tls_version": 772,
  "cipher_suite": 4865
}
```

---

# 20. HTTP Status Codes

|  Code | Meaning                              |
| ----: | ------------------------------------ |
| `200` | Successful request                   |
| `201` | Resource created                     |
| `400` | Invalid request / query parameters   |
| `404` | Target or scan not found             |
| `500` | Internal server / repository error   |
| `502` | TLS scan / upstream endpoint failure |

---

# 21. Current API Routes

Итого API:

```text
GET  /health

POST /api/targets
GET  /api/targets
GET  /api/targets/:id
PUT  /api/targets/:id

POST /api/scans/:targetID

GET  /api/scans/recent
GET  /api/scans/targets/:targetID/latest
```

---

# 22. Dashboard Usage

Для dashboard основной endpoint:

```text
GET /api/scans/recent
```

### Все последние scans

```text
GET /api/scans/recent
```

### Критичные сертификаты

```text
GET /api/scans/recent?status=CRITICAL
```

### Сертификаты, истекающие за 14 дней

```text
GET /api/scans/recent?days_left_max=14&sort=days_left&order=asc
```

### Высокий риск

```text
GET /api/scans/recent?risk_level=HIGH&sort=risk_score&order=desc
```

### Конкретный owner

```text
GET /api/scans/recent?owner=platform
```

### Конкретный issuer

```text
GET /api/scans/recent?issuer=Let's%20Encrypt
```

### Комбинированный dashboard query

```text
GET /api/scans/recent
    ?status=CRITICAL
    &days_left_max=14
    &sort=days_left
    &order=asc
    &limit=50
```

Таким образом frontend может построить таблицу сертификатов без дополнительной бизнес-логики на своей стороне.
