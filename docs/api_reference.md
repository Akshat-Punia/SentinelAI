# Sentinel AI — REST API Reference Guide

Base URL: `http://127.0.0.1:8000/api/v1`  
Interactive OpenAPI UI: `http://127.0.0.1:8000/docs`

---

## 1. Authentication & IAM (`/auth` & `/users`)

### `POST /auth/register`
Creates a new user identity. The first user created automatically receives the `Admin` role.
```json
{
  "username": "analyst1",
  "email": "analyst@sentinel.ai",
  "password": "StrongPassword123!",
  "role": "Security Analyst"
}
```

### `POST /auth/login`
Returns a signed JWT bearer token.
```json
{
  "username": "analyst1",
  "password": "StrongPassword123!"
}
```
**Response:**
```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "bearer",
  "role": "Security Analyst",
  "username": "analyst1"
}
```

### `GET /users` *(Admin Only)*
Lists all system users and roles.

### `PATCH /users/{id}/role` *(Admin Only)*
Modifies a user's role (`Admin`, `Security Analyst`, `Viewer`) and logs an audit trail.

### `GET /users/audit-logs` *(Admin & Analyst)*
Chronological immutable system audit logs.

---

## 2. Telemetry & Threat Detection (`/events` & `/alerts`)

### `POST /events/ingest`
Ingests an event and immediately runs it through the detection engine.
```json
{
  "event_type": "LOGIN_FAILED",
  "source_ip": "203.0.113.88",
  "user_identifier": "target_user",
  "location": "Moscow, RU",
  "failed_attempts": 6,
  "device_info": "Hydra/9.1"
}
```
**Response:**
```json
{
  "message": "Event ingested successfully. Triggered 1 threat alert(s)!",
  "threat_detected": true,
  "alerts": [
    {
      "id": 1,
      "title": "Critical Brute Force Attack (target_user)",
      "severity": "CRITICAL",
      "risk_score": 95.0,
      "rule_triggered": "RULE_BRUTE_FORCE_BURST",
      "status": "NEW"
    }
  ]
}
```

### `GET /alerts`
Lists alerts with optional query parameters: `severity`, `status`, `min_risk_score`.

### `PATCH /alerts/{id}/status`
Triage an alert:
```json
{
  "status": "RESOLVED",
  "comment": "IP blocked on perimeter firewall"
}
```

---

## 3. Machine Learning & Copilot (`/ml` & `/assistant`)

### `POST /ml/predict-risk`
Evaluates multi-factor attributes and returns continuous risk score:
```json
{
  "failed_attempts": 8,
  "hour_of_day": 3,
  "is_new_device": true,
  "is_unusual_location": true,
  "ip_reputation_score": 85.0
}
```

### `POST /assistant/chat`
Ask Sentinel Copilot questions grounded in real alert evidence:
```json
{
  "message": "Why was this alert flagged as critical?",
  "alert_id": 1
}
```

### `GET /assistant/analyze/{id}`
Returns structured blast radius and MITRE ATT&CK mitigation runbook.

---

## 4. Analytics & Compliance Reports (`/analytics`)

### `GET /analytics/overview`
Returns high-level SOC statistics (total events, alert counts, resolution rates).

### `GET /analytics/reports/pdf`
Generates and downloads a binary Executive PDF Compliance & Audit Report.

