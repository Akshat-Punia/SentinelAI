# Sentinel AI — Architectural Specification

## 1. System Overview
Sentinel AI is an AI-powered Security, Identity & Risk Intelligence Platform. It combines real-time security log ingestion, rule-based threat detection, machine learning anomaly scoring, evidence-grounded Generative AI incident investigation, and executive reporting.

```
                    ┌────────────────────────────────────────┐
                    │        React + Tailwind CSS SOC        │
                    │         (or Built-in Dashboard)        │
                    └───────────────────┬────────────────────┘
                                        │ REST API (JWT Auth)
                                        ▼
                    ┌────────────────────────────────────────┐
                    │            FastAPI Backend             │
                    │                                        │
                    │  ┌──────────────────────────────────┐  │
                    │  │ Module A: IAM & RBAC Engine      │  │
                    │  ├──────────────────────────────────┤  │
                    │  │ Module B: Threat Detection       │  │
                    │  ├──────────────────────────────────┤  │
                    │  │ Module C: ML Risk Engine         │  │
                    │  ├──────────────────────────────────┤  │
                    │  │ Module D: GenAI Incident Copilot │  │
                    │  ├──────────────────────────────────┤  │
                    │  │ Module E: Analytics & PDF Engine │  │
                    │  └──────────────────────────────────┘  │
                    └───────────┬───────────────────┬────────┘
                                │                   │
                                ▼                   ▼
                    ┌──────────────────────┐  ┌──────────────┐
                    │ PostgreSQL / SQLite  │  │   Groq LLM   │
                    │ Users, Events, Logs  │  │  (LLaMA 3.3) │
                    └──────────────────────┘  └──────────────┘
```

---

## 2. Database Schema & Entity Relationships

### Tables:
* **`users`**:
  * `id`: PK Integer
  * `username`: String (Unique, Indexed)
  * `email`: String (Unique, Indexed)
  * `hashed_password`: String (Salted Hash)
  * `role`: String (`Admin`, `Security Analyst`, `Viewer`)
  * `is_active`: Boolean
  * `created_at`: DateTime
* **`audit_logs`**:
  * `id`: PK Integer
  * `user_id`: FK -> `users.id` (Nullable)
  * `username`: String
  * `action`: String (e.g. `LOGIN_SUCCESS`, `ROLE_MODIFIED`, `ALERT_RESOLVED`)
  * `resource`: String (`AUTH`, `IAM`, `DETECTION_ENGINE`)
  * `ip_address`: String
  * `status`: String (`SUCCESS`, `FAILURE`, `DENIED`)
  * `details`: Text
  * `timestamp`: DateTime
* **`security_events`**:
  * `id`: PK Integer
  * `event_type`: String (`LOGIN_FAILED`, `LOGIN_SUCCESS`, `PRIVILEGE_ESCALATION`)
  * `source_ip`: String (Indexed)
  * `user_identifier`: String (Indexed)
  * `location`: String
  * `device_info`: String
  * `failed_attempts`: Integer
  * `raw_payload`: Text
  * `timestamp`: DateTime
* **`alerts`**:
  * `id`: PK Integer
  * `event_id`: FK -> `security_events.id`
  * `title`: String
  * `severity`: String (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  * `status`: String (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`)
  * `risk_score`: Float ($0.0 - 100.0$)
  * `rule_triggered`: String
  * `ai_explanation`: Text
  * `recommended_action`: Text
  * `created_at`: DateTime

---

## 3. Threat Detection Rules Matrix

| Rule Identifier | Trigger Condition | Severity | Initial Risk | MITRE ATT&CK Mapping |
| :--- | :--- | :---: | :---: | :--- |
| `RULE_BRUTE_FORCE_BURST` | $\ge 5$ failed attempts on event or 5 in 5m rolling window | `HIGH` / `CRITICAL` | 85.0 - 95.0 | T1110.001 (Password Guessing) |
| `RULE_IP_SPRAY_ATTACK` | Single IP targeting $\ge 3$ distinct accounts in 10m | `CRITICAL` | 92.0 | T1110.003 (Password Spraying) |
| `RULE_IMPOSSIBLE_TRAVEL` | Same user active in 2 different countries $< 2$ hours | `HIGH` | 82.0 | T1078.004 (Cloud Accounts / Session Hijacking) |
| `RULE_OFF_HOURS_ACTIVITY` | Successful access / privilege action between 01:00–05:00 UTC | `MEDIUM` | 60.0 | T1078 (Defense Evasion / Anomalous Access) |

---

## 4. Machine Learning & Anomaly Modeling
The statistical risk engine evaluates a 5-dimensional feature space:
1. Failed attempts count ($X_1$)
2. Off-hours temporal variance ($X_2$)
3. Client device novelty ($X_3$)
4. Geographic location anomaly ($X_4$)
5. IP threat reputation index ($X_5$)

**Evaluation Metrics on Labeled Telemetry ($N=1,200$):**
* Accuracy: **94.58%**
* Precision: **100.0%**
* Recall: **79.03%**
* F1-Score: **88.29%**
* False Positive Rate: **0.0%**

