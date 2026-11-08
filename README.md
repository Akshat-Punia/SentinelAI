# Sentinel AI
### AI-Powered Security, Identity & Risk Intelligence Platform

Sentinel AI is an enterprise-grade cybersecurity and risk intelligence platform designed to monitor security events, detect malicious activities in real time, enforce granular Identity and Access Management (IAM), predict risk using Machine Learning, and provide an interactive GenAI assistant for incident response.

---

## 🌟 Key Highlights & Certificate Alignment
Sentinel AI synthesizes competencies demonstrated across four industry simulations:
- **Deloitte – Technology Job Simulation**: End-to-end fullstack development, clean architecture, automated testing, and API design.
- **Deloitte – Cyber Job Simulation**: Threat detection, incident investigation, log telemetry analysis, and security hardening.
- **Cybersecurity Analyst Simulation (IAM & Security Solutions)**: Role-Based Access Control (RBAC), least-privilege enforcement, audit logging, and credential governance.
- **GenAI Powered Data Analytics**: Risk profiling, exploratory anomaly analytics, delinquency prediction, and executive reporting.

---

## 🏗️ Architecture & Core Modules

```
                ┌───────────────────────────────────────┐
                │         React + Vite Frontend         │
                │  (Tailwind CSS + Recharts Dashboard)  │
                └───────────────────┬───────────────────┘
                                    │ REST API / JWT
                                    ▼
                ┌───────────────────────────────────────┐
                │            FastAPI Backend            │
                │  ┌─────────────────────────────────┐  │
                │  │ IAM & RBAC Engine (Admin/Sec/Vi) │  │
                │  ├─────────────────────────────────┤  │
                │  │ Real-Time Threat Detection      │  │
                │  ├─────────────────────────────────┤  │
                │  │ ML Anomaly & Risk Scoring       │  │
                │  ├─────────────────────────────────┤  │
                │  │ GenAI Incident Assistant (Groq) │  │
                │  ├─────────────────────────────────┤  │
                │  │ Executive PDF Report Generator  │  │
                │  └─────────────────────────────────┘  │
                └───────┬───────────────────────┬───────┘
                        │                       │
                        ▼                       ▼
            ┌───────────────────────┐   ┌───────────────┐
            │ PostgreSQL / SQLite   │   │ Groq LLM API  │
            │ Users, Events, Alerts │   │ Incident LLM  │
            └───────────────────────┘   └───────────────┘
```

### Core Modules
1. **Module A — Identity & Access Management (IAM)**:
   - Secure registration, login, and password hashing (`Argon2` / `bcrypt`).
   - Role-Based Access Control: `Admin` (full control), `Security Analyst` (triaging and alert investigations), `Viewer` (read-only audit).
   - Immutable audit logging for identity changes and access violations.
2. **Module B — Security Event Ingestion & Threat Detection**:
   - High-throughput event ingestion endpoint (`POST /api/events/ingest`).
   - Rule-based detection: Brute force logins (e.g. 10 failed attempts within 5 minutes), geographical anomalies, off-hours access, repeated privilege escalations.
   - Dynamic alert generation with assigned severity levels (Low, Medium, High, Critical).
3. **Module C — Machine Learning Risk Engine**:
   - Feature engineering on authentication parameters (failed count, hour of day, device novelty, location risk).
   - Scikit-learn classification & anomaly model calculating 0–100 normalized risk scores.
4. **Module D — GenAI Incident Assistant**:
   - Powered by Groq API (LLaMA-3) with strict evidence-grounded prompt engineering.
   - Summarizes incident blast radius, explains why events were flagged, and suggests defensive remediation runbooks.
5. **Module E — Analytics & Executive Reporting**:
   - Threat distribution, unresolved incidents, trend lines, and downloadable PDF compliance reports.
6. **Module F — React Dashboard**:
   - Modern, responsive security operations center (SOC) interface.

---

## 🛠️ Technology Stack
- **Frontend**: React, TypeScript, Tailwind CSS, Lucide Icons, Recharts
- **Backend**: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0
- **Database**: PostgreSQL (Production) / SQLite (Zero-friction local dev)
- **Machine Learning**: Scikit-Learn, Pandas, NumPy
- **GenAI**: Groq API (LLaMA 3)
- **Security & Auth**: PyJWT, Passlib, Bcrypt, OWASP Compliance
- **Reporting**: ReportLab (PDF)

---

## 🚀 Quickstart Guide

### 1. Backend Setup
```bash
# Navigate to backend
cd backend

# Create and activate virtual environment (if not already done)
python -m venv .venv
.\.venv\Scripts\activate   # On Windows
# source .venv/bin/activate  # On Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Start FastAPI development server
uvicorn app.main:app --reload --port 8000
```
Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser to view the interactive OpenAPI documentation.

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## 📋 Development Roadmap
- [x] **Phase 1: Project Blueprint & Foundation** (Repository structure, .gitignore, documentation)
- [x] **Phase 2: Backend Architecture & FastAPI Core** (Health endpoints, configuration, database connectivity)
- [x] **Phase 3: Module A — Identity & Access Management (IAM & RBAC)**
- [x] **Phase 4: Module B — Security Event Ingestion & Threat Detection**
- [ ] **Phase 5: Module C — Machine Learning Risk Engine**
- [ ] **Phase 6: Module D — GenAI Incident Assistant**
- [ ] **Phase 7: Module E — Security Reporting & Analytics Engine**
- [ ] **Phase 8: Module F — React SOC Dashboard Integration**
- [ ] **Phase 9: Dockerization, Testing & Portfolio Showcase**

---

## 👤 Author
**Akshat Punia**
- AI, Cybersecurity & Software Development Enthusiast

