# Sentinel AI — Complete User & Evaluation Tutorial

Welcome to the **Sentinel AI** guided tutorial! This guide walks you through every feature of the platform, from running your first simulation to exporting executive compliance reports.

---

## ⚡ 1. Launching Sentinel AI (30 Seconds)

Open your terminal in `e:\sentinel-ai`:

```powershell
# Navigate to backend
cd backend

# Activate your virtual environment
.\.venv\Scripts\activate

# Start the application
python main.py
```

Now open your browser:
👉 **SOC Dashboard:** [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)  
👉 **Interactive API Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧭 2. The 5-Minute Guided Demo Tour

When you open [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard), you are greeted by the cyber dark-mode Security Operations Center (SOC).

```
  [ Sentinel AI SOC Header: Quick Tutorial | Export PDF | Admin (Active) ]
  ┌───────────────────────────────────────────────────────────────────────┐
  │ TABS: [ Threat Monitor ]  [ Identity & Access ]  [ ML Risk Lab ]      │
  └───────────────────────────────────────────────────────────────────────┘
```

### Step 1: Launch the In-App Tutorial
Click the glowing **"Quick Tutorial"** button in the top navigation header.  
An interactive 5-step modal will guide you through:
1. **Telemetry & Metrics**
2. **Attack Simulation Studio**
3. **Incident Triage & Resolution**
4. **Sentinel Copilot (AI Investigator)**
5. **Executive PDF Reports & IAM**

---

### Step 2: Trigger Live Cyber Attacks
Under the **Live Attack Simulation Studio** banner on the main dashboard, you have 4 one-click telemetry generators:

| Click Button | What Happens Under the Hood | Detection Engine Result |
| :--- | :--- | :--- |
| 🔴 **Brute Force** | Ingests 7 consecutive failed login attempts from IP `203.0.113.88` targeting `target_admin`. | Triggers `RULE_BRUTE_FORCE_BURST` with **HIGH / CRITICAL** severity (Risk: 85–95). |
| 🟠 **IP Spraying** | Simulates a single external IP `198.51.100.42` targeting multiple distinct user accounts. | Triggers `RULE_IP_SPRAY_ATTACK` with **CRITICAL** severity (Risk: 92). |
| 🟣 **Geo Velocity** | Ingests consecutive logins for `sarah_analyst` from Tokyo 15 minutes after London. | Triggers `RULE_IMPOSSIBLE_TRAVEL` with **HIGH** severity (Risk: 82). |
| 🟢 **Clean Login** | Normal corporate login from internal subnet. | Ingests event cleanly with zero alerts generated. |

*Watch the **Incident Triage Feed** and **Raw Log Telemetry** update in real time!*

---

### Step 3: Consult the Sentinel AI Copilot
On the right-hand side of the dashboard, you have the **Sentinel Copilot**:
1. Click **"Analyze AI"** on any flagged incident in the table.
2. The AI Copilot instantly generates:
   * **MITRE ATT&CK Matrix Technique**: (e.g., `T1110.001 Brute Force: Password Guessing` or `T1078.004 Cloud Accounts`).
   * **Blast Radius Analysis**: (e.g., *"User account takeover, lateral movement across directory services."*).
   * **Defensive Containment Runbook**: 4 actionable steps (Session revocation, MFA mandate, perimeter IP blocklist, active directory audit).
3. Try asking questions in the chat box:
   * *"Why was this alert flagged?"*
   * *"Show defensive remediation runbook"*
   * *"Explain how ML risk is calculated"*

---

### Step 4: Experiment in the Machine Learning Risk Lab
Click the **"ML Risk Lab"** tab at the top of the screen:
1. Drag the **Consecutive Failed Attempts** slider (0 to 15).
2. Adjust the **Hour of Day** slider (notice off-hours penalty applied between 01:00 and 05:00 UTC).
3. Adjust the **Source IP Threat Score** slider.
4. Toggle **Unrecognized Device** or **Geographic Anomaly** checkboxes.
5. Watch the **Inferred Output Gauge** calculate the normalized risk score ($0.0 - 100.0$) and primary contributing factors live!

---

### Step 5: Manage IAM Roles & Inspect Audit Trails
Click the **"Identity & Access"** tab at the top of the screen:
1. **User Directory**: View registered users (`Admin`, `Security Analyst`, `Viewer`).
2. **Role Governance**: Change a user's role using the dropdown selector.
3. **Immutable Audit Trail**: Scroll down to view the chronological security ledger documenting who changed what, their IP address, and timestamp.

---

### Step 6: Export the Executive Compliance PDF Report
Click the **"Export PDF"** button in the header (or under the **Reports & Audits** tab):
* Downloads `Sentinel_AI_Security_Report_<timestamp>.pdf`.
* Contains executive summary metrics, incident inventories, MITRE ATT&CK mappings, and compliance audit stamps ready for stakeholders.

---

## 🛠️ 3. Running Automated Tests & ML Training

### Run the 13-Test Automated Suite:
```powershell
cd e:\sentinel-ai\backend
python tests\run_tests.py
```
*Output: `Ran 13 tests in 0.255s — OK`*

### Re-Train and Evaluate the ML Model:
```powershell
python -m app.ml.train
```
*Output: Evaluates on 1,200 records in `data/auth_events_dataset.csv` with 94.58% accuracy and 100% precision!*

---

## 🎤 4. 2-Minute Interview / Viva Presentation Script

If presenting Sentinel AI in a technical interview or college viva:

1. **Introduction:**  
   *"I built **Sentinel AI**, a security intelligence and identity platform combining cybersecurity log monitoring, IAM role-based access control, machine learning risk scoring, and Generative AI incident investigation."*
2. **Live Attack Demo:**  
   *"Here in the Live Attack Simulator, I click 'Brute Force'. The backend ingests the event and the detection engine evaluates the burst, triggering RULE_BRUTE_FORCE_BURST with critical severity."*
3. **AI Copilot Grounding:**  
   *"When I click 'Analyze AI', the Copilot does not hallucinate. It grounds its response strictly in the incident telemetry, maps it to MITRE ATT&CK Technique T1110, assesses the blast radius, and produces a step-by-step defensive runbook."*
4. **Governance & Reporting:**  
   *"All administrative actions are permanently recorded in our immutable audit trail, and with one click, analysts can export a compliant executive PDF security dossier."*
