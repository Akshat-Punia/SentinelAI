import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.alert import Alert
from app.models.security_event import SecurityEvent


class GenAIAssistantService:
    """
    Sentinel AI Security Copilot.
    Evidence-grounded incident analysis and interactive SOC guidance.
    Integrates Groq LLaMA-3.3 with deterministic MITRE ATT&CK fallbacks.
    """

    MITRE_MAPPINGS = {
        "RULE_BRUTE_FORCE_BURST": {
            "technique": "T1110.001 (Brute Force: Password Guessing)",
            "tactic": "Credential Access",
            "blast_radius": "User account takeover, lateral movement across directory services.",
            "runbook": [
                "1. Enforce immediate session termination for targeted user.",
                "2. Temporarily lock account or mandate an out-of-band MFA challenge.",
                "3. Ingest source IP into perimeter blocklist for 24 hours.",
                "4. Check Active Directory/IAM logs for any successful logins immediately after."
            ]
        },
        "RULE_IP_SPRAY_ATTACK": {
            "technique": "T1110.003 (Brute Force: Password Spraying)",
            "tactic": "Credential Access",
            "blast_radius": "Broad domain-wide credential exposure across multiple employee identities.",
            "runbook": [
                "1. Immediately block source IP across edge load balancer / WAF.",
                "2. Force global password reset for all targeted usernames.",
                "3. Audit privileged accounts (Domain Admins) for concurrent anomalous logins.",
                "4. Correlate with threat intelligence feeds (AbuseIPDB, VirusTotal)."
            ]
        },
        "RULE_IMPOSSIBLE_TRAVEL": {
            "technique": "T1078.004 (Valid Accounts: Cloud Accounts)",
            "tactic": "Initial Access & Persistence",
            "blast_radius": "Active session hijacking, stolen session cookies, or proxy/VPN evasion.",
            "runbook": [
                "1. Revoke active JWT refresh tokens and kill active web sessions.",
                "2. Contact user via verified secondary phone number to confirm travel.",
                "3. Enforce FIDO2 WebAuthn / Hardware key re-authentication.",
                "4. Review downloaded files and modified permissions during session."
            ]
        },
        "RULE_OFF_HOURS_ACTIVITY": {
            "technique": "T1078 (Valid Accounts: Anomalous Access)",
            "tactic": "Defense Evasion",
            "blast_radius": "Insider threat or compromised credentials executing off-hours data staging.",
            "runbook": [
                "1. Verify scheduled automation or approved change-management ticket.",
                "2. Check command execution history and audit logs for sensitive file access.",
                "3. Restrict administrative privileges until confirmation from manager."
            ]
        }
    }

    @classmethod
    def call_groq_api(cls, prompt: str, system_prompt: str) -> Optional[str]:
        """Calls Groq API via standard urllib if GROQ_API_KEY is configured."""
        if not settings.GROQ_API_KEY:
            return None

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.GROQ_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "Sentinel-AI/1.0"
        }
        payload = {
            "model": settings.GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 800
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception:
            return None

    @classmethod
    def analyze_alert(cls, alert: Alert, event: Optional[SecurityEvent]) -> Dict[str, Any]:
        """Provides evidence-grounded structured analysis for a given alert."""
        mapping = cls.MITRE_MAPPINGS.get(alert.rule_triggered, {
            "technique": "T1078 (Uncategorized Access Anomaly)",
            "tactic": "Security Monitoring",
            "blast_radius": "Potential unauthorized access to corporate resources.",
            "runbook": [
                "1. Review source IP and targeted accounts in audit logs.",
                "2. Quarantine affected system or credentials pending investigation."
            ]
        })

        # Try Groq API for enhanced narrative
        groq_summary = None
        if settings.GROQ_API_KEY:
            system_prompt = (
                "You are Sentinel AI, an expert Tier-3 Cyber Incident Responder. "
                "Analyze the provided security alert using only verified facts. Be concise, authoritative, and actionable."
            )
            user_prompt = (
                f"Alert Title: {alert.title}\n"
                f"Severity: {alert.severity}\n"
                f"Risk Score: {alert.risk_score}/100\n"
                f"Rule Triggered: {alert.rule_triggered}\n"
                f"Target User: {event.user_identifier if event else 'Unknown'}\n"
                f"Source IP: {event.source_ip if event else 'Unknown'}\n"
                f"Location: {event.location if event else 'Unknown'}\n"
                "Provide an executive summary and primary risk assessment."
            )
            groq_summary = cls.call_groq_api(user_prompt, system_prompt)

        executive_summary = groq_summary or (
            f"Alert #{alert.id} was triggered with {alert.severity} severity and risk score {alert.risk_score:.1f}/100. "
            f"{alert.ai_explanation or 'Suspicious pattern identified by detection engine.'}"
        )

        return {
            "alert_id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "executive_summary": executive_summary,
            "technical_root_cause": f"Rule {alert.rule_triggered} matched telemetry thresholds in the detection pipeline.",
            "blast_radius": mapping["blast_radius"],
            "mitre_reference": mapping["technique"],
            "defensive_runbook": mapping["runbook"]
        }

    @classmethod
    def chat_response(
        cls,
        message: str,
        alert: Optional[Alert] = None,
        event: Optional[SecurityEvent] = None
    ) -> Dict[str, Any]:
        """Handles conversational interaction with security analysts."""
        evidence: List[str] = []
        tactics: List[str] = ["Initial Access", "Credential Access", "Defense Evasion"]
        actions: List[str] = []
        provider = "Groq LLaMA-3.3" if settings.GROQ_API_KEY else "Sentinel AI Cyber Defense Engine (Grounded Playbooks)"

        if alert:
            evidence.append(f"Referenced Alert #{alert.id}: '{alert.title}'")
            evidence.append(f"Severity: {alert.severity} (Risk Score: {alert.risk_score}/100)")
            evidence.append(f"Rule Triggered: {alert.rule_triggered}")
            if event:
                evidence.append(f"Target User: {event.user_identifier or 'N/A'}")
                evidence.append(f"Source IP: {event.source_ip} (Location: {event.location or 'Unknown'})")
            mapping = cls.MITRE_MAPPINGS.get(alert.rule_triggered)
            if mapping:
                tactics = [mapping["tactic"]]
                actions = mapping["runbook"]
        else:
            actions = [
                "Inspect open alerts in the Alerts Dashboard.",
                "Review recent authentication failures under Security Events.",
                "Verify IAM permissions and role assignments."
            ]

        # Check Groq API
        if settings.GROQ_API_KEY:
            system_prompt = (
                "You are Sentinel AI Security Copilot. Answer cybersecurity and SOC questions professionally. "
                "Ground answers strictly in provided evidence."
            )
            context = "\n".join(evidence) if evidence else "No specific alert selected."
            full_prompt = f"Context:\n{context}\n\nUser Question: {message}"
            groq_reply = cls.call_groq_api(full_prompt, system_prompt)
            if groq_reply:
                return {
                    "reply": groq_reply,
                    "alert_id": alert.id if alert else None,
                    "evidence_grounding": evidence,
                    "mitre_attack_tactics": tactics,
                    "recommended_actions": actions,
                    "model_provider": "Groq LLaMA-3.3"
                }

        # Deterministic Grounded Assistant Response
        msg_lower = message.lower()
        if "why" in msg_lower or "explain" in msg_lower or "cause" in msg_lower:
            if alert:
                reply = (
                    f"Alert #{alert.id} was flagged as **{alert.severity}** (Risk Score: **{alert.risk_score}/100**) "
                    f"because it matched `{alert.rule_triggered}`.\n\n"
                    f"**Evidence:**\n"
                    f"- {alert.ai_explanation}\n"
                    f"- Source IP: `{event.source_ip if event else 'Recorded in log'}`\n"
                    f"- Target User: `{event.user_identifier if event else 'Recorded in log'}`\n\n"
                    f"This maps directly to MITRE ATT&CK technique **{cls.MITRE_MAPPINGS.get(alert.rule_triggered, {}).get('technique', 'T1078')}**."
                )
            else:
                reply = (
                    "Sentinel AI flags alerts by correlating real-time authentication logs against rule-based anomaly engines "
                    "and a statistical machine learning risk classifier. Select an alert from the dashboard to examine its specific evidence."
                )
        elif "action" in msg_lower or "mitigate" in msg_lower or "do" in msg_lower or "fix" in msg_lower:
            reply = (
                "### Recommended Defensive Remediation Runbook:\n" +
                "\n".join([f"- {a}" for a in actions])
            )
        else:
            reply = (
                f"Hello! I am your Sentinel AI Security Assistant. I am monitoring active security events, IAM permissions, and threat alerts.\n\n"
                f"You can ask me to explain any flagged alert, suggest containment actions, or describe how risk scores are calculated."
            )

        return {
            "reply": reply,
            "alert_id": alert.id if alert else None,
            "evidence_grounding": evidence,
            "mitre_attack_tactics": tactics,
            "recommended_actions": actions,
            "model_provider": provider
        }

