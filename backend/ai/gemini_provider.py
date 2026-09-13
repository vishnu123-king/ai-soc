import os
import json
from typing import Dict, Any, List
from datetime import datetime
from backend.ai.provider import AIProvider
from backend.schemas import AIAnalysisSchema

class GeminiProvider(AIProvider):
    provider_name = "Gemini AI (Google GenAI)"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[GeminiProvider] Warning initializing google-genai client: {e}")

    async def analyze_incident(self, incident_data: Dict[str, Any]) -> AIAnalysisSchema:
        """
        Receives structured incident context and produces comprehensive SOC analysis.
        Strictly strictly read-only.
        """
        if not self.client and not self.api_key:
            return self._heuristic_fallback(incident_data, reason="Gemini API Key not set; using deterministic rule-augmented analysis engine.")

        prompt = f"""You are a Tier-3 Senior SOC Analyst and Incident Responder.
Analyze the following security incident structured data carefully.

CRITICAL INSTRUCTIONS:
1. Ground every claim STRICTLY in the provided evidence and alerts. Do NOT hallucinate or invent non-existent IP addresses, commands, or files.
2. Output ONLY valid JSON matching the exact schema requested.
3. Keep analysis actionable, rigorous, and technical.

STRUCTURED INCIDENT CONTEXT:
{json.dumps(incident_data, indent=2, default=str)}

JSON SCHEMA TO RETURN:
{{
  "incident_summary": "High-level executive and technical summary of the security event.",
  "likely_attack_type": "Specific attack taxonomy (e.g., SSH Brute Force with Credential Compromise, Web Shell Persistence, C2 Exfiltration, Privilege Escalation)",
  "severity_assessment": "CRITICAL / HIGH / MEDIUM / LOW with justification",
  "confidence": 0.95,
  "attack_progression": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
  "evidence": ["Verbatim evidence fact 1 from logs", "Verbatim evidence fact 2 from logs"],
  "mitre_techniques": ["T1110: Brute Force", "T1078: Valid Accounts", ...],
  "recommended_investigation_steps": ["Step 1: Check auth.log for ...", "Step 2: Inspect netstat ..."],
  "recommended_containment_steps": ["Step 1: Isolate host ...", "Step 2: Revoke compromised credentials ..."]
}}
"""

        try:
            from google.genai import types
            model_to_use = "gemini-3.8-flash"
            response = self.client.models.generate_content(
                model=model_to_use,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                )
            )

            response_text = response.text or "{}"
            parsed = json.loads(response_text)

            return AIAnalysisSchema(
                incident_summary=parsed.get("incident_summary", "Incident analysis completed."),
                likely_attack_type=parsed.get("likely_attack_type", "Multi-stage Cyber Incident"),
                severity_assessment=parsed.get("severity_assessment", incident_data.get("severity", "HIGH")),
                confidence=float(parsed.get("confidence", 0.9)),
                attack_progression=parsed.get("attack_progression", []),
                evidence=parsed.get("evidence", []),
                mitre_techniques=parsed.get("mitre_techniques", []),
                recommended_investigation_steps=parsed.get("recommended_investigation_steps", []),
                recommended_containment_steps=parsed.get("recommended_containment_steps", []),
                model_provider=f"Gemini ({model_to_use})",
                analyzed_at=datetime.utcnow()
            )

        except Exception as e:
            print(f"[GeminiProvider] API generation error, falling back: {e}")
            return self._heuristic_fallback(incident_data, reason=f"Gemini API invocation fallback ({str(e)})")

    def _heuristic_fallback(self, incident_data: Dict[str, Any], reason: str = "") -> AIAnalysisSchema:
        """
        Deterministic expert SOC reasoning fallback ensuring 100% operational availability
        even in offline/test environments.
        """
        alerts = incident_data.get("alerts", [])
        host = incident_data.get("affected_host", "unknown-host")
        src_ip = incident_data.get("source_ip", "external-source")
        user = incident_data.get("username", "system-user")
        score = incident_data.get("risk_score", 50)
        mitre_list = [f"{m.get('id')}: {m.get('name')}" for m in incident_data.get("mitre_techniques", [])]

        progression = []
        evidence = []
        attack_type = "Multi-Stage Host Intrusion"

        rule_names = [a.get("rule_name", "") for a in alerts]
        
        if any("Brute Force" in r for r in rule_names):
            progression.append(f"1. Reconnaissance & Credential Access: Adversary from {src_ip} subjected {host} to repeated authentication attempts.")
        if any("Successful Login" in r for r in rule_names):
            progression.append(f"2. Initial Access & Account Compromise: Adversary successfully authenticated as '{user}' following brute force attempts.")
            attack_type = "Account Compromise via Credential Guessing"
        if any("Privilege Escalation" in r for r in rule_names):
            progression.append(f"3. Privilege Escalation: Elevated root execution was performed via sudo invocation.")
            attack_type = "Privilege Escalation & Root Compromise"
        if any("Process" in r for r in rule_names):
            progression.append(f"4. Execution & Persistence: Spawned abnormal shell or utility from service daemon.")
        if any("Outbound" in r for r in rule_names):
            progression.append(f"5. Command & Control / Exfiltration: Established outbound network socket to external destination.")
            attack_type = "Full Attack Chain: Compromise to C2 Exfiltration"

        for a in alerts:
            for ev in a.get("evidence", []):
                if isinstance(ev, dict):
                    msg = ev.get("raw_message") or ev.get("command") or ev.get("detection_reason")
                    if msg:
                        evidence.append(f"[{a.get('rule_id')}] {msg}")
                else:
                    evidence.append(str(ev))

        investigation_steps = [
            f"Audit authentication logs (/var/log/auth.log) on {host} around target timeframe.",
            f"Review bash command history (.bash_history) for user '{user}'.",
            f"Cross-reference source IP {src_ip} against threat intelligence feeds (VirusTotal / AbuseIPDB).",
            f"Inspect active network connections and listening sockets using 'ss -tulpn' or 'lsof -i'.",
            f"Check scheduled jobs (/etc/crontab, /var/spool/cron) and systemd services for persistence."
        ]

        containment_steps = [
            f"Temporarily isolate host '{host}' from the corporate network at the switch/firewall level.",
            f"Terminate all active SSH and shell sessions for user '{user}'.",
            f"Force password reset and revoke SSH authorized_keys for account '{user}'.",
            f"Block ingress and egress traffic from source IP {src_ip} at perimeter firewall.",
            f"Capture volatile memory dump and triage forensic artifact package before reboot."
        ]

        summary = (
            f"Automated security incident correlation detected {len(alerts)} alert(s) targeting host '{host}'. "
            f"Primary indicators demonstrate {attack_type.lower()} by actor from {src_ip} impacting user '{user}'. "
            f"Determined calculated risk score is {score}/100. (Note: {reason})"
        )

        return AIAnalysisSchema(
            incident_summary=summary,
            likely_attack_type=attack_type,
            severity_assessment=f"{incident_data.get('severity', 'HIGH')} (Risk Score: {score}/100)",
            confidence=0.96,
            attack_progression=progression or ["Alert activity detected on monitored endpoints."],
            evidence=evidence[:10] or ["Correlated alert telemetry records."],
            mitre_techniques=mitre_list,
            recommended_investigation_steps=investigation_steps,
            recommended_containment_steps=containment_steps,
            model_provider="GeminiProvider (Rule-Engine Assisted Fallback)",
            analyzed_at=datetime.utcnow()
        )
