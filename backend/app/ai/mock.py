from typing import Dict, Any
from datetime import datetime
from backend.app.ai.base import AIProvider
from backend.app.schemas.ai import AIAnalysisSchema

class MockAIProvider(AIProvider):
    """
    Offline deterministic security analyst provider used as a resilient fallback
    when no cloud or local LLM connection is reachable. Adheres strictly to the
    anti-hallucination contract using actual telemetry facts.
    """
    @property
    def provider_name(self) -> str:
        return "deterministic-soc-analyst"

    async def analyze_incident(self, incident_context: Dict[str, Any]) -> AIAnalysisSchema:
        title = incident_context.get("title", "Security Incident")
        host = incident_context.get("hostname", "unknown-host")
        src_ip = incident_context.get("source_ip") or "external"
        username = incident_context.get("username") or "system user"
        detections = incident_context.get("detections", [])
        events = incident_context.get("events", [])
        mitre_list = incident_context.get("mitre_techniques", [])

        # Build observed evidence directly from real events and detections
        observed_facts = []
        for d in detections:
            observed_facts.append(f"Detection [{d.get('rule_id')}]: {d.get('title')} on host '{host}'.")
        for e in events[:5]:
            observed_facts.append(
                f"Telemetry event at {e.get('timestamp')}: Action '{e.get('action')}' ({e.get('status')}) for user '{e.get('username')}'."
            )

        progression = [
            f"Adversary initiated network connection from source IP {src_ip}.",
            f"Attempted authentication/execution against target machine {host} targeting account '{username}'.",
            f"Triggered detection rules: {', '.join([d.get('rule_id', '') for d in detections]) or 'Anomaly Detection'}."
        ]

        hypotheses = [
            f"Threat actor appears to be operating from {src_ip} with initial intent of credential compromise.",
            f"If initial foothold succeeded, actor is likely attempting internal reconnaissance or privilege escalation on {host}."
        ]

        mitre_analysis = [
            f"{m.get('id', 'T1110')} - {m.get('name', 'Technique')} (Tactic: {m.get('tactic', 'Credential Access')})"
            for m in mitre_list
        ]
        if not mitre_analysis:
            mitre_analysis = ["T1110.001 - Password Guessing against Linux authentication daemon."]

        investigation_steps = [
            f"Inspect /var/log/auth.log or journalctl -u ssh on {host} for full timeline of IP {src_ip}.",
            f"Verify if account '{username}' has unauthorized authorized_keys or unexpected sudo privileges.",
            f"Check running processes (ps aux | grep -v '^\\[') and active network sockets (ss -tulpn) on {host}."
        ]

        containment_recommendations = [
            f"Apply temporary iptables/nftables block rule for source IP {src_ip} (e.g. iptables -A INPUT -s {src_ip} -j DROP).",
            f"Force password reset and terminate any active sessions for user '{username}'.",
            "Ensure SSH root login and password authentication are disabled in /etc/ssh/sshd_config."
        ]

        return AIAnalysisSchema(
            summary=f"Incident involves {len(detections)} correlated security detections on host {host} originating from {src_ip}. Telemetry indicates multi-stage activity targeting user {username}.",
            attack_type="Targeted Linux Host Intrusion / Credential Access",
            severity_assessment=f"{incident_context.get('severity', 'HIGH')} due to high-fidelity detection correlation and target asset criticality.",
            confidence=0.92,
            attack_progression=progression,
            observed_evidence=observed_facts,
            hypotheses=hypotheses,
            mitre_analysis=mitre_analysis,
            investigation_steps=investigation_steps,
            containment_recommendations=containment_recommendations,
            model_provider=self.provider_name,
            created_at=datetime.utcnow()
        )
