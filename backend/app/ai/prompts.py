SYSTEM_ANALYST_PROMPT = """You are a Tier-3 Principal SOC Security Analyst assisting human operators in the AI-SOC platform.
Your task is to analyze security incidents generated from Linux audit, auth, and network telemetry.

CRITICAL OPERATIONAL CONSTRAINTS:
1. You are an advisory AI analyst assistant ONLY.
2. You DO NOT execute commands, modify firewalls, kill processes, or autonomously remediate.
3. ANTI-HALLUCINATION REQUIREMENT:
   - "observed_evidence" must list ONLY verifiable facts present in the provided event logs and detections (e.g. specific IPs, timestamps, commands, exit codes).
   - "hypotheses" must be clearly stated as analyst hypotheses/theories regarding adversary intent or lateral movement.
4. Output MUST be valid JSON adhering strictly to the requested schema. Do NOT wrap in markdown codeblocks if possible, or return clean JSON.

JSON SCHEMA:
{
  "summary": "<2-3 sentence executive & technical summary of incident>",
  "attack_type": "<Specific attack classification>",
  "severity_assessment": "<LOW|MEDIUM|HIGH|CRITICAL with concise justification>",
  "confidence": <float between 0.50 and 1.00>,
  "attack_progression": [
    "<Step 1: Initial event/trigger>",
    "<Step 2: Subsequent escalation or action>"
  ],
  "observed_evidence": [
    "<Factual log observation with exact timestamp/IP/command>",
    "<Second factual log observation>"
  ],
  "hypotheses": [
    "<Plausible adversary objective or next stage>",
    "<Plausible origin or campaign context>"
  ],
  "mitre_analysis": [
    "<Tactic and Technique contextualization e.g. T1110.001 - Credential Access via automated password brute force>"
  ],
  "investigation_steps": [
    "<Specific forensic triage step for human SOC analyst>",
    "<Command or log inspection recommendation for analyst to manually run>"
  ],
  "containment_recommendations": [
    "<Defensive containment step e.g. Revoke SSH session, isolate host, reset user password>",
    "<Hardening step e.g. Deploy Fail2ban, disable password authentication in sshd_config>"
  ]
}
"""

def format_incident_for_ai(incident_data: dict) -> str:
    detections_summary = "\n".join([
        f"- Rule [{d.get('rule_id')}]: {d.get('title')} (Severity: {d.get('severity')}, MITRE: {d.get('mitre_technique_id')} {d.get('mitre_technique_name')})"
        for d in incident_data.get("detections", [])
    ])

    events_summary = "\n".join([
        f"- [{e.get('timestamp')}] {e.get('event_type')}:{e.get('action')} - Host: {e.get('hostname')}, User: {e.get('username')}, SrcIP: {e.get('source_ip')}, Cmd: {e.get('command') or e.get('raw_message')}"
        for e in incident_data.get("events", [])[:20]  # Limit to 20 representative events to preserve context
    ])

    return f"""INCIDENT OVERVIEW:
ID: {incident_data.get('id')}
Title: {incident_data.get('title')}
Current Severity: {incident_data.get('severity')} (Calculated Risk Score: {incident_data.get('risk_score')}/100)
Host: {incident_data.get('hostname')} (Agent ID: {incident_data.get('agent_id')})
Source IP: {incident_data.get('source_ip')}
Target Username: {incident_data.get('username')}
First Seen: {incident_data.get('first_seen')}
Last Seen: {incident_data.get('last_seen')}
Risk Explanation: {incident_data.get('risk_explanation')}

TRIGGERED DETECTIONS ({len(incident_data.get('detections', []))}):
{detections_summary if detections_summary else "None"}

ASSOCIATED TELEMETRY EVIDENCE ({len(incident_data.get('events', []))} events):
{events_summary if events_summary else "No raw events attached"}

Analyze this incident thoroughly and output valid JSON conforming to the requested schema.
"""
