from typing import Dict, Any, Optional

MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt authentication on systems by iterating through credentials."
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts to gain initial access, elevate privileges, or evade detection."
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions (e.g., sudo abuse)."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (such as bash, sh, Python, PowerShell) to execute commands."
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable targets."
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection by network monitoring systems."
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may log in to remote systems to execute commands and move within an enterprise network."
    }
}

def get_technique(technique_id: str) -> Optional[Dict[str, str]]:
    return MITRE_TECHNIQUES.get(technique_id)

def enrich_mitre_data(technique_id: Optional[str]) -> Dict[str, Any]:
    if not technique_id or technique_id not in MITRE_TECHNIQUES:
        return {
            "id": technique_id or "UNKNOWN",
            "name": "Generic Security Technique",
            "tactic": "Unknown",
            "description": "Unclassified technique."
        }
    return MITRE_TECHNIQUES[technique_id]
