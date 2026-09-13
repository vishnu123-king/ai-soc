MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact"
}

MITRE_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown."
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "description": "Adversaries may systematically guess passwords to authenticate against network services."
    },
    "T1078.003": {
        "name": "Valid Accounts: Local Accounts",
        "tactic_id": "TA0001",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing local accounts."
    },
    "T1548.003": {
        "name": "Sudo and Sudo Caching",
        "tactic_id": "TA0004",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may perform sudo caching or elevate privileges using sudo rights."
    },
    "T1003.008": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "description": "Adversaries may dump password hashes and user accounts from /etc/shadow or /etc/passwd."
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic_id": "TA0002",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shells (sh, bash) for execution and reverse connections."
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic_id": "TA0007",
        "tactic": "Discovery",
        "description": "Adversaries may get detailed information about the operating system and hardware."
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic_id": "TA0007",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts."
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic_id": "TA0003",
        "tactic": "Persistence",
        "description": "Adversaries may abuse Linux cron to maintain persistent execution of malicious code."
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic_id": "TA0011",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection."
    }
}
