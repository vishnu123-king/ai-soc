from typing import List, Dict, Any, Tuple
from backend.app.models.detection import Detection

SEVERITY_WEIGHTS = {
    "LOW": 20.0,
    "MEDIUM": 45.0,
    "HIGH": 75.0,
    "CRITICAL": 95.0
}

TACTIC_KILL_CHAIN_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control",
    "Collection",
    "Exfiltration",
    "Impact"
]

class RiskEngine:
    @staticmethod
    def calculate_risk(detections: List[Detection], mitre_techniques: List[Dict[str, Any]]) -> Tuple[float, str, str]:
        """
        Computes composite risk score (0-100), overall severity level, and a human-readable explanation.
        """
        if not detections:
            return 10.0, "LOW", "No active high-fidelity detections associated with this incident."

        # 1. Base score from max severity detection and cumulative weighted average
        max_base = max(SEVERITY_WEIGHTS.get(d.severity.upper(), 30.0) for d in detections)
        total_weight = sum(SEVERITY_WEIGHTS.get(d.severity.upper(), 30.0) for d in detections)
        count = len(detections)
        
        # Dampened multi-detection accumulation
        combined_score = max_base + (min(total_weight - max_base, 35.0) * 0.4)

        factors = []
        factors.append(f"Base severity from highest detection: {max_base:.0f}")

        # 2. Multi-stage attack chain multiplier (Tactics span)
        tactics_represented = {t.get("tactic") for t in mitre_techniques if t.get("tactic")}
        if len(tactics_represented) >= 3:
            combined_score += 15.0
            factors.append(f"Attack spans {len(tactics_represented)} distinct MITRE ATT&CK tactics (+15 risk)")
        elif len(tactics_represented) >= 2:
            combined_score += 8.0
            factors.append(f"Correlated across {len(tactics_represented)} tactics (+8 risk)")

        # 3. Privilege / Critical Asset impact
        has_root_or_priv = any(
            (d.username == "root") or 
            ("privilege" in d.title.lower()) or 
            ("reverse shell" in d.title.lower()) or
            ("shadow" in d.title.lower())
            for d in detections
        )
        if has_root_or_priv:
            combined_score += 10.0
            factors.append("Involves privileged execution or sensitive root credentials (+10 risk)")

        # Cap score between 10.0 and 100.0
        final_score = max(10.0, min(100.0, round(combined_score, 1)))

        # Determine overall incident severity
        if final_score >= 85.0:
            severity = "CRITICAL"
        elif final_score >= 65.0:
            severity = "HIGH"
        elif final_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        explanation = f"Calculated composite score of {final_score:.1f}/100. " + "; ".join(factors) + "."
        return final_score, severity, explanation

risk_engine = RiskEngine()
