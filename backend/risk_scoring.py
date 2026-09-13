from typing import List, Dict, Any, Tuple
from datetime import datetime
from backend.models import Alert
from backend.mitre import get_technique

SEVERITY_WEIGHTS = {
    "CRITICAL": 45,
    "HIGH": 30,
    "MEDIUM": 18,
    "LOW": 8,
    "INFO": 3,
}

TECHNIQUE_WEIGHTS = {
    "T1078": 20,  # Account Compromise
    "T1548": 18,  # Privilege Escalation
    "T1071": 18,  # Command & Control Outbound
    "T1059": 14,  # Execution
    "T1110": 12,  # Brute Force
    "T1046": 8,   # Discovery
}

def calculate_incident_risk_score(alerts: List[Alert]) -> Tuple[float, str, str]:
    """
    Computes a deterministic risk score (0-100), overall severity,
    and a clear explanation breakdown from correlated alerts.
    """
    if not alerts:
        return 0.0, "LOW", "No alerts associated with this incident."

    factors = []
    base_score = 0.0

    # 1. Base Severity Factor (Highest severity alert + additive for others)
    severities = [a.severity.upper() for a in alerts]
    max_sev = "LOW"
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if s in severities:
            max_sev = s
            break

    primary_sev_score = SEVERITY_WEIGHTS.get(max_sev, 10)
    base_score += primary_sev_score
    factors.append(f"Base severity rating '{max_sev}' contributes +{primary_sev_score} pts")

    # 2. Number of Related Alerts Factor
    alert_count = len(alerts)
    if alert_count > 1:
        count_bonus = min(20.0, (alert_count - 1) * 6.0)
        base_score += count_bonus
        factors.append(f"Multi-event correlation ({alert_count} alerts) adds +{count_bonus:.1f} pts")

    # 3. MITRE Technique Impact Factor
    unique_techniques = set()
    technique_pts = 0
    for a in alerts:
        if a.mitre_technique_id:
            unique_techniques.add(a.mitre_technique_id)

    for tech in unique_techniques:
        pts = TECHNIQUE_WEIGHTS.get(tech, 10)
        technique_pts += pts

    technique_pts = min(30.0, technique_pts)
    if technique_pts > 0:
        base_score += technique_pts
        tech_list_str = ", ".join(unique_techniques)
        factors.append(f"MITRE techniques ({tech_list_str}) add +{technique_pts:.1f} pts")

    # 4. Attack Chain Multi-stage Multiplier
    if len(unique_techniques) >= 3:
        chain_bonus = 15.0
        base_score += chain_bonus
        factors.append(f"Attack progression spanning {len(unique_techniques)} distinct techniques triggers Kill Chain bonus +{chain_bonus:.1f} pts")

    # 5. Temporal Velocity Factor (Event Frequency)
    if len(alerts) >= 2:
        timestamps = sorted([a.timestamp for a in alerts if a.timestamp])
        if timestamps:
            time_delta = (timestamps[-1] - timestamps[0]).total_seconds()
            if time_delta <= 600:  # <= 10 minutes
                velocity_pts = 10.0
                base_score += velocity_pts
                factors.append(f"High-frequency clustering ({int(time_delta)}s between alerts) adds +{velocity_pts:.1f} pts")

    # Clamp score to 0 - 100
    final_score = round(min(100.0, max(5.0, base_score)), 1)

    # Determine aggregated severity
    if final_score >= 80.0:
        severity_label = "CRITICAL"
    elif final_score >= 60.0:
        severity_label = "HIGH"
    elif final_score >= 35.0:
        severity_label = "MEDIUM"
    else:
        severity_label = "LOW"

    explanation = (
        f"Incident evaluated with a risk score of {final_score}/100 ({severity_label}). "
        f"Key risk drivers: {'; '.join(factors)}."
    )

    return final_score, severity_label, explanation
