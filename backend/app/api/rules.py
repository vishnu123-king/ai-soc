from fastapi import APIRouter
from backend.app.detection.engine import detection_engine
from backend.app.mitre.data import MITRE_TECHNIQUES, MITRE_TACTICS

router = APIRouter()

@router.get("/rules")
def get_rules():
    return [
        {
            "rule_id": r.rule_id,
            "rule_name": r.title,
            "description": r.description,
            "severity": r.severity,
            "confidence": r.confidence,
            "mitre_technique_id": r.mitre_technique_id,
            "mitre_technique_name": r.mitre_technique_name
        }
        for r in detection_engine.rules
    ]

@router.get("/mitre")
def get_mitre():
    return [
        {
            "id": k,
            "name": v["name"],
            "tactic": v["tactic"],
            "tactic_id": v["tactic_id"],
            "description": v.get("description", "")
        }
        for k, v in MITRE_TECHNIQUES.items()
    ]
