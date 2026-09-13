from typing import Dict, Any, List
from backend.app.mitre.data import MITRE_TECHNIQUES, MITRE_TACTICS

class MitreMapper:
    @staticmethod
    def get_technique(technique_id: str) -> Dict[str, Any]:
        info = MITRE_TECHNIQUES.get(technique_id)
        if info:
            return {
                "id": technique_id,
                "name": info["name"],
                "tactic_id": info["tactic_id"],
                "tactic": info["tactic"],
                "description": info.get("description", "")
            }
        return {
            "id": technique_id,
            "name": "Unknown Technique",
            "tactic_id": "TA0000",
            "tactic": "General Threat",
            "description": ""
        }

    @staticmethod
    def consolidate_techniques(technique_ids: List[str]) -> List[Dict[str, Any]]:
        seen = set()
        consolidated = []
        for tid in technique_ids:
            if tid not in seen:
                seen.add(tid)
                consolidated.append(MitreMapper.get_technique(tid))
        return consolidated

mitre_mapper = MitreMapper()
